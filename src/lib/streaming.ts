/**
 * PocketStream Desktop — Stream, RTSP server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.ts";
import { $, state, log, showToast, formatUptime } from "./state.ts";
import type { DeviceTarget } from "./store.ts";
import * as deviceList from "./device-list.ts";
import { formatError } from "./errors.ts";
import { getActiveCamTarget } from "./network.ts";
import type { StreamStatus } from "./types.ts";

/** Full RTSP URL (with token) — stored for QR code generation */
let rtspFullUrl: string | null = null;

// ── Video area bounds ───────────────────────────────────────────────

export interface VideoBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export function getVideoAreaBounds(): VideoBounds {
  const el = $("#video-area");
  const rect = el.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  return {
    x: Math.round(rect.x * dpr),
    y: Math.round(rect.y * dpr),
    width: Math.round(rect.width * dpr),
    height: Math.round(rect.height * dpr),
  };
}

// ── Video visibility (centralized) ──────────────────────────────────
//
// The video child is a native Win32 window z-ordered above the WebView
// content. Three independent inputs decide whether it should be visible
// at any moment:
//   - `state.isStreaming` — user wants a stream
//   - `state.streamLost`  — connection dropped, render is stale
//   - `openModalCount`    — number of modals currently demanding the
//                            screen unobstructed
//
// Every place that flips one of those inputs calls `syncVideoVisibility`
// instead of poking `setVideoVisible(true/false)` directly. Without this
// centralization, a stream reconnect (which calls createVideoWindow,
// born visible) covers any open dialog mid-flight, and a dialog close
// during a lost-stream period would briefly re-show stale video.
//
// Counter rather than DOM check (`dialog[open]`) so the increment can
// happen BEFORE showModal — synchronously gating the video without
// chicken-and-egg ordering with the open attribute.
let openModalCount = 0;

export function syncVideoVisibility(): Promise<void> {
  const wantVisible =
    state.isStreaming && !state.streamLost && openModalCount === 0;
  return api.setVideoVisible(wantVisible).catch(() => {});
}

/**
 * Create the native video child window and immediately reconcile its
 * visibility against `syncVideoVisibility`. The child is born WS_VISIBLE
 * and z-orders above the WebView, so without this reconciliation it
 * covers any open modal — briefly on paths that sync later, permanently
 * on paths that never do. Routing every creation through here keeps the
 * born-visible child from covering a dialog on ANY path (manual start,
 * reconnect, stall recovery, or a future caller), and honours the
 * lost-stream invariant (`streamLost` ⇒ hidden) until a status event
 * flips it back. Callers still sync again after they set the streaming
 * flags, which reveals the video once nothing is obstructing it.
 */
export async function createVideoWindowSynced(bounds: {
  x: number;
  y: number;
  width: number;
  height: number;
}): Promise<string> {
  const handle = await api.createVideoWindow(
    bounds.x,
    bounds.y,
    bounds.width,
    bounds.height
  );
  await syncVideoVisibility();
  return handle;
}

/**
 * Open `dialog` as a modal with the video correctly hidden underneath.
 * Awaiting the returned promise guarantees the video child window is
 * gone before the modal paints (no race where the dialog appears
 * behind the still-visible native video).
 *
 * Auto-decrements the counter on `close` so the video can come back
 * when no other modal is open. Safe to call when another modal is
 * already open (counter handles nesting). `canOpen` rechecks a cancelable
 * request after video IPC; cancellation releases the reservation too.
 * A launch notice may skip the IPC wait before any video window exists.
 */
export async function showModalWithVideo(
  dialog: HTMLDialogElement, canOpen: () => boolean = () => true,
  waitForVideo = true,
): Promise<void> {
  openModalCount++;
  let opened = false;
  try {
    const visibility = syncVideoVisibility();
    if (waitForVideo) await visibility;
    if (!canOpen()) return;
    dialog.showModal();
    dialog.addEventListener(
      "close",
      () => {
        openModalCount = Math.max(0, openModalCount - 1);
        void syncVideoVisibility();
      },
      { once: true }
    );
    opened = true;
  } finally {
    // Cancellation or a failed show must also release the video reservation.
    if (!opened) {
      openModalCount = Math.max(0, openModalCount - 1);
      await syncVideoVisibility();
    }
  }
}

// ── Stream controls ─────────────────────────────────────────────────

// Stuck-input defense for the record button. Phantom touches on the
// Getac touchscreen (electrostatic noise, water droplets, foreign
// objects on a rugged tablet's screen) have driven the record toggle
// into a sub-second start/stop cycle in the field, producing a
// clutter of useless tiny MP4s. Drop any record-button click that
// arrives within RECORD_DEBOUNCE_MS of the previous one — a real
// user can't legitimately need to start+stop a recording faster
// than this. Bump the threshold if a recurrence shows the phantom
// cadence is slower than 1Hz.
const RECORD_DEBOUNCE_MS = 1000;
let lastRecordToggleAt = 0;

// Busy latch for the stream toggle. A touchscreen double-tap used to
// race two full start sequences (two child windows, two pipelines)
// through the same handler before the first await resolved.
let streamToggleBusy = false;

/** Busy latch for the mute toggle (see streamToggleBusy): a double-tap
 *  would compute `next` twice from the same pre-toggle config value and
 *  apply the same state twice instead of toggling back. */
let muteToggleBusy = false;

/** Audio availability from the last stream-status event. Module-local
 *  rather than AppState: nothing outside this file consumes them — the
 *  persisted mute preference itself lives in state.config.stream. */
let audioPresent = false;
let audioCodec: string | null = null;

/** Identity of the playback the user intends to keep, including recovery. */
let activePlaybackTarget: DeviceTarget | null = null;
let playbackRequest = 0;

export function getActivePlaybackTarget(): DeviceTarget | null { return activePlaybackTarget; }

/** Every start preserves the intended MAC beside the current endpoint.
 *  The route/freshness readiness gate is added by S6. */
async function persistPlaybackTarget(target: DeviceTarget): Promise<void> {
  const record = deviceList.resolveTarget(target);
  if (!record || record.alias === "PTU" || record.ip.startsWith("169.254.")) {
    throw new Error("Selected device is unavailable; select a node before starting");
  }
  if (!state.config) throw new Error("Stream settings are not loaded");
  state.config.stream.camera_ip = record.ip;
  state.config.stream.camera_mac = deviceList.targetFor(record).expectedMac;
  await api.updateStreamSettings(state.config.stream);
}

/** Stop the stream and reset every piece of frontend stream state.
 *  Flags flip before the async stop so an in-flight status event
 *  can't race a false "Stream Lost"; the playback request is cancelled so a
 *  stopped stream never auto-resumes on a later reconnect; and the
 *  recording indicator resets — the backend finalizes an in-progress
 *  recording (EOS flush) inside the stop itself. Idempotent: safe
 *  when nothing is streaming, and safe mid-start (the backend
 *  playback epoch makes a late start observe the stop). */
export async function stopStreamNow(message = "Stream stopped"): Promise<void> {
  playbackRequest++;
  state.isStreaming = false;
  state.streamLost = false;
  activePlaybackTarget = null;
  hideStreamLost();
  state.isRecording = false;
  $("#btn-record").classList.remove("recording");
  try {
    await api.stopStream();
    updateStreamUI();
    showToast(message);
  } catch (e) {
    showToast("Failed to stop: " + formatError(e), true);
  }
}

export function setupStreamControls(): void {
  $<HTMLButtonElement>("#btn-toggle-stream").addEventListener("click", async () => {
    if (streamToggleBusy) return;
    streamToggleBusy = true;
    const toggleBtn = $<HTMLButtonElement>("#btn-toggle-stream");
    toggleBtn.disabled = true;
    try {
      if (state.isStreaming) {
        await stopStreamNow();
      } else {
        try {
          const request = ++playbackRequest;
          const udp = state.config?.stream.protocol === "udp";
          const target = udp ? null : getActiveCamTarget();
          if (!udp && !target) {
            showToast("Pick a node first (click it in the Nodes panel)", true);
            return;
          }
          // Claim the playback identity before the slow awaits so a
          // concurrent teardown (role change) can observe and cancel
          // this start.
          activePlaybackTarget = target;
          if (target) await persistPlaybackTarget(target);
          if (request !== playbackRequest) return;
          const bounds = getVideoAreaBounds();
          // createVideoWindowSynced hides the born-visible child if a
          // dialog is open, so it can't cover one before startStream
          // returns. A second sync after the flags flip reveals it.
          state.isStreaming = true;
          state.streamLost = true;
          updateStreamUI();
          const handle = await createVideoWindowSynced(bounds);
          if (request !== playbackRequest) {
            await api.stopStream().catch(() => {});
            return;
          }
          await api.startStream(handle);
          if (request !== playbackRequest) {
            // A teardown landed while the start was in flight (the
            // backend playback epoch already observed its stop) —
            // make sure this just-started pipeline and its video
            // child are gone rather than resurrecting the UI state.
            await api.stopStream().catch(() => {});
            updateStreamUI();
            return;
          }
          state.isStreaming = true;
          updateStreamUI();
          syncVideoVisibility();
          showToast("Playback requested");
        } catch (e) {
          activePlaybackTarget = null;
          state.isStreaming = false;
          hideStreamLost();
          updateStreamUI();
          showToast("Stream failed: " + formatError(e), true);
        }
      }
    } finally {
      streamToggleBusy = false;
      toggleBtn.disabled = false;
    }
  });

  $<HTMLButtonElement>("#btn-screenshot").addEventListener("click", async () => {
    try {
      const path = await api.takeScreenshot();
      showToast("Screenshot saved: " + path);
    } catch (e) {
      showToast("Screenshot failed: " + formatError(e), true);
    }
  });

  $<HTMLButtonElement>("#btn-mute").addEventListener("click", async () => {
    if (muteToggleBusy) return;
    muteToggleBusy = true;
    const next = !(state.config?.stream.audio_muted ?? false);
    try {
      await api.setAudioMuted(next);
      // Keep the shared config in sync so a later Settings save or
      // path switch (both send state.config.stream wholesale) can't
      // revert the preference the backend just persisted.
      if (state.config) {
        state.config.stream.audio_muted = next;
      }
      updateMuteButton();
    } catch (e) {
      showToast(`Failed to ${next ? "mute" : "unmute"} audio: ` + formatError(e), true);
    } finally {
      muteToggleBusy = false;
    }
  });

  $<HTMLButtonElement>("#btn-record").addEventListener("click", async () => {
    const now = Date.now();
    const sinceLast = now - lastRecordToggleAt;
    if (sinceLast < RECORD_DEBOUNCE_MS) {
      // Logged so a stuck-input event in the wild leaves a
      // breadcrumb instead of failing silently.
      log(`Record click ignored (${sinceLast}ms since last toggle)`);
      return;
    }
    lastRecordToggleAt = now;

    if (state.isRecording) {
      try {
        const path = await api.stopRecording();
        state.isRecording = false;
        $("#btn-record").classList.remove("recording");
        showToast("Recording saved: " + path);
      } catch (e) {
        // Backend keeps its recording state on a failed finalize so the
        // user can retry — stay in sync by keeping ours too.
        showToast(formatError(e), true);
      }
    } else {
      try {
        await api.startRecording();
        state.isRecording = true;
        $("#btn-record").classList.add("recording");
        showToast("Recording started");
      } catch (e) {
        // A rejected start (no playback, already recording) used to
        // reject unhandled — no toast, and the button state could
        // drift from the backend.
        showToast(formatError(e), true);
        state.isRecording = false;
        $("#btn-record").classList.remove("recording");
      }
    }
  });
}

// ── Stream UI updates ───────────────────────────────────────────────

export function updateStreamUI(): void {
  const btn = $<HTMLButtonElement>("#btn-toggle-stream");
  btn.textContent = state.isStreaming ? "Stop Stream" : "Start Stream";
  btn.className = state.isStreaming ? "outlined-btn active-btn" : "filled-btn";
  // Screenshot and record need a healthy pipeline — disable them while
  // the stream is lost even though isStreaming is still true (the user
  // intends to stream; the stream just isn't alive right now).
  const canInteract = state.isStreaming && !state.streamLost;
  $<HTMLButtonElement>("#btn-screenshot").disabled = !canInteract;
  $<HTMLButtonElement>("#btn-record").disabled = !canInteract;
  updateMuteButton();

  const area = $("#video-area");
  const placeholder = area.querySelector<HTMLElement>(".placeholder-text");
  if (!placeholder) return;
  if (state.isStreaming) {
    placeholder.style.display = "none";
  } else {
    placeholder.style.display = "";
    placeholder.textContent = "Select a camera and start stream";
  }
}

/** Single renderer for the mute button: enabled only while a healthy
 *  stream is carrying audio; muted visual from the persisted
 *  preference; codec named in the tooltip when known. Exported so init
 *  can paint the persisted state as soon as config loads. */
export function updateMuteButton(): void {
  const btn = $<HTMLButtonElement>("#btn-mute");
  btn.disabled = !(state.isStreaming && !state.streamLost && audioPresent);
  const muted = state.config?.stream.audio_muted ?? false;
  btn.classList.toggle("muted", muted);
  const action = muted ? "Unmute audio" : "Mute audio";
  btn.title = audioCodec ? `${action} (${audioCodec})` : action;
}

// ── RTSP server controls ────────────────────────────────────────────

/** Busy latch for the RTSP toggle (see streamToggleBusy). */
let rtspToggleBusy = false;

/**
 * Re-derive the RTSP Start button's enabled state from the Enable
 * checkbox. `loadConfig` sets `.checked` programmatically, which fires
 * no `change` event — without this call, a user whose config has the
 * server enabled got a dead Start button until they toggled the
 * checkbox off and on.
 */
export function syncRtspStartButton(): void {
  const startBtn = $<HTMLButtonElement>("#btn-toggle-rtsp");
  startBtn.disabled = state.isRtspDesired
    ? false
    : !$<HTMLInputElement>("#rtsp-server-enable").checked;
}

export function setupRtspControls(): void {
  // The Enable toggle is also a kill switch: turning it off while the
  // server is running stops it immediately (rather than only blocking
  // a future start). Persistence still happens on Save Settings — the
  // toggle change here only affects live state.
  const enableToggle = $<HTMLInputElement>("#rtsp-server-enable");
  const startBtn = $<HTMLButtonElement>("#btn-toggle-rtsp");
  startBtn.disabled = !enableToggle.checked;
  enableToggle.addEventListener("change", async () => {
    startBtn.disabled = !enableToggle.checked;
    if (!enableToggle.checked && state.isRtspDesired) {
      try {
        await api.stopRtspServer();
        state.isRtspDesired = false;
        updateRtspUI(null);
        showToast("RTSP server stopped");
      } catch (e) {
        showToast("Failed to stop RTSP server: " + formatError(e), true);
      }
    }
  });

  // Populate VPN dropdown in background — don't block other setup
  populateVpnDropdown();

  $<HTMLSelectElement>("#rtsp-bind-interface").addEventListener("change", async () => {
    if (!state.config) return;
    state.config.rtsp_server.bind_interface = $<HTMLSelectElement>(
      "#rtsp-bind-interface"
    ).value;
    try {
      await api.updateRtspSettings(state.config.rtsp_server);
    } catch (e) {
      showToast("Failed to save VPN selection: " + formatError(e), true);
    }
  });

  $<HTMLButtonElement>("#btn-toggle-rtsp").addEventListener("click", async () => {
    // Same double-tap defense as the stream toggle.
    if (rtspToggleBusy) return;
    rtspToggleBusy = true;
    startBtn.disabled = true;

    const spinner = $<HTMLElement>("#rtsp-spinner");
    spinner.style.display = "";

    if (state.isRtspDesired) {
      try {
        await api.stopRtspServer();
        state.isRtspDesired = false;
        updateRtspUI(null);
        showToast("RTSP server stopped");
      } catch (e) {
        showToast("Failed to stop: " + formatError(e), true);
      }
    } else {
      try {
        // bind_interface is persisted by the dropdown's change handler,
        // so don't re-copy the <select> value here. During startup the
        // VPN options are still being populated asynchronously and the
        // select can briefly read empty; writing that back would wipe
        // the saved interface.
        const target = getActiveCamTarget();
        if (state.config?.stream.protocol !== "udp") {
          if (!target) throw new Error("Pick a node before starting the RTSP server");
          await persistPlaybackTarget(target);
        }
        const info = await api.startRtspServer();
        state.isRtspDesired = true;
        rtspFullUrl = info.rtsp_url;
        updateRtspUI(info.display_url);
        showToast("RTSP server started");
      } catch (e) {
        showToast("RTSP server failed: " + formatError(e), true);
      }
    }

    spinner.style.display = "none";
    rtspToggleBusy = false;
    // updateRtspUI ran in the happy paths; re-derive here so a thrown
    // start/stop doesn't leave the button stuck disabled.
    startBtn.disabled = state.isRtspDesired ? false : !enableToggle.checked;
  });

  // QR code button + dialog
  setupQrDialog();
}

async function populateVpnDropdown(): Promise<void> {
  const select = $<HTMLSelectElement>("#rtsp-bind-interface");
  try {
    const vpns = (await api.listVpnInterfaces()).filter((i) => i.ips.length > 0);
    for (const iface of vpns) {
      const opt = document.createElement("option");
      opt.value = iface.name;
      const firstIp = iface.ips[0];
      opt.textContent = firstIp ? `${iface.name} (${firstIp.address})` : iface.name;
      select.appendChild(opt);
    }
    // Restore saved selection
    if (state.config && state.config.rtsp_server.bind_interface) {
      select.value = state.config.rtsp_server.bind_interface;
    }
  } catch (e) {
    console.warn("Failed to list VPN interfaces:", e);
  }
}

function updateRtspUI(displayUrl: string | null, status?: StreamStatus): void {
  const btn = $<HTMLButtonElement>("#btn-toggle-rtsp");
  btn.textContent = state.isRtspDesired ? "Stop Server" : "Start Server";
  // Always allow stopping, including while the listener is rebuilding.
  btn.disabled = state.isRtspDesired
    ? false
    : !$<HTMLInputElement>("#rtsp-server-enable").checked;

  const statusEl = $("#rtsp-status");
  const qrBtn = $<HTMLButtonElement>("#btn-show-qr");
  const errorRow = $("#rtsp-error-row");
  const errorEl = $("#rtsp-error");

  if (state.isRtspDesired) {
    const relayState = status?.rtsp_relay_state ?? "starting";
    switch (relayState) {
      case "listening":
      case "streaming":
        statusEl.textContent = "Online";
        statusEl.className = "status-value status-online";
        break;
      case "recovering":
        statusEl.textContent = status?.rtsp_recovery_attempt
          ? `Reconnecting (attempt ${status.rtsp_recovery_attempt})`
          : "Reconnecting";
        statusEl.className = "status-value status-warning";
        break;
      case "failed":
        statusEl.textContent = "Failed";
        statusEl.className = "status-value status-warning";
        break;
      default:
        statusEl.textContent = "Starting";
        statusEl.className = "status-value status-warning";
        break;
    }
    $("#rtsp-url").textContent = displayUrl || "--";
    qrBtn.disabled = !rtspFullUrl;
    const error = status?.rtsp_error ?? null;
    errorEl.textContent = error || "";
    errorRow.style.display = error ? "contents" : "none";
  } else {
    statusEl.textContent = "Offline";
    statusEl.className = "status-value status-offline";
    $("#rtsp-url").textContent = "--";
    $("#rtsp-uptime").textContent = "--";
    $("#rtsp-clients").textContent = "--";
    $("#rtsp-bandwidth").textContent = "--";
    errorEl.textContent = "";
    errorRow.style.display = "none";
    rtspFullUrl = null;
    qrBtn.disabled = true;
  }
}

// ── QR Code Dialog ──────────────────────────────────────────────────

function setupQrDialog(): void {
  const dialog = $<HTMLDialogElement>("#qr-dialog");
  const qrBtn = $<HTMLButtonElement>("#btn-show-qr");
  const closeBtn = $<HTMLButtonElement>("#qr-close");

  qrBtn.addEventListener("click", async () => {
    if (!rtspFullUrl) return;

    // Show dialog first so the canvas is in the visible DOM —
    // rendering to a canvas inside a hidden <dialog> can produce
    // blank output on some WebView2 / Chromium builds.
    $("#qr-url").textContent = rtspFullUrl;
    await showModalWithVideo(dialog);

    const canvas = $<HTMLCanvasElement>("#qr-canvas");
    try {
      await QRCode.toCanvas(canvas, rtspFullUrl, {
        width: 256,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
      });
    } catch (e) {
      log(`QR code generation failed: ${formatError(e)}`);
      showToast("Failed to generate QR code", true);
    }
  });

  closeBtn.addEventListener("click", () => dialog.close());

  // Click URL to copy to clipboard
  $("#qr-url").addEventListener("click", async () => {
    const url = $("#qr-url").textContent;
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      $("#qr-copy-hint").textContent = "Copied!";
      setTimeout(() => {
        $("#qr-copy-hint").textContent = "Click URL to copy to clipboard";
      }, 2000);
    } catch (_) {
      showToast("Failed to copy", true);
    }
  });

  // Close on backdrop click
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });
}

// ── Status events ───────────────────────────────────────────────────
//
// Backend pushes `stream-status` events whenever the snapshot changes
// (1Hz internal ticker plus an immediate refresh after every command-
// side mutation). Frontend subscribes once at startup; no polling.

let lastRecordingReport: string | null = null;

/** Subscribe to backend stream-status push events. Call once at app
 *  startup. Replaces the old setInterval(pollStatus, 1000). */
export function startStatusListener(): void {
  api.onEvent<StreamStatus>("stream-status", handleStatus);
}

function handleStatus(status: StreamStatus | null): void {
  if (!status) return;

  // Heal webview-reload desync from backend-owned desired and health state.
  // Listener liveness may be false during recovery without making the relay
  // an actionable Start state in the UI.
  state.isRtspDesired = status.rtsp_desired;
  if (status.rtsp_url) {
    rtspFullUrl = status.rtsp_url;
  }
  updateRtspUI(status.display_url ?? null, status);

  if (status.rtsp_desired) {
    $("#rtsp-uptime").textContent = formatUptime(status.uptime_secs);
    $("#rtsp-clients").textContent =
      `${status.rtsp_connected_clients} / ${status.rtsp_client_limit}`;
    $("#rtsp-bandwidth").textContent = `${status.bandwidth_kbps.toFixed(1)} kbps`;
  }

  // Audio availability drives the mute button. Change-detected so the
  // 1 Hz ticker doesn't re-render the button every second.
  if (status.audio_present !== audioPresent || status.audio_codec !== audioCodec) {
    audioPresent = status.audio_present;
    audioCodec = status.audio_codec;
    updateMuteButton();
  }

  state.isStreaming = status.playback_desired;
  state.isRecording = status.recording;
  $("#btn-record").classList.toggle("recording", status.recording);
  const recordingReport = status.recording_report
    ? `${status.recording_report}${status.recording_finalized_path ? `: ${status.recording_finalized_path}` : ""}` : null;
  if (recordingReport && recordingReport !== lastRecordingReport) showToast(recordingReport, true);
  lastRecordingReport = recordingReport;
  if (status.playback_desired && status.playback_state !== "playing") showStreamLost(status);
  else hideStreamLost();
  updateStreamUI();
}

/** Compatibility hook for the NIC UI; backend readiness owns fault detection. */
export function handleHardDisconnect(reason: string): void {
  log(`Ethernet unavailable: ${reason}`);
}

/** Reassert existing backend intent, preserving its exact source and identity. */
export async function handleReconnect(): Promise<void> {
  if (!state.isStreaming) return;
  try { await api.reassertPlayback(); }
  catch (e) { log(`Playback readiness wake failed: ${formatError(e)}`); }
}

/** Render only. Submission and handshake never hide this overlay. */
function showStreamLost(status: StreamStatus): void {
  state.streamLost = true;
  void syncVideoVisibility();
  const area = $("#video-area");
  let overlay = area.querySelector<HTMLDivElement>(".stream-lost-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "stream-lost-overlay";
    overlay.style.cssText = "flex-direction: column; gap: 16px; padding: 24px; text-align: center";
    const label = document.createElement("span");
    label.className = "playback-reason";
    const retry = document.createElement("button");
    retry.className = "outlined-btn";
    retry.textContent = "Retry";
    retry.addEventListener("click", async () => {
      retry.disabled = true;
      try { await api.retryPlayback(); }
      catch (e) { showToast("Retry failed: " + formatError(e), true); }
      finally { retry.disabled = false; }
    });
    overlay.append(label, retry);
    area.appendChild(overlay);
  }
  const reason = status.playback_fault?.reason;
  const recovering = status.playback_state === "recovering"
    || (status.playback_state === "starting" && status.playback_fault !== null);
  const message = recovering
    ? `Network Error: Check link. Retrying in ${status.playback_next_retry_secs ?? 0}s…`
    : status.playback_state === "failed" ? `Playback failed${reason ? `: ${reason}` : ""}` : "Connecting";
  overlay.querySelector<HTMLElement>(".playback-reason")!.textContent = message;
  overlay.classList.add("visible");
}

function hideStreamLost(): void {
  state.streamLost = false;
  void syncVideoVisibility();
  $("#video-area").querySelector(".stream-lost-overlay")?.classList.remove("visible");
}

// ── Video resize handler ────────────────────────────────────────────

export function setupVideoResize(): void {
  let resizeTimer: ReturnType<typeof setTimeout> | null = null;
  window.addEventListener("resize", () => {
    if (!state.isStreaming) return;
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(async () => {
      try {
        const bounds = getVideoAreaBounds();
        await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
      } catch (_) {}
    }, 50);
  });
}
