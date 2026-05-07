/**
 * PocketStream Desktop — Stream, RTSP server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.ts";
import { $, state, log, showToast, formatUptime } from "./state.ts";
import { formatError } from "./errors.ts";
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
 * Open `dialog` as a modal with the video correctly hidden underneath.
 * Awaiting the returned promise guarantees the video child window is
 * gone before the modal paints (no race where the dialog appears
 * behind the still-visible native video).
 *
 * Auto-decrements the counter on `close` so the video can come back
 * when no other modal is open. Safe to call when another modal is
 * already open (counter handles nesting).
 */
export async function showModalWithVideo(dialog: HTMLDialogElement): Promise<void> {
  openModalCount++;
  await syncVideoVisibility();
  dialog.showModal();
  dialog.addEventListener(
    "close",
    () => {
      openModalCount = Math.max(0, openModalCount - 1);
      syncVideoVisibility();
    },
    { once: true }
  );
}

// ── Stream controls ─────────────────────────────────────────────────

export function setupStreamControls(): void {
  $<HTMLButtonElement>("#btn-toggle-stream").addEventListener("click", async () => {
    if (state.isStreaming) {
      try {
        // Set flags BEFORE the async stop so an in-flight status event
        // doesn't race and trigger a false "Stream Lost".
        state.isStreaming = false;
        state.streamLost = false;
        // User asked to stop — don't auto-resume on a later reconnect.
        resumeSnapshot = null;
        // Clear any stuck overlay from an earlier drop in this session.
        hideStreamLost();
        await api.stopStream();
        updateStreamUI();
        showToast("Stream stopped");
      } catch (e) {
        showToast("Failed to stop: " + formatError(e), true);
      }
    } else {
      try {
        const selectedIp = $<HTMLSelectElement>("#camera-ip").value;
        if (!selectedIp) {
          showToast("Select a camera IP first", true);
          return;
        }
        if (state.config) {
          state.config.stream.camera_ip = selectedIp;
          await api.saveConfig(state.config);
        }
        const bounds = getVideoAreaBounds();
        const handle = await api.createVideoWindow(
          bounds.x,
          bounds.y,
          bounds.width,
          bounds.height
        );
        // Newly-created child window is born visible (WS_VISIBLE). If a
        // dialog happens to be open right now, sync immediately so the
        // child doesn't briefly cover it before startStream returns.
        syncVideoVisibility();
        await api.startStream(handle);
        state.isStreaming = true;
        updateStreamUI();
        syncVideoVisibility();
        notPlayingStreak = 0;
        showToast("Stream started");
      } catch (e) {
        showToast("Stream failed: " + formatError(e), true);
      }
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

  $<HTMLButtonElement>("#btn-record").addEventListener("click", async () => {
    if (state.isRecording) {
      const path = await api.stopRecording();
      state.isRecording = false;
      $("#btn-record").classList.remove("recording");
      showToast("Recording saved: " + path);
    } else {
      await api.startRecording();
      state.isRecording = true;
      $("#btn-record").classList.add("recording");
      showToast("Recording started");
    }
  });
}

// ── Stream UI updates ───────────────────────────────────────────────

function updateStreamUI(): void {
  const btn = $<HTMLButtonElement>("#btn-toggle-stream");
  btn.textContent = state.isStreaming ? "Stop Stream" : "Start Stream";
  btn.className = state.isStreaming ? "outlined-btn active-btn" : "filled-btn";
  // Screenshot and record need a healthy pipeline — disable them while
  // the stream is lost even though isStreaming is still true (the user
  // intends to stream; the stream just isn't alive right now).
  const canInteract = state.isStreaming && !state.streamLost;
  $<HTMLButtonElement>("#btn-screenshot").disabled = !canInteract;
  $<HTMLButtonElement>("#btn-record").disabled = !canInteract;

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

// ── RTSP server controls ────────────────────────────────────────────

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
    if (!enableToggle.checked && state.isRtspRunning) {
      try {
        await api.stopRtspServer();
        state.isRtspRunning = false;
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
      await api.saveConfig(state.config);
    } catch (e) {
      showToast("Failed to save VPN selection: " + formatError(e), true);
    }
  });

  $<HTMLButtonElement>("#btn-toggle-rtsp").addEventListener("click", async () => {
    const spinner = $<HTMLElement>("#rtsp-spinner");
    spinner.style.display = "";

    if (state.isRtspRunning) {
      try {
        await api.stopRtspServer();
        state.isRtspRunning = false;
        updateRtspUI(null);
        showToast("RTSP server stopped");
      } catch (e) {
        showToast("Failed to stop: " + formatError(e), true);
      }
    } else {
      try {
        // Save bind_interface selection before starting
        if (state.config) {
          state.config.rtsp_server.bind_interface = $<HTMLSelectElement>(
            "#rtsp-bind-interface"
          ).value;
          await api.saveConfig(state.config);
        }
        const info = await api.startRtspServer();
        state.isRtspRunning = true;
        rtspFullUrl = info.rtsp_url;
        updateRtspUI(info.display_url);
        showToast("RTSP server started");
      } catch (e) {
        showToast("RTSP server failed: " + formatError(e), true);
      }
    }

    spinner.style.display = "none";
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

function updateRtspUI(displayUrl: string | null): void {
  const btn = $<HTMLButtonElement>("#btn-toggle-rtsp");
  btn.textContent = state.isRtspRunning ? "Stop Server" : "Start Server";
  // Always allow stopping; respect Enable toggle when stopped
  btn.disabled = state.isRtspRunning
    ? false
    : !$<HTMLInputElement>("#rtsp-server-enable").checked;

  const statusEl = $("#rtsp-status");
  const qrBtn = $<HTMLButtonElement>("#btn-show-qr");

  if (state.isRtspRunning) {
    statusEl.textContent = "Online";
    statusEl.className = "status-value status-online";
    $("#rtsp-url").textContent = displayUrl || "--";
    qrBtn.disabled = false;
  } else {
    statusEl.textContent = "Offline";
    statusEl.className = "status-value status-offline";
    $("#rtsp-url").textContent = "--";
    $("#rtsp-uptime").textContent = "--";
    $("#rtsp-bandwidth").textContent = "--";
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
      console.error("QR code generation failed:", e);
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

// Require the backend to report `playing=false` across N consecutive
// status events before declaring the stream lost. A single blip
// (transient state transition, RTCP jitter, GStreamer bus race)
// self-heals on the next event and shouldn't nuke an otherwise-healthy
// stream. The backend ticks at 1Hz, so this is ~3 seconds.
const DROP_THRESHOLD_EVENTS = 3;
let notPlayingStreak = 0;

// ── Stall auto-recovery ─────────────────────────────────────────────
//
// When health_check reports "Stream stalled — no frames for Ns" the
// pipeline is sitting on a TCP socket the OS still thinks is alive
// (default Windows keepalive is 2 hours). Manually clicking
// stop/start would fix it but the user shouldn't have to babysit a
// long-running camera. Auto-restart with backoff: try immediately,
// then 60s, then 60s. After three failed attempts fall through to
// the manual "Stream Lost" UX so we don't loop on a genuinely broken
// camera.
const STALL_RETRY_SCHEDULE_MS = [0, 60_000, 60_000];
let stallRetryIndex = 0;
let stallRetryTimer: ReturnType<typeof setTimeout> | null = null;

function isStallError(msg: string | null | undefined): boolean {
  return !!msg && msg.toLowerCase().includes("stalled");
}

/** Subscribe to backend stream-status push events. Call once at app
 *  startup. Replaces the old setInterval(pollStatus, 1000). */
export function startStatusListener(): void {
  api.onEvent<StreamStatus>("stream-status", handleStatus);
}

function handleStatus(status: StreamStatus | null): void {
  if (!status) return;

  if (status.rtsp_server_running) {
    $("#rtsp-uptime").textContent = formatUptime(status.uptime_secs);
    $("#rtsp-bandwidth").textContent = `${status.bandwidth_kbps.toFixed(1)} kbps`;
    // Keep rtspFullUrl in sync — it may have been cleared by a
    // transient stream-loss event while the server kept running.
    if (!rtspFullUrl && status.rtsp_url) {
      rtspFullUrl = status.rtsp_url;
    }
  }

  // Detect stream drop — backend says not playing but we think we're streaming
  if (state.isStreaming && !status.playing) {
    notPlayingStreak++;
    if (notPlayingStreak >= DROP_THRESHOLD_EVENTS) {
      showStreamLost(status.error);
    }
  } else if (state.isStreaming && status.playing) {
    if (notPlayingStreak > 0) {
      log(`Stream recovered after ${notPlayingStreak} bad event(s)`);
    }
    notPlayingStreak = 0;
    hideStreamLost();
  }
}

interface ResumeSnapshot {
  cameraIp: string | null;
  ptuIp: string | null;
  wasRtspRunning: boolean;
}

/** Stream state captured at the moment of a hard network disconnect,
 *  so we can re-start the stream (and any associated RTSP server) as
 *  soon as the link comes back. Cleared on manual stop or after a
 *  successful resume. */
let resumeSnapshot: ResumeSnapshot | null = null;

/** Called by the interface watcher when it detects a physical unplug /
 *  APIPA-only state. Bypasses the poll debounce so the user gets
 *  immediate "Stream Lost..." feedback instead of waiting for GStreamer
 *  to time out. Captures what was running so handleReconnect() can
 *  put it back together on replug. */
export function handleHardDisconnect(reason: string): void {
  if (state.isStreaming && !state.streamLost) {
    resumeSnapshot = {
      cameraIp:
        $<HTMLSelectElement>("#camera-ip").value ||
        state.config?.stream?.camera_ip ||
        null,
      ptuIp: $<HTMLSelectElement>("#ptu-ip").value || null,
      wasRtspRunning: !!state.isRtspRunning,
    };
    log(`Stream lost on network disconnect: ${reason}`);
    showStreamLost(reason);
  }
}

/** Called by the interface watcher on reconnect (wasDown=true).
 *  Restores dropdown selections and restarts the stream + RTSP server
 *  if they were running before the disconnect. */
export async function handleReconnect(): Promise<void> {
  if (!resumeSnapshot) return;
  const snap = resumeSnapshot;
  resumeSnapshot = null;

  // Give Windows + auto-adopt a moment to finish re-binding IPs and
  // routes before we try to open a socket to the camera. Two seconds
  // is long enough to catch most settling but short enough to feel
  // responsive when the user's waiting for the stream to come back.
  await new Promise((r) => setTimeout(r, 2000));

  // Restore dropdown selections (dropdown may have been repopulated
  // during reconnect; set values explicitly so the pre-disconnect
  // choices are back).
  if (snap.cameraIp) {
    const camSelect = $<HTMLSelectElement>("#camera-ip");
    camSelect.value = snap.cameraIp;
    if (state.config) {
      state.config.stream.camera_ip = snap.cameraIp;
    }
  }
  if (snap.ptuIp) $<HTMLSelectElement>("#ptu-ip").value = snap.ptuIp;

  if (!snap.cameraIp) return;

  try {
    const bounds = getVideoAreaBounds();
    const handle = await api.createVideoWindow(
      bounds.x,
      bounds.y,
      bounds.width,
      bounds.height
    );
    await api.startStream(handle);
    state.isStreaming = true;
    state.streamLost = false;
    hideStreamLost();
    updateStreamUI();
    notPlayingStreak = 0;
    showToast("Stream resumed");

    // RTSP server was running — bring it back too. Errors here aren't
    // fatal (the stream is already back); toast and move on.
    if (snap.wasRtspRunning) {
      try {
        const info = await api.startRtspServer();
        state.isRtspRunning = true;
        rtspFullUrl = info.rtsp_url;
        updateRtspUI(info.display_url);
      } catch (e) {
        log(`RTSP auto-resume failed: ${formatError(e)}`);
        showToast("Stream back — RTSP server failed to resume", true);
      }
    }
  } catch (e) {
    log(`Stream auto-resume failed: ${formatError(e)}`);
    showToast("Auto-resume failed — restart stream manually", true);
  }
}

function showStreamLost(errorMsg: string | null | undefined): void {
  if (state.streamLost) return;
  state.streamLost = true;
  notPlayingStreak = 0;

  // Hide stale video frame and show overlay. Overlay defaults to
  // display:none via CSS; the .visible class is what reveals it.
  syncVideoVisibility();
  const area = $("#video-area");
  let overlay = area.querySelector<HTMLDivElement>(".stream-lost-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "stream-lost-overlay";
    overlay.textContent = "Stream Lost...";
    area.appendChild(overlay);
  }
  overlay.classList.add("visible");

  // Reset stream and RTSP server
  api.stopStream().catch(() => {});
  if (state.isRtspRunning) {
    api.stopRtspServer().catch(() => {});
    state.isRtspRunning = false;
    updateRtspUI(null);
  }
  // Deliberately leave state.isStreaming = true: the user's intent is
  // still "I want to stream", the connection just failed. Keeps the
  // button labelled "Stop Stream" so clicking it means "give up", not
  // "start fresh". The status-event subscriber keeps running so
  // recovery is detected on the next push.
  state.isRecording = false;
  $("#btn-record").classList.remove("recording");
  updateStreamUI();

  // Show the actual GStreamer error if available
  const reason = errorMsg || "connection dropped";
  showToast("Stream lost — " + reason, true);

  if (isStallError(errorMsg)) {
    scheduleStallRecovery();
  }
}

function hideStreamLost(): void {
  state.streamLost = false;
  // Reset the drop-detection streak: during the lost window the status
  // listener kept counting every `playing=false` event (often 10+),
  // which would otherwise instantly re-fire showStreamLost on the
  // next event after handleReconnect resets the lost state — faster
  // than the newly-started pipeline can reach Playing.
  notPlayingStreak = 0;
  // Stream is healthy again — reset the auto-recovery counter and
  // cancel any pending retry. This also covers the "user manually
  // stopped" case indirectly: the next status event with playing=true
  // can't happen if state.isStreaming is false, but if the user
  // restarts and the previous run had retries pending, those should
  // not carry over.
  stallRetryIndex = 0;
  if (stallRetryTimer) {
    clearTimeout(stallRetryTimer);
    stallRetryTimer = null;
  }
  // syncVideoVisibility leaves the video hidden if a dialog is open —
  // dialog close handler will sync again and reveal it then.
  syncVideoVisibility();
  const overlay = $("#video-area").querySelector(".stream-lost-overlay");
  if (overlay) overlay.classList.remove("visible");
}

function scheduleStallRecovery(): void {
  if (stallRetryIndex >= STALL_RETRY_SCHEDULE_MS.length) {
    log(
      `Stall recovery exhausted after ${STALL_RETRY_SCHEDULE_MS.length} attempts; manual restart required`
    );
    return;
  }
  const delay = STALL_RETRY_SCHEDULE_MS[stallRetryIndex]!;
  const attempt = stallRetryIndex + 1;
  stallRetryIndex++;
  log(
    `Scheduling stall recovery attempt ${attempt}/${STALL_RETRY_SCHEDULE_MS.length} in ${delay}ms`
  );
  if (stallRetryTimer) clearTimeout(stallRetryTimer);
  stallRetryTimer = setTimeout(attemptStallRecovery, delay);
}

async function attemptStallRecovery(): Promise<void> {
  stallRetryTimer = null;
  // User may have manually stopped or the watcher path may have
  // taken over — bail without consuming another retry slot.
  if (!state.isStreaming || !state.streamLost) return;

  const cameraIp =
    $<HTMLSelectElement>("#camera-ip").value ||
    state.config?.stream?.camera_ip ||
    null;
  if (!cameraIp) {
    log("Stall recovery: no camera IP available, aborting");
    return;
  }

  log("Stall recovery: restarting pipeline");
  try {
    // Make sure the previous pipeline is fully torn down before we
    // ask for a new video window — startStream below will fail
    // ambiguously if a stale pipeline still owns the HWND.
    await api.stopStream().catch(() => {});
    const bounds = getVideoAreaBounds();
    const handle = await api.createVideoWindow(
      bounds.x,
      bounds.y,
      bounds.width,
      bounds.height
    );
    await api.startStream(handle);
    log("Stall recovery: stream restart submitted");
    // startStream returns when set_state(Playing) was REQUESTED, not
    // when the pipeline actually reaches Playing. Set a watchdog that
    // schedules another retry if the new pipeline doesn't recover
    // within 30s. Cleared by hideStreamLost on success (status event
    // with playing=true) or by manual stop.
    stallRetryTimer = setTimeout(() => {
      stallRetryTimer = null;
      if (state.isStreaming && state.streamLost) {
        log("Stall recovery: restart did not reach Playing within 30s");
        scheduleStallRecovery();
      }
    }, 30_000);
  } catch (e) {
    log(`Stall recovery attempt failed: ${formatError(e)}`);
    scheduleStallRecovery();
  }
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
