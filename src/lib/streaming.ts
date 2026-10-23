/**
 * PocketStream Desktop — Stream, re-stream server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.ts";
import { $, $$, state, log, showToast, formatUptime } from "./state.ts";
import type { DeviceTarget } from "./store.ts";
import * as deviceList from "./device-list.ts";
import { formatError } from "./errors.ts";
import { formatRestreamBitrate } from "./restream-format.ts";
import {
  buildRestreamBindOptions,
  buildRestreamBindUpdate,
  buildRestreamSettingsUpdate,
  resolveSrtPassphraseUpdate,
  restreamSwitchStatusIsFinal,
  srtPassphraseClearNeedsConfirmation,
  RestreamBindRequestGate,
  selectedRestreamBindInterface,
} from "./restream-settings.ts";
import { getActiveCamTarget } from "./network.ts";
import type {
  RestreamBindRequest,
} from "./restream-settings.ts";
import type {
  RestreamOperationResult,
  RestreamProtocol,
  RestreamSettingsUpdate,
  SrtPassphraseView,
  StreamStatus,
} from "./types.ts";

/** Full client URL (including protocol access data) for QR generation. */
let restreamFullUrl: string | null = null;

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
  if (!record || record.alias !== "CAM" || record.ip.startsWith("169.254.")) {
    throw new Error("Assign a node as CAM in the Nodes dropdown before streaming");
  }
  if (!state.config) throw new Error("Stream settings are not loaded");
  state.config.stream.camera_ip = record.ip;
  state.config.stream.camera_mac = deviceList.targetFor(record).expectedMac;
  await api.updateStreamSettings(state.config.stream);
  if (deviceList.resolveTarget(target)?.alias !== "CAM" || !getActiveCamTarget()) {
    throw new Error("CAM assignment changed; select CAM in the Nodes dropdown before streaming");
  }
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
            showToast("Assign a node as CAM in the Nodes dropdown before streaming", true);
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

// ── Re-stream server controls ──────────────────────────────────────

/** Busy latch for the re-stream toggle (see streamToggleBusy). */
let restreamToggleBusy = false;
let restreamProtocolBusy = false;
let restreamProtocolPending: RestreamProtocol | null = null;
let restreamProtocolExpectedDesired: boolean | null = null;
let restreamProtocolRequestGeneration = 0;
let renderedRestreamProtocol: RestreamProtocol = "rtsp";
const restreamBindRequests = new RestreamBindRequestGate();
let restreamBindReady = false;
let restreamBindApplyBusy = false;
let restreamSettingsBusy = false;
let srtPassphraseCurrent: SrtPassphraseView = {
  state: "unencrypted",
  value: null,
};
let srtPassphraseDirty = false;
let srtPassphraseClearConfirmed = false;
let srtPassphraseClearPromptOpening = false;

function currentRestreamProtocol(): RestreamProtocol {
  return state.config?.restream_protocol ?? renderedRestreamProtocol;
}

function syncRestreamProtocolButtons(): void {
  const disabled =
    !state.config ||
    restreamToggleBusy ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy;
  $$<HTMLButtonElement>("[data-restream-protocol]").forEach((button) => {
    const active = button.dataset["restreamProtocol"] === renderedRestreamProtocol;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
    button.disabled = disabled;
  });
}

function syncRestreamSpinner(): void {
  $("#restream-spinner").style.display =
    restreamToggleBusy ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy
      ? ""
      : "none";
}

function syncRestreamBindAvailability(): void {
  $<HTMLSelectElement>("#restream-bind-interface").disabled =
    !restreamBindReady ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy;
}

function syncRestreamOperationControls(): void {
  syncRestreamStartButton();
  syncRestreamProtocolButtons();
  syncRestreamSpinner();
  syncRestreamBindAvailability();
  $<HTMLButtonElement>("#save-settings").disabled =
    !state.config ||
    restreamToggleBusy ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy;
}

function finishRestreamProtocolSwitch(expected?: RestreamProtocol): void {
  if (expected && restreamProtocolPending !== expected) return;
  restreamProtocolPending = null;
  restreamProtocolExpectedDesired = null;
  restreamProtocolBusy = false;
  syncRestreamOperationControls();
}

function renderRestreamProtocol(protocol: RestreamProtocol): void {
  renderedRestreamProtocol = protocol;
  $("#restream-rtsp-settings").style.display = protocol === "rtsp" ? "" : "none";
  $("#restream-srt-settings").style.display = protocol === "srt" ? "" : "none";
  syncRestreamProtocolButtons();
}

function acceptRestreamProtocol(
  protocol: RestreamProtocol,
  refreshBindOnChange = true
): void {
  const changed = currentRestreamProtocol() !== protocol || renderedRestreamProtocol !== protocol;
  if (state.config) state.config.restream_protocol = protocol;
  renderRestreamProtocol(protocol);
  if (changed && refreshBindOnChange && state.config) refreshRestreamBindOptions();
}

/**
 * Re-derive the re-stream Start button's enabled state from the Enable
 * checkbox. `loadConfig` sets `.checked` programmatically, which fires
 * no `change` event — without this call, a user whose config has the
 * server enabled got a dead Start button until they toggled the
 * checkbox off and on.
 */
export function syncRestreamStartButton(): void {
  const startBtn = $<HTMLButtonElement>("#btn-toggle-restream");
  startBtn.disabled =
    restreamToggleBusy ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy ||
    (!state.isRestreamDesired &&
      !$<HTMLInputElement>("#restream-server-enable").checked);
}

/** Serialize the shared Settings Save button with live re-stream controls so
 * two frontend requests cannot submit competing canonical bind snapshots. */
export function beginRestreamSettingsSave(): boolean {
  if (
    restreamToggleBusy ||
    restreamProtocolBusy ||
    restreamBindApplyBusy ||
    restreamSettingsBusy
  ) {
    return false;
  }
  restreamSettingsBusy = true;
  syncRestreamOperationControls();
  return true;
}

export function finishRestreamSettingsSave(): void {
  restreamSettingsBusy = false;
  syncRestreamOperationControls();
}

/** An empty edited field is the user's clear intent, but it remains fail-closed
 * until the save flow receives an explicit passwordless confirmation. */
export async function confirmSrtPassphraseClearIfNeeded(): Promise<boolean> {
  const input = $<HTMLInputElement>("#srt-passphrase");
  if (!srtPassphraseClearNeedsConfirmation(
    srtPassphraseCurrent,
    input.value,
    srtPassphraseDirty,
    srtPassphraseClearConfirmed
  )) {
    return true;
  }

  const dialog = $<HTMLDialogElement>("#srt-clear-passphrase-dialog");
  if (srtPassphraseClearPromptOpening || dialog.open) return false;
  srtPassphraseClearPromptOpening = true;
  dialog.returnValue = "";
  const closed = new Promise<boolean>((resolve) => {
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "passwordless"),
      { once: true }
    );
  });
  try {
    await showModalWithVideo(dialog);
    const confirmed = await closed;
    if (confirmed) {
      srtPassphraseClearConfirmed = true;
      srtPassphraseDirty = false;
      input.value = "";
      renderSrtPassphraseState();
    }
    return confirmed;
  } finally {
    srtPassphraseClearPromptOpening = false;
  }
}

export function setupRestreamControls(): void {
  const enableToggle = $<HTMLInputElement>("#restream-server-enable");
  enableToggle.addEventListener("change", () => {
    // Enable is persisted and enforced by the atomic Settings Save command.
    // A desired output always remains stoppable before that save.
    syncRestreamStartButton();
  });

  $$<HTMLButtonElement>("[data-restream-protocol]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.dataset["restreamProtocol"];
      if (
        !state.config ||
        restreamProtocolBusy ||
        restreamToggleBusy ||
        restreamBindApplyBusy ||
        restreamSettingsBusy ||
        (value !== "rtsp" && value !== "srt") ||
        value === currentRestreamProtocol()
      ) {
        return;
      }

      const protocol: RestreamProtocol = value;
      const requestGeneration = ++restreamProtocolRequestGeneration;
      restreamProtocolPending = protocol;
      restreamProtocolExpectedDesired = state.isRestreamDesired;
      restreamProtocolBusy = true;
      restreamBindReady = false;
      $<HTMLSelectElement>("#restream-bind-interface").disabled = true;
      syncRestreamOperationControls();
      try {
        const result = await api.switchRestreamProtocol(protocol);
        if (requestGeneration !== restreamProtocolRequestGeneration) return;
        applyRestreamOperationResult(result);
        showToast(`Re-stream output switched to ${protocol.toUpperCase()}`);
      } catch (error) {
        if (requestGeneration !== restreamProtocolRequestGeneration) return;
        await reloadCanonicalRestreamConfig();
        showToast("Failed to switch re-stream output: " + formatError(error), true);
      } finally {
        // A matching status event may have released the latch before the
        // command returned. Never let this older completion release a newer
        // selector request.
        if (requestGeneration === restreamProtocolRequestGeneration) {
          finishRestreamProtocolSwitch();
        }
      }
    });
  });

  refreshRestreamBindOptions();

  $<HTMLSelectElement>("#restream-bind-interface").addEventListener("change", async () => {
    if (
      !state.config ||
      !restreamBindReady ||
      restreamProtocolBusy ||
      restreamToggleBusy ||
      restreamBindApplyBusy ||
      restreamSettingsBusy
    ) {
      return;
    }
    const select = $<HTMLSelectElement>("#restream-bind-interface");
    const protocol = currentRestreamProtocol();
    const previous = selectedRestreamBindInterface(state.config, protocol);
    const requested = select.value;
    restreamBindApplyBusy = true;
    syncRestreamOperationControls();
    try {
      const result = await api.applyRestreamSettings(
        buildRestreamBindUpdate(state.config, protocol, requested)
      );
      if (protocol === "srt") {
        state.config.srt_server.bind_interface = requested;
      } else {
        state.config.rtsp_server.bind_interface = requested;
      }
      applyRestreamOperationResult(result);
    } catch (e) {
      if (!(await reloadCanonicalRestreamConfig())) {
        select.value = previous;
      }
      showToast("Failed to save VPN selection: " + formatError(e), true);
    } finally {
      restreamBindApplyBusy = false;
      syncRestreamOperationControls();
    }
  });

  const passphraseInput = $<HTMLInputElement>("#srt-passphrase");
  passphraseInput.addEventListener("input", () => {
    srtPassphraseDirty = true;
    srtPassphraseClearConfirmed = false;
    renderSrtPassphraseState();
  });
  passphraseInput.addEventListener("keydown", (event) => {
    if (
      (event.key === "Backspace" || event.key === "Delete") &&
      passphraseInput.value.length === 0 &&
      srtPassphraseCurrent.state === "unavailable"
    ) {
      // The protected value cannot be displayed, so Backspace/Delete on the
      // empty repair field is the explicit removal gesture for this state.
      srtPassphraseDirty = true;
      srtPassphraseClearConfirmed = false;
      renderSrtPassphraseState();
    }
  });

  $<HTMLButtonElement>("#srt-copy-passphrase").addEventListener("click", async () => {
    if (!passphraseInput.value || srtPassphraseClearConfirmed) return;
    try {
      await navigator.clipboard.writeText(passphraseInput.value);
      showToast("SRT passphrase copied");
    } catch (_) {
      showToast("Failed to copy SRT passphrase", true);
    }
  });

  const clearDialog = $<HTMLDialogElement>("#srt-clear-passphrase-dialog");
  $<HTMLButtonElement>("#srt-clear-passphrase-confirm").addEventListener("click", () => {
    clearDialog.close("passwordless");
  });
  $<HTMLButtonElement>("#srt-clear-passphrase-cancel").addEventListener("click", () => {
    clearDialog.close("cancel");
  });
  clearDialog.addEventListener("click", (event) => {
    if (event.target === clearDialog) clearDialog.close("cancel");
  });

  $<HTMLButtonElement>("#btn-toggle-restream").addEventListener("click", async () => {
    // Same double-tap defense as the stream toggle.
    if (
      restreamToggleBusy ||
      restreamProtocolBusy ||
      restreamBindApplyBusy ||
      restreamSettingsBusy
    ) {
      return;
    }
    restreamToggleBusy = true;
    syncRestreamOperationControls();

    if (state.isRestreamDesired) {
      try {
        await api.stopRestreamServer();
        state.isRestreamDesired = false;
        updateRestreamUI(null);
        showToast("Re-stream server stopped");
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
          if (!target) throw new Error("Assign a node as CAM in the Nodes dropdown before streaming");
          await persistPlaybackTarget(target);
        }
        const info = await api.startRestreamServer();
        state.isRestreamDesired = true;
        restreamFullUrl = info.server_url;
        updateRestreamUI(info.display_url);
        showToast("Re-stream server started");
      } catch (e) {
        showToast("Re-stream server failed: " + formatError(e), true);
      }
    }

    restreamToggleBusy = false;
    // updateRestreamUI ran in the happy paths; re-derive here so a thrown
    // start/stop doesn't leave the button stuck disabled.
    syncRestreamOperationControls();
  });

  // QR code button + dialog
  setupQrDialog();
  syncRestreamOperationControls();
}

export function refreshRestreamBindOptions(): void {
  const protocol = currentRestreamProtocol();
  const request = restreamBindRequests.begin(protocol);
  const select = $<HTMLSelectElement>("#restream-bind-interface");
  restreamBindReady = false;
  select.disabled = true;
  void populateRestreamBindOptions(request);
}

/** Reconcile local state after a command error. A settings transaction may
 * have committed successfully before its live restart failed, so an error is
 * not proof that the old frontend snapshot remains authoritative. */
export async function reloadCanonicalRestreamConfig(): Promise<boolean> {
  try {
    state.config = await api.getConfig();
    syncRestreamSettingsUI();
    return true;
  } catch (error) {
    log(`Failed to reload canonical re-stream settings: ${formatError(error)}`);
    return false;
  }
}

function renderRestreamBindOptions(
  interfaces: Awaited<ReturnType<typeof api.listVpnInterfaces>>,
  saved: string
): void {
  const select = $<HTMLSelectElement>("#restream-bind-interface");
  select.replaceChildren();
  for (const model of buildRestreamBindOptions(interfaces, saved)) {
    const option = document.createElement("option");
    option.value = model.value;
    option.textContent = model.label;
    if (model.unavailable) option.dataset["unavailable"] = "true";
    select.appendChild(option);
  }
  select.value = saved;
}

async function populateRestreamBindOptions(request: RestreamBindRequest): Promise<void> {
  const select = $<HTMLSelectElement>("#restream-bind-interface");
  try {
    const vpns = (await api.listVpnInterfaces()).filter((i) => i.ips.length > 0);
    if (!restreamBindRequests.isCurrent(request, currentRestreamProtocol())) return;
    const saved = state.config
      ? selectedRestreamBindInterface(state.config, request.protocol)
      : "";
    renderRestreamBindOptions(vpns, saved);
  } catch (e) {
    if (!restreamBindRequests.isCurrent(request, currentRestreamProtocol())) return;
    console.warn("Failed to list VPN interfaces:", e);
    const saved = state.config
      ? selectedRestreamBindInterface(state.config, request.protocol)
      : "";
    renderRestreamBindOptions([], saved);
  } finally {
    if (restreamBindRequests.isCurrent(request, currentRestreamProtocol())) {
      restreamBindReady = state.config !== null;
      syncRestreamBindAvailability();
    }
  }
}

export function applyRestreamOperationResult(result: RestreamOperationResult): void {
  state.isRestreamDesired = result.desired;
  acceptRestreamProtocol(result.selected_protocol);
  if (result.server_info) {
    restreamFullUrl = result.server_info.server_url;
    updateRestreamUI(result.server_info.display_url);
  } else if (!result.desired) {
    updateRestreamUI(null);
  }
}

function renderSrtPassphraseState(): void {
  const input = $<HTMLInputElement>("#srt-passphrase");
  const status = $("#srt-passphrase-state");
  const copy = $<HTMLButtonElement>("#srt-copy-passphrase");

  status.className = "setting-helper";
  if (srtPassphraseClearConfirmed) {
    input.placeholder = "No passphrase (unencrypted)";
    status.textContent = "Passwordless SRT confirmed; save settings to apply.";
    status.classList.add("warning");
  } else if (srtPassphraseDirty) {
    input.placeholder = "10-79 visible ASCII characters (no spaces)";
    if (input.value.length === 0) {
      status.textContent = "Passphrase removed; save settings to confirm passwordless SRT.";
      status.classList.add("warning");
    } else if (
      srtPassphraseCurrent.state === "available" &&
      srtPassphraseCurrent.value === input.value
    ) {
      status.textContent = "Protected passphrase unchanged.";
    } else {
      status.textContent = "Replacement will be protected when settings are saved.";
    }
  } else {
    switch (srtPassphraseCurrent.state) {
      case "available":
        input.placeholder = "Protected passphrase";
        status.textContent = "Protected passphrase saved.";
        break;
      case "unencrypted":
        input.placeholder = "No passphrase (unencrypted)";
        status.textContent = "Unencrypted output is intentionally enabled.";
        status.classList.add("warning");
        break;
      case "unavailable":
        input.placeholder = "Re-entry required";
        status.textContent =
          "Saved passphrase is unavailable; enter a replacement, or press Backspace then save to use no password.";
        status.classList.add("error");
        break;
    }
  }

  copy.disabled = input.value.length === 0 || srtPassphraseClearConfirmed;
}

function loadSrtPassphraseView(passphrase: SrtPassphraseView): void {
  srtPassphraseCurrent = { ...passphrase };
  srtPassphraseDirty = false;
  srtPassphraseClearConfirmed = false;
  $<HTMLInputElement>("#srt-passphrase").value =
    passphrase.state === "available" ? (passphrase.value ?? "") : "";
  renderSrtPassphraseState();
}

/** Paint only the complete re-stream settings model from a canonical backend
 * snapshot. It is never called with transient DOM values. */
export function syncRestreamSettingsUI(): void {
  const config = state.config;
  if (!config) return;

  $<HTMLInputElement>("#restream-server-enable").checked = config.rtsp_server.enabled;
  $<HTMLInputElement>("#rtsp-server-port").value = String(config.rtsp_server.port);
  $<HTMLInputElement>("#rtsp-token").value = config.rtsp_server.token;
  $<HTMLInputElement>("#srt-server-port").value = String(config.srt_server.port);
  $<HTMLInputElement>("#srt-latency-ms").value = String(config.srt_server.latency_ms);
  $<HTMLInputElement>("#srt-stream-id").value = config.srt_server.stream_id;
  loadSrtPassphraseView(config.srt_server.passphrase);
  acceptRestreamProtocol(config.restream_protocol, false);
  syncRestreamOperationControls();
  refreshRestreamBindOptions();
}

function readIntegerInput(selector: string): number {
  const parsed = Number.parseInt($<HTMLInputElement>(selector).value, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/** Read both output sections for the one atomic Settings Save command. */
export function readRestreamSettingsUpdate(): RestreamSettingsUpdate {
  if (!state.config) throw new Error("Settings are still loading");
  const passphraseInput = $<HTMLInputElement>("#srt-passphrase");
  return buildRestreamSettingsUpdate(state.config, {
    enabled: $<HTMLInputElement>("#restream-server-enable").checked,
    rtspPort: readIntegerInput("#rtsp-server-port"),
    rtspToken: $<HTMLInputElement>("#rtsp-token").value,
    srtPort: readIntegerInput("#srt-server-port"),
    srtLatencyMs: readIntegerInput("#srt-latency-ms"),
    srtStreamId: $<HTMLInputElement>("#srt-stream-id").value,
    srtPassphrase: resolveSrtPassphraseUpdate(
      srtPassphraseCurrent,
      passphraseInput.value,
      srtPassphraseDirty,
      srtPassphraseClearConfirmed
    ),
  });
}

export function updateRestreamUI(displayUrl: string | null, status?: StreamStatus): void {
  const btn = $<HTMLButtonElement>("#btn-toggle-restream");
  btn.textContent = state.isRestreamDesired ? "Stop Server" : "Start Server";
  // A desired listener remains stoppable while rebuilding; transaction busy
  // latches only disable actions until their backend operation establishes state.
  syncRestreamStartButton();

  const statusEl = $("#restream-status");
  const qrBtn = $<HTMLButtonElement>("#btn-show-qr");
  const errorRow = $("#restream-error-row");
  const errorEl = $("#restream-error");

  if (state.isRestreamDesired) {
    const relayState = status?.relay_state ?? "starting";
    switch (relayState) {
      case "listening":
      case "streaming":
        statusEl.textContent = "Online";
        statusEl.className = "status-value status-online";
        break;
      case "recovering":
        statusEl.textContent = status?.recovery_attempt
          ? `Reconnecting (attempt ${status.recovery_attempt})`
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
    $("#restream-url").textContent = displayUrl || "--";
    qrBtn.disabled = !restreamFullUrl;
    const error = status?.relay_error ?? null;
    errorEl.textContent = error || "";
    errorRow.style.display = error ? "contents" : "none";
  } else {
    statusEl.textContent = "Offline";
    statusEl.className = "status-value status-offline";
    $("#restream-url").textContent = "--";
    $("#restream-uptime").textContent = "--";
    $("#restream-clients").textContent = "--";
    $("#restream-bandwidth").textContent = "--";
    errorEl.textContent = "";
    errorRow.style.display = "none";
    restreamFullUrl = null;
    qrBtn.disabled = true;
  }
}

// ── QR Code Dialog ──────────────────────────────────────────────────

function setupQrDialog(): void {
  const dialog = $<HTMLDialogElement>("#qr-dialog");
  const qrBtn = $<HTMLButtonElement>("#btn-show-qr");
  const closeBtn = $<HTMLButtonElement>("#qr-close");

  qrBtn.addEventListener("click", async () => {
    if (!restreamFullUrl) return;

    // Show dialog first so the canvas is in the visible DOM —
    // rendering to a canvas inside a hidden <dialog> can produce
    // blank output on some WebView2 / Chromium builds.
    $("#qr-url").textContent = restreamFullUrl;
    await showModalWithVideo(dialog);

    const canvas = $<HTMLCanvasElement>("#qr-canvas");
    try {
      await QRCode.toCanvas(canvas, restreamFullUrl, {
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
  state.isRestreamDesired = status.desired;
  acceptRestreamProtocol(status.selected_protocol);
  if (
    restreamSwitchStatusIsFinal(
      restreamProtocolPending,
      restreamProtocolExpectedDesired,
      status.selected_protocol,
      status.desired
    )
  ) {
    finishRestreamProtocolSwitch(status.selected_protocol);
  }
  if (status.server_url) {
    restreamFullUrl = status.server_url;
  }
  updateRestreamUI(status.display_url ?? null, status);

  if (status.desired) {
    $("#restream-uptime").textContent = formatUptime(status.uptime_secs);
    $("#restream-clients").textContent =
      `${status.connected_clients} / ${status.client_limit}`;
    $("#restream-bandwidth").textContent = formatRestreamBitrate(
      status.bandwidth_kbps,
      status.connected_clients
    );
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

let recoveryDotsStartedAt: number | null = null;

/** The existing status tick drives the dots; recovery remains backend-owned. */
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
    overlay.append(label);
    area.appendChild(overlay);
  }
  const reason = status.playback_fault?.reason;
  const recovering = status.playback_state === "recovering"
    || (status.playback_state === "starting" && status.playback_fault !== null);
  if (recovering) recoveryDotsStartedAt ??= Date.now();
  else recoveryDotsStartedAt = null;
  const dots = ".".repeat(1 + Math.floor((Date.now() - (recoveryDotsStartedAt ?? Date.now())) / 1000) % 3);
  const message = recovering
    ? "Network Error: Check link. Retrying"
    : status.playback_state === "failed" ? `Playback failed${reason ? `: ${reason}` : ""}` : "Connecting";
  const label = overlay.querySelector<HTMLElement>(".playback-reason")!;
  label.textContent = message;
  if (recovering) {
    const suffix = document.createElement("span");
    suffix.className = "playback-dots";
    suffix.setAttribute("aria-hidden", "true");
    suffix.textContent = dots;
    label.append(suffix);
  }
  overlay.classList.add("visible");
}

function hideStreamLost(): void {
  recoveryDotsStartedAt = null;
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
