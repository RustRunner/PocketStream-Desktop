/**
 * PocketStream Desktop — Stream, re-stream server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.ts";
import { $, $$, state, log, showToast, formatUptime } from "./state.ts";
import { sessionCamIp } from "./store.ts";
import { formatError } from "./errors.ts";
import { formatRestreamBitrate } from "./restream-format.ts";
import {
  buildRestreamBindOptions,
  buildRestreamBindUpdate,
  buildRestreamSettingsUpdate,
  resolveSrtPassphraseUpdate,
  restreamSwitchStatusIsFinal,
  RestreamBindRequestGate,
  selectedRestreamBindInterface,
} from "./restream-settings.ts";
import { getActiveCamIp, getActivePtuIp } from "./network.ts";
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

/** IP of the pipeline the user currently intends to be streaming.
 *  Set before the start awaits begin at every start site (manual
 *  start, auto-resume, stall recovery), so it covers the window where
 *  `isStreaming` is still false during startup, and it persists
 *  through the stream-lost overlay — the intent survives a drop.
 *  Cleared on stop and on a failed manual start.
 *
 *  This — not the persisted `camera_ip`, which is also rewritten by
 *  CAM designation while an unrelated stream keeps playing — is the
 *  identity that teardown logic must compare against. */
let activePlaybackIp: string | null = null;

export function getActivePlaybackIp(): string | null {
  return activePlaybackIp;
}

/** Stop the stream and reset every piece of frontend stream state.
 *  Flags flip before the async stop so an in-flight status event
 *  can't race a false "Stream Lost"; the resume snapshot drops so a
 *  stopped stream never auto-resumes on a later reconnect; and the
 *  recording indicator resets — the backend finalizes an in-progress
 *  recording (EOS flush) inside the stop itself. Idempotent: safe
 *  when nothing is streaming, and safe mid-start (the backend
 *  playback epoch makes a late start observe the stop). */
export async function stopStreamNow(message = "Stream stopped"): Promise<void> {
  state.isStreaming = false;
  state.streamLost = false;
  resumeSnapshot = null;
  activePlaybackIp = null;
  hideStreamLost();
  state.isRecording = false;
  $("#btn-record").classList.remove("recording");
  try {
    // A loss-triggered teardown may already own the old pipeline. Still
    // issue this stop so a manual Stop wins against a recovery start that
    // has just passed its guard, but do not let the user start again until
    // the original teardown has drained too.
    await Promise.all([api.stopStream(), waitForStreamLossTeardown()]);
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
          const selectedIp = getActiveCamIp();
          if (!selectedIp) {
            showToast("Pick a node first (click it in the Nodes panel)", true);
            return;
          }
          // Claim the playback identity before the slow awaits so a
          // concurrent teardown (role change) can observe and cancel
          // this start.
          activePlaybackIp = selectedIp;
          if (state.config) {
            state.config.stream.camera_ip = selectedIp;
            await api.updateStreamSettings(state.config.stream);
          }
          const bounds = getVideoAreaBounds();
          // createVideoWindowSynced hides the born-visible child if a
          // dialog is open, so it can't cover one before startStream
          // returns. A second sync after the flags flip reveals it.
          const handle = await createVideoWindowSynced(bounds);
          await api.startStream(handle);
          if (activePlaybackIp !== selectedIp) {
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
          notPlayingStreak = 0;
          showToast("Stream started");
        } catch (e) {
          activePlaybackIp = null;
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
  let clearDialogOpening = false;
  $<HTMLButtonElement>("#srt-clear-passphrase").addEventListener("click", async () => {
    if (clearDialog.open || clearDialogOpening) return;
    clearDialogOpening = true;
    try {
      await showModalWithVideo(clearDialog);
    } finally {
      clearDialogOpening = false;
    }
  });
  $<HTMLButtonElement>("#srt-clear-passphrase-confirm").addEventListener("click", () => {
    srtPassphraseClearConfirmed = true;
    srtPassphraseDirty = false;
    passphraseInput.value = "";
    renderSrtPassphraseState();
    clearDialog.close();
  });
  $<HTMLButtonElement>("#srt-clear-passphrase-cancel").addEventListener("click", () => {
    clearDialog.close();
  });
  clearDialog.addEventListener("click", (event) => {
    if (event.target === clearDialog) clearDialog.close();
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
  const clear = $<HTMLButtonElement>("#srt-clear-passphrase");

  status.className = "setting-helper";
  if (srtPassphraseClearConfirmed) {
    input.placeholder = "No passphrase (unencrypted)";
    status.textContent = "Unencrypted output confirmed; save settings to apply.";
    status.classList.add("warning");
  } else if (srtPassphraseDirty) {
    input.placeholder = "10-79 visible ASCII characters (no spaces)";
    if (input.value.length === 0) {
      status.textContent = "Enter a replacement, or use Clear encryption.";
      status.classList.add("error");
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
          "Saved passphrase is unavailable; enter a replacement or confirm Clear encryption.";
        status.classList.add("error");
        break;
    }
  }

  copy.disabled = input.value.length === 0 || srtPassphraseClearConfirmed;
  clear.disabled =
    srtPassphraseClearConfirmed ||
    (srtPassphraseCurrent.state === "unencrypted" && !srtPassphraseDirty);
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

function updateRestreamUI(displayUrl: string | null, status?: StreamStatus): void {
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
        statusEl.textContent = "Degraded / Reconnecting";
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

// Require the backend to report `playing=false` across N consecutive
// status events before declaring the stream lost. A single blip
// (transient state transition, RTCP jitter, GStreamer bus race)
// self-heals on the next event and shouldn't nuke an otherwise-healthy
// stream. The backend ticks at 1Hz, so this is ~3 seconds.
const DROP_THRESHOLD_EVENTS = 3;
let notPlayingStreak = 0;

// Latched across a deliberate stop→start pipeline switch (path change):
// the status events emitted while the new pipeline spins up legitimately
// report playing=false, and on a camera with slow RTSP setup they would
// accumulate past DROP_THRESHOLD_EVENTS and tear down the just-started
// preview pipeline. Only the preview drop-detection block honors the latch;
// relay status rendering remains independent.
let pipelineSwitchInProgress = false;

/** Suppress the drop detector for the duration of a deliberate
 *  stop→start pipeline switch. Pair with endPipelineSwitch() in a
 *  finally block so a failed switch can't leave the detector off. */
export function beginPipelineSwitch(): void {
  pipelineSwitchInProgress = true;
  notPlayingStreak = 0;
}

export function endPipelineSwitch(): void {
  pipelineSwitchInProgress = false;
  notPlayingStreak = 0;
}

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
// `showStreamLost` starts teardown without blocking the status-event
// handler. Every restart path must await this exact work rather than issue
// a second stop: overlapping Tauri commands can finish out of order, and a
// late stop can otherwise clear/stop the replacement pipeline or leave its
// native video HWND untracked.
let streamLossTeardown: Promise<void> | null = null;
function isStallError(msg: string | null | undefined): boolean {
  return !!msg && msg.toLowerCase().includes("stalled");
}

function trackStreamLossTeardown(tasks: Promise<void>[]): void {
  // If an earlier loss teardown somehow still exists, include it in the
  // fence as well. A replacement must never start while any older stop can
  // still arrive late.
  const previous = streamLossTeardown;
  const teardown = Promise.all(previous ? [previous, ...tasks] : tasks).then(
    () => undefined
  );
  streamLossTeardown = teardown;
  void teardown.then(() => {
    if (streamLossTeardown === teardown) streamLossTeardown = null;
  });
}

async function waitForStreamLossTeardown(): Promise<void> {
  const teardown = streamLossTeardown;
  if (teardown) await teardown;
}

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

  // Detect stream drop — backend says not playing but we think we're
  // streaming. Skipped while a deliberate pipeline switch is in
  // progress; those events are the switch itself, not a drop.
  if (!pipelineSwitchInProgress) {
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
}

interface ResumeSnapshot {
  cameraIp: string | null;
  ptuIp: string | null;
  wasRestreamDesired: boolean;
}

/** Stream state captured at the moment of a hard network disconnect,
 *  so we can re-start the stream and explicitly re-resolve a desired relay as
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
      // The playback identity, not getActiveCamIp(): the CAM
      // designation can have moved to another node since this stream
      // started, and a resume must bring back what was playing.
      cameraIp: activePlaybackIp ?? getActiveCamIp(),
      ptuIp: getActivePtuIp(),
      wasRestreamDesired: state.isRestreamDesired,
    };
    log(`Stream lost on network disconnect: ${reason}`);
    showStreamLost(reason);
  }
}

/** Called by the interface watcher on reconnect (wasDown=true).
 *  Restores dropdown selections and restarts the stream + re-stream server
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

  // showStreamLost tears playback down in the background. Do not create its
  // replacement until that exact stop command has fully drained.
  await waitForStreamLossTeardown();

  // The user may have hit Stop during that grace window — a manual
  // stop clears both flags, and resuming anyway would override their
  // decision (same guard attemptStallRecovery uses).
  if (!state.isStreaming || !state.streamLost) return;

  // Restore the session CAM target so getActiveCamIp resolves the same
  // camera that was streaming before the disconnect. Session state, not
  // state.config — a resume is not a persistence event, and writing
  // config here would leak into the next Save Settings. PTU is
  // alias-driven, which survives across the disconnect since aliases
  // live in the registry/cache.
  if (snap.cameraIp) {
    sessionCamIp.set(snap.cameraIp);
  }

  if (!snap.cameraIp) return;

  // Re-claim the playback identity before the start awaits — a role
  // change during the resume window compares against this.
  activePlaybackIp = snap.cameraIp;

  try {
    const bounds = getVideoAreaBounds();
    const handle = await createVideoWindowSynced(bounds);
    await api.startStream(handle);
    state.isStreaming = true;
    state.streamLost = false;
    hideStreamLost();
    updateStreamUI();
    notPlayingStreak = 0;
    showToast("Stream resumed");

    // A hard reconnect may have changed host addresses. Re-submit the desired
    // relay as an explicit Start: the backend no-ops an identical healthy
    // endpoint and supersedes recovery when resolution actually changed.
    if (snap.wasRestreamDesired && state.isRestreamDesired) {
      try {
        const info = await api.startRestreamServer();
        state.isRestreamDesired = true;
        restreamFullUrl = info.server_url;
        updateRestreamUI(info.display_url);
      } catch (e) {
        log(`Re-stream auto-resume failed: ${formatError(e)}`);
        showToast("Stream back — re-stream server failed to resume", true);
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

  // Reset preview only. Relay health and recovery belong to the backend and
  // remain independent of a preview-only failure.
  const teardownTasks: Promise<void>[] = [
    api.stopStream().catch((e) => {
      log(`Stream-loss playback teardown failed: ${formatError(e)}`);
    }),
  ];
  trackStreamLossTeardown(teardownTasks);
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

  try {
    await waitForStreamLossTeardown();

    // Stop may have been clicked, or the interface-watcher reconnect path
    // may have taken ownership, while teardown was draining.
    if (!state.isStreaming || !state.streamLost) return;

    const cameraIp = getActiveCamIp();
    if (!cameraIp) {
      log("Stall recovery: no camera IP available, aborting");
      return;
    }
    activePlaybackIp = cameraIp;

    log("Stall recovery: restarting pipeline");
    const bounds = getVideoAreaBounds();
    const handle = await createVideoWindowSynced(bounds);
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
