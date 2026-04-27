/**
 * PocketStream Desktop — FLIR PTU controls
 */

import * as api from "./tauri-api.js";
import { $, state, log, showToast } from "./state.js";
import { formatError } from "./errors.js";

// ── Local PTU state ─────────────────────────────────────────────────

let ptuSpeedBig = 100;
let ptuSpeedSmall = 10;
let ptuSpeedQueried = false;
const ptuPresets = new Map(); // preset# -> { pan, tilt, zoom }
// Set by setupZoomSlider so preset recall can enqueue a zoom through the
// same serialised drain loop as slider drags. Keeping preset-zoom off the
// direct-send path avoids two concurrent HTTP requests wedging the camera's
// single-threaded control.cgi handler.
let zoomRequest = null;

function getPtuIp() {
  return $("#ptu-ip").value || null;
}

async function ptuCmd(cmd) {
  const ip = getPtuIp();
  if (!ip) return null;
  return api.ptuSend(ip, cmd);
}

/**
 * Block until a goto (`C=I&PP=...&TP=...`) finishes, then flip the PTU
 * back to velocity mode (`C=V`) so subsequent D-pad presses are safe.
 *
 * Termination logic:
 *   1. Reached the target (within encoder tolerance) → done.
 *   2. Two consecutive identical samples *after* we've observed at
 *      least one position change → done (stopped before reaching
 *      target — stuck, hit a limit, or external cancel).
 *   3. maxTries reached (10 s default) → bail anyway.
 *
 * The `started` gate in #2 fixes the short-stroke bug: previously the
 * loop broke on the first two equal samples, which routinely fired
 * during the PTU's motor-spool-up window before motion began. The
 * trailing C=V then halted what little motion had started.
 */
async function waitForPtuTarget(targetPan, targetTilt, maxTries = 40) {
  // PP/TP encoders can jitter by a unit or two even at rest; tolerance
  // avoids missing the "reached target" detection on the last pixel.
  const TOLERANCE = 2;
  let last = null;
  let started = false;
  for (let i = 0; i < maxTries; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const data = await ptuCmd("PP&TP");
      if (!data) break;
      const pan = parseInt(data.PP, 10);
      const tilt = parseInt(data.TP, 10);
      if (!Number.isFinite(pan) || !Number.isFinite(tilt)) break;

      // Reached the target — done immediately, no further polls.
      if (
        Math.abs(pan - targetPan) <= TOLERANCE &&
        Math.abs(tilt - targetTilt) <= TOLERANCE
      ) {
        break;
      }

      const sample = `${pan},${tilt}`;
      if (last !== null) {
        if (sample !== last) {
          started = true;
        } else if (started) {
          // Stopped short of the target — stuck or limit reached.
          break;
        }
        // sample === last && !started → motors haven't spooled up yet,
        // keep polling.
      }
      last = sample;
    } catch (_) {
      break;
    }
  }
  await ptuCmd("C=V").catch(() => {});
  log("PTU: back to speed mode");
}

// ── PTZ control setup ───────────────────────────────────────────────

async function queryPtuSpeed() {
  if (!getPtuIp()) return;
  try {
    const data = await ptuCmd("PU&TU&PL&TL");
    if (data) {
      const panUpper = parseInt(data.PU) || 100;
      const tiltUpper = parseInt(data.TU) || 100;
      ptuSpeedBig = Math.min(panUpper, tiltUpper);
      ptuSpeedSmall = Math.max(Math.round(ptuSpeedBig / 10), parseInt(data.PL) || 1);
      ptuSpeedQueried = true;
      log(`PTU limits: big=${ptuSpeedBig} small=${ptuSpeedSmall}`);
      await ptuCmd("C=V");
    }
  } catch (e) {
    log(`PTU init failed: ${formatError(e)}`);
  }
}

export function setupPtzControls() {
  // Query PTU speed limits when PTU IP is selected
  $("#ptu-ip").addEventListener("change", () => {
    ptuSpeedQueried = false;
    queryPtuSpeed();
  });

  // D-pad buttons — hold to move at speed, release to stop
  const speedCmds = {
    up:    () => `TS=${ptuSpeedBig}`,
    down:  () => `TS=${-ptuSpeedBig}`,
    left:  () => `PS=${ptuSpeedBig}`,
    right: () => `PS=${-ptuSpeedBig}`,
  };

  document.querySelectorAll(".ptz-btn[data-ptz]").forEach((btn) => {
    const action = btn.dataset.ptz;

    if (action === "home") {
      btn.addEventListener("click", async () => {
        if (!getPtuIp()) return;
        try {
          await ptuCmd(`C=I&PS=${ptuSpeedBig}&TS=${ptuSpeedBig}&PP=0&TP=0`);
          showToast("PTU homing");
          await waitForPtuTarget(0, 0);
        } catch (e) {
          log(`PTU home: ${formatError(e)}`);
        }
      });
      return;
    }

    const startMove = async () => {
      if (!getPtuIp()) return;
      if (!ptuSpeedQueried) await queryPtuSpeed();
      const cmdFn = speedCmds[action];
      if (cmdFn) ptuCmd(cmdFn()).catch((e) => log(`PTU ${action}: ${formatError(e)}`));
    };
    const stopMove = () => {
      if (!getPtuIp()) return;
      ptuCmd("PS=0&TS=0").catch(() => {});
    };

    btn.addEventListener("pointerdown", (e) => { e.preventDefault(); startMove(); });
    btn.addEventListener("pointerup", stopMove);
    btn.addEventListener("pointerleave", stopMove);
    btn.addEventListener("pointercancel", stopMove);
  });

  // Preset buttons — click to recall, long-press to save current position
  document.querySelectorAll(".ptz-preset-btn[data-preset]").forEach((btn) => {
    let pressTimer = null;
    const preset = parseInt(btn.dataset.preset);

    btn.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      pressTimer = setTimeout(async () => {
        pressTimer = null;
        if (!getPtuIp()) return;
        try {
          const data = await ptuCmd("PP&TP");
          if (data) {
            // Also snapshot current zoom slider position so recalling
            // this preset restores framing on the CAM that's selected
            // now. `zoom` is nullable: a preset saved with no CAM
            // chosen just doesn't touch zoom on recall.
            const zoomEl = $("#zoom-slider");
            const zoomVal = zoomEl ? parseInt(zoomEl.value, 10) : NaN;
            const zoom = Number.isFinite(zoomVal) ? zoomVal : null;
            ptuPresets.set(preset, { pan: data.PP, tilt: data.TP, zoom });
            const zoomLabel = zoom !== null ? ` Z:${zoom}%` : "";
            showToast(`Preset ${preset} saved (P:${data.PP} T:${data.TP}${zoomLabel})`);
          }
        } catch (e) {
          showToast(`Failed: ${formatError(e)}`, true);
        }
      }, 800);
    });

    btn.addEventListener("pointerup", async () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
        if (!getPtuIp()) return;
        const saved = ptuPresets.get(preset);
        if (saved) {
          try {
            // Await the goto ACK before the handler returns — otherwise a
            // D-pad press arriving mid-goto lands while the PTU is still in
            // C=I (absolute) mode, before waitForPtuTarget flips it back to
            // C=V. A PS=SPEED command in C=I mode can drive the unit past
            // its limits (observed in 0.2.9 as runaway pan).
            await ptuCmd(
              `C=I&PS=${ptuSpeedBig}&TS=${ptuSpeedBig}&PP=${saved.pan}&TP=${saved.tilt}`
            );
            waitForPtuTarget(
              parseInt(saved.pan, 10),
              parseInt(saved.tilt, 10),
            ).catch(() => {});

            // Route preset-zoom through the slider's drain queue so it
            // can't overlap an in-flight slider request (two concurrent
            // HTTP requests to control.cgi can wedge the camera's Lua
            // server, freezing the RTSP stream).
            if (saved.zoom !== null && saved.zoom !== undefined && getCameraIp()) {
              const zoomEl = $("#zoom-slider");
              if (zoomEl) zoomEl.value = String(saved.zoom);
              if (zoomRequest) zoomRequest(saved.zoom);
            }
          } catch (e) {
            log(`PTU preset ${preset}: ${formatError(e)}`);
          }
        } else {
          showToast(`Preset ${preset} not saved yet`, true);
        }
      }
    });

    btn.addEventListener("pointerleave", () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
    });

    btn.addEventListener("pointercancel", () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
    });
  });

  setupZoomSlider();
}

// ── Zoom slider (EV-7520 via Nexus control.cgi) ─────────────────────
// Absolute-position control: slider value 0–100 maps to the camera's raw
// 0..ZOOM_MAX range. No spring-back — the slider reflects the current
// zoom level, like the camera's own web UI.

const ZOOM_MAX = 31424;

function getCameraIp() {
  return $("#camera-ip").value || null;
}

let zoomErrorToasted = false;

async function sendZoomPosition(percent) {
  const ip = getCameraIp();
  if (!ip) {
    if (!zoomErrorToasted) {
      showToast("Select a CAM IP to use zoom", true);
      zoomErrorToasted = true;
    }
    return;
  }
  const position = Math.round((percent / 100) * ZOOM_MAX);
  log(`Zoom: ${percent}% (${position}) ip=${ip}`);
  try {
    await api.controlCgiZoomDirect(ip, position);
    zoomErrorToasted = false;
  } catch (e) {
    log(`Zoom failed: ${formatError(e)}`);
    if (!zoomErrorToasted) {
      showToast(`Zoom failed: ${formatError(e)}`, true);
      zoomErrorToasted = true;
    }
  }
}

function setupZoomSlider() {
  const slider = $("#zoom-slider");
  if (!slider) return;

  // Existing HTML was wired for speed control (min=-100, max=100). For
  // position control we want 0..100 representing Wide..Telephoto. Step=2
  // halves the input-event rate during drag vs step=1, which means far
  // fewer HTTP requests reach the camera's single-threaded handler.
  slider.min = "0";
  slider.max = "100";
  slider.step = "2";
  slider.value = "0";

  // Serialize requests: exactly one in flight; coalesce rapid drag
  // updates into a single "latest value" slot. Larger slider step + this
  // serialization is enough to keep the camera happy; the cooldown can
  // stay small since the retry in the backend absorbs any leftover
  // transients.
  const MIN_GAP_MS = 100;
  let inFlight = false;
  let queuedPercent = null;
  let lastSentPercent = null;

  async function drain() {
    while (queuedPercent !== null) {
      const target = queuedPercent;
      queuedPercent = null;
      if (target === lastSentPercent) continue;
      lastSentPercent = target;
      await sendZoomPosition(target);
      if (queuedPercent !== null) {
        await new Promise((r) => setTimeout(r, MIN_GAP_MS));
      }
    }
    inFlight = false;
  }

  function request(percent) {
    queuedPercent = percent;
    if (inFlight) return;
    inFlight = true;
    drain();
  }

  // Expose to preset-recall path so it shares this serialised queue.
  zoomRequest = request;

  slider.addEventListener("input", (e) => {
    request(parseInt(e.target.value, 10));
  });

  // ── Position persistence ──────────────────────────────────────────
  // The camera firmware doesn't expose a zoom-query endpoint, so we
  // can't pull the live position on launch. Instead, persist the last
  // slider percent per-IP and restore it on CAM selection. Accurate as
  // long as we're the only controller; goes stale if someone also
  // moves the camera via its own web UI.
  async function persistCurrent(ip, percent) {
    try {
      await api.setZoomPosition(ip, percent);
      if (state.config) {
        state.config.zoom_positions = state.config.zoom_positions || {};
        state.config.zoom_positions[ip] = percent;
      }
    } catch (e) {
      log(`Save zoom position: ${formatError(e)}`);
    }
  }

  // Debounced save: write to config 500 ms after the user stops moving
  // the slider. Keeps disk I/O minimal during a drag while still catching
  // the final resting position.
  let saveTimer = null;
  slider.addEventListener("input", () => {
    const ip = getCameraIp();
    if (!ip) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      persistCurrent(ip, parseInt(slider.value, 10));
    }, 500);
  });

  // Apply the persisted zoom for the currently-selected CAM IP:
  // set the slider AND push the value to the camera so the slider
  // becomes the source of truth if they've drifted apart. Skips when
  // no IP is selected or no saved position exists.
  function applySavedZoom() {
    const ip = getCameraIp();
    if (!ip) return;
    const saved = state.config?.zoom_positions?.[ip];
    if (typeof saved !== "number") return;
    slider.value = String(saved);
    // Don't pre-set lastSentPercent — we want request() below to fire
    // so the camera catches up to the slider.
    request(saved);
  }

  // Fires when the user picks a CAM from the dropdown.
  $("#camera-ip").addEventListener("change", applySavedZoom);

  // Programmatic dropdown population (via updateCameraIpDropdown) does
  // NOT fire a change event, so we also poll briefly after startup for
  // the dropdown+config to be ready, then apply once.
  (async () => {
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (state.config && getCameraIp()) {
        applySavedZoom();
        return;
      }
    }
  })();
}
