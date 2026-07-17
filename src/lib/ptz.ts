/**
 * PocketStream Desktop — FLIR PTU controls
 */

import * as api from "./tauri-api.ts";
import { $, state, log, showToast } from "./state.ts";
import { formatError } from "./errors.ts";
import { getActiveCamIp, getActivePtuIp } from "./network.ts";
import { selectedDevice } from "./store.ts";
import * as deviceList from "./device-list.ts";

// ── Local PTU state ─────────────────────────────────────────────────

let ptuSpeedBig = 100;
let ptuSpeedSmall = 10;
let ptuSpeedQueried = false;

/** Monotonic D-pad press counter. */
let ptuPressSeq = 0;
/** Highest press sequence whose release has been recorded. A queued
 *  move with seq <= this is dropped at dequeue (see startMove). */
let ptuReleasedThrough = 0;

interface SavedPreset {
  /** PP value as the camera returned it — kept as string so re-sending
   *  it doesn't introduce a parseInt round-trip. */
  pan: string;
  tilt: string;
  /** Zoom slider percent at the time of save, or null if no CAM was
   *  selected. Recall touches zoom only when this is non-null. */
  zoom: number | null;
}

const ptuPresets = new Map<number, SavedPreset>();

/** Set by setupZoomSlider so preset recall can enqueue a zoom through the
 *  same serialised drain loop as slider drags. Keeping preset-zoom off the
 *  direct-send path avoids two concurrent HTTP requests wedging the camera's
 *  single-threaded control.cgi handler. */
let zoomRequest: ((percent: number) => void) | null = null;

/** Set by setupZoomSlider for the Home button: pull the zoom back to
 *  full wide through the same serialised queue, and persist it — home
 *  is the park pose, and an unpersisted reset would let the next launch
 *  push the stale pre-home zoom straight back to the camera. */
let zoomParkWide: (() => void) | null = null;

function getPtuIp(): string | null {
  return getActivePtuIp();
}

// ── PTU command FIFO ────────────────────────────────────────────────
// Every PTU HTTP send goes through this queue, so exactly one request
// is in flight and commands reach the unit in the order they were
// issued. Without it, a quick D-pad tap could deliver stop before move
// (the move used to wait behind a speed-limit query while the stop
// fired immediately) and the PTU would drive at full speed until the
// next command. One global queue is enough: only one PTU is active at
// a time (alias-driven), and the target IP is resolved at dequeue so a
// PTU re-alias mid-queue sends to the current unit.

interface QueuedPtuCmd {
  /** Command string, or a thunk evaluated at dequeue time — used by
   *  D-pad moves so a just-completed speed-limit query ahead of them in
   *  the queue is reflected in the speed they send. */
  cmd: string | (() => string);
  resolve: (v: Record<string, string> | null) => void;
  reject: (e: unknown) => void;
  /** Checked at dequeue: return false to drop the command unsent
   *  (resolves null). Used to drop a queued move whose release already
   *  happened. */
  stillWanted?: () => boolean;
  /** Explicit target for entries that must reach a specific unit
   *  regardless of the current alias state (the farewell halt) —
   *  dequeue-time resolution would otherwise drop them once the alias
   *  is cleared, or worse, send them to the new holder. */
  targetIp?: string;
}

const ptuQueue: QueuedPtuCmd[] = [];
let ptuDraining = false;

function enqueuePtuCmd(
  cmd: string | (() => string),
  opts?: { stillWanted?: () => boolean; targetIp?: string }
): Promise<Record<string, string> | null> {
  return new Promise((resolve, reject) => {
    ptuQueue.push({
      cmd,
      resolve,
      reject,
      stillWanted: opts?.stillWanted,
      targetIp: opts?.targetIp,
    });
    if (!ptuDraining) {
      ptuDraining = true;
      void drainPtuQueue();
    }
  });
}

async function drainPtuQueue(): Promise<void> {
  while (ptuQueue.length > 0) {
    const item = ptuQueue.shift()!;
    if (item.stillWanted && !item.stillWanted()) {
      item.resolve(null);
      continue;
    }
    const ip = item.targetIp ?? getPtuIp();
    if (!ip) {
      item.resolve(null);
      continue;
    }
    const cmdStr = typeof item.cmd === "function" ? item.cmd() : item.cmd;
    try {
      item.resolve(await api.ptuSend(ip, cmdStr));
    } catch (e) {
      item.reject(e);
    }
  }
  ptuDraining = false;
}

/** Drop every pending queue entry, resolved null — the same
 *  disposition as a stillWanted drop. The single in-flight command,
 *  if any, already left the queue and completes first. */
function purgePtuQueue(): void {
  while (ptuQueue.length > 0) {
    ptuQueue.shift()!.resolve(null);
  }
}

/** Halt a specific PTU unit by IP, bypassing alias resolution. Called
 *  when a unit loses its PTU designation while it may be moving: a
 *  delivered move whose release-stop is still queued would otherwise
 *  drive the unit until its firmware limits (and extreme angles are a
 *  known firmware-crash trigger). Pending entries are purged first —
 *  they were intended for this unit and are superseded by the halt,
 *  and once the alias moves they would resolve against the wrong
 *  target. The velocity-stop then rides the FIFO pinned to the
 *  outgoing IP so it cannot race the in-flight command on the unit's
 *  single-threaded control handler. Fire-and-track: the caller is
 *  never blocked; a failed halt retries once, then surfaces loudly —
 *  a possibly-still-moving PTU is the one physical-safety event in
 *  role reassignment. */
export function haltPtuUnit(ip: string): void {
  purgePtuQueue();
  void (async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await enqueuePtuCmd("PS=0&TS=0", { targetIp: ip });
        return;
      } catch (e) {
        if (attempt === 0) continue;
        log(`PTU halt failed for ${ip}: ${formatError(e)}`);
        showToast(
          `PTU halt failed — ${ip} may still be moving; stop it via its web interface or power`,
          true
        );
      }
    }
  })();
}

async function ptuCmd(cmd: string): Promise<Record<string, string> | null> {
  if (!getPtuIp()) return null;
  return enqueuePtuCmd(cmd);
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
async function waitForPtuTarget(
  targetPan: number,
  targetTilt: number,
  maxTries = 40
): Promise<void> {
  // PP/TP encoders can jitter by a unit or two even at rest; tolerance
  // avoids missing the "reached target" detection on the last pixel.
  const TOLERANCE = 2;
  let last: string | null = null;
  let started = false;
  for (let i = 0; i < maxTries; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const data = await ptuCmd("PP&TP");
      if (!data) break;
      const pan = parseInt(data["PP"] ?? "", 10);
      const tilt = parseInt(data["TP"] ?? "", 10);
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

async function queryPtuSpeed(): Promise<void> {
  if (!getPtuIp()) return;
  try {
    const data = await ptuCmd("PU&TU&PL&TL");
    if (data) {
      const panUpper = parseInt(data["PU"] ?? "") || 100;
      const tiltUpper = parseInt(data["TU"] ?? "") || 100;
      ptuSpeedBig = Math.min(panUpper, tiltUpper);
      ptuSpeedSmall = Math.max(
        Math.round(ptuSpeedBig / 10),
        parseInt(data["PL"] ?? "") || 1
      );
      ptuSpeedQueried = true;
      log(`PTU limits: big=${ptuSpeedBig} small=${ptuSpeedSmall}`);
      await ptuCmd("C=V");
    }
  } catch (e) {
    log(`PTU init failed: ${formatError(e)}`);
  }
}

type SpeedAction = "up" | "down" | "left" | "right";

export function setupPtzControls(): void {
  // PTU IP is alias-driven now (no dropdown). Watch the device list
  // and re-query speed limits whenever the PTU-aliased device changes.
  let lastPtuIp: string | null = null;
  deviceList.subscribe(() => {
    const current = getActivePtuIp();
    if (current !== lastPtuIp) {
      lastPtuIp = current;
      ptuSpeedQueried = false;
      queryPtuSpeed();
    }
  });

  // D-pad buttons — hold to move at speed, release to stop
  const speedCmds: Record<SpeedAction, () => string> = {
    up: () => `TS=${ptuSpeedBig}`,
    down: () => `TS=${-ptuSpeedBig}`,
    left: () => `PS=${ptuSpeedBig}`,
    right: () => `PS=${-ptuSpeedBig}`,
  };

  document.querySelectorAll<HTMLElement>(".ptz-btn[data-ptz]").forEach((btn) => {
    const action = btn.dataset["ptz"];

    if (action === "home") {
      btn.addEventListener("click", async () => {
        if (!getPtuIp()) return;
        try {
          await ptuCmd(`C=I&PS=${ptuSpeedBig}&TS=${ptuSpeedBig}&PP=0&TP=0`);
          showToast("PTU homing");
          // Home is the full resting pose: zoom pulls back to wide while
          // the pan/tilt goto runs. Gated on a resolved CAM like preset
          // recall — no CAM means no zoom to park, not a toast.
          if (getCameraIp() && zoomParkWide) zoomParkWide();
          await waitForPtuTarget(0, 0);
        } catch (e) {
          log(`PTU home: ${formatError(e)}`);
        }
      });
      return;
    }

    // Press bookkeeping for the FIFO: each press gets a sequence number,
    // and a queued move whose release has already been recorded is
    // dropped at dequeue instead of sent — a tap released while the move
    // was still waiting in the queue must not start motion that only the
    // (already-processed) stop could end.
    //
    // All speed commands are C=V-prefixed: a D-pad press landing during
    // a Home/preset goto used to arrive while the PTU was still in C=I
    // (absolute) mode, where a PS=<speed> can drive the unit past its
    // limits (the 0.2.9 runaway-pan case). The prefix flips the unit
    // back to velocity mode in the same command, which both closes that
    // window and makes grabbing the D-pad cancel an in-flight goto.
    const startMove = (): void => {
      if (!getPtuIp()) return;
      if (!ptuSpeedQueried) void queryPtuSpeed();
      const seq = ++ptuPressSeq;
      if (action && action in speedCmds) {
        const cmdFn = speedCmds[action as SpeedAction];
        enqueuePtuCmd(() => `C=V&${cmdFn()}`, {
          stillWanted: () => ptuReleasedThrough < seq,
        }).catch((e) => log(`PTU ${action}: ${formatError(e)}`));
      }
    };
    const stopMove = (): void => {
      if (!getPtuIp()) return;
      ptuReleasedThrough = ptuPressSeq;
      ptuCmd("C=V&PS=0&TS=0").catch(() => {});
    };

    btn.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      startMove();
    });
    btn.addEventListener("pointerup", stopMove);
    btn.addEventListener("pointerleave", stopMove);
    btn.addEventListener("pointercancel", stopMove);
  });

  // Preset buttons — click to recall, long-press to save current position
  document
    .querySelectorAll<HTMLElement>(".ptz-preset-btn[data-preset]")
    .forEach((btn) => {
      let pressTimer: ReturnType<typeof setTimeout> | null = null;
      const preset = parseInt(btn.dataset["preset"] ?? "", 10);

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
              const zoomEl = $<HTMLInputElement>("#zoom-slider");
              const zoomVal = zoomEl ? parseInt(zoomEl.value, 10) : NaN;
              const zoom = Number.isFinite(zoomVal) ? zoomVal : null;
              ptuPresets.set(preset, {
                pan: data["PP"] ?? "0",
                tilt: data["TP"] ?? "0",
                zoom,
              });
              const zoomLabel = zoom !== null ? ` Z:${zoom}%` : "";
              showToast(
                `Preset ${preset} saved (P:${data["PP"]} T:${data["TP"]}${zoomLabel})`
              );
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
                parseInt(saved.tilt, 10)
              ).catch(() => {});

              // Route preset-zoom through the slider's drain queue so it
              // can't overlap an in-flight slider request (two concurrent
              // HTTP requests to control.cgi can wedge the camera's Lua
              // server, freezing the RTSP stream).
              if (saved.zoom !== null && getCameraIp()) {
                const zoomEl = $<HTMLInputElement>("#zoom-slider");
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

function getCameraIp(): string | null {
  return getActiveCamIp();
}

let zoomErrorToasted = false;

/** `quiet` marks a background push (saved-position restore): failures
 *  log but never toast — a toast about an action the user didn't take
 *  is noise. User-initiated sends (drag, preset recall) keep toasting. */
async function sendZoomPosition(percent: number, quiet: boolean): Promise<void> {
  const ip = getCameraIp();
  if (!ip) {
    if (!quiet && !zoomErrorToasted) {
      showToast("Select a CAM IP to use zoom", true);
      zoomErrorToasted = true;
    }
    return;
  }
  const position = Math.round((percent / 100) * ZOOM_MAX);
  log(`Zoom: ${percent}% (${position}) ip=${ip}${quiet ? " (restore)" : ""}`);
  try {
    await api.controlCgiZoomDirect(ip, position);
    zoomErrorToasted = false;
  } catch (e) {
    log(`Zoom failed: ${formatError(e)}`);
    if (!quiet && !zoomErrorToasted) {
      showToast(`Zoom failed: ${formatError(e)}`, true);
      zoomErrorToasted = true;
    }
  }
}

function setupZoomSlider(): void {
  const slider = $<HTMLInputElement>("#zoom-slider");
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
  let queued: { percent: number; quiet: boolean } | null = null;
  let lastSentPercent: number | null = null;

  async function drain(): Promise<void> {
    while (queued !== null) {
      const target = queued;
      queued = null;
      if (target.percent === lastSentPercent) continue;
      lastSentPercent = target.percent;
      await sendZoomPosition(target.percent, target.quiet);
      if (queued !== null) {
        await new Promise((r) => setTimeout(r, MIN_GAP_MS));
      }
    }
    inFlight = false;
  }

  // Coalescing keeps only the newest entry, so a loud user drag
  // supersedes a queued quiet restore — the failure toast then belongs
  // to the value the user actually asked for.
  function request(percent: number, quiet = false): void {
    queued = { percent, quiet };
    if (inFlight) return;
    inFlight = true;
    drain();
  }

  // Expose to preset-recall path so it shares this serialised queue.
  zoomRequest = request;

  // Home-button park: slider to wide, send through the shared queue
  // (loud — it's a user action), and persist so the saved position
  // stays truthful for the restore-on-selection path.
  zoomParkWide = () => {
    slider.value = "0";
    request(0);
    const ip = getCameraIp();
    if (ip) persistCurrent(ip, 0);
  };

  slider.addEventListener("input", (e) => {
    const target = e.target as HTMLInputElement;
    request(parseInt(target.value, 10));
  });

  // ── Position persistence ──────────────────────────────────────────
  // The camera firmware doesn't expose a zoom-query endpoint, so we
  // can't pull the live position on launch. Instead, persist the last
  // slider percent per-IP and restore it on CAM selection. Accurate as
  // long as we're the only controller; goes stale if someone also
  // moves the camera via its own web UI.
  async function persistCurrent(ip: string, percent: number): Promise<void> {
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
  let saveTimer: ReturnType<typeof setTimeout> | null = null;
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
  //
  // The push is gated on the CAM's registry status: at cold start the
  // node resolves from cache seconds after launch, long before subnet
  // adoption binds a route to it, and pushing then just burns an HTTP
  // timeout. Until the record exists AND reports live, hold the push
  // and let the deviceList subscription below fire it the moment the
  // CAM flips live (also covers a camera that boots after the app).
  let pendingRestoreIp: string | null = null;

  function applySavedZoom(): void {
    const ip = getCameraIp();
    if (!ip) return;
    const saved = state.config?.zoom_positions?.[ip];
    if (typeof saved !== "number") return;
    slider.value = String(saved);
    // A missing record is held exactly like a non-live one: the restore
    // can run before the registry has hydrated its cache at all, which
    // is precisely the no-route window. Nothing legitimate is lost by
    // holding — manually-entered IPs hydrate as Live records, so the
    // only record-less state is "not discovered yet".
    const record = deviceList.deviceByIp(ip);
    if (!record || record.status !== "live") {
      pendingRestoreIp = ip;
      return;
    }
    pendingRestoreIp = null;
    // Don't pre-set lastSentPercent — we want request() below to fire
    // so the camera catches up to the slider. Quiet: this is a
    // background restore, not a user action.
    request(saved, true);
  }

  deviceList.subscribe(() => {
    if (!pendingRestoreIp) return;
    const record = deviceList.deviceByIp(pendingRestoreIp);
    if (record?.status !== "live") return;
    // Re-check the selection — the user may have moved on while the
    // restore was pending; applySavedZoom re-derives everything.
    if (getCameraIp() !== pendingRestoreIp) {
      pendingRestoreIp = null;
      return;
    }
    applySavedZoom();
  });

  // Fires when the user clicks a different node (selectedDevice
  // moves) — the equivalent of the old dropdown change event.
  selectedDevice.subscribe(applySavedZoom);

  // Cold start: the click hasn't happened yet, so selectedDevice
  // is null. Poll briefly for state.config to land and the alias-
  // backed CAM to resolve, then apply once.
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
