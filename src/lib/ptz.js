/**
 * PocketStream Desktop — FLIR PTU controls
 */

import * as api from "./tauri-api.js";
import { $, log, showToast } from "./state.js";

// ── Local PTU state ─────────────────────────────────────────────────

let ptuSpeedBig = 100;
let ptuSpeedSmall = 10;
const ptuPresets = new Map(); // preset# -> { pan, tilt }

function getPtuIp() {
  return $("#ptu-ip").value || null;
}

async function ptuCmd(cmd) {
  const ip = getPtuIp();
  if (!ip) return null;
  return api.ptuSend(ip, cmd);
}

async function waitForPtuHome(maxTries = 40) {
  let lastPan = null, lastTilt = null;
  for (let i = 0; i < maxTries; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const data = await ptuCmd("PP&TP");
      if (!data) break;
      const pan = data.PP;
      const tilt = data.TP;
      if (pan === lastPan && tilt === lastTilt) break;
      lastPan = pan;
      lastTilt = tilt;
    } catch (_) {
      break;
    }
  }
  await ptuCmd("C=V").catch(() => {});
  log("PTU: back to speed mode");
}

// ── PTZ control setup ───────────────────────────────────────────────

export function setupPtzControls() {
  // Query PTU speed limits when PTU IP is selected
  $("#ptu-ip").addEventListener("change", async () => {
    if (!getPtuIp()) return;
    try {
      const data = await ptuCmd("PU&TU&PL&TL");
      if (data) {
        const panUpper = parseInt(data.PU) || 100;
        const tiltUpper = parseInt(data.TU) || 100;
        ptuSpeedBig = Math.min(panUpper, tiltUpper);
        ptuSpeedSmall = Math.max(Math.round(ptuSpeedBig / 10), parseInt(data.PL) || 1);
        log(`PTU limits: big=${ptuSpeedBig} small=${ptuSpeedSmall}`);
        await ptuCmd("C=V");
      }
    } catch (e) {
      log(`PTU init failed: ${e}`);
    }
  });

  // D-pad buttons — hold to move at speed, release to stop
  const speedCmds = {
    up:         () => `TS=${ptuSpeedBig}`,
    down:       () => `TS=${-ptuSpeedBig}`,
    left:       () => `PS=${ptuSpeedBig}`,
    right:      () => `PS=${-ptuSpeedBig}`,
    "zoom-in":  () => `TS=${ptuSpeedSmall}`,
    "zoom-out": () => `TS=${-ptuSpeedSmall}`,
  };

  document.querySelectorAll(".ptz-btn[data-ptz]").forEach((btn) => {
    const action = btn.dataset.ptz;

    if (action === "home") {
      btn.addEventListener("click", async () => {
        if (!getPtuIp()) return;
        try {
          await ptuCmd(`C=I&PS=${ptuSpeedBig}&TS=${ptuSpeedBig}&PP=0&TP=0`);
          showToast("PTU homing");
          await waitForPtuHome();
        } catch (e) {
          log(`PTU home: ${e}`);
        }
      });
      return;
    }

    const startMove = () => {
      if (!getPtuIp()) return;
      const cmdFn = speedCmds[action];
      if (cmdFn) ptuCmd(cmdFn()).catch((e) => log(`PTU ${action}: ${e}`));
    };
    const stopMove = () => {
      if (!getPtuIp()) return;
      ptuCmd("PS=0&TS=0").catch(() => {});
    };

    btn.addEventListener("mousedown", startMove);
    btn.addEventListener("mouseup", stopMove);
    btn.addEventListener("mouseleave", stopMove);
  });

  // Preset buttons — click to recall, long-press to save current position
  document.querySelectorAll(".ptz-preset-btn[data-preset]").forEach((btn) => {
    let pressTimer = null;
    const preset = parseInt(btn.dataset.preset);

    btn.addEventListener("mousedown", () => {
      pressTimer = setTimeout(async () => {
        pressTimer = null;
        if (!getPtuIp()) return;
        try {
          const data = await ptuCmd("PP&TP");
          if (data) {
            ptuPresets.set(preset, { pan: data.PP, tilt: data.TP });
            showToast(`Preset ${preset} saved (P:${data.PP} T:${data.TP})`);
          }
        } catch (e) {
          showToast(`Failed: ${e}`, true);
        }
      }, 800);
    });

    btn.addEventListener("mouseup", async () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
        if (!getPtuIp()) return;
        const saved = ptuPresets.get(preset);
        if (saved) {
          try {
            await ptuCmd(`C=I&PS=${ptuSpeedBig}&TS=${ptuSpeedBig}&PP=${saved.pan}&TP=${saved.tilt}`);
            waitForPtuHome().catch(() => {});
          } catch (e) {
            log(`PTU preset ${preset}: ${e}`);
          }
        } else {
          showToast(`Preset ${preset} not saved yet`, true);
        }
      }
    });

    btn.addEventListener("mouseleave", () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
    });
  });
}
