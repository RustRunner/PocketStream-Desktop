/**
 * "Clear Offline Devices" management dialog.
 *
 * The persistent device cache itself lives entirely on the backend
 * (device_cache.toml + DeviceRegistry); this module only owns the UI
 * for letting the user prune offline / unreachable cached entries.
 * Triggered by clicking the "Nodes" card title.
 */

import * as api from "./tauri-api.js";
import { $, log, escapeHtml } from "./state.js";
import { hasRouteToSubnet } from "./device-state.js";
import * as deviceList from "./device-list.js";
import { formatError } from "./errors.js";

/** Open the dialog that lists offline / stale cached devices and lets
 *  the user forget them individually or all at once. */
function openCacheDialog() {
  const dialog = $("#cache-dialog");
  if (!dialog) return;

  // Build the candidate list: anything in the registry that is NOT
  // currently confirmed working — i.e. visibly offline, or hidden
  // because its subnet isn't routable right now (cache-only on
  // unroutable subnet).
  const entries = [];
  for (const r of deviceList.getDevices()) {
    const isOffline = r.status === "offline";
    const isStaleHidden = r.status === "cached_only" && !hasRouteToSubnet(r.subnet);
    if (!isOffline && !isStaleHidden) continue;
    entries.push({
      mac: r.mac,
      ip: r.ip,
      subnet: r.subnet,
      alias: r.alias || "",
      reason: isOffline ? "offline" : "no route",
    });
  }
  entries.sort((a, b) => {
    if (a.subnet !== b.subnet) return a.subnet.localeCompare(b.subnet);
    return a.ip.localeCompare(b.ip, undefined, { numeric: true });
  });

  const listEl = $("#cache-dialog-list");
  const emptyEl = $("#cache-dialog-empty");
  const clearAllBtn = $("#cache-clear-all");

  if (entries.length === 0) {
    listEl.innerHTML = "";
    emptyEl.style.display = "";
    clearAllBtn.disabled = true;
  } else {
    emptyEl.style.display = "none";
    clearAllBtn.disabled = false;
    listEl.innerHTML = entries
      .map((e) => {
        const name = e.alias || `(unnamed)`;
        return `
          <div class="cache-item" data-mac="${escapeHtml(e.mac)}" data-ip="${escapeHtml(e.ip)}">
            <div class="cache-item-info">
              <div class="cache-item-name">${escapeHtml(name)}</div>
              <div class="cache-item-detail">
                <span class="cache-item-ip">${escapeHtml(e.ip)}</span>
                <span class="cache-item-subnet">${escapeHtml(e.subnet)}</span>
                <span class="cache-item-reason">${escapeHtml(e.reason)}</span>
              </div>
            </div>
            <button class="cache-forget-btn icon-btn small" data-forget-mac="${escapeHtml(e.mac)}" title="Forget this device">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
            </button>
          </div>`;
      })
      .join("");

    // Per-row forget handlers
    listEl.querySelectorAll(".cache-forget-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const mac = btn.dataset.forgetMac;
        await forgetCachedDevice(mac);
        // Re-open with the refreshed list
        openCacheDialog();
      });
    });
  }

  if (dialog.open) dialog.close();
  api.setVideoVisible(false).catch(() => {});
  dialog.showModal();
  dialog.addEventListener(
    "close",
    () => api.setVideoVisible(true).catch(() => {}),
    { once: true }
  );
}

/** Drop a single cached device by MAC. Backend removes from the
 *  registry, deletes from the cache file, and emits a snapshot —
 *  the render path picks up the change automatically. */
async function forgetCachedDevice(mac) {
  if (!mac) return;
  try {
    await api.forgetDevice(mac);
  } catch (e) {
    log(`Failed to forget device ${mac}: ${formatError(e)}`);
  }
}

/** Drop every offline + stale-hidden cached device. Walks the same
 *  candidate set the dialog displays so what's listed is what's cleared. */
async function clearAllOfflineCached() {
  const macs = [];
  for (const r of deviceList.getDevices()) {
    const isOffline = r.status === "offline";
    const isStaleHidden = r.status === "cached_only" && !hasRouteToSubnet(r.subnet);
    if (isOffline || isStaleHidden) macs.push(r.mac);
  }
  for (const mac of macs) {
    await forgetCachedDevice(mac);
  }
}

export function setupCacheDialog() {
  const titleEl = $("#nodes-title");
  if (titleEl) {
    titleEl.addEventListener("click", openCacheDialog);
  }

  const dialog = $("#cache-dialog");
  if (!dialog) return;

  $("#cache-close").addEventListener("click", () => dialog.close());
  $("#cache-clear-all").addEventListener("click", async () => {
    await clearAllOfflineCached();
    openCacheDialog(); // refresh the now-empty list
  });
}
