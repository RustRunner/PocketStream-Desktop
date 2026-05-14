/**
 * "Clear Cached Devices" management dialog.
 *
 * The persistent device cache itself lives entirely on the backend
 * (device_cache.toml + DeviceRegistry); this module only owns the UI
 * for letting the user prune any cached entry it chooses.
 * Triggered by clicking the "Nodes" card title.
 */

import * as api from "./tauri-api.ts";
import { $, log, escapeHtml } from "./state.ts";
import { hasRouteToSubnet } from "./device-state.ts";
import * as deviceList from "./device-list.ts";
import { showModalWithVideo } from "./streaming.js";
import { formatError } from "./errors.ts";

interface CacheEntry {
  mac: string;
  ip: string;
  subnet: string;
  alias: string;
  reason: string;
}

/** Open the dialog that lists every cached device and lets the user
 *  forget them individually or all at once. */
async function openCacheDialog(): Promise<void> {
  const dialog = $<HTMLDialogElement>("#cache-dialog");
  if (!dialog) return;

  // Show every record in the registry — live, verifying, offline, and
  // unroutable cached_only — so the user can prune stale entries that
  // accumulated from prior networks (e.g. an old CAM IP that responds
  // to port scans but isn't actually the cached device).
  const entries: CacheEntry[] = [];
  for (const r of deviceList.getDevices()) {
    let reason: string;
    switch (r.status) {
      case "offline":
        reason = "offline";
        break;
      case "cached_only":
        reason = hasRouteToSubnet(r.subnet) ? "cached" : "no route";
        break;
      case "verifying":
        reason = "verifying";
        break;
      case "live":
        reason = "live";
        break;
      default:
        reason = r.status;
    }
    entries.push({
      mac: r.mac,
      ip: r.ip,
      subnet: r.subnet,
      alias: r.alias || "",
      reason,
    });
  }
  entries.sort((a, b) => {
    if (a.subnet !== b.subnet) return a.subnet.localeCompare(b.subnet);
    return a.ip.localeCompare(b.ip, undefined, { numeric: true });
  });

  const listEl = $("#cache-dialog-list");
  const emptyEl = $<HTMLElement>("#cache-dialog-empty");
  const clearAllBtn = $<HTMLButtonElement>("#cache-clear-all");

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
    listEl
      .querySelectorAll<HTMLButtonElement>(".cache-forget-btn")
      .forEach((btn) => {
        btn.addEventListener("click", async () => {
          const mac = btn.dataset["forgetMac"];
          await forgetCachedDevice(mac);
          // Re-open with the refreshed list
          openCacheDialog();
        });
      });
  }

  if (dialog.open) dialog.close();
  await showModalWithVideo(dialog);
}

/** Drop a single cached device by MAC. Backend removes from the
 *  registry, deletes from the cache file, and emits a snapshot —
 *  the render path picks up the change automatically. */
async function forgetCachedDevice(mac: string | undefined): Promise<void> {
  if (!mac) return;
  try {
    await api.forgetDevice(mac);
  } catch (e) {
    log(`Failed to forget device ${mac}: ${formatError(e)}`);
  }
}

/** Drop every cached device. Walks the same candidate set the dialog
 *  displays so what's listed is what's cleared. */
async function clearAllCached(): Promise<void> {
  const macs = deviceList.getDevices().map((r) => r.mac);
  for (const mac of macs) {
    await forgetCachedDevice(mac);
  }
}

export function setupCacheDialog(): void {
  const titleEl = $("#nodes-title");
  if (titleEl) {
    titleEl.addEventListener("click", openCacheDialog);
  }

  const dialog = $<HTMLDialogElement>("#cache-dialog");
  if (!dialog) return;

  $<HTMLButtonElement>("#cache-close").addEventListener("click", () => dialog.close());
  $<HTMLButtonElement>("#cache-clear-all").addEventListener("click", async () => {
    await clearAllCached();
    openCacheDialog(); // refresh the now-empty list
  });
}
