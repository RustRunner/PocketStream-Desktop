/**
 * PocketStream Desktop — Persistent device cache + management dialog.
 *
 * Owns the on-disk cache of previously-discovered devices and the UI
 * for clearing offline / stale entries. Exposes:
 *
 *   - State sets (verifyingDevices / offlineDevices / cachedOnlyMacs)
 *     consumed by the render path in devices.js
 *   - loadDeviceCache() — hydrate from disk on startup
 *   - persistDeviceToCache() — called after every successful port scan
 *   - persistAliasForIp() — called whenever a device alias changes
 *   - setupCacheDialog() — wire the "Nodes" title click → modal
 */

import * as api from "./tauri-api.js";
import {
  $,
  state,
  log,
  escapeHtml,
  nodeAliases,
  arpDevices,
  tcpScanResults,
} from "./state.js";
// devices.js imports back from this module — ES module circular imports
// resolve correctly as long as the imported symbols are only accessed
// inside function bodies (never at module top-level), which is the case
// for both directions here.
import { renderArpDeviceList, hasRouteToSubnet, markIpScanned, isIpScanned } from "./devices.js";

// ── Cache state (exported for the render path in devices.js) ───────

/// IPs of cached devices that haven't been verified by a fresh scan yet.
/// Cleared as fast-path verification completes for each entry.
export const verifyingDevices = new Set();

/// IPs of cached devices whose verification scan failed (no open ports
/// or network error). Stay in the list so the user can still see what
/// was last known, but are visually marked as not-currently-reachable.
export const offlineDevices = new Set();

/// MACs that were hydrated from the on-disk cache but haven't (yet) been
/// confirmed by a live ARP discovery in this session. Used to scope
/// rendering: cached entries on subnets we don't currently route to are
/// hidden, since they're stale ghosts from a previous network. They stay
/// in the cache file so they reappear automatically when the subnet
/// becomes routable again.
export const cachedOnlyMacs = new Set();

/// One-shot per-app-session: refresh buttons don't reload the cache.
let cacheLoaded = false;

// ── Cache I/O ──────────────────────────────────────────────────────

/**
 * Load the persisted device cache from disk and render immediately.
 *
 * Cached entries pre-populate `arpDevices`, `tcpScanResults`, and
 * `nodeAliases` so the nodes panel paints with last-known state on
 * startup. Then a fast-path port scan runs in parallel against entries
 * on currently-routable subnets to confirm they're still reachable —
 * no debounce, no retries, since this path exists to verify the cache
 * not to discover new devices.
 */
export async function loadDeviceCache() {
  if (cacheLoaded) return;
  cacheLoaded = true;

  let cache;
  try {
    cache = await api.getDeviceCache();
  } catch (e) {
    log(`Failed to load device cache: ${e}`);
    return;
  }
  if (!cache || cache.length === 0) return;

  for (const entry of cache) {
    if (!entry.mac || !entry.ip) continue;
    // Don't clobber a fresh ARP discovery that arrived before the cache load.
    if (!arpDevices.has(entry.mac)) {
      arpDevices.set(entry.mac, {
        mac: entry.mac,
        ip: entry.ip,
        subnet: entry.subnet,
        first_seen: entry.last_seen,
        last_seen: entry.last_seen,
      });
      // Mark as cache-only until live ARP confirms the device is here now.
      cachedOnlyMacs.add(entry.mac);
    }
    // Pre-populate scan results so the device renders with its known ports.
    if (entry.open_ports && entry.open_ports.length > 0) {
      if (!tcpScanResults.has(entry.ip)) {
        tcpScanResults.set(entry.ip, {
          ip: entry.ip,
          reachable: true,
          open_ports: entry.open_ports,
        });
      }
    }
    if (entry.alias && !nodeAliases.has(entry.ip)) {
      nodeAliases.set(entry.ip, entry.alias);
    }
  }

  // Mark cached devices on routable subnets as "verifying" so the UI
  // shows a subtle indicator until the targeted scan returns. Entries on
  // non-routable subnets aren't tracked here — they're hidden by the
  // render filter (cachedOnlyMacs + hasRouteToSubnet) and will reappear
  // automatically when the subnet becomes reachable again.
  for (const entry of cache) {
    if (!entry.ip) continue;
    if (hasRouteToSubnet(entry.subnet)) {
      verifyingDevices.add(entry.ip);
    }
  }

  log(`Loaded ${cache.length} cached device(s) from disk`);
  renderArpDeviceList();

  // Fast-path verify: targeted scans for cached devices on routable
  // subnets. Parallel, no debounce, no retries — the cache is being
  // verified, not discovered.
  for (const entry of cache) {
    if (!hasRouteToSubnet(entry.subnet)) continue;
    if (isIpScanned(entry.ip)) continue;
    fastVerifyCachedDevice(entry.ip);
  }
}

/**
 * Targeted port scan for a cached device. On success, the entry is
 * refreshed in the on-disk cache. On failure, retries once with a short
 * delay before flagging offline — cold-start has many sources of
 * transient failure (Npcap loading, GStreamer init, OS ARP ping sweep,
 * just-bound secondary IPs not yet in the routing table) and the first
 * attempt routinely fails for devices that are perfectly reachable a
 * second later.
 */
// Three attempts handles devices (notably the FLIR PTU) that need an
// extra moment to respond to TCP probes on a freshly bound secondary
// IP. Worst case before flagging offline: ~5s (1.5s + 3s + ~1s scans).
const VERIFY_MAX_ATTEMPTS = 3;
const VERIFY_RETRY_DELAY_MS = 1500;

async function fastVerifyCachedDevice(ip, attempt = 0) {
  if (attempt === 0) markIpScanned(ip);
  let verified = false;
  try {
    const results = await api.scanNetwork(`${ip}/32`);
    if (results) {
      for (const r of results) {
        if (r.ip === ip && r.reachable && r.open_ports.length > 0) {
          tcpScanResults.set(r.ip, r);
          verified = true;
          // Find the MAC for this IP so we can refresh the cache entry
          for (const dev of arpDevices.values()) {
            if (dev.ip === r.ip) {
              persistDeviceToCache(dev, r.open_ports);
              break;
            }
          }
        }
      }
    }
  } catch (e) {
    // Verification failure isn't fatal — keep the cached entry visible.
    log(`Cache verify failed for ${ip} (attempt ${attempt + 1}): ${e}`);
  }

  if (verified) {
    verifyingDevices.delete(ip);
    offlineDevices.delete(ip);
    renderArpDeviceList();
  } else if (attempt + 1 < VERIFY_MAX_ATTEMPTS) {
    // Hold the verifying badge through the retry — flipping to offline
    // just to flip back would be jarring.
    setTimeout(() => fastVerifyCachedDevice(ip, attempt + 1), VERIFY_RETRY_DELAY_MS);
  } else {
    // Final attempt failed — flag offline so the UI can dim it and the
    // user knows clicking it may not work right now.
    verifyingDevices.delete(ip);
    offlineDevices.add(ip);
    renderArpDeviceList();
  }
}

/**
 * Write a single device to the persistent cache.
 * Called after every successful port scan that finds open ports.
 */
export function persistDeviceToCache(device, openPorts) {
  if (!device || !device.mac || !openPorts || openPorts.length === 0) return;
  const entry = {
    mac: device.mac,
    ip: device.ip,
    subnet: device.subnet,
    open_ports: openPorts,
    alias: nodeAliases.get(device.ip) || "",
    last_seen: new Date().toISOString(),
  };
  api.upsertCachedDevice(entry).catch((e) => {
    log(`Failed to persist device to cache: ${e}`);
  });
}

/**
 * Persist the current alias for the device with this IP.
 * Looks up the matching MAC and ports from in-memory state, then writes
 * the cache entry. No-op if the device isn't in the cache-eligible set
 * (no MAC known, or no open ports observed).
 */
export function persistAliasForIp(ip) {
  if (!ip) return;
  const ports = tcpScanResults.get(ip)?.open_ports;
  if (!ports || ports.length === 0) return;
  for (const dev of arpDevices.values()) {
    if (dev.ip === ip) {
      persistDeviceToCache(dev, ports);
      return;
    }
  }
}

// ── Cache management dialog (Nodes title → "Clear Offline Devices") ─

/**
 * Open the dialog that lists offline / stale cached devices and lets
 * the user forget them individually or all at once. Triggered by
 * clicking the "Nodes" card title.
 */
function openCacheDialog() {
  const dialog = $("#cache-dialog");
  if (!dialog) return;

  // Build the candidate list: anything cached that is NOT currently
  // confirmed working — i.e. visibly offline, or hidden because its
  // subnet isn't routable right now (cache-only on unroutable subnet).
  const entries = [];
  for (const dev of arpDevices.values()) {
    const isOffline = offlineDevices.has(dev.ip);
    const isStaleHidden =
      cachedOnlyMacs.has(dev.mac) && !hasRouteToSubnet(dev.subnet);
    if (!isOffline && !isStaleHidden) continue;
    entries.push({
      mac: dev.mac,
      ip: dev.ip,
      subnet: dev.subnet,
      alias: nodeAliases.get(dev.ip) || "",
      reason: isOffline ? "offline" : "no route",
    });
  }
  // Sort by subnet, then IP for predictable ordering.
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

/**
 * Drop a single cached device by MAC: remove from in-memory state,
 * clear its visual flags, and delete from the persisted cache file.
 */
async function forgetCachedDevice(mac) {
  if (!mac) return;
  const dev = arpDevices.get(mac);
  if (dev) {
    arpDevices.delete(mac);
    tcpScanResults.delete(dev.ip);
    nodeAliases.delete(dev.ip);
    verifyingDevices.delete(dev.ip);
    offlineDevices.delete(dev.ip);
    // Allow this IP to be rescanned if it ever returns.
    markIpScanned(dev.ip, /* clear */ true);
  }
  cachedOnlyMacs.delete(mac);
  try {
    await api.removeCachedDevice(mac);
  } catch (e) {
    log(`Failed to remove cached device ${mac}: ${e}`);
  }
  renderArpDeviceList();
}

/**
 * Drop every offline + stale-hidden cached device. Walks the same
 * candidate set the dialog displays so what's listed is what's cleared.
 */
async function clearAllOfflineCached() {
  const macs = [];
  for (const dev of arpDevices.values()) {
    const isOffline = offlineDevices.has(dev.ip);
    const isStaleHidden =
      cachedOnlyMacs.has(dev.mac) && !hasRouteToSubnet(dev.subnet);
    if (isOffline || isStaleHidden) macs.push(dev.mac);
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

// Suppress reference state.* — kept in import for symmetry with other lib files.
void state;
