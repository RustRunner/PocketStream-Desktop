/**
 * PocketStream Desktop — ARP discovery, device list, aliases
 */

import * as api from "./tauri-api.js";
import { $, state, log, nodeAliases, arpDevices, adoptedSubnets, tcpScanResults } from "./state.js";
import { renderSubnetList, updateCameraIpDropdown } from "./network.js";

// ── Helpers ─────────────────────────────────────────────────────────

/** Escape HTML special characters to prevent injection via innerHTML. */
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Subnet helpers ──────────────────────────────────────────────────

/** Check if we have an IP on the same /24 subnet (native or adopted). */
function hasRouteToSubnet(subnet) {
  // Check adopted subnets
  if (adoptedSubnets.has(subnet)) return true;
  // Check native interface IPs
  if (!state.activeInterface) return false;
  return state.activeInterface.ips.some((ip) => {
    const parts = ip.address.split(".");
    if (parts.length !== 4) return false;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24` === subnet;
  });
}

// ── Local scanning state ────────────────────────────────────────────

const scannedIps = new Set();
let pendingScans = 0;

/// Whether the persisted device cache has been loaded into memory yet.
/// Cache load is a one-shot per-app-session — refresh buttons don't reload it.
let cacheLoaded = false;

/// IPs of cached devices that haven't been verified by a fresh scan yet.
/// Cleared as fast-path verification completes for each entry.
const verifyingDevices = new Set();

/// IPs of cached devices whose verification scan failed (no open ports
/// or network error). Stay in the list so the user can still see what
/// was last known, but are visually marked as not-currently-reachable.
const offlineDevices = new Set();

/// MACs that were hydrated from the on-disk cache but haven't (yet) been
/// confirmed by a live ARP discovery in this session. Used to scope
/// rendering: cached entries on subnets we don't currently route to are
/// hidden, since they're stale ghosts from a previous network. They stay
/// in the cache file so they reappear automatically when the subnet
/// becomes routable again.
const cachedOnlyMacs = new Set();

// ── Debounced scan trigger ─────────────────────────────────────────
// Collect all ARP discoveries and subnet adoptions, then scan once
// after activity settles. This prevents partial renders and flicker.

const SETTLE_MS = 6000; // wait 6s after last ARP/adopt event
let settleTimer = null;

/** Reset the settle timer — called on every new ARP device or adoption. */
function debounceScan() {
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = setTimeout(() => {
    settleTimer = null;
    scanAllRoutableDevices();
  }, SETTLE_MS);
}

/** Scan all ARP-discovered devices that are on reachable subnets. */
function scanAllRoutableDevices() {
  const toScan = [];
  for (const device of arpDevices.values()) {
    if (!scannedIps.has(device.ip) && hasRouteToSubnet(device.subnet)) {
      toScan.push(device.ip);
    }
  }
  if (toScan.length === 0) {
    showDiscoveryStatus(null);
    return;
  }
  log(`Scanning ${toScan.length} routable device(s)...`);
  showDiscoveryStatus("Port Scan...");
  for (const ip of toScan) {
    scanDevicePorts(ip);
  }
}

// ── Discovery status ─────────────────────────────────────────────────

function showDiscoveryStatus(label) {
  const container = $("#discovery-status");
  if (!container) return;
  if (label) {
    $("#discovery-label").textContent = label;
    container.classList.remove("hidden");
  } else {
    container.classList.add("hidden");
  }
}

export function resetDiscoveryStatus() {
  scannedIps.clear();
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = null;
  showDiscoveryStatus("IP Discovery...");
}

// ── ARP event listeners ─────────────────────────────────────────────

export function setupArpListeners() {
  if (state.activeInterface) {
    showDiscoveryStatus("IP Discovery...");
  } else {
    showDiscoveryStatus(null);
  }

  api.onEvent("arp-device-discovered", (device) => {
    if (!state.activeInterface) return;
    if (state.activeInterface.ips.some((ip) => ip.address === device.ip)) return;

    const isNew = !arpDevices.has(device.mac);
    arpDevices.set(device.mac, device);
    // Live ARP confirmation — the entry is no longer cache-only.
    cachedOnlyMacs.delete(device.mac);

    if (isNew) {
      log(`ARP: discovered ${device.ip} (${device.mac})`);
      showDiscoveryStatus("IP Discovery...");
      debounceScan();
    }
  });

  api.onEvent("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    renderSubnetList();
    // Reset the settle timer — netsh needs time to activate the IP
    debounceScan();
  });

  loadExistingArpState();
}

export async function loadExistingArpState() {
  if (!state.activeInterface) {
    showDiscoveryStatus(null);
    return;
  }

  try {
    const [devices, subnets] = await Promise.all([
      api.getArpDevices(),
      api.getAdoptedSubnets(),
    ]);

    if (subnets) {
      for (const [subnet, ip] of Object.entries(subnets)) {
        adoptedSubnets.set(subnet, ip);
      }
      if (Object.keys(subnets).length > 0) renderSubnetList();
    }

    // Load persisted device cache once per session — renders the nodes
    // panel immediately with last-known state, before any new ARP/scan
    // traffic. Done after adoptedSubnets is populated so hasRouteToSubnet()
    // sees the right adopted IPs when deciding which entries to fast-scan.
    if (!cacheLoaded) {
      cacheLoaded = true;
      await loadDeviceCache();
    }

    if (devices && devices.length > 0) {
      for (const d of devices) {
        arpDevices.set(d.mac, d);
      }
      scanAllRoutableDevices();
    } else if (arpDevices.size === 0) {
      showDiscoveryStatus("IP Discovery...");
    }
  } catch (e) {
    console.error("Failed to load ARP state:", e);
  }
}

// ── Device cache (persisted across sessions) ───────────────────────

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
async function loadDeviceCache() {
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
    if (scannedIps.has(entry.ip)) continue;
    fastVerifyCachedDevice(entry.ip);
  }
}

/**
 * Targeted port scan for a cached device — fail-fast, no retries.
 * On success, the entry is refreshed in the on-disk cache via the
 * normal scanDevicePorts() path. On failure, we leave the cache entry
 * intact (the device may just be offline temporarily) but the cached
 * port data stays visible until the next discovery sweep.
 */
async function fastVerifyCachedDevice(ip) {
  scannedIps.add(ip);
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
    log(`Cache verify failed for ${ip}: ${e}`);
  } finally {
    verifyingDevices.delete(ip);
    if (verified) {
      offlineDevices.delete(ip);
    } else {
      // Couldn't reach the device — flag offline so the UI can dim it
      // and the user knows clicking it may not work right now.
      offlineDevices.add(ip);
    }
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

// ── Cached devices management dialog ────────────────────────────────

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
    scannedIps.delete(dev.ip);
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

// ── Alias persistence helper ────────────────────────────────────────

/**
 * Persist the current alias for the device with this IP.
 * Looks up the matching MAC and ports from in-memory state, then writes
 * the cache entry. No-op if the device isn't in the cache-eligible set
 * (no MAC known, or no open ports observed).
 */
function persistAliasForIp(ip) {
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

// ── Port scanning ───────────────────────────────────────────────────

const MAX_SCAN_RETRIES = 2;
const RETRY_DELAY_MS = 4000;

async function scanDevicePorts(ip, attempt = 0) {
  if (attempt === 0 && scannedIps.has(ip)) return;
  scannedIps.add(ip);
  if (attempt === 0) pendingScans++;

  try {
    const results = await api.scanNetwork(`${ip}/32`);
    let found = false;
    if (results) {
      for (const r of results) {
        if (r.reachable && r.open_ports.length > 0) {
          tcpScanResults.set(r.ip, r);
          found = true;
          // Device just responded — clear any stale offline flag from
          // a prior failed cache verification.
          offlineDevices.delete(r.ip);
          // Persist to disk so the next session can render this device
          // immediately without waiting for ARP/scan to complete.
          for (const dev of arpDevices.values()) {
            if (dev.ip === r.ip) {
              persistDeviceToCache(dev, r.open_ports);
              break;
            }
          }
        }
      }
    }
    if (!found) {
      scannedIps.delete(ip);
      // Retry — the device may be on a subnet that was just adopted
      if (attempt < MAX_SCAN_RETRIES) {
        setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
        return; // don't decrement pendingScans yet
      }
    }
  } catch (e) {
    log(`Port scan failed for ${ip}: ${e}`);
    scannedIps.delete(ip);
    if (attempt < MAX_SCAN_RETRIES) {
      setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
      return;
    }
  }

  pendingScans--;
  renderArpDeviceList();
  if (pendingScans <= 0) {
    showDiscoveryStatus(null);
  }
}

// ── Device list rendering ───────────────────────────────────────────

function renderArpDeviceList() {
  const list = $("#device-list");

  const bySubnet = new Map();
  for (const device of arpDevices.values()) {
    // Hide cached-only entries on subnets we don't currently route to —
    // they're stale ghosts from a different network. Stay in the cache
    // file so they reappear when the subnet is reachable again.
    if (cachedOnlyMacs.has(device.mac) && !hasRouteToSubnet(device.subnet)) {
      continue;
    }
    if (!bySubnet.has(device.subnet)) {
      bySubnet.set(device.subnet, []);
    }
    bySubnet.get(device.subnet).push(device);
  }

  if (bySubnet.size === 0 && pendingScans <= 0) {
    list.innerHTML = '<p class="placeholder-text">No devices found.</p>';
    updateCameraIpDropdown(null);
    return;
  }

  const subnetResults = [];

  const pencilSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.001 1.001 0 000-1.41l-2.34-2.34a1.001 1.001 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

  let html = "";
  let nodeIndex = 0;
  for (const [subnet, devices] of bySubnet) {
    const ownIps = new Set();
    if (state.activeInterface) {
      state.activeInterface.ips.forEach((ip) => ownIps.add(ip.address));
    }
    for (const ip of adoptedSubnets.values()) {
      ownIps.add(ip);
    }

    const filtered = devices.filter((d) => {
      if (ownIps.has(d.ip)) return false;
      const tcpData = tcpScanResults.get(d.ip);
      return tcpData && tcpData.open_ports && tcpData.open_ports.length > 0;
    });
    if (filtered.length === 0) continue;

    const devicesForDropdown = [];

    html += `<div class="subnet-group">`;

    for (const d of filtered) {
      nodeIndex++;
      const alias = nodeAliases.get(d.ip);
      const name = alias || `Node ${nodeIndex}`;
      const tcpData = tcpScanResults.get(d.ip);
      const ports = tcpData ? tcpData.open_ports : [];

      devicesForDropdown.push({ ip: d.ip, open_ports: ports });

      const classes = ["device-item"];
      if (state.selectedDevice === d.ip) classes.push("selected");
      // Cached devices being verified by an in-flight scan
      if (verifyingDevices.has(d.ip)) classes.push("verifying");
      // Cached devices whose verification scan failed (no route, or
      // device isn't responding to a targeted port scan right now)
      if (offlineDevices.has(d.ip)) classes.push("offline");

      const statusBadge = verifyingDevices.has(d.ip)
        ? '<span class="device-status" title="Verifying...">verifying</span>'
        : offlineDevices.has(d.ip)
          ? '<span class="device-status" title="Last-known state — device not responding">offline</span>'
          : "";

      html += `
        <div class="${classes.join(" ")}" data-ip="${d.ip}">
          <div class="device-name-row">
            <span class="device-name">${escapeHtml(name)}</span>
            ${statusBadge}
            <button class="edit-alias-btn" data-alias-ip="${d.ip}" title="Rename">${pencilSvg}</button>
          </div>
          <div class="device-detail-row">
            <a class="device-ip" href="#" data-browse="${d.ip}" title="Open in browser">${d.ip}</a>
            <span class="device-ports">${ports.join(", ")}</span>
          </div>
        </div>`;
    }

    html += `</div>`;

    subnetResults.push({
      subnet,
      localIp: adoptedSubnets.get(subnet) || (state.activeInterface?.ips[0]?.address ?? ""),
      devices: devicesForDropdown,
    });
  }

  if (!html && pendingScans > 0) return;
  if (!html) {
    list.innerHTML = '<p class="placeholder-text">No devices found.</p>';
    updateCameraIpDropdown(null);
    return;
  }

  list.innerHTML = html;

  // Wire up event handlers
  list.querySelectorAll(".device-item").forEach((item) => {
    item.addEventListener("click", (e) => {
      if (e.target.closest(".device-ip") || e.target.closest(".edit-alias-btn")) return;
      list.querySelectorAll(".device-item").forEach((i) => i.classList.remove("selected"));
      item.classList.add("selected");
      state.selectedDevice = item.dataset.ip;
      const select = $("#camera-ip");
      select.value = state.selectedDevice;
      if (state.config) {
        state.config.stream.camera_ip = state.selectedDevice;
      }
    });
  });

  list.querySelectorAll(".device-ip[data-browse]").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const ip = link.dataset.browse;
      const invoke = window.__TAURI__?.core?.invoke;
      if (invoke) {
        invoke("plugin:shell|open", { path: `http://${ip}` }).catch(() => {
          window.open(`http://${ip}`, "_blank");
        });
      } else {
        window.open(`http://${ip}`, "_blank");
      }
    });
  });

  list.querySelectorAll(".edit-alias-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      openAliasDialog(btn.dataset.aliasIp);
    });
  });

  state.lastSubnetResults = subnetResults;
  updateCameraIpDropdown(subnetResults);
}

// ── Alias dialog ────────────────────────────────────────────────────

function openAliasDialog(ip) {
  const dialog = $("#alias-dialog");
  $("#alias-dialog-ip").textContent = ip;
  $("#alias-input").value = "";
  $("#alias-custom-field").style.display = "none";
  dialog.dataset.ip = ip;

  // Reset role buttons
  const existing = nodeAliases.get(ip) || "";
  const roleBtns = dialog.querySelectorAll("[data-role]");
  roleBtns.forEach((b) => b.classList.remove("active"));

  const isCustom = existing && existing !== "CAM" && existing !== "PTU";
  if (existing === "CAM") {
    dialog.querySelector("[data-role='cam']").classList.add("active");
  } else if (existing === "PTU") {
    dialog.querySelector("[data-role='ptu']").classList.add("active");
  } else if (existing) {
    dialog.querySelector("[data-role='custom']").classList.add("active");
    $("#alias-input").value = existing;
    $("#alias-custom-field").style.display = "";
  }

  // Show Clear/Save only for custom role
  $("#alias-clear").style.display = isCustom ? "" : "none";
  $("#alias-save").style.display = isCustom ? "" : "none";

  if (dialog.open) dialog.close();
  api.setVideoVisible(false).catch(() => {});
  dialog.showModal();
  dialog.addEventListener("close", () => api.setVideoVisible(true).catch(() => {}), { once: true });
}

export function setupAliasDialog() {
  const dialog = $("#alias-dialog");

  function updateAliasActions(role) {
    const isCustom = role === "custom";
    $("#alias-clear").style.display = isCustom ? "" : "none";
    $("#alias-save").style.display = isCustom ? "" : "none";
  }

  // Role toggle buttons
  const roleBtns = document.querySelectorAll(".alias-role-group [data-role]");
  roleBtns.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      roleBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const role = btn.dataset.role;

      if (role === "cam") {
        const ip = dialog.dataset.ip;
        nodeAliases.set(ip, "CAM");
        $("#camera-ip").value = ip;
        if (state.config) state.config.stream.camera_ip = ip;
        persistAliasForIp(ip);
        dialog.close();
        renderArpDeviceList();
      } else if (role === "ptu") {
        const ip = dialog.dataset.ip;
        nodeAliases.set(ip, "PTU");
        $("#ptu-ip").value = ip;
        persistAliasForIp(ip);
        dialog.close();
        renderArpDeviceList();
      } else {
        $("#alias-custom-field").style.display = "";
        updateAliasActions("custom");
        $("#alias-input").focus();
      }
    });
  });

  $("#alias-save").addEventListener("click", () => {
    const ip = dialog.dataset.ip;
    const alias = $("#alias-input").value.trim();
    if (alias) {
      nodeAliases.set(ip, alias);
    } else {
      nodeAliases.delete(ip);
    }
    persistAliasForIp(ip);
    dialog.close();
    renderArpDeviceList();
  });

  $("#alias-clear").addEventListener("click", () => {
    const dialog = $("#alias-dialog");
    const ip = dialog.dataset.ip;
    nodeAliases.delete(ip);
    persistAliasForIp(ip);
    dialog.close();
    renderArpDeviceList();
  });

  $("#alias-cancel").addEventListener("click", () => {
    $("#alias-dialog").close();
  });

  $("#alias-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("#alias-save").click();
    }
  });
}
