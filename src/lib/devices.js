/**
 * PocketStream Desktop — ARP discovery, port scanning, device list,
 * and the per-device alias dialog.
 *
 * Cache persistence and the "Clear Offline Devices" management dialog
 * live in device-cache.js; this module imports the cache hooks and
 * status sets where the discovery/scan/render flows need them.
 */

import * as api from "./tauri-api.js";
import {
  $,
  state,
  log,
  escapeHtml,
  nodeAliases,
  arpDevices,
  adoptedSubnets,
  tcpScanResults,
} from "./state.js";
import { renderSubnetList, updateCameraIpDropdown } from "./network.js";
import {
  loadDeviceCache,
  persistDeviceToCache,
  persistAliasForIp,
  verifyingDevices,
  offlineDevices,
  cachedOnlyMacs,
} from "./device-cache.js";

// ── Subnet helpers ──────────────────────────────────────────────────

/** Check if we have an IP on the same /24 subnet (native or adopted). */
export function hasRouteToSubnet(subnet) {
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

/**
 * Accessor for the device-cache module: check whether an IP has been
 * scanned this session. Cache verification skips IPs already in flight
 * via the regular discovery path.
 */
export function isIpScanned(ip) {
  return scannedIps.has(ip);
}

/**
 * Accessor for the device-cache module: mark an IP as scanned, or clear
 * the mark when a cached entry is forgotten so it can be re-scanned if
 * the device ever returns.
 */
export function markIpScanned(ip, clear = false) {
  if (clear) {
    scannedIps.delete(ip);
  } else {
    scannedIps.add(ip);
  }
}

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

    // Hydrate the persisted device cache once per session — renders the
    // nodes panel immediately with last-known state, before any new ARP
    // or scan traffic. Done after adoptedSubnets is populated so the
    // cache module's hasRouteToSubnet() checks see the right routes.
    await loadDeviceCache();

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

export function renderArpDeviceList() {
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
