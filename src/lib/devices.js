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

// ── Local scanning state ────────────────────────────────────────────

const scannedIps = new Set();
let pendingScans = 0;

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

    if (isNew) {
      log(`ARP: discovered ${device.ip} (${device.mac})`);
      showDiscoveryStatus("Port Scan...");
      scanDevicePorts(device.ip);
    }
  });

  api.onEvent("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    renderSubnetList();

    // Re-scan devices on the adopted subnet after a delay.
    // netsh takes a few seconds to fully activate the new IP.
    setTimeout(() => {
      for (const device of arpDevices.values()) {
        if (device.subnet === data.subnet) {
          scannedIps.delete(device.ip);
          tcpScanResults.delete(device.ip);
          showDiscoveryStatus("Port Scan...");
          scanDevicePorts(device.ip);
        }
      }
    }, 2000);
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

    if (devices && devices.length > 0) {
      for (const d of devices) {
        arpDevices.set(d.mac, d);
      }
      showDiscoveryStatus("Port Scan...");
      for (const d of devices) {
        scanDevicePorts(d.ip);
      }
    } else {
      showDiscoveryStatus("IP Discovery...");
    }

    if (subnets) {
      for (const [subnet, ip] of Object.entries(subnets)) {
        adoptedSubnets.set(subnet, ip);
      }
      if (Object.keys(subnets).length > 0) renderSubnetList();
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

      html += `
        <div class="device-item${state.selectedDevice === d.ip ? " selected" : ""}" data-ip="${d.ip}">
          <div class="device-name-row">
            <span class="device-name">${escapeHtml(name)}</span>
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
        dialog.close();
        renderArpDeviceList();
      } else if (role === "ptu") {
        const ip = dialog.dataset.ip;
        nodeAliases.set(ip, "PTU");
        $("#ptu-ip").value = ip;
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
    dialog.close();
    renderArpDeviceList();
  });

  $("#alias-clear").addEventListener("click", () => {
    const dialog = $("#alias-dialog");
    const ip = dialog.dataset.ip;
    nodeAliases.delete(ip);
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
