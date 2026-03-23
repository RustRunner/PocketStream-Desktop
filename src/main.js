/**
 * PocketStream Desktop — Main Application
 */

import * as api from "./lib/tauri-api.js";

// ── State ───────────────────────────────────────────────────────────

let config = null;
let selectedDevice = null;
let isStreaming = false;
let isRtspRunning = false;
let isRecording = false;
let statusPollInterval = null;
const nodeAliases = new Map(); // IP -> alias string
let lastSubnetResults = []; // cache for re-rendering after alias changes

// ARP discovery state
const arpDevices = new Map(); // MAC -> ArpDevice
const adoptedSubnets = new Map(); // subnet -> adopted IP string

// ── DOM References ──────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Init ────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  setupMenuAndAbout();
  setupProtocolToggle();
  setupStreamControls();
  setupRtspControls();
  setupIpConfigDialog();
  setupSettingsSave();
  setupAliasDialog();
  setupCameraIpDropdown();

  setupRefreshButton();
  setupPtzControls();

  await loadConfig();
  await refreshInterfaces();

  // Start listening for ARP events (backend auto-starts ARP discovery)
  setupArpListeners();
});

// ── Config ──────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    config = await api.getConfig();
    if (!config) return;

    // Populate settings UI
    $("#rtsp-port").value = config.stream.rtsp_port;
    $("#rtsp-path").value = config.stream.rtsp_path;
    $("#udp-port").value = config.stream.udp_port;
    $("#camera-user").value = config.credentials.username;
    $("#camera-pass").value = config.credentials.password;
    $("#rtsp-server-enable").checked = config.rtsp_server.enabled;
    $("#rtsp-server-port").value = config.rtsp_server.port;
    $("#rtsp-token").value = config.rtsp_server.token;

    // Set active protocol
    const proto = config.stream.protocol;
    $$("[data-protocol]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.protocol === proto);
    });
    updateProtocolVisibility(proto);
  } catch (e) {
    console.error("Failed to load config:", e);
  }
}

function setupSettingsSave() {
  $("#save-settings").addEventListener("click", async () => {
    const activeProto = $("[data-protocol].active")?.dataset.protocol || "rtsp";

    const settings = {
      stream: {
        protocol: activeProto,
        rtsp_port: parseInt($("#rtsp-port").value) || 554,
        rtsp_path: $("#rtsp-path").value || "/live",
        udp_port: parseInt($("#udp-port").value) || 8600,
        camera_ip: config?.stream?.camera_ip || "",
      },
      rtsp_server: {
        enabled: $("#rtsp-server-enable").checked,
        port: parseInt($("#rtsp-server-port").value) || 8554,
        token: $("#rtsp-token").value,
      },
      credentials: {
        username: $("#camera-user").value,
        password: $("#camera-pass").value,
      },
    };

    try {
      await api.saveConfig(settings);
      config = settings;
      showToast("Settings saved");
    } catch (e) {
      showToast("Failed to save: " + e, true);
    }
  });

  // Regenerate token
  $("#regen-token").addEventListener("click", () => {
    const hex = Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    $("#rtsp-token").value = hex;
  });
}

// ── Sidebar ─────────────────────────────────────────────────────────

function setupMenuAndAbout() {
  // Hamburger toggles settings sidebar
  $("#menu-toggle").addEventListener("click", () => {
    const sidebar = $("#sidebar");
    sidebar.classList.toggle("collapsed");

    // Reposition video after sidebar animation completes
    if (isStreaming) {
      // Hide during animation to prevent overlap
      api.setVideoVisible(false);
      setTimeout(async () => {
        try {
          const bounds = getVideoAreaBounds();
          await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
          await api.setVideoVisible(true);
        } catch (_) {}
      }, 250);
    }
  });

  // About icon toggles about panel
  const aboutPanel = $("#about-panel");
  $("#about-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    aboutPanel.classList.toggle("open");
  });

  // Close about panel when clicking elsewhere
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".about-wrapper")) {
      aboutPanel.classList.remove("open");
    }
  });
}

// ── Protocol Toggle ─────────────────────────────────────────────────

function setupProtocolToggle() {
  $$("[data-protocol]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("[data-protocol]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      updateProtocolVisibility(btn.dataset.protocol);
    });
  });
}

function updateProtocolVisibility(protocol) {
  $("#rtsp-settings").style.display = protocol === "rtsp" ? "" : "none";
  $("#udp-settings").style.display = protocol === "udp" ? "" : "none";
}

// ── Network ─────────────────────────────────────────────────────────

// Track the active ethernet interface and its subnets
let activeInterface = null;

async function refreshInterfaces() {
  try {
    const interfaces = await api.listInterfaces();
    if (!interfaces || interfaces.length === 0) {
      $("#iface-name").textContent = "None found";
      return;
    }

    // Find the ethernet adapter (ethernet only, no wifi)
    const eth =
      interfaces.find((i) => i.is_up && i.is_ethernet && i.ips.length > 0);

    if (eth) {
      activeInterface = eth;
      $("#iface-name").textContent = eth.display_name || eth.name;
      renderSubnetList();
      updateCameraIpDropdown(null);
    } else {
      $("#iface-name").textContent = "None found";
    }
  } catch (e) {
    console.error("Failed to list interfaces:", e);
    $("#iface-name").textContent = "Error";
  }
}

/** Render the subnet list in the Host card, including auto-adopted subnets. */
function renderSubnetList() {
  const subnetList = $("#subnet-list");
  if (!activeInterface) return;

  let html = activeInterface.ips
    .map(
      (ip) => `
      <div class="status-row subnet-row" data-subnet="${ip.subnet}">
        <span class="status-label">IP:</span>
        <span class="status-value">${ip.address}/${ip.prefix}</span>
      </div>`
    )
    .join("");

  // Add auto-adopted subnets
  for (const [subnet, adoptedIp] of adoptedSubnets) {
    html += `
      <div class="status-row subnet-row subnet-row-auto" data-subnet="${subnet}">
        <span class="status-label">IP:</span>
        <span class="status-value">${adoptedIp}/24 <span class="badge-auto">(auto)</span></span>
        <button class="btn-remove-ip" data-remove-subnet="${subnet}" title="Remove adopted IP">&times;</button>
      </div>`;
  }

  subnetList.innerHTML = html;

  // Wire up remove buttons
  subnetList.querySelectorAll(".btn-remove-ip").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const subnet = btn.dataset.removeSubnet;
      try {
        await api.removeAdoptedSubnet(subnet);
        adoptedSubnets.delete(subnet);
        renderSubnetList();
        showToast("Removed adopted IP");
      } catch (err) {
        showToast("Failed to remove: " + err, true);
      }
    });
  });
}

// ── Refresh & ARP Status ────────────────────────────────────────────

function setupRefreshButton() {
  $("#btn-refresh-host").addEventListener("click", async () => {
    const btn = $("#btn-refresh-host");
    btn.disabled = true;
    btn.classList.add("spinning");

    try {
      await refreshInterfaces();
      await loadExistingArpState();
      showToast("Refreshed");
    } catch (e) {
      showToast("Refresh failed: " + e, true);
    } finally {
      btn.disabled = false;
      btn.classList.remove("spinning");
    }
  });
}

// ── ARP Discovery ───────────────────────────────────────────────────

const scannedIps = new Set(); // IPs already being/been port-scanned
let pendingScans = 0; // number of port scans in flight

function setupArpListeners() {
  // Listen for individual ARP device discoveries
  api.onEvent("arp-device-discovered", (device) => {
    // Skip our own IPs
    if (activeInterface?.ips.some((ip) => ip.address === device.ip)) return;

    const isNew = !arpDevices.has(device.mac);
    arpDevices.set(device.mac, device);

    if (isNew) {
      log(`ARP: discovered ${device.ip} (${device.mac})`);
      showScanSpinner(true);
      scanDevicePorts(device.ip);
    }
  });

  // Listen for subnet adoption events — rescan devices on the adopted subnet
  api.onEvent("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    renderSubnetList();

    // Retry port scan for all devices on this subnet (now reachable)
    for (const device of arpDevices.values()) {
      if (device.subnet === data.subnet) {
        scannedIps.delete(device.ip); // allow rescan
        showScanSpinner(true);
        scanDevicePorts(device.ip);
      }
    }
  });

  // Load any already-discovered devices and adopted subnets
  loadExistingArpState();
}

async function loadExistingArpState() {
  try {
    const [devices, subnets] = await Promise.all([
      api.getArpDevices(),
      api.getAdoptedSubnets(),
    ]);

    if (devices && devices.length > 0) {
      for (const d of devices) {
        arpDevices.set(d.mac, d);
      }
      showScanSpinner(true);
      for (const d of devices) {
        scanDevicePorts(d.ip);
      }
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

// Map to store TCP scan results by IP
const tcpScanResults = new Map(); // IP -> ScanResult

/** Scan a single device's ports and update the UI when done. */
async function scanDevicePorts(ip) {
  if (scannedIps.has(ip)) return;
  scannedIps.add(ip);
  pendingScans++;

  try {
    const results = await api.scanNetwork(`${ip}/32`);
    if (results) {
      for (const r of results) {
        if (r.reachable && r.open_ports.length > 0) {
          tcpScanResults.set(r.ip, r);
        }
      }
    }
  } catch (e) {
    log(`Port scan failed for ${ip}: ${e}`);
  }

  pendingScans--;
  // Re-render with latest scan results; hide spinner when all done
  renderArpDeviceList();
  if (pendingScans <= 0) {
    showScanSpinner(false);
  }
}

/** Show or hide the scanning spinner in the Nodes card. */
function showScanSpinner(show) {
  const list = $("#device-list");
  const existing = list.querySelector(".scan-spinner");
  if (show && !existing) {
    list.innerHTML = '<div class="scan-spinner"><div class="spinner"></div><span>Scanning devices...</span></div>';
  } else if (!show && existing) {
    existing.remove();
  }
}

/** Render the Nodes card with ARP-discovered devices + TCP scan data. */
function renderArpDeviceList() {
  const list = $("#device-list");

  // Group devices by subnet
  const bySubnet = new Map();
  for (const device of arpDevices.values()) {
    if (!bySubnet.has(device.subnet)) {
      bySubnet.set(device.subnet, []);
    }
    bySubnet.get(device.subnet).push(device);
  }

  // Only show devices that have completed port scan with open ports
  // If scans are still running, keep the spinner visible
  if (bySubnet.size === 0 && pendingScans <= 0) {
    list.innerHTML = '<p class="placeholder-text">No devices found.</p>';
    updateCameraIpDropdown(null);
    return;
  }

  // Also build subnetResults format for camera IP dropdown
  const subnetResults = [];

  const pencilSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.001 1.001 0 000-1.41l-2.34-2.34a1.001 1.001 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

  let html = "";
  let nodeIndex = 0;
  for (const [subnet, devices] of bySubnet) {
    // Filter: skip devices that are our own IPs
    const ownIps = new Set();
    if (activeInterface) {
      activeInterface.ips.forEach((ip) => ownIps.add(ip.address));
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
        <div class="device-item${selectedDevice === d.ip ? " selected" : ""}" data-ip="${d.ip}">
          <div class="device-name-row">
            <span class="device-name">${name}</span>
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
      localIp: adoptedSubnets.get(subnet) || (activeInterface?.ips[0]?.address ?? ""),
      devices: devicesForDropdown,
    });
  }

  // If no devices passed the filter, don't overwrite the spinner
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
      selectedDevice = item.dataset.ip;
      const select = $("#camera-ip");
      select.value = selectedDevice;
      if (config) {
        config.stream.camera_ip = selectedDevice;
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

  // Update the camera IP dropdown with ARP-discovered nodes
  lastSubnetResults = subnetResults;
  updateCameraIpDropdown(subnetResults);
}

// Filter to likely network/camera devices:
// - Has SSH (port 22) — managed network devices
// - Has RTSP (port 554 or 8554) — IP cameras
// - Only port 80 open — web-managed switches, APs, etc.
// - Exclude gateway (x.x.x.1) and local host for each subnet
function filterDevices(devices, localIp) {
  // Derive gateway: same subnet prefix + .1
  const parts = localIp.split(".");
  const gateway = `${parts[0]}.${parts[1]}.${parts[2]}.1`;

  return devices.filter((d) => {
    if (d.ip === gateway) return false;
    if (d.ip === localIp) return false;
    const ports = d.open_ports;
    if (ports.includes(22)) return true;
    if (ports.includes(554) || ports.includes(8554)) return true;
    if (ports.length === 1 && ports[0] === 80) return true;
    return false;
  });
}

function updateCameraIpDropdown(filteredSubnets) {
  const select = $("#camera-ip");
  const currentVal = select.value;

  // Build options: host IPs + node IPs
  let options = '<option value="">-- Select --</option>';

  // Host IPs
  if (activeInterface) {
    options += '<optgroup label="Host">';
    activeInterface.ips.forEach((ip) => {
      options += `<option value="${ip.address}">${ip.address}</option>`;
    });
    options += '</optgroup>';
  }

  // Node IPs (from ARP-discovered + scan results)
  if (filteredSubnets) {
    let hasNodes = false;
    let nodeOptions = "";
    filteredSubnets.forEach((sr) => {
      sr.devices.forEach((d) => {
        hasNodes = true;
        const alias = nodeAliases.get(d.ip);
        const label = alias ? `${d.ip} (${alias})` : d.ip;
        nodeOptions += `<option value="${d.ip}">${label}</option>`;
      });
    });
    if (hasNodes) {
      options += `<optgroup label="Nodes">${nodeOptions}</optgroup>`;
    }
  }

  select.innerHTML = options;

  // Restore selection
  if (currentVal) {
    select.value = currentVal;
  }
}

function setupCameraIpDropdown() {
  $("#camera-ip").addEventListener("change", (e) => {
    selectedDevice = e.target.value || null;
    if (config && selectedDevice) {
      config.stream.camera_ip = selectedDevice;
    }
  });
}

function openAliasDialog(ip) {
  const dialog = $("#alias-dialog");
  $("#alias-dialog-ip").textContent = ip;
  $("#alias-input").value = nodeAliases.get(ip) || "";
  dialog.dataset.ip = ip;
  api.setVideoVisible(false);
  dialog.showModal();
  dialog.addEventListener("close", () => api.setVideoVisible(true), { once: true });
  $("#alias-input").focus();
}

function setupAliasDialog() {
  $("#alias-save").addEventListener("click", () => {
    const dialog = $("#alias-dialog");
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

  // Enter key saves
  $("#alias-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("#alias-save").click();
    }
  });
}

// ── Stream Controls ─────────────────────────────────────────────────

function setupStreamControls() {
  $("#btn-toggle-stream").addEventListener("click", async () => {
    if (isStreaming) {
      try {
        await api.stopStream();
        isStreaming = false;
        updateStreamUI();
        stopStatusPolling();
        showToast("Stream stopped");
      } catch (e) {
        showToast("Failed to stop: " + e, true);
      }
    } else {
      try {
        // Ensure current camera IP is saved to backend before starting
        if (config) {
          config.stream.camera_ip = $("#camera-ip").value || config.stream.camera_ip;
          await api.saveConfig(config);
        }
        // Create a child window for GStreamer to render into
        const bounds = getVideoAreaBounds();
        const handle = await api.createVideoWindow(bounds.x, bounds.y, bounds.width, bounds.height);
        // Start stream with the window handle — GStreamer renders directly into it
        await api.startStream(handle);
        isStreaming = true;
        updateStreamUI();
        startStatusPolling();
        showToast("Stream started");
      } catch (e) {
        showToast("Stream failed: " + e, true);
      }
    }
  });

  $("#btn-screenshot").addEventListener("click", async () => {
    try {
      const path = await api.takeScreenshot();
      showToast("Screenshot saved: " + path);
    } catch (e) {
      showToast("Screenshot failed: " + e, true);
    }
  });

  $("#btn-record").addEventListener("click", async () => {
    if (isRecording) {
      const path = await api.stopRecording();
      isRecording = false;
      $("#btn-record").classList.remove("recording");
      showToast("Recording saved: " + path);
    } else {
      await api.startRecording();
      isRecording = true;
      $("#btn-record").classList.add("recording");
      showToast("Recording started");
    }
  });
}

function updateStreamUI() {
  const btn = $("#btn-toggle-stream");
  btn.textContent = isStreaming ? "Stop Stream" : "Start Stream";
  btn.className = isStreaming ? "outlined-btn active-btn" : "filled-btn";
  $("#btn-screenshot").disabled = !isStreaming;
  $("#btn-record").disabled = !isStreaming;

  const area = $("#video-area");
  const placeholder = area.querySelector(".placeholder-text");
  if (isStreaming) {
    placeholder.style.display = "none";
  } else {
    placeholder.style.display = "";
    placeholder.textContent = "Select a camera and start stream";
  }
}

/** Get the video-area bounds in physical pixels relative to the window client area. */
function getVideoAreaBounds() {
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

function log(msg) {
  console.log(`[PocketStream] ${msg}`);
}

// Reposition embedded video on window resize
let resizeTimer = null;
window.addEventListener("resize", () => {
  if (!isStreaming) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(async () => {
    try {
      const bounds = getVideoAreaBounds();
      await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
    } catch (_) {}
  }, 50);
});

// ── PTZ Controls ─────────────────────────────────────────────────────

function setupPtzControls() {
  const ptzActions = {
    up:         () => api.ptzMove(getCameraUrl(), 0, 0.5, 0),
    down:       () => api.ptzMove(getCameraUrl(), 0, -0.5, 0),
    left:       () => api.ptzMove(getCameraUrl(), -0.5, 0, 0),
    right:      () => api.ptzMove(getCameraUrl(), 0.5, 0, 0),
    home:       () => api.ptzGotoPreset(getCameraUrl(), 1),
    "zoom-in":  () => api.ptzMove(getCameraUrl(), 0, 0, 0.5),
    "zoom-out": () => api.ptzMove(getCameraUrl(), 0, 0, -0.5),
  };

  // D-pad and zoom buttons — hold to move, release to stop
  document.querySelectorAll(".ptz-btn[data-ptz]").forEach((btn) => {
    const action = btn.dataset.ptz;
    if (action === "home") {
      btn.addEventListener("click", () => {
        if (!getCameraUrl()) return;
        ptzActions.home().catch((e) => log(`PTZ home: ${e}`));
      });
      return;
    }

    const startMove = () => {
      if (!getCameraUrl()) return;
      const fn = ptzActions[action];
      if (fn) fn().catch((e) => log(`PTZ ${action}: ${e}`));
    };
    const stopMove = () => {
      if (!getCameraUrl()) return;
      api.ptzStop(getCameraUrl()).catch(() => {});
    };

    btn.addEventListener("mousedown", startMove);
    btn.addEventListener("mouseup", stopMove);
    btn.addEventListener("mouseleave", stopMove);
  });

  // Preset buttons — click to go, long-press to save
  document.querySelectorAll(".ptz-preset-btn[data-preset]").forEach((btn) => {
    let pressTimer = null;
    const preset = parseInt(btn.dataset.preset);

    btn.addEventListener("mousedown", () => {
      pressTimer = setTimeout(() => {
        pressTimer = null;
        if (!getCameraUrl()) return;
        api.ptzSetPreset(getCameraUrl(), preset, `Preset ${preset}`)
          .then(() => showToast(`Preset ${preset} saved`))
          .catch((e) => showToast(`Failed: ${e}`, true));
      }, 800);
    });

    btn.addEventListener("mouseup", () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
        if (!getCameraUrl()) return;
        api.ptzGotoPreset(getCameraUrl(), preset)
          .catch((e) => log(`PTZ preset ${preset}: ${e}`));
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

function getCameraUrl() {
  const ip = $("#camera-ip").value;
  if (!ip || !config) return null;
  const port = config.stream.rtsp_port || 554;
  const path = config.stream.rtsp_path || "/live";
  return `rtsp://${ip}:${port}${path}`;
}

// ── RTSP Server Controls ────────────────────────────────────────────

function setupRtspControls() {
  $("#btn-toggle-rtsp").addEventListener("click", async () => {
    if (isRtspRunning) {
      try {
        await api.stopRtspServer();
        isRtspRunning = false;
        updateRtspUI(null);
        showToast("RTSP server stopped");
      } catch (e) {
        showToast("Failed to stop: " + e, true);
      }
    } else {
      try {
        const url = await api.startRtspServer();
        isRtspRunning = true;
        updateRtspUI(url);
        startStatusPolling();
        showToast("RTSP server started");
      } catch (e) {
        showToast("RTSP server failed: " + e, true);
      }
    }
  });

}

function updateRtspUI(url) {
  const btn = $("#btn-toggle-rtsp");
  btn.textContent = isRtspRunning ? "Stop Server" : "Start Server";

  const statusEl = $("#rtsp-status");
  if (isRtspRunning) {
    statusEl.textContent = "Online";
    statusEl.className = "status-value status-online";
    $("#rtsp-url").textContent = url || "--";
  } else {
    statusEl.textContent = "Offline";
    statusEl.className = "status-value status-offline";
    $("#rtsp-url").textContent = "--";
    $("#rtsp-uptime").textContent = "--";
    $("#rtsp-bandwidth").textContent = "--";
  }
}

// ── IP Config Dialog ────────────────────────────────────────────────

function setupIpConfigDialog() {
  const dialog = $("#ip-config-dialog");
  let activeMode = "static";

  // Open dialog
  $("#btn-ip-config").addEventListener("click", async () => {
    try {
      const interfaces = await api.listInterfaces();
      const select = $("#static-iface");
      select.innerHTML = (interfaces || [])
        .filter((i) => i.is_ethernet)
        .map((i) => `<option value="${i.name}">${i.display_name || i.name} (${i.ip || "no IP"})</option>`)
        .join("");
    } catch (_) {}

    api.setVideoVisible(false);
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true), { once: true });
  });

  // Mode toggle within dialog
  $$("[data-ip-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("[data-ip-mode]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeMode = btn.dataset.ipMode;

      // Show/hide sections
      $$("#ip-config-static, #ip-config-dhcp-client, #ip-config-dhcp-server").forEach(
        (s) => (s.style.display = "none")
      );
      $(`#ip-config-${activeMode}`).style.display = "";
    });
  });

  $("#ip-config-cancel").addEventListener("click", () => dialog.close());

  $("#ip-config-apply").addEventListener("click", async () => {
    if (activeMode === "static") {
      const iface = $("#static-iface").value;
      const ip = $("#static-ip").value;
      const mask = $("#static-mask").value;
      const gw = $("#static-gateway").value || null;

      if (!iface || !ip || !mask) {
        showToast("Please fill in all required fields", true);
        return;
      }

      try {
        await api.setStaticIp(iface, ip, mask, gw);
        $("#ip-mode").textContent = "Static";
        showToast("Static IP assigned");
        dialog.close();
        await refreshInterfaces();
      } catch (e) {
        showToast("Failed: " + e, true);
      }
    } else if (activeMode === "dhcp-client") {
      $("#ip-mode").textContent = "DHCP Client";
      showToast("DHCP Client — coming soon");
      dialog.close();
    } else if (activeMode === "dhcp-server") {
      $("#ip-mode").textContent = "DHCP Server";
      showToast("DHCP Server — coming soon");
      dialog.close();
    }
  });
}

// ── Status Polling ──────────────────────────────────────────────────

function startStatusPolling() {
  if (statusPollInterval) return;
  statusPollInterval = setInterval(pollStatus, 1000);
}

function stopStatusPolling() {
  if (!isStreaming && !isRtspRunning) {
    clearInterval(statusPollInterval);
    statusPollInterval = null;
  }
}

async function pollStatus() {
  try {
    const status = await api.getStreamStatus();
    if (!status) return;

    if (status.rtsp_server_running) {
      $("#rtsp-uptime").textContent = formatUptime(status.uptime_secs);
      $("#rtsp-bandwidth").textContent = `${status.bandwidth_kbps.toFixed(1)} kbps`;
    }
  } catch (_) {}
}

// ── Utilities ───────────────────────────────────────────────────────

function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

function showToast(message, isError = false) {
  // Simple toast notification
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = `toast ${isError ? "toast-error" : ""}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    background: ${isError ? "var(--md-error)" : "var(--md-surface-variant)"};
    color: ${isError ? "var(--md-on-error)" : "var(--md-on-surface)"};
    padding: 12px 24px;
    border-radius: var(--md-radius-sm);
    font-size: 14px;
    z-index: 1000;
    box-shadow: var(--md-elevation-2);
    animation: toast-in 200ms ease-out;
  `;

  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 200ms";
    setTimeout(() => toast.remove(), 200);
  }, 3000);
}

// Toast animation
const style = document.createElement("style");
style.textContent = `
  @keyframes toast-in {
    from { opacity: 0; transform: translateX(-50%) translateY(10px); }
    to { opacity: 1; transform: translateX(-50%) translateY(0); }
  }
`;
document.head.appendChild(style);
