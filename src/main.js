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

// ── DOM References ──────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Init ────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  setupMenuAndAbout();
  setupProtocolToggle();
  setupNetworkActions();
  setupStreamControls();
  setupRtspControls();
  setupPtzControls();
  setupIpConfigDialog();
  setupSettingsSave();
  setupAliasDialog();
  setupCameraIpDropdown();

  await loadConfig();
  await refreshInterfaces();
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
    $("#sidebar").classList.toggle("collapsed");
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

    // Find the ethernet adapter (prefer physical ethernet over wifi)
    const eth =
      interfaces.find((i) => i.is_up && i.is_ethernet && i.ips.length > 0) ||
      interfaces.find((i) => i.is_up && i.ips.length > 0);

    if (eth) {
      activeInterface = eth;
      $("#iface-name").textContent = eth.display_name || eth.name;

      // Render all IPs for this adapter
      const subnetList = $("#subnet-list");
      subnetList.innerHTML = eth.ips
        .map(
          (ip) => `
        <div class="status-row subnet-row" data-subnet="${ip.subnet}">
          <span class="status-label">IP:</span>
          <span class="status-value">${ip.address}/${ip.prefix}</span>
        </div>`
        )
        .join("");
      // Populate camera IP dropdown with host IPs
      updateCameraIpDropdown(null);
    } else {
      $("#iface-name").textContent = "None found";
    }
  } catch (e) {
    console.error("Failed to list interfaces:", e);
    $("#iface-name").textContent = "Error";
  }
}

function setupNetworkActions() {
  $("#btn-scan-all").addEventListener("click", async () => {
    if (!activeInterface || activeInterface.ips.length === 0) {
      showToast("No active network interface", true);
      return;
    }

    const progress = $("#scan-progress");
    progress.style.display = "";
    progress.classList.add("indeterminate");
    $("#btn-scan-all").disabled = true;

    try {
      // Scan all subnets in parallel
      const scanPromises = activeInterface.ips.map((ip) =>
        api.scanNetwork(ip.subnet).then((results) => ({
          subnet: ip.subnet,
          localIp: ip.address,
          devices: results || [],
        }))
      );
      const subnetResults = await Promise.all(scanPromises);
      renderDeviceList(subnetResults);
    } catch (e) {
      showToast("Scan failed: " + e, true);
    } finally {
      progress.style.display = "none";
      progress.classList.remove("indeterminate");
      $("#btn-scan-all").disabled = false;
    }
  });
}

// Filter to likely network devices:
// - Only port 80 open (web-managed switches, APs, etc.)
// - Port 22 open with any combo of other ports (SSH-capable devices)
// - Exclude gateway (x.x.x.1) for each subnet
function filterDevices(devices, localIp) {
  // Derive gateway: same subnet prefix + .1
  const parts = localIp.split(".");
  const gateway = `${parts[0]}.${parts[1]}.${parts[2]}.1`;

  return devices.filter((d) => {
    if (d.ip === gateway) return false;
    if (d.ip === localIp) return false;
    const ports = d.open_ports;
    if (ports.length === 1 && ports[0] === 80) return true;
    if (ports.includes(22)) return true;
    return false;
  });
}

function renderDeviceList(subnetResults) {
  lastSubnetResults = subnetResults;
  const list = $("#device-list");

  // Apply device filter to each subnet
  const filtered = subnetResults.map((sr) => ({
    ...sr,
    devices: filterDevices(sr.devices, sr.localIp),
  }));

  const totalDevices = filtered.reduce((n, s) => n + s.devices.length, 0);
  if (totalDevices === 0) {
    list.innerHTML = '<p class="placeholder-text">No matching nodes found on any subnet.</p>';
    updateCameraIpDropdown(filtered);
    return;
  }

  const pencilSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.001 1.001 0 000-1.41l-2.34-2.34a1.001 1.001 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

  list.innerHTML = filtered
    .map(
      (sr) => `
    <div class="subnet-group">
      <div class="subnet-header">${sr.subnet} <span class="subnet-count">(${sr.devices.length} nodes)</span></div>
      ${
        sr.devices.length === 0
          ? '<p class="placeholder-text">No matching nodes.</p>'
          : sr.devices
              .map((d) => {
                const alias = nodeAliases.get(d.ip);
                return `
        <div class="device-item${selectedDevice === d.ip ? " selected" : ""}" data-ip="${d.ip}">
          <a class="device-ip" href="#" data-browse="${d.ip}" title="Open in browser">${d.ip}</a>
          <div class="device-right">
            ${alias ? `<span class="device-alias">${alias}</span>` : `<span class="device-ports">${d.open_ports.join(", ")}</span>`}
            <button class="edit-alias-btn" data-alias-ip="${d.ip}" title="Set alias">${pencilSvg}</button>
          </div>
        </div>`;
              })
              .join("")
      }
    </div>`
    )
    .join("");

  // Click device row to select as camera target
  list.querySelectorAll(".device-item").forEach((item) => {
    item.addEventListener("click", (e) => {
      // Don't select if clicking the IP link, alias button
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

  // Click IP to open in browser
  list.querySelectorAll(".device-ip[data-browse]").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const ip = link.dataset.browse;
      // Use Tauri shell plugin to open URL in default browser
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

  // Click pencil to edit alias
  list.querySelectorAll(".edit-alias-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const ip = btn.dataset.aliasIp;
      openAliasDialog(ip);
    });
  });

  updateCameraIpDropdown(filtered);
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

  // Node IPs (from filtered scan results)
  if (filteredSubnets) {
    filteredSubnets.forEach((sr) => {
      if (sr.devices.length === 0) return;
      options += `<optgroup label="Nodes - ${sr.subnet}">`;
      sr.devices.forEach((d) => {
        const alias = nodeAliases.get(d.ip);
        const label = alias ? `${d.ip} (${alias})` : d.ip;
        options += `<option value="${d.ip}">${label}</option>`;
      });
      options += '</optgroup>';
    });
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
  dialog.showModal();
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
    renderDeviceList(lastSubnetResults);
  });

  $("#alias-clear").addEventListener("click", () => {
    const dialog = $("#alias-dialog");
    const ip = dialog.dataset.ip;
    nodeAliases.delete(ip);
    dialog.close();
    renderDeviceList(lastSubnetResults);
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
        await api.startStream();
        isStreaming = true;
        updateStreamUI();
        startStatusPolling();
        showToast("Stream started");
        // Wait for GStreamer to create its window, then embed it
        await tryEmbedVideo();
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

/** Try to embed the GStreamer video window into the video-area with retries. */
async function tryEmbedVideo(retries = 8, delayMs = 500) {
  for (let i = 0; i < retries; i++) {
    await new Promise((r) => setTimeout(r, delayMs));
    if (!isStreaming) return; // user stopped before embed
    try {
      const bounds = getVideoAreaBounds();
      await api.embedVideo(bounds.x, bounds.y, bounds.width, bounds.height);
      log("Video embedded successfully");
      return;
    } catch (e) {
      log(`Embed attempt ${i + 1}/${retries}: ${e}`);
    }
  }
  log("Could not embed video — it may remain in a separate window");
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

  $("#btn-copy-url").addEventListener("click", () => {
    const url = $("#rtsp-url").textContent;
    if (url && url !== "--") {
      navigator.clipboard.writeText(url);
      showToast("URL copied to clipboard");
    }
  });
}

function updateRtspUI(url) {
  const btn = $("#btn-toggle-rtsp");
  btn.textContent = isRtspRunning ? "Stop Server" : "Start Server";
  btn.className = isRtspRunning ? "outlined-btn active-btn" : "filled-btn";
  $("#btn-copy-url").disabled = !isRtspRunning;

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

// ── PTZ Controls ────────────────────────────────────────────────────

function setupPtzControls() {
  const cameraUrl = () => {
    if (!selectedDevice) return null;
    return `http://${selectedDevice}`;
  };

  // Direction buttons — press and hold
  $$(".ptz-btn[data-dir]").forEach((btn) => {
    const dir = btn.dataset.dir;

    btn.addEventListener("mousedown", () => {
      const url = cameraUrl();
      if (!url) return;

      const moves = {
        up: [0, 1, 0],
        down: [0, -1, 0],
        left: [-1, 0, 0],
        right: [1, 0, 0],
        home: null,
      };

      if (dir === "home") {
        api.ptzGotoPreset(url, 1);
      } else {
        const [pan, tilt, zoom] = moves[dir];
        api.ptzMove(url, pan, tilt, zoom);
      }
    });

    btn.addEventListener("mouseup", () => {
      const url = cameraUrl();
      if (url && dir !== "home") api.ptzStop(url);
    });

    btn.addEventListener("mouseleave", () => {
      const url = cameraUrl();
      if (url && dir !== "home") api.ptzStop(url);
    });
  });

  // Zoom buttons
  $("#btn-zoom-in").addEventListener("mousedown", () => {
    const url = cameraUrl();
    if (url) api.ptzMove(url, 0, 0, 1);
  });
  $("#btn-zoom-in").addEventListener("mouseup", () => {
    const url = cameraUrl();
    if (url) api.ptzStop(url);
  });

  $("#btn-zoom-out").addEventListener("mousedown", () => {
    const url = cameraUrl();
    if (url) api.ptzMove(url, 0, 0, -1);
  });
  $("#btn-zoom-out").addEventListener("mouseup", () => {
    const url = cameraUrl();
    if (url) api.ptzStop(url);
  });

  // Presets — click to go, long-press to save
  $$(".preset-btn").forEach((btn) => {
    let holdTimer;

    btn.addEventListener("mousedown", () => {
      holdTimer = setTimeout(() => {
        const url = cameraUrl();
        if (url) {
          const num = parseInt(btn.dataset.preset);
          api.ptzSetPreset(url, num, `Preset ${num}`);
          showToast(`Preset ${num} saved`);
        }
        holdTimer = null;
      }, 1000);
    });

    btn.addEventListener("mouseup", () => {
      if (holdTimer) {
        clearTimeout(holdTimer);
        const url = cameraUrl();
        if (url) {
          api.ptzGotoPreset(url, parseInt(btn.dataset.preset));
        }
      }
    });
  });
}

// ── IP Config Dialog ────────────────────────────────────────────────

function setupIpConfigDialog() {
  const dialog = $("#ip-config-dialog");

  $("#btn-ip-config").addEventListener("click", async () => {
    // Populate interface dropdown
    try {
      const interfaces = await api.listInterfaces();
      const select = $("#static-iface");
      select.innerHTML = (interfaces || [])
        .filter((i) => i.is_ethernet)
        .map((i) => `<option value="${i.name}">${i.display_name || i.name} (${i.ip || "no IP"})</option>`)
        .join("");
    } catch (_) {}

    dialog.showModal();
  });

  $("#ip-config-cancel").addEventListener("click", () => dialog.close());

  $("#ip-config-apply").addEventListener("click", async () => {
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
      showToast("Static IP assigned");
      dialog.close();
      await refreshInterfaces();
    } catch (e) {
      showToast("Failed: " + e, true);
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
