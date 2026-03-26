/**
 * PocketStream Desktop — Stream, RTSP server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.js";
import { $, state, showToast, formatUptime, arpDevices, tcpScanResults } from "./state.js";
import { resetDiscoveryStatus } from "./devices.js";
import { updateCameraIpDropdown } from "./network.js";

/** Full RTSP URL (with token) — stored for QR code generation */
let rtspFullUrl = null;

// ── Video area bounds ───────────────────────────────────────────────

export function getVideoAreaBounds() {
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

// ── Stream controls ─────────────────────────────────────────────────

export function setupStreamControls() {
  $("#btn-toggle-stream").addEventListener("click", async () => {
    if (state.isStreaming) {
      try {
        await api.stopStream();
        state.isStreaming = false;
        state.streamLost = false;
        updateStreamUI();
        stopStatusPolling();
        showToast("Stream stopped");
      } catch (e) {
        showToast("Failed to stop: " + e, true);
      }
    } else {
      try {
        const selectedIp = $("#camera-ip").value;
        if (!selectedIp) {
          showToast("Select a camera IP first", true);
          return;
        }
        if (state.config) {
          state.config.stream.camera_ip = selectedIp;
          await api.saveConfig(state.config);
        }
        const bounds = getVideoAreaBounds();
        const handle = await api.createVideoWindow(bounds.x, bounds.y, bounds.width, bounds.height);
        await api.startStream(handle);
        state.isStreaming = true;
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
    if (state.isRecording) {
      const path = await api.stopRecording();
      state.isRecording = false;
      $("#btn-record").classList.remove("recording");
      showToast("Recording saved: " + path);
    } else {
      await api.startRecording();
      state.isRecording = true;
      $("#btn-record").classList.add("recording");
      showToast("Recording started");
    }
  });
}

// ── Stream UI updates ───────────────────────────────────────────────

function updateStreamUI() {
  const btn = $("#btn-toggle-stream");
  btn.textContent = state.isStreaming ? "Stop Stream" : "Start Stream";
  btn.className = state.isStreaming ? "outlined-btn active-btn" : "filled-btn";
  $("#btn-screenshot").disabled = !state.isStreaming;
  $("#btn-record").disabled = !state.isStreaming;

  const area = $("#video-area");
  const placeholder = area.querySelector(".placeholder-text");
  if (state.isStreaming) {
    placeholder.style.display = "none";
  } else {
    placeholder.style.display = "";
    placeholder.textContent = "Select a camera and start stream";
  }
}

// ── RTSP server controls ────────────────────────────────────────────

export async function setupRtspControls() {
  // Sync Start button disabled state with the Enable toggle
  const enableToggle = $("#rtsp-server-enable");
  const startBtn = $("#btn-toggle-rtsp");
  startBtn.disabled = !enableToggle.checked;
  enableToggle.addEventListener("change", () => {
    startBtn.disabled = !enableToggle.checked;
  });

  // Populate VPN dropdown in background — don't block other setup
  populateVpnDropdown();

  $("#rtsp-bind-interface").addEventListener("change", async () => {
    if (!state.config) return;
    state.config.rtsp_server.bind_interface = $("#rtsp-bind-interface").value;
    try {
      await api.saveConfig(state.config);
    } catch (e) {
      showToast("Failed to save VPN selection: " + e, true);
    }
  });

  $("#btn-toggle-rtsp").addEventListener("click", async () => {
    const spinner = $("#rtsp-spinner");
    spinner.style.display = "";

    if (state.isRtspRunning) {
      try {
        await api.stopRtspServer();
        state.isRtspRunning = false;
        updateRtspUI(null);
        showToast("RTSP server stopped");
      } catch (e) {
        showToast("Failed to stop: " + e, true);
      }
    } else {
      try {
        // Save bind_interface selection before starting
        if (state.config) {
          state.config.rtsp_server.bind_interface = $("#rtsp-bind-interface").value;
          await api.saveConfig(state.config);
        }
        const info = await api.startRtspServer();
        state.isRtspRunning = true;
        rtspFullUrl = info.rtsp_url;
        updateRtspUI(info.display_url);
        startStatusPolling();
        showToast("RTSP server started");
      } catch (e) {
        showToast("RTSP server failed: " + e, true);
      }
    }

    spinner.style.display = "none";
  });

  // QR code button + dialog
  setupQrDialog();
}

async function populateVpnDropdown() {
  const select = $("#rtsp-bind-interface");
  try {
    const vpns = (await api.listVpnInterfaces()).filter((i) => i.ips.length > 0);
    for (const iface of vpns) {
      const opt = document.createElement("option");
      opt.value = iface.name;
      opt.textContent = `${iface.name} (${iface.ips[0].address})`;
      select.appendChild(opt);
    }
    // Restore saved selection
    if (state.config && state.config.rtsp_server.bind_interface) {
      select.value = state.config.rtsp_server.bind_interface;
    }
  } catch (e) {
    console.warn("Failed to list VPN interfaces:", e);
  }
}

function updateRtspUI(displayUrl) {
  const btn = $("#btn-toggle-rtsp");
  btn.textContent = state.isRtspRunning ? "Stop Server" : "Start Server";
  // Always allow stopping; respect Enable toggle when stopped
  btn.disabled = state.isRtspRunning ? false : !$("#rtsp-server-enable").checked;

  const statusEl = $("#rtsp-status");
  const qrBtn = $("#btn-show-qr");

  if (state.isRtspRunning) {
    statusEl.textContent = "Online";
    statusEl.className = "status-value status-online";
    $("#rtsp-url").textContent = displayUrl || "--";
    qrBtn.disabled = false;
  } else {
    statusEl.textContent = "Offline";
    statusEl.className = "status-value status-offline";
    $("#rtsp-url").textContent = "--";
    $("#rtsp-uptime").textContent = "--";
    $("#rtsp-bandwidth").textContent = "--";
    rtspFullUrl = null;
    qrBtn.disabled = true;
  }
}

// ── QR Code Dialog ──────────────────────────────────────────────────

function setupQrDialog() {
  const dialog = $("#qr-dialog");
  const qrBtn = $("#btn-show-qr");
  const closeBtn = $("#qr-close");

  qrBtn.addEventListener("click", async () => {
    if (!rtspFullUrl) return;

    const canvas = $("#qr-canvas");
    try {
      await QRCode.toCanvas(canvas, rtspFullUrl, {
        width: 256,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
      });
    } catch (e) {
      console.error("QR code generation failed:", e);
      showToast("Failed to generate QR code", true);
      return;
    }

    $("#qr-url").textContent = rtspFullUrl;
    api.setVideoVisible(false).catch(() => {});
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true).catch(() => {}), { once: true });
  });

  closeBtn.addEventListener("click", () => dialog.close());

  // Close on backdrop click
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });
}

// ── Status polling ──────────────────────────────────────────────────

function startStatusPolling() {
  if (state.statusPollInterval) return;
  state.statusPollInterval = setInterval(pollStatus, 1000);
}

function stopStatusPolling() {
  if (!state.isStreaming && !state.isRtspRunning) {
    clearInterval(state.statusPollInterval);
    state.statusPollInterval = null;
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

    // Detect stream drop — backend says not playing but we think we're streaming
    if (state.isStreaming && !status.playing) {
      showStreamLost();
    } else if (state.isStreaming && status.playing) {
      hideStreamLost();
    }
  } catch (_) {}
}

function showStreamLost() {
  if (state.streamLost) return;
  state.streamLost = true;

  // Hide stale video frame and show overlay
  api.setVideoVisible(false).catch(() => {});
  const area = $("#video-area");
  let overlay = area.querySelector(".stream-lost-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "stream-lost-overlay";
    overlay.textContent = "Stream Lost...";
    area.appendChild(overlay);
  }
  overlay.style.display = "";

  // Reset stream and RTSP server
  api.stopStream().catch(() => {});
  if (state.isRtspRunning) {
    api.stopRtspServer().catch(() => {});
    state.isRtspRunning = false;
    updateRtspUI(null);
  }
  state.isStreaming = false;
  state.isRecording = false;
  updateStreamUI();
  stopStatusPolling();

  // Clear stale nodes
  arpDevices.clear();
  tcpScanResults.clear();
  $("#device-list").innerHTML = "";
  updateCameraIpDropdown(null);
  resetDiscoveryStatus();

  showToast("Stream lost — connection dropped", true);
}

function hideStreamLost() {
  if (!state.streamLost) return;
  state.streamLost = false;
  api.setVideoVisible(true).catch(() => {});
  const overlay = $("#video-area").querySelector(".stream-lost-overlay");
  if (overlay) overlay.style.display = "none";
}

// ── Video resize handler ────────────────────────────────────────────

export function setupVideoResize() {
  let resizeTimer = null;
  window.addEventListener("resize", () => {
    if (!state.isStreaming) return;
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(async () => {
      try {
        const bounds = getVideoAreaBounds();
        await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
      } catch (_) {}
    }, 50);
  });
}
