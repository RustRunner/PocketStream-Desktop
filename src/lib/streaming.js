/**
 * PocketStream Desktop — Stream, RTSP server, recording
 */

import * as api from "./tauri-api.js";
import { $, state, showToast, formatUptime } from "./state.js";

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
        updateStreamUI();
        stopStatusPolling();
        showToast("Stream stopped");
      } catch (e) {
        showToast("Failed to stop: " + e, true);
      }
    } else {
      try {
        if (state.config) {
          state.config.stream.camera_ip = $("#camera-ip").value || state.config.stream.camera_ip;
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

export function setupRtspControls() {
  $("#btn-toggle-rtsp").addEventListener("click", async () => {
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
        const url = await api.startRtspServer();
        state.isRtspRunning = true;
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
  btn.textContent = state.isRtspRunning ? "Stop Server" : "Start Server";

  const statusEl = $("#rtsp-status");
  if (state.isRtspRunning) {
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
  } catch (_) {}
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
