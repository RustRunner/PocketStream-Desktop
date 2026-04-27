/**
 * PocketStream Desktop — Stream, RTSP server, recording, QR code
 */

import QRCode from "qrcode";
import * as api from "./tauri-api.js";
import { $, state, log, showToast, formatUptime } from "./state.js";

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
        // Set flags BEFORE the async stop so the status poll
        // doesn't race and trigger a false "Stream Lost".
        state.isStreaming = false;
        state.streamLost = false;
        // User asked to stop — don't auto-resume on a later reconnect.
        resumeSnapshot = null;
        // Clear any stuck overlay from an earlier drop in this session.
        hideStreamLost();
        stopStatusPolling();
        await api.stopStream();
        updateStreamUI();
        showToast("Stream stopped");
      } catch (e) {
        showToast("Failed to stop: " + formatError(e), true);
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
        showToast("Stream failed: " + formatError(e), true);
      }
    }
  });

  $("#btn-screenshot").addEventListener("click", async () => {
    try {
      const path = await api.takeScreenshot();
      showToast("Screenshot saved: " + path);
    } catch (e) {
      showToast("Screenshot failed: " + formatError(e), true);
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
  // Screenshot and record need a healthy pipeline — disable them while
  // the stream is lost even though isStreaming is still true (the user
  // intends to stream; the stream just isn't alive right now).
  const canInteract = state.isStreaming && !state.streamLost;
  $("#btn-screenshot").disabled = !canInteract;
  $("#btn-record").disabled = !canInteract;

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
      showToast("Failed to save VPN selection: " + formatError(e), true);
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
        showToast("Failed to stop: " + formatError(e), true);
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
        showToast("RTSP server failed: " + formatError(e), true);
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

    // Show dialog first so the canvas is in the visible DOM —
    // rendering to a canvas inside a hidden <dialog> can produce
    // blank output on some WebView2 / Chromium builds.
    $("#qr-url").textContent = rtspFullUrl;
    api.setVideoVisible(false).catch(() => {});
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true).catch(() => {}), { once: true });

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
    }
  });

  closeBtn.addEventListener("click", () => dialog.close());

  // Click URL to copy to clipboard
  $("#qr-url").addEventListener("click", async () => {
    const url = $("#qr-url").textContent;
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      $("#qr-copy-hint").textContent = "Copied!";
      setTimeout(() => {
        $("#qr-copy-hint").textContent = "Click URL to copy to clipboard";
      }, 2000);
    } catch (_) {
      showToast("Failed to copy", true);
    }
  });

  // Close on backdrop click
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });
}

// ── Status polling ──────────────────────────────────────────────────

function startStatusPolling() {
  if (state.statusPollInterval) return;
  notPlayingStreak = 0;
  state.statusPollInterval = setInterval(pollStatus, 1000);
}

function stopStatusPolling() {
  if (!state.isStreaming && !state.isRtspRunning) {
    clearInterval(state.statusPollInterval);
    state.statusPollInterval = null;
  }
}

// Require the backend to report `playing=false` across N consecutive
// 1s polls before declaring the stream lost. A single blip (transient
// state transition, RTCP jitter, GStreamer bus race) self-heals within
// one poll and shouldn't nuke an otherwise-healthy stream.
const DROP_THRESHOLD_POLLS = 3;
let notPlayingStreak = 0;

async function pollStatus() {
  try {
    const status = await api.getStreamStatus();
    if (!status) return;

    if (status.rtsp_server_running) {
      $("#rtsp-uptime").textContent = formatUptime(status.uptime_secs);
      $("#rtsp-bandwidth").textContent = `${status.bandwidth_kbps.toFixed(1)} kbps`;
      // Keep rtspFullUrl in sync — it may have been cleared by a
      // transient stream-loss event while the server kept running.
      if (!rtspFullUrl && status.rtsp_url) {
        rtspFullUrl = status.rtsp_url;
      }
    }

    // Detect stream drop — backend says not playing but we think we're streaming
    if (state.isStreaming && !status.playing) {
      notPlayingStreak++;
      if (notPlayingStreak >= DROP_THRESHOLD_POLLS) {
        showStreamLost(status.error);
      }
    } else if (state.isStreaming && status.playing) {
      if (notPlayingStreak > 0) {
        log(`Stream recovered after ${notPlayingStreak} bad poll(s)`);
      }
      notPlayingStreak = 0;
      hideStreamLost();
    }
  } catch (_) {}
}

/// Stream state captured at the moment of a hard network disconnect,
/// so we can re-start the stream (and any associated RTSP server) as
/// soon as the link comes back. Cleared on manual stop or after a
/// successful resume.
let resumeSnapshot = null;

/// Called by the interface watcher when it detects a physical unplug /
/// APIPA-only state. Bypasses the poll debounce so the user gets
/// immediate "Stream Lost..." feedback instead of waiting for GStreamer
/// to time out. Captures what was running so handleReconnect() can
/// put it back together on replug.
export function handleHardDisconnect(reason) {
  if (state.isStreaming && !state.streamLost) {
    resumeSnapshot = {
      cameraIp:
        $("#camera-ip").value ||
        state.config?.stream?.camera_ip ||
        null,
      ptuIp: $("#ptu-ip").value || null,
      wasRtspRunning: !!state.isRtspRunning,
    };
    log(`Stream lost on network disconnect: ${reason}`);
    showStreamLost(reason);
  }
}

/// Called by the interface watcher on reconnect (wasDown=true).
/// Restores dropdown selections and restarts the stream + RTSP server
/// if they were running before the disconnect.
export async function handleReconnect() {
  if (!resumeSnapshot) return;
  const snap = resumeSnapshot;
  resumeSnapshot = null;

  // Give Windows + auto-adopt a moment to finish re-binding IPs and
  // routes before we try to open a socket to the camera. Two seconds
  // is long enough to catch most settling but short enough to feel
  // responsive when the user's waiting for the stream to come back.
  await new Promise((r) => setTimeout(r, 2000));

  // Restore dropdown selections (dropdown may have been repopulated
  // during reconnect; set values explicitly so the pre-disconnect
  // choices are back).
  if (snap.cameraIp) {
    const camSelect = $("#camera-ip");
    camSelect.value = snap.cameraIp;
    if (state.config) {
      state.config.stream.camera_ip = snap.cameraIp;
    }
  }
  if (snap.ptuIp) $("#ptu-ip").value = snap.ptuIp;

  if (!snap.cameraIp) return;

  try {
    const bounds = getVideoAreaBounds();
    const handle = await api.createVideoWindow(
      bounds.x,
      bounds.y,
      bounds.width,
      bounds.height
    );
    await api.startStream(handle);
    state.isStreaming = true;
    state.streamLost = false;
    hideStreamLost();
    updateStreamUI();
    startStatusPolling();
    showToast("Stream resumed");

    // RTSP server was running — bring it back too. Errors here aren't
    // fatal (the stream is already back); toast and move on.
    if (snap.wasRtspRunning) {
      try {
        const info = await api.startRtspServer();
        state.isRtspRunning = true;
        rtspFullUrl = info.rtsp_url;
        updateRtspUI(info.display_url);
      } catch (e) {
        log(`RTSP auto-resume failed: ${formatError(e)}`);
        showToast("Stream back — RTSP server failed to resume", true);
      }
    }
  } catch (e) {
    log(`Stream auto-resume failed: ${formatError(e)}`);
    showToast("Auto-resume failed — restart stream manually", true);
  }
}

function showStreamLost(errorMsg) {
  if (state.streamLost) return;
  state.streamLost = true;
  notPlayingStreak = 0;

  // Hide stale video frame and show overlay. Overlay defaults to
  // display:none via CSS; the .visible class is what reveals it.
  api.setVideoVisible(false).catch(() => {});
  const area = $("#video-area");
  let overlay = area.querySelector(".stream-lost-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.className = "stream-lost-overlay";
    overlay.textContent = "Stream Lost...";
    area.appendChild(overlay);
  }
  overlay.classList.add("visible");

  // Reset stream and RTSP server
  api.stopStream().catch(() => {});
  if (state.isRtspRunning) {
    api.stopRtspServer().catch(() => {});
    state.isRtspRunning = false;
    updateRtspUI(null);
  }
  // Deliberately leave state.isStreaming = true: the user's intent is
  // still "I want to stream", the connection just failed. Keeps the
  // button labelled "Stop Stream" so clicking it means "give up", not
  // "start fresh". pollStatus keeps running (stopStatusPolling is a
  // no-op while isStreaming is true) so recovery is detected.
  state.isRecording = false;
  $("#btn-record").classList.remove("recording");
  updateStreamUI();

  // Show the actual GStreamer error if available
  const reason = errorMsg || "connection dropped";
  showToast("Stream lost — " + reason, true);
}

function hideStreamLost() {
  state.streamLost = false;
  // Reset the drop-detection streak: during the lost window pollStatus
  // kept running and counted every `playing=false` poll (often 10+),
  // which would otherwise instantly re-fire showStreamLost on the
  // next tick after handleReconnect resets the lost state — faster
  // than the newly-started pipeline can reach Playing.
  notPlayingStreak = 0;
  api.setVideoVisible(true).catch(() => {});
  const overlay = $("#video-area").querySelector(".stream-lost-overlay");
  if (overlay) overlay.classList.remove("visible");
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
