/**
 * PocketStream Desktop — Main Application (orchestrator)
 */

import * as api from "./lib/tauri-api.js";
import { $, $$, state, showToast } from "./lib/state.js";
import { refreshInterfaces, setupIpConfigDialog, setupCameraIpDropdown } from "./lib/network.js";
import { setupArpListeners, loadExistingArpState, setupAliasDialog, resetDiscoveryStatus } from "./lib/devices.js";
import { setupStreamControls, setupRtspControls, setupVideoResize, getVideoAreaBounds } from "./lib/streaming.js";
import { setupPtzControls } from "./lib/ptz.js";

// ── Init ────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  setupMenuAndAbout();
  setupWindowControls();
  setupProtocolToggle();
  setupStreamControls();
  setupRtspControls();
  setupIpConfigDialog();
  setupSettingsSave();
  setupAliasDialog();
  setupCameraIpDropdown();
  setupRefreshButton();
  setupPtzControls();
  setupVideoResize();

  await loadConfig();
  await refreshInterfaces();

  // Start listening for ARP events (backend auto-starts ARP discovery)
  setupArpListeners();
});

// ── Config ──────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    state.config = await api.getConfig();
    if (!state.config) return;

    // Populate settings UI
    $("#rtsp-port").value = state.config.stream.rtsp_port;
    $("#rtsp-path").value = state.config.stream.rtsp_path;
    $("#udp-port").value = state.config.stream.udp_port;
    $("#camera-user").value = state.config.credentials.username;
    $("#camera-pass").value = state.config.credentials.password;
    $("#rtsp-server-enable").checked = state.config.rtsp_server.enabled;
    $("#rtsp-server-port").value = state.config.rtsp_server.port;
    $("#rtsp-token").value = state.config.rtsp_server.token;
    if (state.config.rtsp_server.bind_interface) {
      $("#rtsp-bind-interface").value = state.config.rtsp_server.bind_interface;
    }

    // Set active protocol
    const proto = state.config.stream.protocol;
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
        camera_ip: state.config?.stream?.camera_ip || "",
      },
      rtsp_server: {
        enabled: $("#rtsp-server-enable").checked,
        port: parseInt($("#rtsp-server-port").value) || 8554,
        token: $("#rtsp-token").value,
        bind_interface: state.config?.rtsp_server?.bind_interface || "",
      },
      credentials: {
        username: $("#camera-user").value,
        password: $("#camera-pass").value,
      },
      adopted_subnets: state.config?.adopted_subnets || {},
    };

    try {
      await api.saveConfig(settings);
      state.config = settings;
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
    if (state.isStreaming) {
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

// ── Window Controls ─────────────────────────────────────────────────

function setupWindowControls() {
  const win = window.__TAURI__?.window?.getCurrentWindow?.();
  if (!win) return;

  const maximizeIcon = `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 3v10h10V3H3zm9 9H4V4h8v8z"/></svg>`;
  const restoreIcon = `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 5v8h8V5H3zm7 7H4V6h6v6zm1-9H5v1h7v7h1V3h-2z"/></svg>`;

  async function updateMaximizeIcon() {
    $("#btn-maximize").innerHTML = (await win.isMaximized()) ? restoreIcon : maximizeIcon;
  }

  $("#btn-minimize").addEventListener("click", () => win.minimize());
  $("#btn-maximize").addEventListener("click", async () => {
    await win.toggleMaximize();
    updateMaximizeIcon();
  });
  $("#btn-close").addEventListener("click", () => win.close());

  win.onResized?.(() => updateMaximizeIcon());
  updateMaximizeIcon();
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

// ── Refresh Button ──────────────────────────────────────────────────

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

  $("#btn-refresh-nodes").addEventListener("click", async () => {
    const btn = $("#btn-refresh-nodes");
    btn.disabled = true;
    btn.classList.add("spinning");

    try {
      resetDiscoveryStatus();
      await loadExistingArpState();
    } catch (e) {
      showToast("Refresh failed: " + e, true);
    } finally {
      btn.disabled = false;
      btn.classList.remove("spinning");
    }
  });
}
