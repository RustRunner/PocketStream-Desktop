/**
 * PocketStream Desktop — Main Application (orchestrator)
 */

import * as api from "./lib/tauri-api.ts";
import { $, $$, state, showToast, log, adoptedSubnets } from "./lib/state.ts";
import { formatError } from "./lib/errors.ts";
import {
  refreshInterfaces,
  setupIpConfigDialog,
  setupInterfaceWatcher,
  isInterfaceConnected,
  syncHostModeFromConfig,
  warnNoEthernet,
} from "./lib/network.ts";
import {
  setupArpListeners,
  loadExistingArpState,
  setupAliasDialog,
  resetDiscoveryStatus,
} from "./lib/devices.ts";
import { setupCacheDialog } from "./lib/device-cache.ts";
import * as deviceList from "./lib/device-list.ts";
import {
  setupStreamControls,
  setupRtspControls,
  setupVideoResize,
  getVideoAreaBounds,
  startStatusListener,
  handleHardDisconnect,
  syncRtspStartButton,
  syncVideoVisibility,
  showModalWithVideo,
  createVideoWindowSynced,
} from "./lib/streaming.ts";
import { setupPtzControls } from "./lib/ptz.ts";
import type {
  Credentials,
  RtspServerConfig,
  StreamConfig,
  StreamProtocol,
} from "./lib/types.ts";
import type { TauriUpdate } from "./lib/tauri-global.d.ts";

// ── Global error capture ────────────────────────────────────────────
// Registered before any wiring runs: uncaught errors and rejections
// otherwise only reach DevTools and are invisible in pocketstream.log
// when a field unit misbehaves.

window.addEventListener("error", (e) => {
  api.logToFile(
    "error",
    `Uncaught error: ${e.message} (${e.filename || "?"}:${e.lineno ?? "?"})`,
  );
});

window.addEventListener("unhandledrejection", (e) => {
  api.logToFile("error", `Unhandled rejection: ${formatError(e.reason)}`);
});

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
  setupCacheDialog();
  setupRefreshButton();
  setupResetAdapterButton();
  setupPtzControls();
  setupVideoResize();
  startStatusListener();

  await loadConfig();

  // Surface backend load-time salvage events (e.g. a corrupted config
  // quarantined and reset to defaults) — without this the reset is
  // silent and the operator only notices when settings look wrong.
  try {
    for (const notice of await api.getStartupNotices()) {
      showToast(notice, true);
    }
  } catch (_) {}

  // Paint the mode badge as soon as config is loaded, well before the
  // slower listInterfaces enumeration in refreshInterfaces lands. The
  // mode is a user-set preference that doesn't depend on adapter
  // state — no reason to leave the Host card showing "--" while we
  // wait on Windows to enumerate physical adapters.
  syncHostModeFromConfig();

  // Preload adopted subnets before the first render so renderSubnetList
  // can correctly badge "(auto)" on entries persisted from prior sessions.
  // Without this, the first frame shows every IP as primary, and the
  // badges only appear after loadExistingArpState() runs below.
  try {
    const subnets = await api.getAdoptedSubnets();
    if (subnets) {
      for (const [subnet, ip] of Object.entries(subnets)) {
        adoptedSubnets.set(subnet, ip);
      }
    }
  } catch (_) {}

  await refreshInterfaces();

  // Subscribe to the backend's canonical device list before wiring the
  // render path, so the very first snapshot triggers an initial paint
  // instead of requiring a separate kick.
  setupArpListeners();
  setupInterfaceWatcher();
  await deviceList.start();

  // Load any devices the backend discovered before our listeners were ready
  await loadExistingArpState();

  // Check for updates (non-blocking)
  checkForUpdates();
});

// ── Auto-updater ───────────────────────────────────────────────────

async function checkForUpdates(): Promise<void> {
  const updater = window.__TAURI__?.updater;
  if (!updater) {
    // A plugin rename, withGlobalTauri regression, or capability change
    // would otherwise disable update checks fleet-wide with no trace.
    api.logToFile("warn", "Updater API unavailable — update checks disabled");
    return;
  }

  try {
    const update = await updater.check();
    if (!update) return;

    api.logToFile("info", `Update available: v${update.version}`);
    showUpdateToast(update);
  } catch (e) {
    // Non-fatal — don't block the app if the update check fails
    api.logToFile("warn", `Update check failed: ${formatError(e)}`);
  }
}

function showUpdateToast(update: TauriUpdate): void {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = "toast update-toast";
  toast.style.cssText = `
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    background: var(--md-surface-variant);
    color: var(--md-on-surface);
    padding: 12px 20px;
    border-radius: var(--md-radius-sm);
    font-size: 14px;
    z-index: 1000;
    box-shadow: var(--md-elevation-2);
    animation: toast-in 200ms ease-out;
    display: flex;
    align-items: center;
    gap: 16px;
  `;

  const msg = document.createElement("span");
  msg.textContent = `Update v${update.version} available`;

  const btnInstall = document.createElement("button");
  btnInstall.textContent = "Install";
  btnInstall.style.cssText = `
    background: var(--md-primary);
    color: var(--md-on-primary);
    border: none;
    padding: 6px 16px;
    border-radius: var(--md-radius-sm);
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  `;

  const btnDismiss = document.createElement("button");
  btnDismiss.textContent = "Later";
  btnDismiss.style.cssText = `
    background: transparent;
    color: var(--md-on-surface-variant);
    border: none;
    padding: 6px 12px;
    cursor: pointer;
    font-size: 13px;
  `;

  btnInstall.addEventListener("click", async () => {
    msg.textContent = `Downloading v${update.version}...`;
    btnInstall.remove();
    btnDismiss.remove();
    try {
      await update.downloadAndInstall();
      api.logToFile("info", "Update installed, prompting restart");
      msg.textContent = "Update installed. Restart to apply.";
      setTimeout(() => toast.remove(), 5000);
    } catch (e) {
      api.logToFile("warn", `Update install failed: ${formatError(e)}`);
      msg.textContent = "Update failed.";
      setTimeout(() => toast.remove(), 3000);
    }
  });

  btnDismiss.addEventListener("click", () => {
    api.logToFile("info", "User dismissed update notification");
    toast.style.opacity = "0";
    toast.style.transition = "opacity 200ms";
    setTimeout(() => toast.remove(), 200);
  });

  toast.appendChild(msg);
  toast.appendChild(btnInstall);
  toast.appendChild(btnDismiss);
  document.body.appendChild(toast);
}

// ── Config ──────────────────────────────────────────────────────────

/** Set the Path dropdown from a saved config value. If the saved path
 *  matches one of the preset options, select it and hide the custom
 *  input. Otherwise switch to Custom… and put the saved value into
 *  the custom input so it round-trips through Save Settings without
 *  loss for users on non-listed cameras. */
function applyRtspPath(path: string): void {
  const select = $<HTMLSelectElement>("#rtsp-path");
  const customField = $<HTMLElement>("#rtsp-path-custom-field");
  const customInput = $<HTMLInputElement>("#rtsp-path-custom");
  const presets = Array.from(select.options)
    .map((o) => o.value)
    .filter((v) => v !== "__custom__");
  if (presets.includes(path)) {
    select.value = path;
    customField.style.display = "none";
    customInput.value = "";
  } else {
    select.value = "__custom__";
    customInput.value = path;
    customField.style.display = "";
  }
  // Record this as the applied path so an immediate blur on the
  // custom input (after a click-in / click-out with no edit) doesn't
  // re-fire applyPathChange and restart the stream.
  lastAppliedRtspPath = path;
}

/** Read the effective Path value from the dropdown (or custom input
 *  when Custom… is selected). Whitespace-trimmed so a stray trailing
 *  space doesn't break the RTSP URL build. */
function readRtspPath(): string {
  const select = $<HTMLSelectElement>("#rtsp-path");
  if (select.value === "__custom__") {
    return $<HTMLInputElement>("#rtsp-path-custom").value.trim();
  }
  return select.value;
}

/** Tracks the last successfully-applied path so consecutive Custom…
 *  blurs without an edit don't trigger redundant restarts. */
let lastAppliedRtspPath: string | null = null;

/** Persist the current Path selection to backend config and, if a
 *  stream is running, restart the pipeline so the new URL takes
 *  effect immediately. Treated as a channel switch rather than a
 *  settings change — no Save Settings click required.
 *
 *  No-op when the path didn't actually change (avoids restarting
 *  the stream on a blur that follows a no-edit click on the custom
 *  input). */
async function applyPathChange(): Promise<void> {
  const newPath = readRtspPath();
  if (!newPath) return;
  if (newPath === lastAppliedRtspPath) return;
  if (!state.config) return;

  state.config.stream.rtsp_path = newPath;
  try {
    await api.updateStreamSettings(state.config.stream);
  } catch (e) {
    showToast("Failed to save path: " + formatError(e), true);
    return;
  }
  lastAppliedRtspPath = newPath;

  // Only restart if there's actually a stream to switch. If the user
  // hasn't started one yet, the new path is queued for the next
  // Start Stream click via state.config.stream.rtsp_path.
  if (!state.isStreaming || state.streamLost) return;

  try {
    await api.stopStream();
    const bounds = getVideoAreaBounds();
    const handle = await createVideoWindowSynced(bounds);
    await api.startStream(handle);
    showToast("Switched to " + newPath);
  } catch (e) {
    showToast("Failed to switch path: " + formatError(e), true);
  }
}

async function loadConfig(): Promise<void> {
  try {
    state.config = await api.getConfig();
    if (!state.config) return;

    // Populate settings UI
    $<HTMLInputElement>("#rtsp-port").value = String(state.config.stream.rtsp_port);
    applyRtspPath(state.config.stream.rtsp_path);
    $<HTMLInputElement>("#udp-port").value = String(state.config.stream.udp_port);
    $<HTMLInputElement>("#camera-user").value = state.config.credentials.username;
    $<HTMLInputElement>("#camera-pass").value = state.config.credentials.password;
    $<HTMLInputElement>("#rtsp-server-enable").checked = state.config.rtsp_server.enabled;
    // Programmatic .checked fires no change event — re-derive the Start
    // button's enabled state, or enabled-in-config users get a dead
    // button until they toggle the checkbox off and on.
    syncRtspStartButton();
    $<HTMLInputElement>("#rtsp-server-port").value = String(state.config.rtsp_server.port);
    $<HTMLInputElement>("#rtsp-token").value = state.config.rtsp_server.token;
    // The bind-interface <select> is restored in one place only —
    // populateVpnDropdown, after its options exist. Setting .value here
    // (before the VPN options are appended) silently resolves to "",
    // which a later start/save could then persist over the saved value.

    // Set active protocol
    const proto = state.config.stream.protocol;
    $$<HTMLElement>("[data-protocol]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset["protocol"] === proto);
    });
    updateProtocolVisibility(proto);
  } catch (e) {
    log(`Failed to load config: ${formatError(e)}`);
  }
}

function setupSettingsSave(): void {
  // Path dropdown: act like a channel selector. Picking a preset
  // immediately persists the new path AND restarts the stream if
  // one is running, so the user doesn't have to click Save Settings
  // then Stop then Start to switch between e.g. /z3-1.sdp and
  // /z3-2.sdp. Picking Custom… reveals the text input but does
  // NOT apply yet — the user is mid-edit; apply on Enter or blur.
  $<HTMLSelectElement>("#rtsp-path").addEventListener("change", () => {
    const isCustom = $<HTMLSelectElement>("#rtsp-path").value === "__custom__";
    $<HTMLElement>("#rtsp-path-custom-field").style.display = isCustom ? "" : "none";
    if (isCustom) {
      $<HTMLInputElement>("#rtsp-path-custom").focus();
      return;
    }
    applyPathChange();
  });

  // Custom path text input: apply on Enter (explicit commit) or on
  // blur (implicit commit when the user clicks away). Both feel
  // natural for form-style text entry and avoid restarting the
  // stream on every keystroke.
  $<HTMLInputElement>("#rtsp-path-custom").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      applyPathChange();
    }
  });
  $<HTMLInputElement>("#rtsp-path-custom").addEventListener("blur", () => {
    applyPathChange();
  });

  $<HTMLButtonElement>("#save-settings").addEventListener("click", async () => {
    // Narrow to the StreamProtocol union — the backend enum rejects
    // anything else, and the only two toggle buttons carry these values.
    const activeProto: StreamProtocol =
      $<HTMLElement>("[data-protocol].active")?.dataset["protocol"] === "udp"
        ? "udp"
        : "rtsp";

    // An empty Custom… input must not clobber the configured path.
    // Fall back to the currently-saved path, and only to the hard
    // default when nothing is configured yet.
    const rtspPath =
      readRtspPath() || state.config?.stream?.rtsp_path || "/z3-1.sdp";
    const stream: StreamConfig = {
      protocol: activeProto,
      rtsp_port: parseInt($<HTMLInputElement>("#rtsp-port").value) || 554,
      rtsp_path: rtspPath,
      udp_port: parseInt($<HTMLInputElement>("#udp-port").value) || 8600,
      camera_ip: state.config?.stream?.camera_ip || "",
    };
    const rtspServer: RtspServerConfig = {
      enabled: $<HTMLInputElement>("#rtsp-server-enable").checked,
      port: parseInt($<HTMLInputElement>("#rtsp-server-port").value) || 8554,
      token: $<HTMLInputElement>("#rtsp-token").value,
      bind_interface: state.config?.rtsp_server?.bind_interface || "",
    };
    const credentials: Credentials = {
      username: $<HTMLInputElement>("#camera-user").value,
      password: $<HTMLInputElement>("#camera-pass").value,
    };

    try {
      // Sequential so a failure points clearly at one section. Each
      // command mutates only its own slice of AppSettings server-side
      // — backend-owned fields (device_cache, adopted_subnets,
      // zoom_positions) stay intact.
      await api.updateStreamSettings(stream);
      await api.updateRtspSettings(rtspServer);
      await api.updateCredentials(credentials);
      // Re-pull the canonical settings so state.config reflects whatever
      // the backend currently holds for the fields we don't own.
      state.config = await api.getConfig();
      // Re-sync the Path UI (and lastAppliedRtspPath) to what was saved,
      // so a later blur on the custom input doesn't re-fire applyPathChange
      // and needlessly restart the stream — and so an empty-Custom save
      // that kept the existing path is reflected back in the dropdown.
      applyRtspPath(stream.rtsp_path);
      showToast("Settings saved");
    } catch (e) {
      showToast("Failed to save: " + formatError(e), true);
    }
  });

  // Regenerate token
  $<HTMLButtonElement>("#regen-token").addEventListener("click", () => {
    const hex = Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    $<HTMLInputElement>("#rtsp-token").value = hex;
  });
}

// ── Sidebar ─────────────────────────────────────────────────────────

function setupMenuAndAbout(): void {
  // Open Log Folder button
  $<HTMLButtonElement>("#open-logs").addEventListener("click", () => {
    api
      .openLogFolder()
      .catch((e: unknown) => showToast("Failed to open logs: " + formatError(e), true));
  });

  // Hamburger toggles settings sidebar
  $<HTMLButtonElement>("#menu-toggle").addEventListener("click", () => {
    const sidebar = $("#sidebar");
    sidebar.classList.toggle("collapsed");

    // Reposition video after sidebar animation completes
    if (state.isStreaming) {
      api.setVideoVisible(false).catch(() => {});
      setTimeout(async () => {
        try {
          const bounds = getVideoAreaBounds();
          await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
          // Route through syncVideoVisibility rather than an
          // unconditional show — during a lost stream or with a modal
          // open the video must stay hidden.
          await syncVideoVisibility();
        } catch (_) {}
      }, 250);
    }
  });

  // About icon toggles about panel
  const aboutPanel = $("#about-panel");
  $<HTMLButtonElement>("#about-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    aboutPanel.classList.toggle("open");
  });

  // Populate version from Tauri runtime so it can't drift from Cargo.toml.
  (async () => {
    try {
      const v = await window.__TAURI__?.app?.getVersion?.();
      if (v) $("#app-version").textContent = `PocketStream Desktop v${v}`;
    } catch (_) {}
  })();

  // Close about panel when clicking elsewhere
  document.addEventListener("click", (e) => {
    const target = e.target as Element | null;
    if (!target?.closest(".about-wrapper")) {
      aboutPanel.classList.remove("open");
    }
  });
}

// ── Window Controls ─────────────────────────────────────────────────

function setupWindowControls(): void {
  const win = window.__TAURI__?.window?.getCurrentWindow?.();
  if (!win) return;

  const maximizeIcon = `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 3v10h10V3H3zm9 9H4V4h8v8z"/></svg>`;
  const restoreIcon = `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 5v8h8V5H3zm7 7H4V6h6v6zm1-9H5v1h7v7h1V3h-2z"/></svg>`;

  async function updateMaximizeIcon(): Promise<void> {
    $("#btn-maximize").innerHTML = (await win!.isMaximized()) ? restoreIcon : maximizeIcon;
  }

  $<HTMLButtonElement>("#btn-minimize").addEventListener("click", () => win.minimize());
  $<HTMLButtonElement>("#btn-maximize").addEventListener("click", async () => {
    await win.toggleMaximize();
    updateMaximizeIcon();
  });
  $<HTMLButtonElement>("#btn-close").addEventListener("click", () => win.close());

  win.onResized?.(() => updateMaximizeIcon());
  updateMaximizeIcon();
}

// ── Protocol Toggle ─────────────────────────────────────────────────

function setupProtocolToggle(): void {
  $$<HTMLElement>("[data-protocol]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$<HTMLElement>("[data-protocol]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const proto = btn.dataset["protocol"];
      if (proto) updateProtocolVisibility(proto);
    });
  });
}

function updateProtocolVisibility(protocol: string): void {
  $<HTMLElement>("#rtsp-settings").style.display = protocol === "rtsp" ? "" : "none";
  $<HTMLElement>("#udp-settings").style.display = protocol === "udp" ? "" : "none";
}

// ── Refresh Button ──────────────────────────────────────────────────

function setupRefreshButton(): void {
  $<HTMLButtonElement>("#btn-refresh-host").addEventListener("click", async () => {
    const btn = $<HTMLButtonElement>("#btn-refresh-host");
    btn.disabled = true;
    btn.classList.add("spinning");

    try {
      await refreshInterfaces();
      // Only kick off discovery when the link is actually up. A stale
      // disconnected adapter has no IPs and nothing to scan — running
      // ARP capture against it is wasted effort.
      if (isInterfaceConnected() && state.activeInterface) {
        await api.startArpDiscovery(state.activeInterface.name);
        await loadExistingArpState();
        showToast("Refreshed");
      } else {
        warnNoEthernet();
      }
    } catch (e) {
      showToast("Refresh failed: " + formatError(e), true);
    } finally {
      btn.disabled = false;
      btn.classList.remove("spinning");
    }
  });

  $<HTMLButtonElement>("#btn-refresh-nodes").addEventListener("click", async () => {
    const btn = $<HTMLButtonElement>("#btn-refresh-nodes");
    btn.disabled = true;
    btn.classList.add("spinning");

    try {
      if (!isInterfaceConnected() || !state.activeInterface) {
        warnNoEthernet();
        return;
      }
      resetDiscoveryStatus();
      await api.startArpDiscovery(state.activeInterface.name);
      await loadExistingArpState();
    } catch (e) {
      showToast("Refresh failed: " + formatError(e), true);
    } finally {
      btn.disabled = false;
      btn.classList.remove("spinning");
    }
  });
}

// ── Reset Adapter Dialog ────────────────────────────────────────────
// Forces Windows to re-probe NIC driver state via Restart-NetAdapter.
// This is the programmatic equivalent of opening adapter Properties,
// which is the known workaround for a Windows quirk where a plugged-in
// Ethernet adapter stays marked "Disconnected" until the driver state
// is forcibly refreshed. Triggers a UAC prompt when the app isn't
// already elevated.
//
// Behind a dedicated dialog (rather than an icon + native confirm())
// to make accidental triggers harmless: the previous icon in the Host
// card header could be hit by a stray click and the native confirm()
// proved easy to dismiss-by-Enter without a deliberate read. The
// dialog pattern matches "Clear Offline Devices" — destructive
// action is the unobtrusive text button, Cancel is the prominent
// filled button.

function setupResetAdapterButton(): void {
  const titleEl = $<HTMLElement>("#host-title");
  const dialog = $<HTMLDialogElement>("#reset-adapter-dialog");

  titleEl.addEventListener("click", async () => {
    const iface = state.activeInterface;
    if (!iface || !iface.name) {
      showToast(
        "No Ethernet adapter to reset — plug one in and try again",
        true
      );
      return;
    }
    $<HTMLElement>("#reset-adapter-name").textContent =
      iface.display_name || iface.name;
    // Through showModalWithVideo, not showModal: the native video child
    // z-orders above the WebView, so a bare showModal leaves the dialog
    // buried under (and unclickable through) a running stream.
    await showModalWithVideo(dialog);
  });

  $<HTMLButtonElement>("#reset-adapter-cancel").addEventListener("click", () => {
    dialog.close();
  });

  $<HTMLButtonElement>("#reset-adapter-confirm").addEventListener(
    "click",
    async () => {
      dialog.close();
      const iface = state.activeInterface;
      if (!iface || !iface.name) return;
      const name = iface.name;

      // Tear down the stream before pulling the rug out from under
      // the adapter. Restart-NetAdapter would kill the TCP socket
      // anyway, but doing it explicitly:
      //   - captures resumeSnapshot so handleReconnect picks up the
      //     stream cleanly after the adapter comes back
      //   - avoids the pipeline holding a dead socket through the
      //     restart window (which 0.3.7's stuck-Paused watchdog
      //     would eventually catch, but starting clean is cheaper)
      if (state.isStreaming && !state.streamLost) {
        handleHardDisconnect("Resetting adapter");
      }

      try {
        await api.refreshAdapter(name, "hard");
        showToast("Adapter reset");
        // Restart-NetAdapter on USB Ethernet takes 2–4 s in practice.
        // 1.5 s wasn't always long enough — refreshInterfaces could
        // run before the adapter finished coming back up, which left
        // the auto-resume relying entirely on the watcher's up event.
        // 3 s puts us comfortably past the slow case.
        await new Promise((r) => setTimeout(r, 3000));
        await refreshInterfaces();
        if (isInterfaceConnected() && state.activeInterface) {
          api.startArpDiscovery(state.activeInterface.name).catch(() => {});
        }
      } catch (e) {
        showToast("Reset failed: " + formatError(e), true);
      }
    }
  );
}
