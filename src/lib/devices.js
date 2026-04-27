/**
 * PocketStream Desktop — discovery triggers, port scanning, device
 * list rendering, and the per-device alias dialog.
 *
 * Backend (DeviceRegistry) is the single source of truth for device
 * records. This module is a pure consumer of `device-list.js`'s
 * subscribe-able snapshot. All writes (scan results, aliases, status
 * transitions, forget) go through tauri-api.js IPC calls; the backend
 * mutates the registry, emits a new snapshot, and the render path
 * picks it up via the deviceList subscription.
 *
 * Concerns that live here (not in the backend):
 *   - The discovery phase spinner machine (UX, not data)
 *   - Settle-debounced scan trigger (UX policy)
 *   - Cache verification retry policy (UX policy)
 *   - The DOM rendering itself
 *   - Alias dialog UI
 */

import * as api from "./tauri-api.js";
import { $, state, log, escapeHtml, adoptedSubnets } from "./state.js";
import {
  renderSubnetList,
  updateCameraIpDropdown,
  isInterfaceConnected,
} from "./network.js";
import {
  clearScannedIps,
  hasRouteToSubnet,
  isIpScanned,
  markIpScanned,
} from "./device-state.js";
import * as deviceList from "./device-list.js";
import { lastSubnetResults, selectedDevice } from "./store.js";
import { formatError } from "./errors.js";

// ── Local scanning state ────────────────────────────────────────────

let pendingScans = 0;

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

/** Scan every device the backend currently knows about that's on a
 *  routable subnet and we haven't scanned this session. */
function scanAllRoutableDevices() {
  const toScan = [];
  for (const record of deviceList.getDevices()) {
    if (!isIpScanned(record.ip) && hasRouteToSubnet(record.subnet)) {
      toScan.push(record.ip);
    }
  }
  if (toScan.length === 0) {
    // Nothing to scan yet — stay in whatever phase we're in (typically
    // "discovering"). The 6s settle timer fires whenever event traffic
    // goes quiet for a moment, which during initial adoption can happen
    // *between* subnet-adopted events, before any routable device has
    // landed. Hiding the spinner here was the original "Nodes card goes
    // blank mid-work" gap.
    return;
  }
  log(`Scanning ${toScan.length} routable device(s)...`);
  setDiscoveryPhase("scanning");
  for (const ip of toScan) {
    scanDevicePorts(ip);
  }
}

// ── Discovery status ─────────────────────────────────────────────────
//
// Phase machine with three states driving the Nodes-card spinner:
//   "discovering" → "IP Discovery..."  (ARP + subnet adoption in flight)
//   "scanning"    → "Port Scan..."     (TCP probes in flight)
//   "idle"        → no spinner         (everything settled)
//
// The spinner is a *startup progress indicator*, not a live activity
// readout. Once the initial flow completes (first idle after adoption
// + scanning), background ARP traffic must not resurrect it — otherwise
// the nodes card would flicker back to "IP Discovery..." indefinitely
// on any busy network. `initialFlowComplete` enforces that by coercing
// any post-startup "discovering" request into "idle".
//
// Port-scan feedback for genuinely new devices joining the network
// later is still allowed (phase "scanning" is not locked), because
// that's a bounded, useful signal.

let discoveryPhase = "idle";
let initialFlowComplete = false;

function applyDiscoveryPhaseToDOM() {
  const container = $("#discovery-status");
  if (!container) return;
  if (discoveryPhase === "idle") {
    container.classList.add("hidden");
    return;
  }
  const label = discoveryPhase === "scanning" ? "Port Scan..." : "IP Discovery...";
  $("#discovery-label").textContent = label;
  container.classList.remove("hidden");
}

function setDiscoveryPhase(phase) {
  if (phase === "discovering" && initialFlowComplete) {
    phase = "idle";
  }
  const wasScanning = discoveryPhase === "scanning";
  discoveryPhase = phase;
  // Engage the one-shot lock only on a *real* completion — scanning →
  // idle via scanDevicePorts. A direct discovering → idle (hideDiscoveryStatus
  // on link drop, explicit reset paths) is not completion and must not
  // lock future "IP Discovery..." transitions.
  if (phase === "idle" && wasScanning) initialFlowComplete = true;
  applyDiscoveryPhaseToDOM();
}

/** True when the Nodes card should consider itself still working,
 *  i.e. a spinner is visible. Used by renderArpDeviceList to decide
 *  between "No devices found" (idle, empty) and no placeholder at
 *  all (still working, empty is expected). */
function isDiscoveryActive() {
  return discoveryPhase !== "idle";
}

/** Hide the Nodes-card discovery spinner. Exported for the interface
 *  watcher so it can cancel a stuck spinner on link-down. */
export function hideDiscoveryStatus() {
  setDiscoveryPhase("idle");
}

export function resetDiscoveryStatus() {
  clearScannedIps();
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = null;
  // Clear the one-shot lock so a reconnect / user-initiated rescan can
  // legitimately show "IP Discovery..." again at the start of the fresh
  // flow. Must happen BEFORE setDiscoveryPhase, or the coercion would
  // bounce "discovering" → "idle".
  initialFlowComplete = false;
  setDiscoveryPhase("discovering");
  // Reconnect path: backend preserves device records across disconnect for
  // fast UI recovery, so the backend often doesn't re-fire subnet-adopted
  // or arp-device-discovered events — which means debounceScan never
  // triggers, scanAllRoutableDevices never runs, and the spinner would
  // stay on "IP Discovery..." indefinitely. Kick a scan of the already-
  // known devices immediately; if the deviceList is empty (cold start),
  // the function returns early and we correctly stay in "discovering"
  // waiting for fresh ARP events.
  scanAllRoutableDevices();
}

// ── ARP event listeners ─────────────────────────────────────────────

export function setupArpListeners() {
  // Re-render whenever the backend pushes a new snapshot.
  deviceList.subscribe(renderArpDeviceList);

  // Only show a spinner when the link is actually up. A stale
  // disconnected adapter (state.activeInterface set, but ips=[]) would
  // otherwise leave the spinner running forever with no ARP traffic.
  if (isInterfaceConnected()) {
    setDiscoveryPhase("discovering");
  } else {
    setDiscoveryPhase("idle");
  }

  // Live ARP events still arrive per-device — used purely as a UX
  // signal to debounce the next scan pass. The actual record state
  // is sourced from deviceList; we never mutate anything here.
  api.onEvent("arp-device-discovered", (device) => {
    if (!isInterfaceConnected()) return;
    if (state.activeInterface.ips.some((ip) => ip.address === device.ip)) return;

    const known = deviceList.deviceByMac(device.mac);
    const isNew = !known;

    if (isNew) {
      log(`ARP: discovered ${device.ip} (${device.mac})`);
      // Mid-scan ARPs flip us back to "discovering" only if we're not
      // already showing "Port Scan..." for in-flight scans. That keeps
      // the UX linear (Discovery → Scan → idle) instead of flickering
      // back to Discovery every time a late ARP arrives during a scan.
      if (discoveryPhase === "idle") {
        setDiscoveryPhase("discovering");
      }
      debounceScan();
    }
  });

  api.onEvent("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    renderSubnetList();
    // Briefly flash the row so the user notices a live adoption. The
    // class auto-clears after the CSS animation; the persistent "(auto)"
    // badge stays put. No state to clean up because renderSubnetList
    // rebuilds the row from scratch next render.
    const row = $(`#subnet-list .subnet-row[data-subnet="${data.subnet}"]`);
    if (row) {
      row.classList.add("subnet-row-just-adopted");
      setTimeout(() => row.classList.remove("subnet-row-just-adopted"), 2500);
    }
    // Reset the settle timer — netsh needs time to activate the IP
    debounceScan();
  });

  // Initial hydration / scan kickoff is orchestrated from main.js
  // (deviceList.start() then loadExistingArpState) so the order is
  // explicit at the call site.
}

/** Pull adopted subnets, then scan whichever routable records the
 *  backend has already given us (cached entries from cold start, or
 *  ARP discoveries we missed before subscribing). */
export async function loadExistingArpState() {
  if (!isInterfaceConnected()) {
    setDiscoveryPhase("idle");
    return;
  }

  try {
    const subnets = await api.getAdoptedSubnets();
    if (subnets) {
      for (const [subnet, ip] of Object.entries(subnets)) {
        adoptedSubnets.set(subnet, ip);
      }
      if (Object.keys(subnets).length > 0) renderSubnetList();
    }

    // Kick verification + scanning for whatever's already in the
    // registry. Cached-only records on routable subnets get a fast
    // verify pass; everything else falls through to the regular
    // scan-all path.
    verifyCachedRoutableDevices();

    if (deviceList.getDevices().length > 0) {
      scanAllRoutableDevices();
    } else {
      setDiscoveryPhase("discovering");
    }
  } catch (e) {
    console.error("Failed to load ARP state:", e);
  }
}

// ── Cache verification ─────────────────────────────────────────────
// For cached-only records on currently-routable subnets, run a fast
// targeted scan to confirm they're still reachable. Three attempts
// handles devices (notably the FLIR PTU) that need an extra moment
// to respond on a freshly bound secondary IP. Worst case before
// flagging offline: ~5s (1.5s + 3s + ~1s scans).

const VERIFY_MAX_ATTEMPTS = 3;
const VERIFY_RETRY_DELAY_MS = 1500;

function verifyCachedRoutableDevices() {
  for (const record of deviceList.getDevices()) {
    if (record.status !== "cached_only") continue;
    if (!hasRouteToSubnet(record.subnet)) continue;
    if (isIpScanned(record.ip)) continue;
    fastVerifyCachedDevice(record.mac, record.ip);
  }
}

async function fastVerifyCachedDevice(mac, ip, attempt = 0) {
  if (attempt === 0) {
    markIpScanned(ip);
    // Flip to verifying so the UI shows the badge through retries.
    api.setDeviceStatus(mac, "verifying").catch((e) => {
      log(`set verifying status failed for ${ip}: ${formatError(e)}`);
    });
  }

  let verified = false;
  try {
    const results = await api.scanNetwork(`${ip}/32`);
    if (results) {
      for (const r of results) {
        if (r.ip === ip && r.reachable && r.open_ports.length > 0) {
          // Backend's report_scan_result auto-flips the record to
          // "live" + persists to cache + emits a new snapshot.
          await api.reportScanResult(r.ip, r.open_ports);
          verified = true;
        }
      }
    }
  } catch (e) {
    log(`Cache verify failed for ${ip} (attempt ${attempt + 1}): ${formatError(e)}`);
  }

  if (verified) {
    return;
  }
  if (attempt + 1 < VERIFY_MAX_ATTEMPTS) {
    // Hold the verifying badge through the retry — flipping to offline
    // just to flip back would be jarring.
    setTimeout(() => fastVerifyCachedDevice(mac, ip, attempt + 1), VERIFY_RETRY_DELAY_MS);
  } else {
    // Final attempt failed — flag offline so the UI can dim it and the
    // user knows clicking it may not work right now.
    api.setDeviceStatus(mac, "offline").catch((e) => {
      log(`set offline status failed for ${ip}: ${formatError(e)}`);
    });
  }
}

// ── Port scanning ───────────────────────────────────────────────────

const MAX_SCAN_RETRIES = 2;
const RETRY_DELAY_MS = 4000;

async function scanDevicePorts(ip, attempt = 0) {
  if (attempt === 0 && isIpScanned(ip)) return;
  markIpScanned(ip);
  if (attempt === 0) pendingScans++;

  try {
    const results = await api.scanNetwork(`${ip}/32`);
    let found = false;
    if (results) {
      for (const r of results) {
        if (r.reachable && r.open_ports.length > 0) {
          // Backend persists, flips status to live, and emits a snapshot.
          await api.reportScanResult(r.ip, r.open_ports);
          found = true;
        }
      }
    }
    if (!found) {
      markIpScanned(ip, /* clear */ true);
      // Retry — the device may be on a subnet that was just adopted
      if (attempt < MAX_SCAN_RETRIES) {
        setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
        return; // don't decrement pendingScans yet
      }
    }
  } catch (e) {
    log(`Port scan failed for ${ip}: ${formatError(e)}`);
    markIpScanned(ip, /* clear */ true);
    if (attempt < MAX_SCAN_RETRIES) {
      setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
      return;
    }
  }

  pendingScans--;
  if (pendingScans <= 0) {
    // All port scans done. If the settle timer is still armed from a
    // late ARP / adoption event, drop back to "discovering" until it
    // fires; otherwise we're fully idle.
    setDiscoveryPhase(settleTimer !== null ? "discovering" : "idle");
  }
}

// ── Device list rendering ───────────────────────────────────────────

export function renderArpDeviceList() {
  const list = $("#device-list");

  // While disconnected, render nothing — the records may still be in
  // the backend's registry (preserved deliberately so a replug restores
  // them fast), but they're unreachable right now. Returning early
  // keeps the card empty without having to drop the state.
  if (!isInterfaceConnected()) {
    list.innerHTML = "";
    updateCameraIpDropdown(null);
    return;
  }

  const ownMac = state.activeInterface?.mac?.toLowerCase() || null;

  const bySubnet = new Map();
  for (const record of deviceList.getDevices()) {
    // Hide cached-only entries on subnets we don't currently route to —
    // they're stale ghosts from a different network. Stay in the cache
    // file so they reappear when the subnet is reachable again.
    if (record.status === "cached_only" && !hasRouteToSubnet(record.subnet)) {
      continue;
    }
    // Hide entries whose MAC matches our own adapter. These are ghosts
    // from a prior gratuitous ARP we captured when adding a secondary
    // IP — the backend now filters these at capture time, but existing
    // cache files can still contain them from older sessions.
    if (ownMac && record.mac.toLowerCase() === ownMac) {
      continue;
    }
    if (!bySubnet.has(record.subnet)) {
      bySubnet.set(record.subnet, []);
    }
    bySubnet.get(record.subnet).push(record);
  }

  if (bySubnet.size === 0 && pendingScans <= 0) {
    // Spinner (IP Discovery / Port Scan) carries the "still working"
    // signal — leave the list empty while it's visible. Only show
    // the "No devices found" placeholder once everything's settled.
    list.innerHTML = isDiscoveryActive()
      ? ""
      : '<p class="placeholder-text">No devices found.</p>';
    updateCameraIpDropdown(null);
    return;
  }

  const subnetResults = [];

  const pencilSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.001 1.001 0 000-1.41l-2.34-2.34a1.001 1.001 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

  let html = "";
  let nodeIndex = 0;
  for (const [subnet, records] of bySubnet) {
    const ownIps = new Set();
    if (state.activeInterface) {
      state.activeInterface.ips.forEach((ip) => ownIps.add(ip.address));
    }
    for (const ip of adoptedSubnets.values()) {
      ownIps.add(ip);
    }

    const filtered = records.filter((r) => {
      if (ownIps.has(r.ip)) return false;
      return r.open_ports && r.open_ports.length > 0;
    });
    if (filtered.length === 0) continue;

    const devicesForDropdown = [];

    html += `<div class="subnet-group">`;

    for (const r of filtered) {
      nodeIndex++;
      const name = r.alias || `Node ${nodeIndex}`;
      const ports = r.open_ports;

      devicesForDropdown.push({ ip: r.ip, open_ports: ports, alias: r.alias });

      const classes = ["device-item"];
      if (selectedDevice.get() === r.ip) classes.push("selected");
      if (r.status === "verifying") classes.push("verifying");
      if (r.status === "offline") classes.push("offline");

      const statusBadge =
        r.status === "verifying"
          ? '<span class="device-status" title="Verifying...">verifying</span>'
          : r.status === "offline"
            ? '<span class="device-status" title="Last-known state — device not responding">offline</span>'
            : "";

      html += `
        <div class="${classes.join(" ")}" data-ip="${r.ip}">
          <div class="device-name-row">
            <span class="device-name">${escapeHtml(name)}</span>
            ${statusBadge}
            <button class="edit-alias-btn" data-alias-ip="${r.ip}" title="Rename">${pencilSvg}</button>
          </div>
          <div class="device-detail-row">
            <a class="device-ip" href="#" data-browse="${r.ip}" title="Open in browser">${r.ip}</a>
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
      selectedDevice.set(item.dataset.ip);
      const select = $("#camera-ip");
      select.value = selectedDevice.get();
      if (state.config) {
        state.config.stream.camera_ip = selectedDevice.get();
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

  lastSubnetResults.set(subnetResults);
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
  const record = deviceList.deviceByIp(ip);
  const existing = record?.alias || "";
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

/** Push an alias change to the backend. Render re-fires automatically
 *  via the device-list-changed event the backend emits in response. */
function persistAlias(ip, alias) {
  api.setDeviceAlias(ip, alias).catch((e) => {
    log(`Failed to set alias for ${ip}: ${formatError(e)}`);
  });
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
        persistAlias(ip, "CAM");
        $("#camera-ip").value = ip;
        if (state.config) state.config.stream.camera_ip = ip;
        dialog.close();
      } else if (role === "ptu") {
        const ip = dialog.dataset.ip;
        persistAlias(ip, "PTU");
        $("#ptu-ip").value = ip;
        dialog.close();
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
    persistAlias(ip, alias);
    dialog.close();
  });

  $("#alias-clear").addEventListener("click", () => {
    const ip = dialog.dataset.ip;
    persistAlias(ip, "");
    dialog.close();
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
