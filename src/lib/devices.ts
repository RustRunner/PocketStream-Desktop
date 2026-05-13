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

import * as api from "./tauri-api.ts";
import { $, state, log, escapeHtml, adoptedSubnets } from "./state.ts";
import {
  renderSubnetList,
  updateCameraIpDropdown,
  isInterfaceConnected,
} from "./network.ts";
import {
  clearScannedIps,
  hasRouteToSubnet,
  isIpScanned,
  markIpScanned,
} from "./device-state.ts";
import * as deviceList from "./device-list.ts";
import { showModalWithVideo } from "./streaming.js";
import { lastSubnetResults, selectedDevice } from "./store.ts";
import type { DropdownDevice, SubnetRenderResult } from "./store.ts";
import { formatError } from "./errors.ts";
import type {
  ArpDevicePayload,
  DeviceRecord,
  SubnetAdoptedPayload,
} from "./types.ts";

// ── Local scanning state ────────────────────────────────────────────

let pendingScans = 0;

// ── Debounced scan trigger ─────────────────────────────────────────
// Collect all ARP discoveries and subnet adoptions, then scan once
// after activity settles. This prevents partial renders and flicker.

const SETTLE_MS = 6000; // wait 6s after last ARP/adopt event
let settleTimer: ReturnType<typeof setTimeout> | null = null;

/** Reset the settle timer — called on every new ARP device or adoption. */
function debounceScan(): void {
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = setTimeout(() => {
    settleTimer = null;
    scanAllRoutableDevices();
  }, SETTLE_MS);
}

/** Scan every device the backend currently knows about that's on a
 *  routable subnet and we haven't scanned this session. */
function scanAllRoutableDevices(): void {
  const toScan: string[] = [];
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

type DiscoveryPhase = "discovering" | "scanning" | "idle";

let discoveryPhase: DiscoveryPhase = "idle";
let initialFlowComplete = false;

function applyDiscoveryPhaseToDOM(): void {
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

function setDiscoveryPhase(phase: DiscoveryPhase): void {
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
function isDiscoveryActive(): boolean {
  return discoveryPhase !== "idle";
}

/** Hide the Nodes-card discovery spinner. Exported for the interface
 *  watcher so it can cancel a stuck spinner on link-down. */
export function hideDiscoveryStatus(): void {
  setDiscoveryPhase("idle");
}

export function resetDiscoveryStatus(): void {
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

export function setupArpListeners(): void {
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
  api.onEvent<ArpDevicePayload>("arp-device-discovered", (device) => {
    if (!isInterfaceConnected()) return;
    if (!state.activeInterface) return;
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

  api.onEvent<SubnetAdoptedPayload>("subnet-adopted", (data) => {
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
export async function loadExistingArpState(): Promise<void> {
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

/** How long to wait before re-verifying a device that's currently
 *  flagged offline. Without this, a device that failed the startup
 *  verify race (e.g., a brief ping-sweep saturation during cold
 *  start) stays flagged offline forever — the isIpScanned guard
 *  would normally block any future scan anyway, so we also clear
 *  that on offline-set. */
const OFFLINE_RETRY_INTERVAL_MS = 60_000;
const offlineRetryTimers = new Map<string, ReturnType<typeof setTimeout>>();

function verifyCachedRoutableDevices(): void {
  for (const record of deviceList.getDevices()) {
    if (record.status !== "cached_only") continue;
    if (!hasRouteToSubnet(record.subnet)) continue;
    if (isIpScanned(record.ip)) continue;
    fastVerifyCachedDevice(record.mac, record.ip);
  }
}

/** Schedule a periodic re-verify for an offline device so the status
 *  self-heals once the device responds again (without requiring the
 *  user to click the Nodes refresh button). Replaces any previously
 *  pending retry for the same MAC. */
function scheduleOfflineRetry(mac: string, ip: string): void {
  const existing = offlineRetryTimers.get(mac);
  if (existing) clearTimeout(existing);
  const timer = setTimeout(() => {
    offlineRetryTimers.delete(mac);
    const record = deviceList.getDevices().find((r) => r.mac === mac);
    // Bail if the device went away (forgot), is no longer offline
    // (something else verified it), or the subnet is no longer
    // routable (Ethernet down / subnet dropped).
    if (!record || record.status !== "offline") return;
    if (!hasRouteToSubnet(record.subnet)) return;
    fastVerifyCachedDevice(mac, ip);
  }, OFFLINE_RETRY_INTERVAL_MS);
  offlineRetryTimers.set(mac, timer);
}

async function fastVerifyCachedDevice(
  mac: string,
  ip: string,
  attempt = 0
): Promise<void> {
  if (attempt === 0) {
    markIpScanned(ip);
    // Flip to verifying so the UI shows the badge through retries.
    api.setDeviceStatus(mac, "verifying").catch((e: unknown) => {
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
    setTimeout(
      () => fastVerifyCachedDevice(mac, ip, attempt + 1),
      VERIFY_RETRY_DELAY_MS
    );
  } else {
    // Final attempt failed — flag offline so the UI can dim it and
    // the user knows clicking it may not work right now. Clear the
    // scanned flag so future scans CAN retry this IP (without this,
    // isIpScanned blocks every later attempt and the device stays
    // offline forever even after it comes back), and schedule a
    // periodic re-verify so the status self-heals when conditions
    // improve.
    markIpScanned(ip, /* clear */ true);
    api.setDeviceStatus(mac, "offline").catch((e: unknown) => {
      log(`set offline status failed for ${ip}: ${formatError(e)}`);
    });
    scheduleOfflineRetry(mac, ip);
  }
}

// ── Port scanning ───────────────────────────────────────────────────

const MAX_SCAN_RETRIES = 2;
const RETRY_DELAY_MS = 4000;

async function scanDevicePorts(ip: string, attempt = 0): Promise<void> {
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

export function renderArpDeviceList(): void {
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

  const bySubnet = new Map<string, DeviceRecord[]>();
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
    const bucket = bySubnet.get(record.subnet);
    if (bucket) {
      bucket.push(record);
    } else {
      bySubnet.set(record.subnet, [record]);
    }
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

  const subnetResults: SubnetRenderResult[] = [];

  const pencilSvg =
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.001 1.001 0 000-1.41l-2.34-2.34a1.001 1.001 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';

  let html = "";
  let nodeIndex = 0;
  for (const [subnet, records] of bySubnet) {
    const ownIps = new Set<string>();
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

    const devicesForDropdown: DropdownDevice[] = [];

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
      localIp:
        adoptedSubnets.get(subnet) ?? state.activeInterface?.ips[0]?.address ?? "",
      devices: devicesForDropdown,
    });
  }

  if (!html) {
    // Keep the list empty while either ARP discovery is still running
    // (no devices yet, but they may show up) OR a port scan is still
    // in flight (devices exist but haven't qualified for display yet).
    // Only show "No devices found." once both have settled.
    if (pendingScans > 0 || isDiscoveryActive()) return;
    list.innerHTML = '<p class="placeholder-text">No devices found.</p>';
    updateCameraIpDropdown(null);
    return;
  }

  list.innerHTML = html;

  // Wire up event handlers
  list.querySelectorAll<HTMLElement>(".device-item").forEach((item) => {
    item.addEventListener("click", (e) => {
      const target = e.target as Element;
      if (target.closest(".device-ip") || target.closest(".edit-alias-btn")) return;
      list.querySelectorAll(".device-item").forEach((i) => i.classList.remove("selected"));
      item.classList.add("selected");
      const ip = item.dataset["ip"] ?? null;
      selectedDevice.set(ip);
      const select = $<HTMLSelectElement>("#camera-ip");
      select.value = selectedDevice.get() ?? "";
      if (state.config && ip) {
        state.config.stream.camera_ip = ip;
      }
    });
  });

  list
    .querySelectorAll<HTMLAnchorElement>(".device-ip[data-browse]")
    .forEach((link) => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const ip = link.dataset["browse"];
        if (!ip) return;
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

  list
    .querySelectorAll<HTMLButtonElement>(".edit-alias-btn")
    .forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const ip = btn.dataset["aliasIp"];
        if (ip) openAliasDialog(ip);
      });
    });

  lastSubnetResults.set(subnetResults);
  updateCameraIpDropdown(subnetResults);
}

// ── Alias dialog ────────────────────────────────────────────────────

async function openAliasDialog(ip: string): Promise<void> {
  const dialog = $<HTMLDialogElement>("#alias-dialog");
  $("#alias-dialog-ip").textContent = ip;
  $<HTMLInputElement>("#alias-input").value = "";
  $<HTMLElement>("#alias-custom-field").style.display = "none";
  dialog.dataset["ip"] = ip;

  // Reset role buttons
  const record = deviceList.deviceByIp(ip);
  const existing = record?.alias || "";
  const roleBtns = dialog.querySelectorAll<HTMLElement>("[data-role]");
  roleBtns.forEach((b) => b.classList.remove("active"));

  const isCustom = existing && existing !== "CAM" && existing !== "PTU";
  if (existing === "CAM") {
    dialog.querySelector("[data-role='cam']")?.classList.add("active");
  } else if (existing === "PTU") {
    dialog.querySelector("[data-role='ptu']")?.classList.add("active");
  } else if (existing) {
    dialog.querySelector("[data-role='custom']")?.classList.add("active");
    $<HTMLInputElement>("#alias-input").value = existing;
    $<HTMLElement>("#alias-custom-field").style.display = "";
  }

  // Save is only meaningful when the user has a custom name typed.
  // Clear Name is always visible — it's a no-op for devices with no
  // alias yet, but means the user can revert a CAM/PTU/custom-named
  // node back to the default "Node N" display directly from any
  // dialog state instead of having to switch to Custom first.
  $<HTMLElement>("#alias-clear").style.display = "";
  $<HTMLElement>("#alias-save").style.display = isCustom ? "" : "none";

  if (dialog.open) dialog.close();
  await showModalWithVideo(dialog);
}

/** Push an alias change to the backend. Render re-fires automatically
 *  via the device-list-changed event the backend emits in response. */
function persistAlias(ip: string, alias: string): void {
  api.setDeviceAlias(ip, alias).catch((e: unknown) => {
    log(`Failed to set alias for ${ip}: ${formatError(e)}`);
  });
}

export function setupAliasDialog(): void {
  const dialog = $<HTMLDialogElement>("#alias-dialog");

  function updateAliasActions(role: string): void {
    const isCustom = role === "custom";
    // Save is only meaningful when there's a custom name to commit.
    // Clear Name stays visible whenever the current record actually
    // has an alias (handled at open time in openAliasDialog); for
    // the in-dialog role switch we keep it visible while the user
    // is editing so they can back out of an in-progress rename.
    $<HTMLElement>("#alias-save").style.display = isCustom ? "" : "none";
  }

  // Role toggle buttons
  const roleBtns = document.querySelectorAll<HTMLElement>(
    ".alias-role-group [data-role]"
  );
  roleBtns.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      roleBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const role = btn.dataset["role"];

      if (role === "cam") {
        const ip = dialog.dataset["ip"];
        if (!ip) return;
        persistAlias(ip, "CAM");
        $<HTMLSelectElement>("#camera-ip").value = ip;
        if (state.config) state.config.stream.camera_ip = ip;
        dialog.close();
      } else if (role === "ptu") {
        const ip = dialog.dataset["ip"];
        if (!ip) return;
        persistAlias(ip, "PTU");
        $<HTMLSelectElement>("#ptu-ip").value = ip;
        dialog.close();
      } else {
        $<HTMLElement>("#alias-custom-field").style.display = "";
        updateAliasActions("custom");
        $<HTMLInputElement>("#alias-input").focus();
      }
    });
  });

  $<HTMLButtonElement>("#alias-save").addEventListener("click", () => {
    const ip = dialog.dataset["ip"];
    if (!ip) return;
    const alias = $<HTMLInputElement>("#alias-input").value.trim();
    persistAlias(ip, alias);
    dialog.close();
  });

  $<HTMLButtonElement>("#alias-clear").addEventListener("click", () => {
    const ip = dialog.dataset["ip"];
    if (!ip) return;
    persistAlias(ip, "");
    dialog.close();
  });

  $<HTMLButtonElement>("#alias-cancel").addEventListener("click", () => {
    $<HTMLDialogElement>("#alias-dialog").close();
  });

  $<HTMLInputElement>("#alias-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $<HTMLButtonElement>("#alias-save").click();
    }
  });
}
