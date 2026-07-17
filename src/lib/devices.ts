/**
 * PocketStream Desktop — discovery triggers, port scanning, device
 * list rendering, and the per-node role dropdown.
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
 *   - Role dropdown UI (CAM / PTU / Clear per node)
 */

import * as api from "./tauri-api.ts";
import {
  $,
  state,
  log,
  showToast,
  escapeHtml,
  adoptedSubnets,
  adoptionMeta,
} from "./state.ts";
import {
  renderSubnetList,
  isInterfaceConnected,
  refreshIpDialogIfOpen,
} from "./network.ts";
import {
  clearScannedIps,
  hasRouteToSubnet,
  isIpScanned,
  markIpScanned,
  visibleDevices,
} from "./device-state.ts";
import * as deviceList from "./device-list.ts";
import { getActivePlaybackIp, stopStreamNow } from "./streaming.ts";
import { haltPtuUnit } from "./ptz.ts";
import { selectedDevice, sessionCamIp } from "./store.ts";
import { formatError } from "./errors.ts";
import type {
  AdoptionFailedPayload,
  ArpDevicePayload,
  DevicePingResultPayload,
  DeviceRecord,
  DiscoveryDegradedPayload,
  DiscoveryRecoveredPayload,
  SubnetAdoptedPayload,
  SubnetRemovedPayload,
} from "./types.ts";

/** Escape a value for use inside a double-quoted CSS attribute selector.
 *  Only `"` and `\` are special inside the quotes — escaping just those
 *  (rather than CSS.escape, which mangles `.`/`/` in a subnet) keeps the
 *  selector matching while preventing a stray quote from breaking it. */
function cssAttrValue(value: string): string {
  return value.replace(/["\\]/g, "\\$&");
}

// ── Local scanning state ────────────────────────────────────────────

let pendingScans = 0;

// ── ICMP reachability dots ──────────────────────────────────────────
// IP → latest ping result. Missing entry = no probe yet (gray dot).
// The backend pinger publishes `device-ping-result` events; we treat
// the latest value per IP as the source of truth for the dot.
const pingResults = new Map<string, boolean>();

/** Render a status dot for a device's IP based on the latest ping
 *  result. Gray if no probe has come back yet, green if reachable,
 *  red if the last probe failed. */
function renderReachabilityDot(ip: string): string {
  const result = pingResults.get(ip);
  if (result === undefined) {
    return '<span class="device-dot dot-pending" title="Checking reachability..."></span>';
  }
  if (result) {
    return '<span class="device-dot dot-green" title="Reachable"></span>';
  }
  return '<span class="device-dot dot-red" title="No response on last probe"></span>';
}

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

  api.onEvent<DevicePingResultPayload>("device-ping-result", (data) => {
    const prev = pingResults.get(data.ip);
    pingResults.set(data.ip, data.reachable);
    // Only re-render when the dot color would change. ICMP results
    // are inherently noisy; redrawing every device row twice per
    // minute regardless of change would be a wasted render.
    if (prev !== data.reachable) {
      renderArpDeviceList();
    }
  });

  // Quiet-network watchdog signals. Diagnostic only — the backend never
  // flips discovery availability on silence, so this is a heads-up that a
  // provoked ping sweep drew no ARP frames (dead subnet, or capture not
  // delivering). At most one degraded toast per discovery session.
  api.onEvent<DiscoveryDegradedPayload>("discovery-degraded", (data) => {
    const drops =
      data.missed_packets > 0 ? ` (ring drops: ${data.missed_packets})` : "";
    log(`Discovery degraded: ${data.reason}${drops}`);
    showToast("No devices responding to discovery yet", true);
  });

  api.onEvent<DiscoveryRecoveredPayload>("discovery-recovered", () => {
    log("Discovery recovered — devices responding again");
  });

  api.onEvent<SubnetAdoptedPayload>("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    adoptionMeta.set(data.subnet, {
      adopted_at: data.adopted_at,
      last_device_seen: data.last_device_seen,
      stale: data.stale,
    });
    renderSubnetList();
    // Briefly flash the row so the user notices a live adoption. The
    // class auto-clears after the CSS animation; the persistent "(auto)"
    // badge stays put. No state to clean up because renderSubnetList
    // rebuilds the row from scratch next render.
    const row = $(
      `#subnet-list .subnet-row[data-subnet="${cssAttrValue(data.subnet)}"]`
    );
    if (row) {
      row.classList.add("subnet-row-just-adopted");
      setTimeout(() => row.classList.remove("subnet-row-just-adopted"), 2500);
    }
    // Reset the settle timer — netsh needs time to activate the IP
    debounceScan();
  });

  api.onEvent<AdoptionFailedPayload>("adoption-failed", (data) => {
    // Diagnostic only — the adopt loop retries with backoff on its own.
    log(`Auto-adopt failed for ${data.subnet}: ${data.error}`);
    showToast(`Couldn't join ${data.subnet} — will retry`, true);
  });

  // One removal path for every surface: whether the backend reaped a
  // stale adoption or the user removed one from either panel, this
  // event is what clears the frontend maps and re-renders — the
  // optimistic local deletes in the click handlers are just immediate
  // feedback, this is authoritative.
  api.onEvent<SubnetRemovedPayload>("subnet-removed", (data) => {
    log(`Subnet removed (${data.reason}): ${data.subnet} (${data.adopted_ip})`);
    adoptedSubnets.delete(data.subnet);
    adoptionMeta.delete(data.subnet);
    renderSubnetList();
    void refreshIpDialogIfOpen();
    // Manual removals already toast from their click handler; only a
    // background reap needs to tell the user something happened.
    if (data.reason === "stale_apipa") {
      showToast(`Removed stale adoption ${data.subnet} — no device seen there`);
    }
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
    const snapshot = await api.getAdoptionState();
    const entries = Object.entries(snapshot.adopted_subnets);
    for (const [subnet, ip] of entries) {
      adoptedSubnets.set(subnet, ip);
    }
    for (const [subnet, meta] of Object.entries(snapshot.meta)) {
      adoptionMeta.set(subnet, meta);
    }
    if (entries.length > 0) renderSubnetList();

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
    log(`Failed to load ARP state: ${formatError(e)}`);
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
          // Identity check: a successful port scan only proves *some
          // host* answers at this IP. To claim our cached record is
          // still live, the responder's MAC must also match — otherwise
          // a different device that happens to occupy this IP today
          // would resurrect the record as a false-positive Live.
          const liveMac = await api.resolveMac(ip);
          if (liveMac && liveMac.toLowerCase() === mac.toLowerCase()) {
            // Backend's report_scan_result auto-flips the record to
            // "live" + persists to cache + emits a new snapshot.
            await api.reportScanResult(r.ip, r.open_ports);
            verified = true;
          } else {
            log(
              `Cache verify: identity mismatch at ${ip} — expected ${mac}, found ${liveMac ?? "no ARP"}`
            );
          }
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
    // Evict phantom cache rows: a device that never verifies is probably
    // gone. The backend exempts aliased CAM/PTU, manual nodes, and Live
    // entries, so only genuinely-unimportant phantoms are removed; the
    // exempt ones fall through to the dim-and-re-verify self-heal path.
    let evicted = false;
    try {
      evicted = await api.evictPhantomDevice(ip);
    } catch (e) {
      log(`evict phantom ${ip} failed: ${formatError(e)}`);
    }
    if (evicted) return;
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
      // Retry — the device may be on a subnet that was just adopted.
      // Keep the scanned flag SET across the retry gap so a concurrent
      // discovery trigger (new ARP event, Nodes refresh) can't start a
      // duplicate scan chain for this IP; release it only once retries
      // are exhausted.
      if (attempt < MAX_SCAN_RETRIES) {
        setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
        return; // don't decrement pendingScans yet
      }
      markIpScanned(ip, /* clear */ true);
    }
  } catch (e) {
    log(`Port scan failed for ${ip}: ${formatError(e)}`);
    if (attempt < MAX_SCAN_RETRIES) {
      setTimeout(() => scanDevicePorts(ip, attempt + 1), RETRY_DELAY_MS);
      return;
    }
    markIpScanned(ip, /* clear */ true);
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

// Render deferral while a role menu is open: the list is rebuilt
// wholesale via innerHTML on every snapshot and on ping-dot flips,
// and that teardown would close an open <select> popup mid-pick.
// While one is open, renders queue behind a flag and flush on close.
let roleMenuOpen = false;
let renderPending = false;

function closeRoleMenu(): void {
  if (!roleMenuOpen) return;
  roleMenuOpen = false;
  if (renderPending) {
    renderPending = false;
    renderArpDeviceList();
  }
}

export function renderArpDeviceList(): void {
  if (roleMenuOpen) {
    renderPending = true;
    return;
  }
  const list = $("#device-list");

  // While disconnected, render nothing — the records may still be in
  // the backend's registry (preserved deliberately so a replug restores
  // them fast), but they're unreachable right now. Returning early
  // keeps the card empty without having to drop the state.
  if (!isInterfaceConnected()) {
    list.innerHTML = "";
    return;
  }

  // Shared visibility filter (panel-strict): drops the host's own IPs,
  // cached-only rows on unroutable subnets, own-MAC ghosts, and any
  // non-manual entry without an open port. The Add/Remove Nodes dialog
  // uses the same helper without the strict flag.
  const bySubnet = new Map<string, DeviceRecord[]>();
  for (const record of visibleDevices(deviceList.getDevices(), /* panelStrict */ true)) {
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
    return;
  }

  let html = "";
  let nodeIndex = 0;
  for (const [, records] of bySubnet) {
    if (records.length === 0) continue;

    html += `<div class="subnet-group">`;

    for (const r of records) {
      nodeIndex++;
      const name = r.alias || `Node ${nodeIndex}`;
      const ports = r.open_ports;

      const classes = ["device-item"];
      if (selectedDevice.get() === r.ip) classes.push("selected");

      // ICMP-result dot replaces the old verifying/offline/cached
      // badges — one signal, three colors. Missing entry = no probe
      // yet (gray); the pinger fills it in within seconds.
      const dot = renderReachabilityDot(r.ip);

      // Escape backend-sourced strings before they hit innerHTML — same
      // treatment device-cache.ts gives these fields. escapeHtml quotes
      // are attribute-safe, so the data-* attributes are covered too.
      const ipEsc = escapeHtml(r.ip);
      const portsEsc = escapeHtml(ports.join(", "));

      // The node's name doubles as the role dropdown face: a synthetic
      // first option carries the current display name (selected +
      // disabled + hidden so it shows on the closed face but never
      // duplicates CAM/PTU inside the popup), followed by the actions.
      html += `
        <div class="${classes.join(" ")}" data-ip="${ipEsc}">
          <div class="device-name-row">
            ${dot}
            <select class="node-role-select" data-role-ip="${ipEsc}" title="Assign role">
              <option selected disabled hidden>${escapeHtml(name)}</option>
              <option value="cam">CAM</option>
              <option value="ptu">PTU</option>
              <option value="clear">Clear</option>
            </select>
          </div>
          <div class="device-detail-row">
            <a class="device-ip" href="#" data-browse="${ipEsc}" title="Open in browser">${ipEsc}</a>
            <span class="device-ports">${portsEsc}</span>
          </div>
        </div>`;
    }

    html += `</div>`;
  }

  if (!html) {
    // Keep the list empty while either ARP discovery is still running
    // (no devices yet, but they may show up) OR a port scan is still
    // in flight (devices exist but haven't qualified for display yet).
    // Only show "No devices found." once both have settled.
    if (pendingScans > 0 || isDiscoveryActive()) return;
    list.innerHTML = '<p class="placeholder-text">No devices found.</p>';
    return;
  }

  list.innerHTML = html;

  // Wire up event handlers
  list.querySelectorAll<HTMLElement>(".device-item").forEach((item) => {
    item.addEventListener("click", (e) => {
      const target = e.target as Element;
      if (target.closest(".device-ip") || target.closest(".node-role-select")) return;
      list.querySelectorAll(".device-item").forEach((i) => i.classList.remove("selected"));
      item.classList.add("selected");
      const ip = item.dataset["ip"] ?? null;
      selectedDevice.set(ip);
      // Remember this pick as the session's CAM target (getActiveCamIp
      // reads it first). Deliberately kept out of state.config: Save
      // Settings builds its payload from there, so a click would leak
      // to disk on the next unrelated save. Persistence happens only
      // when a stream actually starts or the device is explicitly
      // assigned CAM — a node the user merely clicks but never streams
      // is not persisted across launches. PTU is alias-driven only,
      // with no click override — and the PTU-designated node itself is
      // never a camera target, so clicking its row keeps the selection
      // highlight but must not hijack the CAM pick away from the
      // assigned CAM (an RTSP start against the PTU wedges in a stall
      // loop).
      if (ip && deviceList.deviceByIp(ip)?.alias !== "PTU") {
        sessionCamIp.set(ip);
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
        // Backend command validates the IP and opens http://<ip> —
        // the webview no longer has a shell-open capability. Fall back
        // to window.open only in a non-Tauri (dev) context.
        if (window.__TAURI__) {
          api.openDeviceBrowser(ip).catch(() => {
            window.open(`http://${ip}`, "_blank");
          });
        } else {
          window.open(`http://${ip}`, "_blank");
        }
      });
    });

  list
    .querySelectorAll<HTMLSelectElement>(".node-role-select")
    .forEach((select) => {
      // Focus arms the render-deferral latch (an open OS popup would
      // be destroyed by an innerHTML rebuild); change/blur/Escape all
      // release it. The row click handler excludes the select, so
      // opening the menu never doubles as a node click.
      select.addEventListener("focus", () => {
        roleMenuOpen = true;
      });
      select.addEventListener("blur", () => closeRoleMenu());
      select.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeRoleMenu();
      });
      select.addEventListener("change", () => {
        const ip = select.dataset["roleIp"];
        const action = select.value;
        if (ip) void handleRoleSelection(select, ip, action);
        closeRoleMenu();
      });
    });
}

// ── Role dropdown handling ──────────────────────────────────────────

/** Apply a role-menu pick through the full transition matrix. Which
 *  roles are lost is derived from the pre-mutation snapshot rather
 *  than from the picked action, because one alias field holds both
 *  roles: assigning CAM onto the node holding PTU strips its PTU
 *  exactly like a PTU steal would, and every loss carries the same
 *  teardown regardless of which action caused it.
 *
 *  A node losing PTU gets a farewell halt (a delivered move whose
 *  release-stop is still queued would otherwise drive the unit
 *  unstoppably). Losing CAM on the node whose stream is playing drops
 *  the stream — compared against the runtime playback identity, not
 *  the persisted camera_ip, so a click-selected stream on an
 *  unrelated node is never touched. Losing CAM without it being
 *  reassigned also detaches the session pick and persisted camera IP;
 *  otherwise Start Stream would silently reconnect to the node the
 *  user just cleared through the fallback chain.
 *
 *  Teardown runs before the alias write on purpose: if the write then
 *  fails, a stopped stream and a halted PTU are the fail-safe
 *  leftovers — the role state is unchanged and the user re-picks. */
async function handleRoleSelection(
  select: HTMLSelectElement,
  ip: string,
  action: string
): Promise<void> {
  const current = deviceList.deviceByIp(ip)?.alias || "";
  const noOp =
    (action === "cam" && current === "CAM") ||
    (action === "ptu" && current === "PTU") ||
    (action === "clear" && current === "");
  if (noOp) {
    select.selectedIndex = 0;
    return;
  }

  const alias = action === "cam" ? "CAM" : action === "ptu" ? "PTU" : "";

  // Pre-mutation holders — the state the user acted on.
  const devices = deviceList.getDevices();
  const prevCamIp = devices.find((r) => r.alias === "CAM")?.ip ?? null;
  const prevPtuIp = devices.find((r) => r.alias === "PTU")?.ip ?? null;

  // A role is lost either by steal (another node takes it) or by the
  // holder itself being overwritten or cleared.
  const lostCamIp =
    prevCamIp && (alias === "CAM" ? prevCamIp !== ip : prevCamIp === ip)
      ? prevCamIp
      : null;
  const lostPtuIp =
    prevPtuIp && (alias === "PTU" ? prevPtuIp !== ip : prevPtuIp === ip)
      ? prevPtuIp
      : null;

  if (lostPtuIp) {
    // Purges the queue and pins the halt to the outgoing IP before
    // the alias moves, so nothing pending can reach the wrong unit.
    haltPtuUnit(lostPtuIp);
  }

  if (lostCamIp && lostCamIp === getActivePlaybackIp()) {
    await stopStreamNow(
      action === "clear"
        ? "Stream stopped — CAM cleared"
        : "Stream stopped — CAM reassigned"
    );
  }

  if (lostCamIp && action !== "cam") {
    // CAM removed without a new holder (Clear, or PTU overwriting the
    // CAM node): fully detach so getActiveCamIp resolves to nothing
    // instead of falling back to the node that just lost the role.
    if (sessionCamIp.get() === lostCamIp) {
      sessionCamIp.set(null);
    }
    if (state.config && state.config.stream.camera_ip === lostCamIp) {
      state.config.stream.camera_ip = "";
      api.updateStreamSettings(state.config.stream).catch((e: unknown) => {
        log(`clear persisted CAM failed for ${lostCamIp}: ${formatError(e)}`);
      });
    }
  }

  if (action === "ptu") {
    // The node just became the PTU, which is never a camera target —
    // independent of what it was called before. A click-streamed
    // unaliased node can be assigned PTU directly: drop a stream
    // playing it, and detach any session pick or persisted camera IP
    // a bare row click left aimed at it. (When the node also held CAM,
    // the blocks above already did all of this and these checks
    // no-op.)
    if (getActivePlaybackIp() === ip) {
      await stopStreamNow("Stream stopped — node is now the PTU");
    }
    if (sessionCamIp.get() === ip) {
      sessionCamIp.set(null);
    }
    if (state.config && state.config.stream.camera_ip === ip) {
      state.config.stream.camera_ip = "";
      api.updateStreamSettings(state.config.stream).catch((e: unknown) => {
        log(`clear persisted CAM failed for ${ip}: ${formatError(e)}`);
      });
    }
  }

  // Disabled while the write is in flight so a double-pick can't race
  // two writes; a failed write restores the current-name face.
  select.disabled = true;
  try {
    await api.setDeviceAlias(ip, alias);
    if (action === "cam") {
      // A CAM designation is deliberate — persist it to disk so
      // getActiveCamIp's config fallback picks it up next session
      // (the click-to-select path only sets this in memory), and
      // mirror into selectedDevice/sessionCamIp so subscribers (zoom
      // restore, panel highlight) react immediately and this newest
      // designation outranks any earlier node click.
      if (state.config) {
        state.config.stream.camera_ip = ip;
        api.updateStreamSettings(state.config.stream).catch((e: unknown) => {
          log(`persist CAM pick failed for ${ip}: ${formatError(e)}`);
        });
      }
      selectedDevice.set(ip);
      sessionCamIp.set(ip);
    }
  } catch (e) {
    showToast(`Failed to set role: ${formatError(e)}`, true);
    select.selectedIndex = 0;
    select.disabled = false;
  }
}
