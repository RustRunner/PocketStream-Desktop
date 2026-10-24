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
  refreshHostBindings,
  refreshNetworkEvent,
  sessionAdoptedSubnets,
} from "./network.ts";
import {
  clearScannedIps,
  hasRouteToSubnet,
  isIpScanned,
  markIpScanned,
  presenceLabel,
  visibleDevices,
} from "./device-state.ts";
import * as deviceList from "./device-list.ts";
import * as ipConflicts from "./ip-conflicts.ts";
import { getActivePlaybackTarget, stopStreamNow, updateRestreamUI } from "./streaming.ts";
import { haltPtuUnit } from "./ptz.ts";
import { selectedDevice, sessionCamTarget } from "./store.ts";
import { formatError } from "./errors.ts";
import type {
  AdoptionFailedPayload,
  ArpDevicePayload,
  CaptureState,
  NetworkMode,
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

/** Current capture state for the launch notice and diagnostics. */
export let captureState: CaptureState = {
  candidate_count: 0,
  active: false,
  adapter_name: null,
  outcome: null,
};

type CaptureSubscriber = (next: CaptureState) => void;
const captureSubscribers = new Set<CaptureSubscriber>();
let captureSubscription: Promise<() => void> | null = null;
let captureRevision = 0;
let captureFetch = 0;

function updateCaptureState(next: CaptureState): void {
  captureState = next;
  captureRevision++;
  const indicator = $("#capture-scope-status");
  // Capture scope remains available to the notice and logger; the Nodes card
  // shows the devices without a permanent explanation of the capture fallback.
  indicator.textContent = "";
  indicator.hidden = true;
  for (const subscriber of captureSubscribers) subscriber(next);
}

export function subscribeCaptureState(subscriber: CaptureSubscriber): () => void {
  captureSubscribers.add(subscriber);
  return () => { captureSubscribers.delete(subscriber); };
}

/** Subscribe before every fetch; an event or newer query wins a stale reply. */
export async function refreshCaptureState(): Promise<CaptureState> {
  captureSubscription ??= api.onEvent<CaptureState>("capture-active", updateCaptureState)
    .catch((error: unknown) => { captureSubscription = null; throw error; });
  await captureSubscription;
  const request = ++captureFetch;
  const revision = captureRevision;
  const current = await api.getCaptureState();
  if (current && request === captureFetch && revision === captureRevision) updateCaptureState(current);
  return captureState;
}

export type ListeningNoticeTrigger = "launch" | "mode_from_manual" | "mode_from_dhcp"
  | "refresh" | "reconnect" | "watchdog" | null;

/** Pure eligibility rule; only launch and a real change to Auto may arm it. */
export function listeningNoticeReady(
  mode: NetworkMode | undefined, discoveryAvailable: boolean,
  trigger: ListeningNoticeTrigger, capture: CaptureState,
): boolean {
  return mode === "static_auto" && (trigger === "launch" || (discoveryAvailable
    && capture.active && capture.outcome !== null && capture.adapter_name !== null
    && (trigger === "mode_from_manual" || trigger === "mode_from_dhcp")));
}

let pendingScans = 0;

/** The dot and text use the same backend presence status. ICMP and
 *  open ports never change either indicator. */
function renderPresenceDot(record: DeviceRecord): string {
  const color = record.status === "live" ? "dot-green"
    : record.status === "verifying" || record.status === "cached_only" ? "dot-pending"
    : "dot-red";
  return `<span class="device-dot ${color}" title="${escapeHtml(presenceLabel(record))}"></span>`;
}

// ── Debounced scan trigger ─────────────────────────────────────────
// Collect all ARP discoveries and subnet adoptions, then scan once
// after activity settles. This prevents partial renders and flicker.

const SETTLE_MS = 6000; // wait 6s after last ARP/adopt event
let settleTimer: ReturnType<typeof setTimeout> | null = null;

/** Reset the settle timer — called on every new ARP device or adoption. */
function debounceScan(): void {
  if (state.config?.network_mode === "static_manual") return;
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = setTimeout(() => {
    settleTimer = null;
    scanAllRoutableDevices();
  }, SETTLE_MS);
}

/** Scan every device the backend currently knows about that's on a
 *  routable subnet and we haven't scanned this session. */
function scanAllRoutableDevices(): void {
  if (state.config?.network_mode === "static_manual") return;
  const toScan: DeviceRecord[] = [];
  for (const record of deviceList.getDevices()) {
    if (!isIpScanned(record.ip) && hasRouteToSubnet(record.subnet)) {
      toScan.push(record);
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
  for (const record of toScan) {
    scanDevicePorts(record.mac, record.ip);
  }
}

// ── Discovery status ─────────────────────────────────────────────────
//
// Phase machine with three states driving the Nodes-card spinner:
//   "discovering" → Discovery + dots  (ARP + subnet adoption in flight)
//   "scanning"    → Discovery + dots  (TCP probes in flight)
//   "idle"        → no spinner         (everything settled)
//
// The spinner is a *startup progress indicator*, not a live activity
// readout. Once the initial flow completes (first idle after adoption
// + scanning), background ARP traffic must not resurrect it — otherwise
// the Nodes header would flicker back to "Discovery..." indefinitely
// on any busy network. `initialFlowComplete` enforces that by coercing
// any post-startup "discovering" request into "idle".
//
// Port-scan feedback for genuinely new devices joining the network
// later is still allowed (phase "scanning" is not locked), because
// that's a bounded, useful signal.

type DiscoveryPhase = "discovering" | "scanning" | "idle";

let discoveryPhase: DiscoveryPhase = "idle";
let initialFlowComplete = false;

// The initial port scans land well before the backend finishes its
// startup hunt (DHCP gate, cache-probe pass, first-sighting probes,
// dwell), so dropping to idle the moment pendingScans hits zero makes
// the card flash "done" and then visibly restart when the adopted
// subnets arrive. Instead, the first flow holds "discovering" through
// this grace window after its scans complete; adoption events landing
// inside it continue the same visual flow. Sized to cover the typical
// hunt (probe budgets are seconds; the cache pass's 90 s ceiling is a
// pathology we accept a break for).
const INITIAL_DISCOVERY_GRACE_MS = 60_000;
let initialFlowStartedAt = 0;
let graceTimer: ReturnType<typeof setTimeout> | null = null;

function initialGraceRemaining(): number {
  if (state.config?.network_mode === "static_manual" || initialFlowComplete || initialFlowStartedAt === 0) return 0;
  return initialFlowStartedAt + INITIAL_DISCOVERY_GRACE_MS - Date.now();
}

function clearGraceTimer(): void {
  if (graceTimer) clearTimeout(graceTimer);
  graceTimer = null;
}

/** Arm the hold-release for the initial flow. When it fires quiet —
 *  no scans in flight, no settle timer pending — the startup flow is
 *  genuinely over and the spinner may complete. A scan cycle running
 *  at expiry re-evaluates on its own completion instead (the grace is
 *  spent by then, so it falls through to idle normally). */
function armGraceTimer(delay: number): void {
  clearGraceTimer();
  graceTimer = setTimeout(() => {
    graceTimer = null;
    if (pendingScans > 0 || settleTimer !== null) return;
    if (discoveryPhase === "discovering") {
      initialFlowComplete = true;
      setDiscoveryPhase("idle");
    }
  }, delay);
}

function applyDiscoveryPhaseToDOM(): void {
  const container = $("#discovery-status");
  if (!container) return;
  // The manual Refresh request owns "spinning" independently of this flow.
  $("#btn-refresh-nodes").classList.toggle("discovery-active", discoveryPhase !== "idle");
  if (discoveryPhase === "idle") {
    container.classList.add("hidden");
    return;
  }
  container.classList.remove("hidden");
}

function setDiscoveryPhase(phase: DiscoveryPhase): void {
  // Late ARP, scan and reconnect callbacks cannot revive Manual discovery.
  if (state.config?.network_mode === "static_manual") phase = "idle";
  if (phase === "discovering" && initialFlowComplete) {
    phase = "idle";
  }
  // First activity of a fresh flow stamps the grace clock — the hold
  // window is anchored to when discovery actually started, not to when
  // the first scan batch finished.
  if (phase !== "idle" && !initialFlowComplete && initialFlowStartedAt === 0) {
    initialFlowStartedAt = Date.now();
  }
  const wasScanning = discoveryPhase === "scanning";
  discoveryPhase = phase;
  // Engage the one-shot lock only on a *real* completion — scanning →
  // idle via scanDevicePorts. A direct discovering → idle (hideDiscoveryStatus
  // on link drop, explicit reset paths) is not completion and must not
  // lock future "Discovery..." transitions.
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

/** Retire pending discovery progress on link-down or entering Manual. */
export function hideDiscoveryStatus(): void {
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = null;
  clearGraceTimer();
  setDiscoveryPhase("idle");
}

export function resetDiscoveryStatus(): void {
  clearScannedIps();
  if (settleTimer) clearTimeout(settleTimer);
  settleTimer = null;
  clearGraceTimer();
  // Clear the one-shot lock so a reconnect / user-initiated rescan can
  // legitimately show "Discovery..." again at the start of the fresh
  // flow. Must happen BEFORE setDiscoveryPhase, or the coercion would
  // bounce "discovering" → "idle". The grace clock restarts with the
  // fresh flow for the same reason.
  initialFlowComplete = false;
  initialFlowStartedAt = 0;
  setDiscoveryPhase("discovering");
  // Reconnect path: backend preserves device records across disconnect for
  // fast UI recovery, so the backend often doesn't re-fire subnet-adopted
  // or arp-device-discovered events — which means debounceScan never
  // triggers, scanAllRoutableDevices never runs, and the spinner would
  // stay on "Discovery..." indefinitely. Kick a scan of the already-
  // known devices immediately; if the deviceList is empty (cold start),
  // the function returns early and we correctly stay in "discovering"
  // waiting for fresh ARP events.
  scanAllRoutableDevices();
}

// ── ARP event listeners ─────────────────────────────────────────────

export function setupArpListeners(): void {
  ipConflicts.subscribe(renderArpDeviceList);
  void ipConflicts.start().catch((e) => log(`Failed to check PC address conflicts: ${formatError(e)}`));
  void refreshCaptureState().catch((e) => log(`Failed to load capture state: ${formatError(e)}`));

  // Re-render whenever the backend pushes a new snapshot.
  let scanReadyKeys = new Set<string>();
  let liveSubnets = new Set<string>();
  deviceList.subscribe((snapshot) => {
    const nextLive = new Set(snapshot.filter((r) => r.status === "live").map((r) => r.subnet));
    for (const subnet of sessionAdoptedSubnets) {
      if (liveSubnets.has(subnet) && !nextLive.has(subnet)) sessionAdoptedSubnets.delete(subnet);
    }
    liveSubnets = nextLive;
    renderSubnetList();
    renderArpDeviceList();
    const ready = snapshot.filter((r) => r.status === "live" && hasRouteToSubnet(r.subnet));
    const newPeer = ready.some((r) => !scanReadyKeys.has(r.mac) && !isIpScanned(r.ip));
    scanReadyKeys = new Set(ready.map((r) => r.mac));
    if (newPeer && state.config?.network_mode !== "static_manual") debounceScan();
  });

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
      // already in the scanning phase for in-flight scans. That keeps
      // the UX linear (Discovery → Scan → idle) instead of flickering
      // back to Discovery every time a late ARP arrives during a scan.
      if (discoveryPhase === "idle") {
        setDiscoveryPhase("discovering");
      }
      debounceScan();
    }
  });

  // Quiet-network watchdog signals. Diagnostic only — the backend never
  // flips discovery availability on silence, so this is a heads-up that a
  // provoked ping sweep drew no ARP frames (dead subnet, or capture not
  // delivering). Keep this in diagnostics and the existing panel state.
  api.onEvent<DiscoveryDegradedPayload>("discovery-degraded", (data) => {
    const drops =
      data.missed_packets > 0 ? ` (ring drops: ${data.missed_packets})` : "";
    log(`Discovery degraded: ${data.reason}${drops}`);
    // If the only thing keeping the startup spinner alive is the grace
    // hold, a dead capture channel means there's nothing left to wait
    // for — unwind just the hold; every other spinner state keeps its
    // existing behavior.
    if (graceTimer) {
      clearGraceTimer();
      if (pendingScans <= 0 && settleTimer === null) {
        initialFlowComplete = true;
        setDiscoveryPhase("idle");
      }
    }
  });

  api.onEvent<DiscoveryRecoveredPayload>("discovery-recovered", () => {
    log("Discovery recovered — devices responding again");
  });

  api.onEvent<SubnetAdoptedPayload & import("./types.ts").AdoptedMetaView & { restored: boolean }>("subnet-adopted", (data) => {
    log(`Subnet adopted: ${data.subnet} -> ${data.adopted_ip}`);
    adoptedSubnets.set(data.subnet, data.adopted_ip);
    adoptionMeta.set(data.subnet, data);
    if (data.restored === false && state.activeInterface?.is_up && data.adapter_mac?.replaceAll("-", ":").toLowerCase() === state.activeInterface.mac.replaceAll("-", ":").toLowerCase()) sessionAdoptedSubnets.add(data.subnet);
    renderSubnetList();
    // Flash only a fresh adoption; restored rows remain plain.
    const row = $(
      `#subnet-list .subnet-row[data-subnet="${cssAttrValue(data.subnet)}"]`
    );
    if (row && data.restored === false) {
      row.classList.add("subnet-row-just-adopted");
      setTimeout(() => row.classList.remove("subnet-row-just-adopted"), 2500);
    }
    // Reset the settle timer — netsh needs time to activate the IP
    debounceScan();
    refreshNetworkEvent();
  });

  api.onEvent<AdoptionFailedPayload>("adoption-failed", (data) => {
    // Diagnostic only — the adopt loop retries with backoff on its own.
    log(`Auto-adopt failed for ${data.subnet}: ${data.error}`);
  });

  // Removal does not erase backend tombstones; refresh their final status.
  api.onEvent<SubnetRemovedPayload>("subnet-removed", (data) => {
    log(`Subnet removed (${data.reason}): ${data.subnet} (${data.adopted_ip})`);
    adoptedSubnets.delete(data.subnet);
    sessionAdoptedSubnets.delete(data.subnet);
    adoptionMeta.delete(data.subnet);
    renderSubnetList();
    refreshNetworkEvent();
  });

  // Initial hydration / scan kickoff is orchestrated from main.js
  // (deviceList.start() then loadExistingArpState) so the order is
  // explicit at the call site.
}

/** Pull adopted subnets, then scan whichever routable records the
 *  backend has already given us (cached entries from cold start, or
 *  ARP discoveries we missed before subscribing). */
export async function loadExistingArpState(): Promise<void> {
  if (state.config?.network_mode === "static_manual") {
    setDiscoveryPhase("idle");
    return;
  }
  if (!isInterfaceConnected()) {
    setDiscoveryPhase("idle");
    return;
  }

  try {
    await refreshHostBindings();

    // Presence is owned by the backend. Scan only for capabilities.

    if (deviceList.getDevices().length > 0) {
      scanAllRoutableDevices();
    } else {
      setDiscoveryPhase("discovering");
    }
  } catch (e) {
    log(`Failed to load ARP state: ${formatError(e)}`);
  }
}

// ── Port scanning ───────────────────────────────────────────────────

const MAX_SCAN_RETRIES = 2;
const RETRY_DELAY_MS = 4000;

async function scanDevicePorts(mac: string, ip: string, attempt = 0): Promise<void> {
  const isManual = () => state.config?.network_mode === "static_manual";
  if (isManual()) {
    if (attempt > 0) pendingScans--;
    return;
  }
  if (attempt === 0 && isIpScanned(ip)) return;
  markIpScanned(ip);
  if (attempt === 0) pendingScans++;

  try {
    const results = await api.scanNetwork(`${ip}/32`);
    if (isManual()) {
      pendingScans--;
      return;
    }
    let found = false;
    if (results) {
      for (const r of results) {
        if (r.reachable && r.open_ports.length > 0) {
          // The backend publishes capabilities with the scan's original
          // adapter epoch and identity before replying; no renderer echo.
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
        setTimeout(() => scanDevicePorts(mac, ip, attempt + 1), RETRY_DELAY_MS);
        return; // don't decrement pendingScans yet
      }
      markIpScanned(ip, /* clear */ true);
    }
  } catch (e) {
    log(`Port scan failed for ${ip}: ${formatError(e)}`);
    if (attempt < MAX_SCAN_RETRIES && !isManual()) {
      setTimeout(() => scanDevicePorts(mac, ip, attempt + 1), RETRY_DELAY_MS);
      return;
    }
    markIpScanned(ip, /* clear */ true);
  }

  pendingScans--;
  if (pendingScans <= 0) {
    // All port scans done. If the settle timer is still armed from a
    // late ARP / adoption event, drop back to "discovering" until it
    // fires. During the initial flow, an otherwise-quiet completion
    // holds "discovering" for the remaining grace instead of flashing
    // idle — the backend is typically still hunting foreign subnets,
    // and their adoption should read as one continuous flow. Only a
    // quiet grace expiry (or a post-grace completion like this one)
    // ends the startup spinner.
    const grace = initialGraceRemaining();
    if (settleTimer !== null) {
      setDiscoveryPhase("discovering");
    } else if (grace > 0) {
      setDiscoveryPhase("discovering");
      armGraceTimer(grace);
    } else {
      setDiscoveryPhase("idle");
    }
  }
}

// ── Device list rendering ───────────────────────────────────────────

// Render deferral while a role menu is open: the list is rebuilt
// wholesale via innerHTML on every snapshot,
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

  // Keep the same history as the manager dialog, including disconnected
  // and zero-port records. The backend owns inactive topology reasons.
  const bySubnet = new Map<string, DeviceRecord[]>();
  for (const record of visibleDevices(deviceList.getDevices())) {
    const bucket = bySubnet.get(record.subnet);
    if (bucket) {
      bucket.push(record);
    } else {
      bySubnet.set(record.subnet, [record]);
    }
  }

  if (bySubnet.size === 0) {
    // An empty backend snapshot retires old rows even with a scan pending.
    // The header's Discovery spinner carries the "still working"
    // signal — leave the list empty while it's visible. Only show
    // the "No devices found" placeholder once everything's settled.
    list.innerHTML = pendingScans > 0 || isDiscoveryActive()
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
      if (selectedDevice.get()?.key === r.mac) classes.push("selected");

      const dot = renderPresenceDot(r);

      // Escape backend-sourced strings before they hit innerHTML — same
      // treatment device-cache.ts gives these fields. escapeHtml quotes
      // are attribute-safe, so the data-* attributes are covered too.
      const ipEsc = escapeHtml(r.ip);
      const portsEsc = escapeHtml(ports.join(", "));
      const conflict = ipConflicts.forIp(r.ip);

      // The node's name doubles as the role dropdown face: a synthetic
      // first option carries the current display name (selected +
      // disabled + hidden so it shows on the closed face but never
      // duplicates CAM/PTU inside the popup), followed by the actions.
      html += `
        <div class="${classes.join(" ")}" data-key="${escapeHtml(r.mac)}" data-ip="${ipEsc}">
          <div class="device-name-row">
            ${dot}
            <select class="node-role-select" data-role-key="${escapeHtml(r.mac)}" title="Assign role">
              <option selected disabled hidden>${escapeHtml(name)}</option>
              <option value="cam">CAM</option>
              <option value="ptu">PTU</option>
              <option value="clear">Clear</option>
            </select>
          </div>
          <div class="device-detail-row">
            <a class="device-ip${conflict ? " conflicting" : ""}" href="#" data-browse="${ipEsc}" title="${escapeHtml(conflict?.message ?? "Open in browser")}">${ipEsc}</a>
            <span class="device-ports">${portsEsc}</span>
          </div>
          ${conflict ? `<div class="device-ip-conflict" title="${escapeHtml(conflict.message)}">${conflict.retainedAdapters?.length ? "IP still reserved by PC" : "IP conflict with PC"}: ${escapeHtml(conflict.adapters.join(", "))}</div>` : ""}
        </div>`;
    }

    html += `</div>`;
  }

  if (!html) {
    // Keep the list empty while either ARP discovery is still running
    // (no devices yet, but they may show up) OR a port scan is still
    // in flight and no records have arrived yet.
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
      const record = deviceList.deviceByKey(item.dataset["key"]);
      if (!record) return;
      const targetChoice = deviceList.targetFor(record);
      selectedDevice.set(targetChoice);
      // Highlighting a row never assigns its role. Only a CAM-designated
      // record may become the session's video target.
      if (record.alias === "CAM") {
        sessionCamTarget.set(targetChoice);
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
        const item = link.closest<HTMLElement>(".device-item");
        const record = deviceList.deviceByKey(item?.dataset["key"]);
        if (!record) return;
        // The badge is a cached hint. Only the backend's fresh ownership and
        // identity/route checks decide whether to open the real device URL.
        if (window.__TAURI__) {
          api.openDeviceBrowser(ip, deviceList.targetFor(record)).catch((error) => {
            showToast(`Unable to open device page: ${formatError(error)}`, true);
          }).finally(() => {
            void ipConflicts.refresh().catch((error) => {
              log(`Failed to refresh PC address conflicts: ${formatError(error)}`);
            });
          });
        } else {
          const conflict = ipConflicts.forIp(ip);
          if (conflict) { showToast(conflict.message, true); return; }
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
        const key = select.dataset["roleKey"];
        const action = select.value;
        if (key) void handleRoleSelection(select, key, action);
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
 *  the stream — compared against the runtime playback identity, so
 *  endpoint changes cannot stop a different record. Losing CAM without it being
 *  reassigned also detaches the session pick and persisted camera IP;
 *  otherwise Start Stream would silently reconnect to the node the
 *  user just cleared through the fallback chain.
 *
 *  Teardown runs before the alias write on purpose: if the write then
 *  fails, a stopped stream and a halted PTU are the fail-safe
 *  leftovers — the role state is unchanged and the user re-picks. */
async function handleRoleSelection(
  select: HTMLSelectElement,
  key: string,
  action: string
): Promise<void> {
  const record = deviceList.deviceByKey(key);
  if (!record) return;
  const target = deviceList.targetFor(record);
  const ip = record.ip;
  const current = record.alias || "";
  // CAM is also explicit playback intent, even when its alias is unchanged.
  const noOp =
    (action === "ptu" && current === "PTU" && deviceList.getDevices().filter((r) => r.alias === "PTU").length === 1) ||
    (action === "clear" && current === "");
  if (noOp) {
    select.selectedIndex = 0;
    return;
  }

  const alias = action === "cam" ? "CAM" : action === "ptu" ? "PTU" : "";

  const devices = deviceList.getDevices();
  const losesRole = (recordKey: string, role: string): boolean =>
    recordKey === key ? alias !== role : alias === role;
  const lostCams = devices.filter((r) => r.alias === "CAM" && losesRole(r.mac, "CAM"));
  const lostPtus = devices.filter((r) => r.alias === "PTU" && losesRole(r.mac, "PTU"));
  for (const outgoing of lostPtus) haltPtuUnit(outgoing.ip, deviceList.targetFor(outgoing));
  if (lostCams.length > 0 && state.isRestreamDesired && state.config?.stream.protocol === "rtsp") {
    try {
      await api.stopRestreamServer();
      state.isRestreamDesired = false;
      updateRestreamUI(null);
    } catch (e) {
      select.selectedIndex = 0;
      showToast(`Failed to stop RTSP server; CAM role unchanged: ${formatError(e)}`, true);
      return;
    }
  }

  function detachCamera(recordKey: string): void {
    if (sessionCamTarget.get()?.key === recordKey) sessionCamTarget.set(null);
    const stream = state.config?.stream;
    const configuredKey = stream?.camera_mac ?? (stream?.camera_ip ? `manual:${stream.camera_ip}` : null);
    if (stream && configuredKey?.toLowerCase() === recordKey.toLowerCase()) {
      stream.camera_ip = "";
      stream.camera_mac = null;
      api.updateStreamSettings(stream).catch((e: unknown) => {
        log(`clear persisted CAM failed for ${recordKey}: ${formatError(e)}`);
      });
    }
  }
  for (const outgoing of lostCams) {
    if (getActivePlaybackTarget()?.key === outgoing.mac) {
      await stopStreamNow(action === "clear" ? "Stream stopped — CAM cleared" : "Stream stopped — CAM reassigned");
    }
    if (action !== "cam") detachCamera(outgoing.mac);
  }
  if (action === "ptu") {
    if (getActivePlaybackTarget()?.key === key) await stopStreamNow("Stream stopped — node is now the PTU");
    detachCamera(key);
  }

  // Disabled while the write is in flight so a double-pick can't race
  // two writes. The backend returns its post-write registry snapshot,
  // so this succeeds even when an event is coalesced or the operation
  // is already a no-op in newer backend state.
  select.disabled = true;
  try {
    await deviceList.setAlias(key, alias);
    if (action === "cam") {
      // A CAM designation is deliberate — persist it to disk so
      // getActiveCamIp's config fallback picks it up next session
      // (clicking an existing CAM only sets this in memory), and
      // mirror into selectedDevice/sessionCamTarget so subscribers (zoom
      // restore, panel highlight) react immediately and this newest
      // designation outranks any earlier node click.
      if (state.config) {
        state.config.stream.camera_ip = ip;
        state.config.stream.camera_mac = target.expectedMac;
        api.updateStreamSettings(state.config.stream).catch((e: unknown) => {
          log(`persist CAM pick failed for ${ip}: ${formatError(e)}`);
        });
      }
      selectedDevice.set(target);
      sessionCamTarget.set(target);
    }
  } catch (e) {
    showToast(`Failed to set role: ${formatError(e)}`, true);
  } finally {
    // A successful authoritative snapshot normally rerenders and detaches
    // this element. If rendering failed, or the backend call rejected,
    // never leave the still-visible native control permanently disabled.
    if (select.isConnected) {
      select.selectedIndex = 0;
      select.disabled = false;
    }
  }
}
