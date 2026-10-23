/**
 * PocketStream Desktop — Network interfaces, subnets, IP config
 */

import * as api from "./tauri-api.ts";
import {
  $,
  $$,
  state,
  adoptedSubnets,
  adoptionMeta,
  showToast,
  log,
  escapeHtml,
} from "./state.ts";
import { resetDiscoveryStatus, hideDiscoveryStatus, renderArpDeviceList } from "./devices.js";
import { handleHardDisconnect, handleReconnect, showModalWithVideo } from "./streaming.js";
import { sessionCamTarget, type DeviceTarget } from "./store.ts";
import { formatError } from "./errors.ts";
import type {
  AdapterSelection,
  AddressReply,
  AdoptionLifecyclePayload,
  InterfaceInfo,
  NetworkMode,
} from "./types.ts";
import * as deviceList from "./device-list.ts";

// Reference $$ once so the import isn't dropped — used elsewhere via the
// state.ts re-export, but TS's verbatimModuleSyntax keeps unused value
// imports as runtime imports. Touching the binding here keeps imports tidy.
void $$;

// ── Host network mode (DHCP / Static-Auto / Static-Manual) ──────────
// Mirrors the backend's NetworkMode. Drives the mode badge in the
// Host card and the radio state in the IP Config dialog. null =
// unknown / not yet probed.
let hostMode: NetworkMode | null = null;
let adapterSelection: AdapterSelection | null = null;
let adapterSelectionRevision = 0;
let interfaceRefresh = 0;
let selectingAdapter = false;
let onDiscoveryReconnect = () => {};
/** Presentation only, empty at launch and never persisted. */
export const sessionAdoptedSubnets = new Set<string>();
let bindingRefresh = 0;

// Ordinary callers share one fetch and, while it runs, one trailing fetch.
// Each caller settles with its current cycle; it does not wait for a later event.
let refreshFlight: Promise<void> | null = null;
let refreshTrailing = false;
let eventRefreshQueued = false;
let verifiedAddressView = false;
let addressBusy: { retired: boolean } | null = null;
const disabledControls = new Map<HTMLButtonElement | HTMLInputElement | HTMLSelectElement, boolean>();

export function refreshHostBindings(): Promise<void> { return refreshInterfaces(); }

/** Collapse a callback burst before entering the shared fetch path. */
export function refreshNetworkEvent(): void {
  if (addressBusy) { refreshTrailing = true; return; }
  if (eventRefreshQueued) return;
  eventRefreshQueued = true;
  void Promise.resolve().then(() => {
    eventRefreshQueued = false;
    return refreshInterfaces();
  });
}


function renderNetwork(): void {
  renderSubnetList();
  if ($<HTMLDialogElement>("#ip-config-dialog").open) {
    renderAdapterChoices();
    populateDialogFields();
  }
  lockAddressControls();
}

function applySelection(selection: AdapterSelection): void {
  rememberAdapterSelection(selection);
  dialogInterfaces = (selection.candidates ?? []).filter(isWiredCandidate);
  const eth = selection.interface_index !== null ? selection.adapter : null;
  state.activeInterface = eth;
  if (!eth?.is_up) sessionAdoptedSubnets.clear();
  renderInterfaceName();
  if (eth && !isDownEvent(eth)) lastAdapterWarningAt = 0;
  else warnNoEthernet();
}

function renderInterfaceName(): void {
  const eth = state.activeInterface;
  $("#iface-name").textContent = eth
    ? (eth.display_name || eth.name) + (isDownEvent(eth) ? " (Disconnected)" : "")
    : unavailableAdapterLabel();
}

function rememberAdapterSelection(next: AdapterSelection): void {
  if (adapterSelection && (adapterSelection.selected_mac !== next.selected_mac ||
      adapterSelection.interface_index !== next.interface_index)) {
    ++adapterSelectionRevision;
    if (addressBusy) addressBusy.retired = true;
    sessionAdoptedSubnets.clear();
    if (pendingDownTimer) clearTimeout(pendingDownTimer);
    pendingDownTimer = null;
    pendingDownIface = null;
    if (state.activeInterface) handleHardDisconnect("Ethernet adapter changed or unavailable");
    state.activeInterface = null;
  }
  adapterSelection = next;
  if (state.config) state.config.selected_adapter_mac = next.selected_mac;
}

function unavailableAdapterLabel(): string {
  if (adapterSelection?.selection_required) return "Select Ethernet adapter in Configure";
  return adapterSelection?.selected_mac
    ? `Selected adapter ${adapterSelection.selected_mac} unavailable`
    : "None found";
}

/** Sync hostMode from state.config (no IPC). Cheap and synchronous —
 *  callable as soon as loadConfig() resolves, which lets the Host card
 *  paint the mode badge before the slower interface enumeration lands. */
export function syncHostModeFromConfig(): void {
  hostMode = state.config?.network_mode ?? null;
  renderModeBadge();
}

// ── Interface discovery ─────────────────────────────────────────────

/**
 * Mirrors the backend's wired-camera-port authority, minus is_up:
 * Disconnected adapters stay listed so the Reset affordance keeps
 * working. A VPN or OS-virtual adapter that claims Ethernet media is
 * never offered for selection — the backend rejects it anyway.
 */
function isWiredCandidate(i: InterfaceInfo): boolean {
  return i.is_ethernet && !i.is_vpn && !i.is_virtual;
}

export function refreshInterfaces(): Promise<void> {
  if (addressBusy) { refreshTrailing = true; return Promise.resolve(); }
  if (refreshFlight) { refreshTrailing = true; return refreshFlight; }
  const request = ++interfaceRefresh, bindings = ++bindingRefresh;
  refreshTrailing = false;
  if (!state.activeInterface && !adapterSelection) $("#iface-name").textContent = "Checking Ethernet…";
  refreshFlight = (async () => {
    try {
      const [selection, snapshot, mode] = await Promise.all([
        api.getAdapterSelection(), api.getAdoptionState(), api.getNetworkMode(),
      ]);
      if (request !== interfaceRefresh || bindings !== bindingRefresh || !selection) return;
      if (snapshot) {
        adoptedSubnets.clear(); adoptionMeta.clear();
        for (const [subnet, ip] of Object.entries(snapshot.adopted_subnets)) adoptedSubnets.set(subnet, ip);
        for (const [subnet, meta] of Object.entries(snapshot.meta)) adoptionMeta.set(subnet, meta);
        for (const subnet of sessionAdoptedSubnets) {
          const meta = adoptionMeta.get(subnet);
          if (!meta?.applied || meta.desired !== "present") sessionAdoptedSubnets.delete(subnet);
        }
      }
      hostMode = mode;
      verifiedAddressView = false;
      applySelection(selection);
      renderNetwork();
    } catch (e) {
      if (request !== interfaceRefresh || bindings !== bindingRefresh) return;
      log(`Failed to list interfaces: ${formatError(e)}`);
      // A failed refresh is not evidence of adapter removal. Keep the last
      // native view, including a disconnected adapter and its observed IPs.
      if (state.activeInterface) renderInterfaceName();
      else if (adapterSelection) applySelection(adapterSelection);
      else $("#iface-name").textContent = "Checking Ethernet…";
      renderNetwork();
      warnNoEthernet();
    }
  })().finally(() => {
    refreshFlight = null;
    if (refreshTrailing && !addressBusy) void refreshInterfaces();
  });
  return refreshFlight;
}

// ── No-Ethernet diagnostic throttling ──────────────────────────────
// refreshInterfaces can fire rapidly (startup + manual refresh + watcher
// events arriving during a disconnect). The Host card and launch modal
// cover the visible state; keep only a throttled diagnostic here.

const NO_ETHERNET_COOLDOWN_MS = 15000;
let lastAdapterWarningAt = 0;

export function warnNoEthernet(): void {
  const now = Date.now();
  if (now - lastAdapterWarningAt < NO_ETHERNET_COOLDOWN_MS) return;
  lastAdapterWarningAt = now;
  log(
    adapterSelection?.selection_required
      ? "Choose the camera's Ethernet adapter in Configure"
      : adapterSelection?.selected_mac && (!adapterSelection.adapter || adapterSelection.interface_index === null)
        ? unavailableAdapterLabel()
        : "No Ethernet detected — check Ethernet connection and/or reset Ethernet adapter"
  );
}

/** True if `address` is in the APIPA range (169.254.0.0/16).
 *  Exclude APIPA from usable host choices; saved host addresses remain
 *  stored. All APIPA Nodes, including historical rows, are hidden by
 *  device-state.ts. APIPA cameras require vendor-side configuration;
 *  discovery never adopts their subnet or attempts an APIPA rescue. */
export function isApipa(address: string): boolean {
  return address.startsWith("169.254.");
}

/** True when an Ethernet adapter is present, link is up, AND it has at
 *  least one non-APIPA IPv4 address. */
export function isInterfaceConnected(): boolean {
  if (!state.activeInterface) return false;
  if (!state.activeInterface.is_up) return false;
  return state.activeInterface.ips.some((ip) => !isApipa(ip.address));
}

// ── Interface status watcher ────────────────────────────────────────
// Backend's NotifyIpInterfaceChange watcher emits `interface-status-
// changed` whenever Windows reports an IP/link transition. The
// payload reflects whatever the OS sees at the 300ms-debounced moment
// — including transient sub-second blips that the link self-heals
// from.

// Stable-down debounce. A "down" event (adapter sentinel, link down,
// or APIPA-only) is held for STABLE_DOWN_MS before the teardown UI
// fires; if an "up" event arrives within that window the down is
// discarded and the user sees nothing. Catches the ASIX/USB-Ethernet
// blip case where a real outage of <2s would otherwise produce a
// Stream Lost / Stream Resumed cycle for no useful reason.
//
// GStreamer's bus error path is not gated by this — if the underlying
// TCP socket actually died during the blip, rtspsrc surfaces a bus
// error and showStreamLost still fires through streaming.ts. The
// debounce only suppresses network-watcher-driven teardowns; pipeline-
// driven teardowns are independent.
const STABLE_DOWN_MS = 2000;
let pendingDownTimer: ReturnType<typeof setTimeout> | null = null;
let pendingDownIface: InterfaceInfo | null = null;

function isDownEvent(iface: InterfaceInfo): boolean {
  if (!iface.name) return true; // sentinel: no adapter at all
  if (!iface.is_up) return true;
  return !iface.ips.some((ip) => !isApipa(ip.address));
}

export function setupInterfaceWatcher(onReconnect: () => void = () => {}): void {
  onDiscoveryReconnect = onReconnect;
  api.onEvent<AdapterSelection>("adapter-selection-changed", (selection) => {
    // The selection query may emit this same snapshot itself. Retire older
    // reads only for an actual change, so opening Configure can finish.
    if (JSON.stringify(selection) === JSON.stringify(adapterSelection)) return;
    ++interfaceRefresh;
    if (verifiedAddressView && !addressBusy) { refreshNetworkEvent(); return; }
    rememberAdapterSelection(selection);
  });
  api.onEvent<InterfaceInfo>("interface-status-changed", (iface) => {
    const expectedMac = adapterSelection?.selected_mac?.replaceAll("-", ":").toLowerCase();
    if (iface.mac.replaceAll("-", ":").toLowerCase() !== (expectedMac ?? "")) return;
    if (addressBusy) { refreshTrailing = true; return; }
    // A query can cause an unchanged status event. Fetching again for that
    // event feeds the same query back into itself, especially with link down.
    if (JSON.stringify(iface) === JSON.stringify(state.activeInterface)) return;
    ++interfaceRefresh;
    // A queued callback describes an earlier observation. After a reply, use
    // a fresh shared read rather than repainting its payload over verified IPs.
    if (verifiedAddressView) { refreshNetworkEvent(); return; }
    if (isDownEvent(iface)) sessionAdoptedSubnets.clear();
    refreshNetworkEvent();
    // Capture the prior connection state BEFORE any state mutation so
    // applyUpEvent can decide whether this is a true reconnect.
    // isInterfaceConnected() is our single source of truth — it also
    // treats APIPA-only state as "down" so the reconnect branch will
    // fire when a real IP is actually bound.
    const wasDown = !isInterfaceConnected();

    if (isDownEvent(iface)) {
      // Defer the teardown. Repeat downs (link still bouncing) just
      // keep the timer running with the most recent iface payload.
      pendingDownIface = iface;
      if (!pendingDownTimer) {
        log(`Network: down event received, debouncing ${STABLE_DOWN_MS}ms`);
        pendingDownTimer = setTimeout(() => {
          pendingDownTimer = null;
          const downIface = pendingDownIface;
          pendingDownIface = null;
          if (!downIface) return;
          applyDownEvent(downIface);
        }, STABLE_DOWN_MS);
      }
      return;
    }

    // Up event. Cancel any pending teardown — link recovered before
    // the threshold expired, so the user never saw an outage. Note:
    // we deliberately treat this as a clean "no event happened"
    // case, not as a reconnect — wasDown will already be false
    // because state.activeInterface still reflects the prior up
    // state (we never updated it during the suppressed window).
    if (pendingDownTimer) {
      log("Network: down event suppressed (recovered within debounce window)");
      clearTimeout(pendingDownTimer);
      pendingDownTimer = null;
      pendingDownIface = null;
    }

    applyUpEvent(iface, wasDown);
  });

  // Adoption gate. The backend brackets every auto-adoption with
  // `adoption-started` / `adoption-finished` (carrying an opaque
  // adoption_id). Between them, the up-events above are the adoption's own
  // IP churn, so applyUpEvent suppresses restarts. `adoption-finished`
  // fires on EVERY terminal path — success, failure, timeout, shutdown —
  // so the gate can never stick closed.
  api.onEvent<AdoptionLifecyclePayload>("adoption-started", (data) => {
    state.activeAdoptionId = data.adoption_id;
    log(`Adoption ${data.adoption_id} started — restart gate closed`);
  });

  api.onEvent<AdoptionLifecyclePayload>("adoption-finished", (data) => {
    // Ignore a stale finish from a superseded adoption: only the active id
    // reopens the gate / consumes the latch. (A finish can arrive after a
    // newer adoption already started because of the settle delay.)
    if (data.adoption_id !== state.activeAdoptionId) {
      return;
    }
    state.activeAdoptionId = null;
    // Consume the latch unconditionally — even on a failed rescue, where
    // the interface is still APIPA and the connected-check below fails —
    // so a leftover latch can't misfire handleReconnect on a later,
    // unrelated adoption.
    const wasLatched = state.suppressedReconnect;
    state.suppressedReconnect = false;
    log(`Adoption ${data.adoption_id} finished — restart gate reopened`);
    if (wasLatched && isInterfaceConnected()) {
      // The APIPA outage tore the stream down and the gate swallowed the
      // up-event that would have resumed it; resume exactly once now. Do
      // NOT restart discovery — it never stopped (it drove the adoption),
      // and restarting would re-enter the loop this gate removes.
      handleReconnect().catch((e: unknown) =>
        log(`Post-adoption resume: ${formatError(e)}`)
      );
    }
  });
}

function applyDownEvent(iface: InterfaceInfo): void {
  sessionAdoptedSubnets.clear();
  // Sentinel from the backend watcher: no ethernet adapter present
  // at all. Deliberately does NOT raise the banner here — a mid-
  // session unplug during active use is noise, not a call to action.
  // Banner is reserved for explicit enumeration (startup + manual
  // refresh), where the user is actively trying to get discovery
  // running. Stream-break UX lives separately in streaming.ts::
  // showStreamLost.
  if (!iface.name) {
    handleHardDisconnect("Ethernet disconnected");
    state.activeInterface = null;
    $("#iface-name").textContent = unavailableAdapterLabel();
    // History stays visible. Backend expiry owns each row's status,
    // including the stable-down hold; this event only updates host UI.
    renderArpDeviceList();
    renderSubnetList();
    hideDiscoveryStatus();
    return;
  }

  // Adapter present but down or APIPA-only.
  state.activeInterface = iface;
  handleHardDisconnect("Ethernet disconnected");
  $("#iface-name").textContent =
    (iface.display_name || iface.name) + " (Disconnected)";
  // Render retained history even without a usable host address.
  // The backend owns verification, expiry and inactive reasons.
  renderArpDeviceList();
  renderSubnetList();
  // Hide the Nodes-card spinner — no link means no discovery to wait on.
  hideDiscoveryStatus();
}

function applyUpEvent(iface: InterfaceInfo, wasDown: boolean): void {
  state.activeInterface = iface;
  $("#iface-name").textContent = iface.display_name || iface.name;
  // Recovery — reset diagnostic throttling for the next outage.
  lastAdapterWarningAt = 0;
  // Refresh the subnet list since adopted IPs may have appeared
  // (load_adopted_from_config completing during cold start triggers
  // this event with the new IP set).
  renderSubnetList();

  // While an auto-adoption is in progress, this up-event is the app's own
  // IP churn (scratch bind/release, final add) — NOT a reconnect. Do not
  // restart discovery or the stream. If the interface had been torn down
  // (an APIPA rescue), latch a one-shot resume for when the adoption
  // finishes: the gate is swallowing the only up-event that would resume
  // the stream, and no further watcher event arrives once the IP set is
  // stable.
  if (state.activeAdoptionId !== null) {
    log(`Up-event during adoption ${state.activeAdoptionId} — suppressing restart`);
    if (wasDown) {
      renderArpDeviceList();
      state.suppressedReconnect = true;
    }
    return;
  }

  if (wasDown) {
    // If we just came back from disconnected, re-render immediately
    // from the preserved state so the Nodes list snaps back, then
    // let backend readiness resume discovery and verification independently
    // of UI query/event ordering.
    renderArpDeviceList();
    resetDiscoveryStatus();
    onDiscoveryReconnect();
    // Restart the stream (and re-stream server) if they were running
    // before the disconnect. Failures are logged; the backend status
    // owns the persistent playback error and retry controls.
    handleReconnect().catch((e: unknown) =>
      log(`Auto-resume: ${formatError(e)}`)
    );
  }
}

// ── Subnet list rendering ───────────────────────────────────────────

/** Drive the existing `#ip-mode` span in the Host card. Three states:
 *   - Static-Auto    → "Static — auto-adopt ready" (green)
 *   - Static-Manual  → "Static — manual nodes" (blue)
 *   - DHCP           → "DHCP — set static to enable auto-adopt"
 *                       (amber, clickable, opens IP Config)
 *  Backend's auto-adopt loop has DHCP/APIPA nuance the badge
 *  intentionally hides — the user-actionable distinction is just
 *  "DHCP" vs "Static." */
export function renderModeBadge(): void {
  const modeEl = $("#ip-mode");
  // Render as soon as the mode is known. The mode is independent of
  // interface state — it's the user's preference, not a property of
  // the adapter — so waiting on state.activeInterface (the slow
  // listInterfaces enumeration) would leave the badge blank for a
  // second or two of cold start. syncHostModeFromConfig calls this
  // right after loadConfig resolves.
  if (hostMode === null) {
    modeEl.textContent = "--";
    modeEl.className = "status-value";
    return;
  }

  if (hostMode === "static_auto") {
    modeEl.textContent = "Static — auto-adopt ready";
    modeEl.className = "status-value mode-static";
    return;
  }

  if (hostMode === "static_manual") {
    modeEl.textContent = "Static — manual nodes";
    modeEl.className = "status-value mode-manual";
    return;
  }

  modeEl.innerHTML =
    `<button type="button" id="mode-cta-static" class="mode-cta-inline" title="Open IP Config to set a static IP">` +
    `DHCP — set static to enable auto-adopt` +
    `</button>`;
  modeEl.className = "status-value mode-dhcp";
  const btn = modeEl.querySelector<HTMLButtonElement>("#mode-cta-static");
  btn?.addEventListener("click", () => {
    $<HTMLButtonElement>("#btn-ip-config").click();
  });
}

export function renderSubnetList(): void {
  const subnetList = $("#subnet-list");
  renderModeBadge();
  type HostRow = { address: string; prefix: number | null; subnet: string; observed: boolean; meta?: import("./types.ts").AdoptedMetaView };
  const rows = new Map<string, HostRow>();
  const savedAddresses = new Set([...adoptionMeta.values()].map((m) => m.address));
  for (const ip of state.activeInterface?.ips ?? []) {
    if (isApipa(ip.address) && !savedAddresses.has(ip.address)) continue;
    rows.set(`${ip.address}/${ip.prefix}`, { ...ip, observed: true });
  }
  for (const [subnet, meta] of adoptionMeta) {
    const address = meta.address ?? adoptedSubnets.get(subnet);
    if (!address || (meta.desired === "removed" && !meta.applied && !meta.last_error)) continue;
    const prefix = meta.prefix ?? null;
    const key = `${address}/${prefix}`;
    rows.set(key, { address, prefix, subnet, observed: rows.get(key)?.observed ?? false, meta });
  }
  const normalizeMac = (mac: string | null | undefined) => mac?.replaceAll("-", ":").toLowerCase();
  subnetList.innerHTML = [...rows.values()].sort((a, b) =>
    a.address.localeCompare(b.address) || (a.prefix ?? -1) - (b.prefix ?? -1)
  ).map(({ address, prefix, subnet, observed, meta }) => {
    const ownerKnown = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(normalizeMac(meta?.adapter_mac) ?? "") && prefix !== null && prefix >= 0 && prefix <= 32;
    const mismatch = observed && normalizeMac(meta?.adapter_mac) !== normalizeMac(state.activeInterface?.mac);
    const managed = ownerKnown && !mismatch && meta?.desired === "present";
    const cidr = `${address}/${prefix ?? "?"}`;
    const badge = managed && observed && meta?.applied && sessionAdoptedSubnets.has(subnet)
      ? '<span class="badge-auto">auto</span>' : "";
    return `<div class="status-row subnet-row" data-subnet="${escapeHtml(subnet)}">
      <span class="status-label">IP:</span><span class="auto-ip-group">${badge}<span class="status-value">${escapeHtml(cidr)}</span></span></div>`;
  }).join("");
  lockAddressControls();
}

// ── CAM / PTU target resolution ─────────────────────────────────────
// Replaces the legacy #camera-ip / #ptu-ip dropdowns. Targets now flow
// from the persisted/session identity and current CAM/PTU assignment.
// Callers ask the resolver
// at the moment they need to act (Start Stream, PTZ command, etc.),
// so any state shift in the Nodes panel takes effect on the next
// action without needing dropdown re-population.

/** Ambiguous legacy roles require an explicit user choice. */
function targetByAlias(alias: string): DeviceTarget | null {
  const matches = deviceList.getDevices().filter((r) => r.alias === alias);
  return matches.length === 1 ? deviceList.targetFor(matches[0]!) : null;
}

export function getActiveCamTarget(): DeviceTarget | null {
  const aliased = targetByAlias("CAM");
  if (!aliased) return null;
  const session = sessionCamTarget.get();
  if (session) {
    // Hold missing selections instead of falling through to a replacement.
    const record = deviceList.resolveTarget(session);
    if (!record) return null;
    if (record.alias === "CAM") return session;
  }
  const configured = state.config?.stream;
  if (configured?.camera_mac) {
    const target = { key: configured.camera_mac, expectedMac: configured.camera_mac };
    const record = deviceList.resolveTarget(target);
    if (!record) return null;
    if (record.alias === "CAM") return target;
  }
  return aliased;
}

export function getActiveCamIp(): string | null {
  const ip = deviceList.endpointFor(getActiveCamTarget());
  return ip && !ip.startsWith("169.254.") ? ip : null;
}

export function getActivePtuTarget(): DeviceTarget | null { return targetByAlias("PTU"); }

export function getActivePtuIp(): string | null {
  const ip = deviceList.endpointFor(getActivePtuTarget());
  return ip && !ip.startsWith("169.254.") ? ip : null;
}

// ── IP Configuration dialog ─────────────────────────────────────────

/** Interfaces loaded when dialog opens — used by add/remove handlers. */
let dialogInterfaces: InterfaceInfo[] = [];
let dialogSession: { primaryEdited: boolean; modeEdited: boolean; primary: string; mode: NetworkMode;
  previousAddress: string | null; primaryChosen: boolean } | null = null;
let dialogSaving = false;

function rememberPrimaryAddress(mac: string | null | undefined, cidr: string | null | undefined): void {
  if (!state.config || !mac || cidr === undefined) return;
  const key = mac.replaceAll("-", ":").toLowerCase();
  const saved = state.config.primary_addresses ??= {};
  if (cidr === null) delete saved[key];
  else saved[key] = cidr;
}

function primaryFields(): string {
  return ["#static-ip", "#static-mask", "#static-gateway"]
    .map((id) => $<HTMLInputElement>(id).value.trim()).join("\n");
}

function renderAdapterChoices(): void {
  const selection = adapterSelection;
  if (!selection) return;
  const select = $<HTMLSelectElement>("#static-iface");
  select.innerHTML = '<option value="" disabled>Select Ethernet adapter</option>' +
    dialogInterfaces.map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(
      `${i.display_name || i.name} (${i.mac})`
    )}</option>`).join("");
  select.value = selection.adapter?.name ?? "";
  const field = select.closest<HTMLElement>(".input-field");
  if (field) field.style.display = dialogInterfaces.length > 1 ? "" : "none";
}

const addressControlSelector = "#static-iface, #btn-add-sec-ip, #static-ip, #static-mask, #static-gateway, #primary-existing-ip, #btn-remove-primary-ip, #add-sec-ip, #add-sec-mask, #ip-mode-dhcp, #ip-mode-static-auto, #ip-mode-static-manual, #reset-adapter-confirm, [data-remove-binding], [data-remove-ip]";
function lockAddressControls(): void {
  if (!addressBusy && !dialogSaving) return;
  document.querySelectorAll<HTMLButtonElement | HTMLInputElement | HTMLSelectElement>(addressControlSelector).forEach((el) => {
    if (!disabledControls.has(el)) disabledControls.set(el, el.disabled);
    el.disabled = true;
  });
  $("#host-title").style.pointerEvents = "none";
}

function unlockAddressControls(pointerEvents: string): void {
  disabledControls.forEach((disabled, el) => { el.disabled = disabled; });
  disabledControls.clear();
  $("#host-title").style.pointerEvents = pointerEvents;
}

/** Apply only this operation's row and its observed adapter, without IPC. */
function applyAddressReply(reply: AddressReply): void {
  ++interfaceRefresh; ++bindingRefresh;
  const view = reply.view;
  rememberPrimaryAddress(view.selection.selected_mac, view.primary_address);
  hostMode = view.mode;
  if (state.config) state.config.network_mode = view.mode;
  if (view.subnet) {
    adoptedSubnets.delete(view.subnet);
    sessionAdoptedSubnets.delete(view.subnet);
    if (view.binding) {
      adoptionMeta.set(view.subnet, view.binding);
      if (view.binding.desired === "present" && view.binding.applied && view.binding.address)
        adoptedSubnets.set(view.subnet, view.binding.address);
    } else adoptionMeta.delete(view.subnet);
  }
  if (!view.observation_error) { applySelection(view.selection); verifiedAddressView = true; }
  else log(`Address observation unavailable: ${view.observation_error}`);
  renderNetwork();
  if ($<HTMLDialogElement>("#ip-config-dialog").open && !dialogSession?.modeEdited && view.dhcp !== null) {
    const mode = view.dhcp ? "dhcp" : view.mode === "dhcp" ? "static_auto" : view.mode;
    $<HTMLInputElement>("#ip-mode-dhcp").checked = mode === "dhcp";
    $<HTMLInputElement>("#ip-mode-static-auto").checked = mode === "static_auto";
    $<HTMLInputElement>("#ip-mode-static-manual").checked = mode === "static_manual";
    if (dialogSession) dialogSession.mode = mode;
    updateModeVisibility();
  }
}

async function mutateAddress(
  progress: string,
  invoke: () => Promise<AddressReply>,
  button?: HTMLButtonElement,
  confirmation?: { message: string; isCurrent: () => boolean },
): Promise<boolean> {
  if (addressBusy || selectingAdapter || dialogSaving) return false;
  const operation = { retired: false };
  const session = dialogSession;
  addressBusy = operation;
  ++interfaceRefresh; ++bindingRefresh;
  const started = performance.now();
  const spinner = $<HTMLElement>("#ip-config-spinner");
  const oldHtml = button?.innerHTML;
  const spinnerClass = spinner.className;
  const hostPointer = $("#host-title").style.pointerEvents;
  try {
    lockAddressControls();
    if (confirmation) {
      // Tauri replaces the browser's synchronous confirm with Promise<boolean>.
      // Reserve the operation before awaiting, but send no mutation until confirmed.
      if (await window.confirm(confirmation.message) !== true) return false;
      if (operation.retired || dialogSession !== session || !$<HTMLDialogElement>("#ip-config-dialog").open || !confirmation.isCurrent()) {
        showToast("Network configuration changed; review the address and try again", true);
        return false;
      }
    }
    spinner.style.display = "";
    spinner.className = "";
    spinner.textContent = progress;
    if (button) button.textContent = progress;
    log(`Address request acknowledged in ${(performance.now() - started).toFixed(1)}ms`);
    const reply = await invoke();
    log(`Address operation ${reply.operation} IPC returned in ${(performance.now() - started).toFixed(1)}ms`);
    if (operation.retired) { log("Address reply retired after adapter change"); return false; }
    applyAddressReply(reply);
    log(`Address operation ${reply.operation} rendered in ${(performance.now() - started).toFixed(1)}ms`);
    showToast(reply.reason ?? (reply.outcome === "success" ? "Address updated" : "Address operation pending"), reply.outcome !== "success");
    return reply.outcome === "success" && !reply.view.observation_error;
  } catch (e) {
    showToast("Failed: " + formatError(e), true);
    return false;
  } finally {
    addressBusy = null;
    unlockAddressControls(hostPointer);
    spinner.style.display = "none";
    spinner.textContent = "";
    spinner.className = spinnerClass;
    if (button) button.innerHTML = oldHtml ?? "Remove";
    // Only an independently received event/open request can schedule this read.
    if (refreshTrailing && !refreshFlight) void refreshInterfaces();
  }
}

export function setupIpConfigDialog(
  onModeApplied: (previous: NetworkMode | null, next: NetworkMode) => void = () => {},
): void {
  const dialog = $<HTMLDialogElement>("#ip-config-dialog");
  const closeButton = $<HTMLButtonElement>("#ip-config-close");
  let closing = false;

  dialog.addEventListener("close", () => { dialogSession = null; ++interfaceRefresh; ++bindingRefresh; });

  // ── Open dialog ──────────────────────────────────────────────────
  $<HTMLButtonElement>("#btn-ip-config").addEventListener("click", async () => {
    if (closing || dialog.open) return;
    const session = { primaryEdited: false, modeEdited: false, primary: primaryFields(),
      mode: hostMode ?? state.config?.network_mode ?? "static_auto", previousAddress: null as string | null, primaryChosen: false };
    dialogSession = session;
    $<HTMLInputElement>("#add-sec-ip").value = "";
    const select = $<HTMLSelectElement>("#static-iface");
    select.innerHTML = '<option value="">Loading…</option>';

    ++interfaceRefresh; ++bindingRefresh;
    await showModalWithVideo(dialog);

    try {
      if (dialogSession !== session || !dialog.open) return;
      // Keep a known adapter usable while the fresh read is in flight. Every
      // write still validates the selected adapter against fresh native state.
      if (adapterSelection) {
        dialogInterfaces = (adapterSelection.candidates ?? []).filter(isWiredCandidate);
        renderNetwork();
      }
      await reloadDialogInterfaces();
      if (dialogSession !== session || !dialog.open || addressBusy) return;
      await syncModeFromInterface();
    } catch (_) {
      select.innerHTML = '<option value="">Failed to load</option>';
    }
  });

  // Re-populate when interface selection changes
  $<HTMLSelectElement>("#static-iface").addEventListener("change", async () => {
    const select = $<HTMLSelectElement>("#static-iface");
    const iface = dialogInterfaces.find((i) => i.name === select.value);
    if (!iface || selectingAdapter || addressBusy || dialogSaving) return;
    selectingAdapter = true;
    select.disabled = true;
    try {
      rememberAdapterSelection(await api.selectAdapter(iface.mac));
      await reloadDialogInterfaces();
      await syncModeFromInterface();
    } catch (e) {
      showToast("Adapter selection failed: " + formatError(e), true);
      await reloadDialogInterfaces();
    } finally {
      selectingAdapter = false;
      select.disabled = false;
    }
  });

  // Native refreshes may update the rows while open, but must not erase edits.
  for (const id of ["#static-ip", "#static-mask", "#static-gateway"]) {
    $<HTMLInputElement>(id).addEventListener("input", () => {
      if (dialogSession) dialogSession.primaryEdited = primaryFields() !== dialogSession.primary;
    });
  }
  for (const id of ["#ip-mode-dhcp", "#ip-mode-static-auto", "#ip-mode-static-manual"]) {
    $<HTMLInputElement>(id).addEventListener("change", () => {
      if (dialogSession) dialogSession.modeEdited = readSelectedMode() !== dialogSession.mode;
      updateModeVisibility();
    });
  }
  $<HTMLSelectElement>("#primary-existing-ip").addEventListener("change", () => {
    if (!dialogSession || addressBusy || dialogSaving) return;
    dialogSession.previousAddress = $<HTMLSelectElement>("#primary-existing-ip").value || null;
    dialogSession.primaryChosen = true;
    populateDialogFields();
  });
  $<HTMLButtonElement>("#btn-remove-primary-ip").addEventListener("click", async () => {
    if (addressBusy || dialogSaving || selectingAdapter) return;
    const iface = dialogInterfaces.find((i) => i.name === $<HTMLSelectElement>("#static-iface").value);
    const previous = dialogSession?.previousAddress;
    const ip = previous?.split("/")[0];
    if (!iface || !ip) return;
    if (await mutateAddress("Removing address…", () => api.removeSecondaryIp(iface.name, ip, true), $<HTMLButtonElement>("#btn-remove-primary-ip"), {
      message: `Remove ${ip} from ${iface.display_name || iface.name}?`,
      isCurrent: () => dialogSession?.previousAddress === previous,
    })) {
      if (dialogSession) { dialogSession.previousAddress = null; dialogSession.primaryChosen = true; }
      renderNetwork();
    }
  });

  // ── Add secondary IP ─────────────────────────────────────────────
  async function addDialogAddress(): Promise<boolean> {
    if (selectingAdapter || addressBusy || dialogSaving) return false;
    const iface = $<HTMLSelectElement>("#static-iface").value;
    const ip = $<HTMLInputElement>("#add-sec-ip").value.trim();
    const mask = $<HTMLInputElement>("#add-sec-mask").value.trim();
    const session = dialogSession;
    if (!iface || !ip || !mask) {
      showToast("Enter an IP and mask", true);
      return false;
    }
    const saved = await mutateAddress("Adding address…", () => api.addSecondaryIp(iface, ip, mask));
    if (saved && dialogSession === session && $<HTMLInputElement>("#add-sec-ip").value.trim() === ip
        && $<HTMLInputElement>("#add-sec-mask").value.trim() === mask) {
      $<HTMLInputElement>("#add-sec-ip").value = "";
    }
    return saved;
  }
  $<HTMLButtonElement>("#btn-add-sec-ip").addEventListener("click", () => addDialogAddress());

  // Close and Escape share one save path. Only user edits trigger writes;
  // merely opening a disconnected/ambiguous adapter needs no primary IP.
  async function saveAndClose(): Promise<void> {
    if (closing || selectingAdapter || !dialog.open) return;
    const session = dialogSession;
    const modeEdited = session?.primaryEdited || session?.modeEdited;
    const secondaryEntered = !!$<HTMLInputElement>("#add-sec-ip").value.trim();
    if (!modeEdited && !secondaryEntered) { dialog.close(); return; }
    if (addressBusy) { showToast("Wait for the address operation to finish", true); return; }
    const name = $<HTMLSelectElement>("#static-iface").value;
    const selectedMac = adapterSelection?.selected_mac;
    const selectedRevision = adapterSelectionRevision;
    const mode = readSelectedMode();
    if (!name) { showToast("Select an interface", true); return; }
    const ip = mode === "dhcp" ? null : $<HTMLInputElement>("#static-ip").value.trim();
    const subnet_mask = mode === "dhcp" ? null : $<HTMLInputElement>("#static-mask").value.trim();
    if (modeEdited && mode !== "dhcp" && (!ip || !subnet_mask)) {
      showToast("Fill in address and mask", true); return;
    }
    if (secondaryEntered && !$<HTMLInputElement>("#add-sec-mask").value.trim()) {
      showToast("Enter an IP and mask", true); return;
    }
    if (secondaryEntered && mode === "dhcp") {
      showToast("Select a static mode to add a secondary IP", true); return;
    }
    const previousMode = state.config?.network_mode ?? null;
    const request = {
      name, mode, ip, subnet_mask,
      gateway: mode === "dhcp" ? null : $<HTMLInputElement>("#static-gateway").value.trim() || null,
      previous_address: mode === "dhcp" ? null : session?.previousAddress ?? null,
      confirmed: false,
    };
    const spinner = $<HTMLElement>("#ip-config-spinner");
    const hostPointer = $("#host-title").style.pointerEvents;
    closing = true;
    closeButton.disabled = true;
    try {
      if (modeEdited) {
        dialogSaving = true;
        lockAddressControls();
        spinner.style.display = "";
        let reply = await api.setNetworkMode(request);
        if (reply.warning) {
          const confirmed = await window.confirm(reply.warning);
          if (dialogSession !== session || !dialog.open || adapterSelectionRevision !== selectedRevision) {
            showToast("Ethernet adapter changed; review the configuration before closing", true);
            return;
          }
          if (confirmed !== true) {
            // Cancel the proposed mode, so Close/Escape can leave without
            // proposing the same DHCP change again. Keep other field edits.
            $<HTMLInputElement>("#ip-mode-dhcp").checked = reply.mode === "dhcp";
            $<HTMLInputElement>("#ip-mode-static-auto").checked = reply.mode === "static_auto";
            $<HTMLInputElement>("#ip-mode-static-manual").checked = reply.mode === "static_manual";
            if (session) { session.mode = reply.mode; session.modeEdited = false; }
            updateModeVisibility();
            return;
          }
          reply = await api.setNetworkMode({ ...request, confirmed: true });
        }
        if (reply.warning) { showToast(reply.warning, true); return; }
        ++interfaceRefresh; ++bindingRefresh;
        hostMode = reply.mode;
        if (state.config) state.config.network_mode = reply.mode;
        rememberPrimaryAddress(selectedMac, reply.primary_address);
        if (session) { session.primaryEdited = false; session.modeEdited = false; session.mode = reply.mode; session.primaryChosen = false; }
        renderModeBadge();
        if (reply.mode === "static_manual") hideDiscoveryStatus();
        onModeApplied(previousMode, reply.mode);
        await refreshInterfaces();
        if (previousMode === "static_manual" && reply.mode !== "static_manual" && isInterfaceConnected()) resetDiscoveryStatus();
        dialogSaving = false;
        unlockAddressControls(hostPointer);
      }
      if (dialogSession !== session || !dialog.open) return;
      if (adapterSelection?.selected_mac !== selectedMac) {
        showToast("Ethernet adapter changed; review the configuration before closing", true); return;
      }
      if (secondaryEntered && !await addDialogAddress()) return;
      dialog.close();
    } catch (e) {
      showToast("Failed: " + formatError(e), true);
    } finally {
      dialogSaving = false;
      closing = false;
      closeButton.disabled = false;
      unlockAddressControls(hostPointer);
      spinner.style.display = "none";
    }
  }
  closeButton.addEventListener("click", saveAndClose);
  dialog.addEventListener("cancel", (event) => { event.preventDefault(); void saveAndClose(); });
}

/** Read the dialog's currently-selected mode radio. */
function readSelectedMode(): NetworkMode {
  if ($<HTMLInputElement>("#ip-mode-dhcp").checked) return "dhcp";
  if ($<HTMLInputElement>("#ip-mode-static-manual").checked) return "static_manual";
  return "static_auto";
}

/** Hide the static-only fields only in DHCP mode — both static modes
 *  share the host-IP fields (the difference is program behavior, not
 *  adapter config). */
function updateModeVisibility(): void {
  const isDhcp = $<HTMLInputElement>("#ip-mode-dhcp").checked;
  $<HTMLElement>("#ip-static-section").style.display = isDhcp ? "none" : "";
}

/** Sync the dialog's mode radio to the backend's currently-saved
 *  NetworkMode. Errors are non-fatal — the radio falls back to its
 *  prior position (defaulting to Static-Auto on fresh opens). */
async function syncModeFromInterface(): Promise<void> {
  const name = $<HTMLSelectElement>("#static-iface").value;
  if (!name) return;
  try {
    const request = interfaceRefresh;
    const savedMode = hostMode ?? state.config?.network_mode ?? "static_auto";
    const dhcp = await api.getDhcpState(name);
    if (request !== interfaceRefresh || addressBusy || dialogSession?.modeEdited || !$<HTMLDialogElement>("#ip-config-dialog").open) return;
    const mode = dhcp ? "dhcp" : savedMode === "dhcp" ? "static_auto" : savedMode;
    $<HTMLInputElement>("#ip-mode-dhcp").checked = mode === "dhcp";
    $<HTMLInputElement>("#ip-mode-static-auto").checked = mode === "static_auto";
    $<HTMLInputElement>("#ip-mode-static-manual").checked = mode === "static_manual";
    if (dialogSession) dialogSession.mode = mode;
  } catch (_) {
    // Leave the radio at its current position on error.
  }
  updateModeVisibility();
}

/** Fill primary IP fields and secondary IP list from the selected interface. */
function populateDialogFields(): void {
  const name = $<HTMLSelectElement>("#static-iface").value;
  const iface = dialogInterfaces.find((i) => i.name === name);
  if (!iface) {
    $("#primary-existing-field").style.display = "none";
    $("#btn-remove-primary-ip").style.display = "none";
    renderSecondaryIps(undefined, undefined); return;
  }

  // Prefer the user's explicit primary. Legacy ambiguous addresses require
  // a choice; neither a secondary nor a newly adopted address becomes primary
  // merely because Windows changed enumeration order.
  const cidr = (ip: { address: string; prefix: number }) => `${ip.address}/${ip.prefix}`;
  const usable = iface.ips.filter((ip) => !isApipa(ip.address));
  const savedIps = new Set([...adoptionMeta.values()].map((m) => m.address));
  const native = usable.filter((ip) => !savedIps.has(ip.address));
  const saved = state.config?.primary_addresses?.[iface.mac.replaceAll("-", ":").toLowerCase()];
  const legacy = native.length === 1 ? native[0] : usable.length === 1 ? usable[0] : undefined;
  const choice = dialogSession && (dialogSession.primaryEdited || dialogSession.primaryChosen)
    ? dialogSession.previousAddress : saved ?? (legacy ? cidr(legacy) : null);
  const primary = usable.find((ip) => cidr(ip) === choice);
  const existing = $<HTMLSelectElement>("#primary-existing-ip");
  existing.innerHTML = '<option value="">Select an address</option>' + usable.map((ip) => `<option value="${escapeHtml(cidr(ip))}">${escapeHtml(cidr(ip))}</option>`).join("");
  existing.value = choice ?? "";
  $("#primary-existing-field").style.display = !primary && saved !== "" && usable.length > 1 ? "" : "none";
  $("#btn-remove-primary-ip").style.display = primary ? "" : "none";
  // Left blank intentionally. The snapshot carries no gateway to seed it
  // with, but a blank gateway on save no longer wipes the configured
  // one — the backend preserves the existing default gateway when this
  // field is empty. Type a value here only to change it.
  if (!dialogSession?.primaryEdited) {
    $<HTMLInputElement>("#static-ip").value = primary ? primary.address : "";
    $<HTMLInputElement>("#static-mask").value = primary ? prefixToMask(primary.prefix) : "255.255.255.0";
    $<HTMLInputElement>("#static-gateway").value = "";
    if (dialogSession) dialogSession.primary = primaryFields();
  }
  if (dialogSession && !dialogSession.primaryEdited) dialogSession.previousAddress = primary ? cidr(primary) : null;

  // Secondary = all IPs except the primary
  renderSecondaryIps(iface, primary);
}

/** Merge observed secondaries with durable pending/failed removal intent. */
function renderSecondaryIps(iface: InterfaceInfo | undefined, primary: { address: string } | undefined): void {
  const list = $("#secondary-ip-list");
  const rows = new Map((iface?.ips ?? []).filter((ip) => !isApipa(ip.address) && ip.address !== primary?.address)
    .map((ip) => [ip.address, ip.prefix]));
  const saved = new Map([...adoptionMeta].filter(([, m]) => m.address && !isApipa(m.address) && m.address !== primary?.address &&
    (m.desired !== "removed" || m.applied || m.last_error)).map(([subnet, m]) => [m.address!, { subnet, meta: m }]));
  for (const [address, { meta }] of saved) rows.set(address, meta.prefix ?? 24);
  list.innerHTML = rows.size ? [...rows].map(([address, prefix]) => {
    const binding = saved.get(address);
    const m = binding?.meta;
    const status = m?.desired === "removed" ? " — pending removal" : m && !m.applied ? " — pending" : "";
    const reason = m?.last_error ? ` — ${m.last_error}` : "";
    return `<div class="secondary-ip-item"><span>${escapeHtml(`${address}/${prefix}${status}${reason}`)}</span>
      ${binding || iface ? `<button class="btn-remove-ip" ${binding ? `data-remove-binding="${escapeHtml(binding.subnet)}"` : `data-remove-ip="${escapeHtml(address)}"`} title="Remove ${escapeHtml(`${address}/${prefix}`)}">Remove</button>` : ""}</div>`;
  }).join("") : '<p class="placeholder-text" style="padding:8px">No secondary IPs</p>';
  list.querySelectorAll<HTMLButtonElement>("[data-remove-binding], [data-remove-ip]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (selectingAdapter || addressBusy || dialogSaving) return;
      const subnet = btn.dataset["removeBinding"];
      const ip = btn.dataset["removeIp"];
      if (!subnet && ip && iface) {
        const prefix = rows.get(ip);
        await mutateAddress("Removing address…", () => api.removeSecondaryIp(iface.name, ip), btn, {
          message: `Remove ${ip}/${prefix} from ${iface.display_name || iface.name}? This may interrupt devices using this host address. Device history is retained.`,
          isCurrent: () => !!dialogInterfaces.find((i) => i.mac === iface.mac && i.name === iface.name)
            ?.ips.some((current) => current.address === ip && current.prefix === prefix),
        });
        return;
      }
      const m = subnet ? adoptionMeta.get(subnet) : undefined;
      if (!subnet || !m?.address) return;
      const identity = (meta: typeof m | undefined) => JSON.stringify([meta?.adapter_mac, meta?.address, meta?.prefix, meta?.desired]);
      const original = identity(m);
      await mutateAddress("Removing address…", () => api.removeAdoptedSubnet(subnet, iface?.name), btn, {
        message: `Remove ${m.address}/${m.prefix ?? "?"} from its saved adapter? Nodes on ${subnet} may share this host address and lose connectivity. Device history is retained.`,
        isCurrent: () => identity(adoptionMeta.get(subnet)) === original,
      });
    });
  });
  lockAddressControls();
}

/** Re-pull interfaces into the IP-config dialog when it's open. Used
 *  by event listeners that change adoption state underneath it (the
 *  lifecycle reaper, a removal from the other panel) — a closed dialog
 *  re-reads everything on open anyway. */
export async function refreshIpDialogIfOpen(): Promise<void> {
  const dialog = $<HTMLDialogElement>("#ip-config-dialog");
  if (dialog.open) await reloadDialogInterfaces();
}

/** Reload interfaces and refresh dialog fields without closing. */
async function reloadDialogInterfaces(): Promise<void> { await refreshInterfaces(); }

/** Convert CIDR prefix to dotted mask (e.g. 24 → "255.255.255.0"). */
function prefixToMask(prefix: number): string {
  const bits = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return [bits >>> 24, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff].join(".");
}
