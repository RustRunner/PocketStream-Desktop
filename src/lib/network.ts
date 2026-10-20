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
let interfaceRefresh = 0;
let selectingAdapter = false;

function rememberAdapterSelection(next: AdapterSelection): void {
  if (adapterSelection && (adapterSelection.selected_mac !== next.selected_mac ||
      adapterSelection.interface_index !== next.interface_index)) {
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

async function refreshHostMode(): Promise<void> {
  try {
    hostMode = await api.getNetworkMode();
  } catch (_) {
    hostMode = null;
  }
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

export async function refreshInterfaces(): Promise<void> {
  const request = ++interfaceRefresh;
  try {
    const selection = await api.getAdapterSelection();
    if (request !== interfaceRefresh || !selection) return;
    rememberAdapterSelection(selection);
    const eth = selection.interface_index !== null ? selection.adapter : null;

    if (eth && eth.is_up && eth.ips.some((ip) => !isApipa(ip.address))) {
      state.activeInterface = eth;
      $("#iface-name").textContent = eth.display_name || eth.name;
      await refreshHostMode();
      renderSubnetList();
      // Recovery — reset the dedup so the next failure toasts again.
      lastAdapterWarningAt = 0;
    } else if (eth) {
      // Adapter is known to Windows but has no IP. Treat this the same
      // as "no ethernet detected" from the user's perspective — the
      // actionable state is identical (click Reset adapter).
      const stale = eth;
      state.activeInterface = stale;
      $("#iface-name").textContent =
        (stale.display_name || stale.name) + " (Disconnected)";
      renderSubnetList();
      warnNoEthernet();
    } else {
      state.activeInterface = null;
      $("#iface-name").textContent = unavailableAdapterLabel();
      renderSubnetList();
      warnNoEthernet();
    }
  } catch (e) {
    if (request !== interfaceRefresh) return;
    state.activeInterface = null;
    log(`Failed to list interfaces: ${formatError(e)}`);
    $("#iface-name").textContent = "Error";
    warnNoEthernet();
  }
}

// ── No-Ethernet toast dedup ─────────────────────────────────────────
// refreshInterfaces can fire rapidly (startup + manual refresh + watcher
// events arriving during a disconnect), so rate-limit the toast to at
// most once per window. Reset to 0 on a successful enumeration so the
// next failure re-toasts.

const NO_ETHERNET_COOLDOWN_MS = 15000;
let lastAdapterWarningAt = 0;

export function warnNoEthernet(): void {
  const now = Date.now();
  if (now - lastAdapterWarningAt < NO_ETHERNET_COOLDOWN_MS) return;
  lastAdapterWarningAt = now;
  showToast(
    adapterSelection?.selection_required
      ? "Choose the camera's Ethernet adapter in Configure"
      : adapterSelection?.selected_mac && (!adapterSelection.adapter || adapterSelection.interface_index === null)
        ? unavailableAdapterLabel()
        : "No Ethernet detected — check Ethernet connection and/or reset Ethernet adapter",
    true
  );
}

/** True if `address` is in the APIPA range (169.254.0.0/16). Windows
 *  assigns these as a fallback when DHCP fails — they technically count
 *  as "an IP" but linger as a secondary on the adapter after DHCP
 *  recovers (Windows doesn't auto-clean them). Used to hide them from
 *  the host subnet list and dropdowns where they'd just be confusing
 *  selectable entries that can't carry usable host-originated traffic.
 *
 *  NOTE: discovered *devices* in 169.254.x.x are NOT filtered — some
 *  cameras (FLIR in particular) fall back to APIPA on DHCP failure
 *  and the auto-adopt path is the user's recovery route. */
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

export function setupInterfaceWatcher(): void {
  api.onEvent<AdapterSelection>("adapter-selection-changed", (selection) => {
    ++interfaceRefresh;
    rememberAdapterSelection(selection);
  });
  api.onEvent<InterfaceInfo>("interface-status-changed", (iface) => {
    const expectedMac = adapterSelection?.selected_mac?.replaceAll("-", ":").toLowerCase();
    if (iface.mac.replaceAll("-", ":").toLowerCase() !== (expectedMac ?? "")) return;
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
  // Recovery — reset the toast dedup so a future failure re-toasts.
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
    // kick off discovery to verify. Verification will dim/mark any
    // devices that genuinely vanished during the downtime.
    renderArpDeviceList();
    resetDiscoveryStatus();
    api.startArpDiscovery(iface.name).catch(() => {});
    // Restart the stream (and RTSP server) if they were running
    // before the disconnect. Fires in the background; failures
    // surface as toasts inside handleReconnect.
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

// Wired once — `#subnet-list` is a stable container whose innerHTML is
// rebuilt on every renderSubnetList call, so a single delegated click
// listener survives re-renders without stacking duplicates.
let subnetRemoveWired = false;

/** Remove an auto-adopted subnet from the host card. Optimistic: on success
 *  drop it from the local map and re-render immediately; the NIC watcher
 *  refreshes the interface IP list shortly after the unbind, and the backend
 *  drops any held-over restore so the row can't resurrect on the next save. */
async function handleRemoveAdopted(subnet: string, btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true;
  try {
    await api.removeAdoptedSubnet(subnet);
    adoptedSubnets.delete(subnet);
    renderSubnetList();
    showToast(`Removed adopted subnet ${subnet}`);
  } catch (e) {
    btn.disabled = false;
    showToast("Failed: " + formatError(e), true);
  }
}

export function renderSubnetList(): void {
  const subnetList = $("#subnet-list");
  if (!subnetRemoveWired) {
    subnetRemoveWired = true;
    subnetList.addEventListener("click", (e) => {
      const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(
        "[data-remove-adopted]"
      );
      if (!btn) return;
      const subnet = btn.dataset["removeAdopted"];
      if (subnet) void handleRemoveAdopted(subnet, btn);
    });
  }
  renderModeBadge();
  if (!state.activeInterface) return;

  const adoptedIpSet = new Set(adoptedSubnets.values());
  // An adopted row stays on the Host card until the adoption is
  // explicitly removed — the per-row trash control, the Configure
  // dialog, or the APIPA reaper (all of which emit subnet-removed and
  // clear the map). It is NOT tied to Nodes-panel contents: clearing or
  // losing the nodes behind an adoption must not make the binding look
  // deleted while the secondary IP is still live on the adapter.
  // Trash-icon control shared by both auto-row shapes below. `subnetEsc`
  // must already be HTML-escaped; it doubles as the removal key.
  const removeBtn = (subnetEsc: string) =>
    `<button class="btn-remove-ip" data-remove-adopted="${subnetEsc}" title="Remove adopted subnet">` +
    `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>` +
    `</button>`;
  // Native rows: hide APIPA addresses — Windows leaves them as a
  // secondary after any brief DHCP failure and they can't carry usable
  // traffic, so showing them as if they were a selectable subnet just
  // confuses users (seen on multiple Getac installs in the field).
  // Adopted rows always render (see above).
  const sortedIps = [...state.activeInterface.ips]
    .filter((ip) => adoptedIpSet.has(ip.address) || !isApipa(ip.address))
    .sort((a, b) => {
      const aAuto = adoptedIpSet.has(a.address) ? 1 : 0;
      const bAuto = adoptedIpSet.has(b.address) ? 1 : 0;
      return aAuto - bAuto;
    });
  let html = sortedIps
    .map((ip) => {
      const isAuto = adoptedIpSet.has(ip.address);
      // Escape backend-sourced strings interpolated into innerHTML.
      const subnetEsc = escapeHtml(ip.subnet);
      const ipEsc = escapeHtml(`${ip.address}/${ip.prefix}`);
      if (isAuto) {
        return `
        <div class="status-row subnet-row subnet-row-auto" data-subnet="${subnetEsc}">
          <span class="status-label">IP:</span>
          <span class="auto-ip-group">
            <span class="badge-auto">(auto)</span>
            <span class="status-value">${ipEsc}</span>
          </span>
          ${removeBtn(subnetEsc)}
        </div>`;
      }
      return `
      <div class="status-row subnet-row" data-subnet="${subnetEsc}">
        <span class="status-label">IP:</span>
        <span class="status-value">${ipEsc}</span>
      </div>`;
    })
    .join("");

  // Add auto-adopted subnets not yet bound as interface IPs (skip if
  // already shown).
  const renderedIps = new Set(state.activeInterface.ips.map((ip) => ip.address));
  for (const [subnet, adoptedIp] of adoptedSubnets) {
    if (renderedIps.has(adoptedIp)) continue;
    html += `
      <div class="status-row subnet-row subnet-row-auto" data-subnet="${escapeHtml(subnet)}">
        <span class="status-label">IP:</span>
        <span class="auto-ip-group">
          <span class="badge-auto">(auto)</span>
          <span class="status-value">${escapeHtml(`${adoptedIp}/24`)}</span>
        </span>
        ${removeBtn(escapeHtml(subnet))}
      </div>`;
  }

  // Auto-adopted rows carry a per-row remove control. Clicks are handled by
  // the delegated listener wired above (keyed on data-remove-adopted), which
  // unbinds the secondary IP and drops the adoption from config.
  subnetList.innerHTML = html;
}

// ── CAM / PTU target resolution ─────────────────────────────────────
// Replaces the legacy #camera-ip / #ptu-ip dropdowns. Targets now flow
// from a precedence chain: current click selection → persisted config
// (CAM only) → alias designation → none. Callers ask the resolver
// at the moment they need to act (Start Stream, PTZ command, etc.),
// so any state shift in the Nodes panel takes effect on the next
// action without needing dropdown re-population.

/** Ambiguous legacy roles require an explicit user choice. */
function targetByAlias(alias: string): DeviceTarget | null {
  const matches = deviceList.getDevices().filter((r) => r.alias === alias);
  return matches.length === 1 ? deviceList.targetFor(matches[0]!) : null;
}

export function getActiveCamTarget(): DeviceTarget | null {
  const session = sessionCamTarget.get();
  if (session) {
    // Hold missing selections instead of falling through to a replacement.
    if (deviceList.resolveTarget(session)?.alias !== "PTU") return session;
  }
  const configured = state.config?.stream;
  if (configured?.camera_mac) {
    const target = { key: configured.camera_mac, expectedMac: configured.camera_mac };
    if (deviceList.resolveTarget(target)?.alias !== "PTU") return target;
  }
  const aliased = targetByAlias("CAM");
  if (aliased) return aliased;
  // Legacy IP-only settings can resolve only an explicit, unbound manual key.
  const manual = deviceList.deviceByKey(`manual:${configured?.camera_ip ?? ""}`);
  return manual && manual.alias !== "PTU" ? deviceList.targetFor(manual) : null;
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

async function loadAdapterChoices(): Promise<void> {
  const selection = await api.getAdapterSelection();
  if (!selection) return;
  rememberAdapterSelection(selection);
  dialogInterfaces = selection.candidates.filter(isWiredCandidate);
  const select = $<HTMLSelectElement>("#static-iface");
  select.innerHTML = '<option value="" disabled>Select Ethernet adapter</option>' +
    dialogInterfaces.map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(
      `${i.display_name || i.name} (${i.mac})`
    )}</option>`).join("");
  select.value = selection.adapter?.name ?? "";
  const field = select.closest<HTMLElement>(".input-field");
  if (field) field.style.display = dialogInterfaces.length > 1 ? "" : "none";
}

export function setupIpConfigDialog(): void {
  const dialog = $<HTMLDialogElement>("#ip-config-dialog");

  // ── Open dialog ──────────────────────────────────────────────────
  $<HTMLButtonElement>("#btn-ip-config").addEventListener("click", async () => {
    const select = $<HTMLSelectElement>("#static-iface");
    select.innerHTML = '<option value="">Loading…</option>';

    await showModalWithVideo(dialog);

    try {
      await reloadDialogInterfaces();
      await syncModeFromInterface();
    } catch (_) {
      select.innerHTML = '<option value="">Failed to load</option>';
    }
  });

  // Re-populate when interface selection changes
  $<HTMLSelectElement>("#static-iface").addEventListener("change", async () => {
    const select = $<HTMLSelectElement>("#static-iface");
    const iface = dialogInterfaces.find((i) => i.name === select.value);
    if (!iface || selectingAdapter) return;
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

  // Mode toggle: hide/show the static-only fields. Applying happens via
  // the existing Apply button — see branch below.
  $<HTMLInputElement>("#ip-mode-dhcp").addEventListener("change", updateModeVisibility);
  $<HTMLInputElement>("#ip-mode-static-auto").addEventListener("change", updateModeVisibility);
  $<HTMLInputElement>("#ip-mode-static-manual").addEventListener("change", updateModeVisibility);

  // ── Add secondary IP ─────────────────────────────────────────────
  $<HTMLButtonElement>("#btn-add-sec-ip").addEventListener("click", async () => {
    if (selectingAdapter) return;
    const iface = $<HTMLSelectElement>("#static-iface").value;
    const ip = $<HTMLInputElement>("#add-sec-ip").value.trim();
    const mask = $<HTMLInputElement>("#add-sec-mask").value.trim();
    if (!iface || !ip || !mask) {
      showToast("Enter an IP and mask", true);
      return;
    }
    const spinner = $<HTMLElement>("#ip-config-spinner");
    spinner.style.display = "";
    try {
      await api.addSecondaryIp(iface, ip, mask);
      $<HTMLInputElement>("#add-sec-ip").value = "";
      showToast("Secondary IP added");
      await reloadDialogInterfaces();
    } catch (e) {
      showToast("Failed: " + formatError(e), true);
    }
    spinner.style.display = "none";
  });

  // ── Cancel ───────────────────────────────────────────────────────
  $<HTMLButtonElement>("#ip-config-cancel").addEventListener("click", () => dialog.close());

  // ── Apply ────────────────────────────────────────────────────────
  $<HTMLButtonElement>("#ip-config-apply").addEventListener("click", async () => {
    if (selectingAdapter) return;
    const name = $<HTMLSelectElement>("#static-iface").value;
    const mode = readSelectedMode();
    if (!name) { showToast("Select an interface", true); return; }
    const ip = mode === "dhcp" ? null : $<HTMLInputElement>("#static-ip").value.trim();
    const subnet_mask = mode === "dhcp" ? null : $<HTMLInputElement>("#static-mask").value.trim();
    if (mode !== "dhcp" && (!ip || !subnet_mask)) {
      showToast("Fill in address and mask", true); return;
    }
    const request = {
      name, mode, ip, subnet_mask,
      gateway: mode === "dhcp" ? null : $<HTMLInputElement>("#static-gateway").value.trim() || null,
      confirmed: false,
    };
    const spinner = $<HTMLElement>("#ip-config-spinner");
    spinner.style.display = "";
    try {
      let reply = await api.setNetworkMode(request);
      if (reply.warning) {
        if (!window.confirm(reply.warning)) return;
        reply = await api.setNetworkMode({ ...request, confirmed: true });
      }
      if (state.config) state.config.network_mode = reply.mode;
      showToast(reply.mode === "dhcp" ? "Switched to DHCP; saved bindings are pending" : "Static configuration applied");
      dialog.close();
      await refreshInterfaces();
    } catch (e) {
      showToast("Failed: " + formatError(e), true);
      await reloadDialogInterfaces();
      await syncModeFromInterface();
    } finally {
      spinner.style.display = "none";
    }
  });
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
    const savedMode = await api.getNetworkMode();
    const mode = await api.getDhcpState(name) ? "dhcp" : savedMode === "dhcp" ? "static_auto" : savedMode;
    $<HTMLInputElement>("#ip-mode-dhcp").checked = mode === "dhcp";
    $<HTMLInputElement>("#ip-mode-static-auto").checked = mode === "static_auto";
    $<HTMLInputElement>("#ip-mode-static-manual").checked = mode === "static_manual";
  } catch (_) {
    // Leave the radio at its current position on error.
  }
  updateModeVisibility();
}

/** Fill primary IP fields and secondary IP list from the selected interface. */
function populateDialogFields(): void {
  const name = $<HTMLSelectElement>("#static-iface").value;
  const iface = dialogInterfaces.find((i) => i.name === name);
  if (!iface) { renderSecondaryIps(undefined, undefined); return; }

  // Multiple unmanaged addresses have ambiguous ownership. Require an
  // explicit address instead of treating enumeration order as primary.
  const savedIps = new Set([...adoptionMeta.values()].map((m) => m.address));
  const native = iface.ips.filter((ip) => !savedIps.has(ip.address) && !isApipa(ip.address));
  const primary = native.length === 1 ? native[0] : undefined;
  $<HTMLInputElement>("#static-ip").value = primary ? primary.address : "";
  $<HTMLInputElement>("#static-mask").value = primary ? prefixToMask(primary.prefix) : "255.255.255.0";
  // Left blank intentionally. The snapshot carries no gateway to seed it
  // with, but a blank gateway on Apply no longer wipes the configured
  // one — the backend preserves the existing default gateway when this
  // field is empty. Type a value here only to change it.
  $<HTMLInputElement>("#static-gateway").value = "";

  // Secondary = all IPs except the primary
  renderSecondaryIps(iface, primary);
}

/** Merge observed secondaries with durable pending/failed removal intent. */
function renderSecondaryIps(iface: InterfaceInfo | undefined, primary: { address: string } | undefined): void {
  const list = $("#secondary-ip-list");
  const rows = new Map((iface?.ips ?? []).filter((ip) => ip.address !== primary?.address)
    .map((ip) => [ip.address, ip.prefix]));
  const saved = new Map([...adoptionMeta].filter(([, m]) => m.address &&
    (m.desired !== "removed" || m.applied || m.last_error)).map(([subnet, m]) => [m.address!, { subnet, meta: m }]));
  for (const [address, { meta }] of saved) rows.set(address, meta.prefix ?? 24);
  list.innerHTML = rows.size ? [...rows].map(([address, prefix]) => {
    const binding = saved.get(address);
    const m = binding?.meta;
    const status = m ? (m.desired === "removed" ? "pending removal" : m.applied ? "applied" : "pending") : "ownership unknown";
    const reason = m?.last_error ? ` — ${m.last_error}` : m && !m.adapter_mac ? " — adapter ownership awaiting reconciliation" : "";
    return `<div class="secondary-ip-item"><span>${escapeHtml(`${address}/${prefix} — ${status}${reason}`)}</span>
      ${binding ? `<button class="btn-remove-ip" data-remove-binding="${escapeHtml(binding.subnet)}" title="Remove ${escapeHtml(`${address}/${prefix}`)}">Remove</button>` : ""}</div>`;
  }).join("") : '<p class="placeholder-text" style="padding:8px">No secondary IPs</p>';
  list.querySelectorAll<HTMLButtonElement>("[data-remove-binding]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (selectingAdapter) return;
      const subnet = btn.dataset["removeBinding"];
      const m = subnet ? adoptionMeta.get(subnet) : undefined;
      if (!subnet || !m?.address) return;
      if (!window.confirm(`Remove ${m.address}/${m.prefix ?? "?"} from its saved adapter? Nodes on ${subnet} may share this host address and lose connectivity. Device history is retained.`)) return;
      const spinner = $<HTMLElement>("#ip-config-spinner");
      spinner.style.display = "";
      try {
        await api.removeAdoptedSubnet(subnet, iface?.name);
        showToast(`Removed ${m.address}`);
      } catch (e) {
        showToast("Failed: " + formatError(e), true);
      } finally {
        await reloadDialogInterfaces();
        spinner.style.display = "none";
      }
    });
  });
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
async function reloadDialogInterfaces(): Promise<void> {
  try {
    await loadAdapterChoices();
    const snapshot = await api.getAdoptionState();
    adoptedSubnets.clear();
    adoptionMeta.clear();
    for (const [subnet, ip] of Object.entries(snapshot.adopted_subnets)) adoptedSubnets.set(subnet, ip);
    for (const [subnet, meta] of Object.entries(snapshot.meta)) adoptionMeta.set(subnet, meta);
    populateDialogFields();
    // Also refresh the host card
    await refreshInterfaces();
  } catch (_) {}
}

/** Convert CIDR prefix to dotted mask (e.g. 24 → "255.255.255.0"). */
function prefixToMask(prefix: number): string {
  const bits = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return [bits >>> 24, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff].join(".");
}
