/**
 * PocketStream Desktop — Network interfaces, subnets, IP config
 */

import * as api from "./tauri-api.ts";
import { $, $$, state, adoptedSubnets, showToast, log } from "./state.ts";
import { resetDiscoveryStatus, hideDiscoveryStatus, renderArpDeviceList } from "./devices.js";
import { handleHardDisconnect, handleReconnect, showModalWithVideo } from "./streaming.js";
import { lastSubnetResults, selectedDevice } from "./store.ts";
import type { SubnetRenderResult } from "./store.ts";
import { formatError } from "./errors.ts";
import type { InterfaceInfo } from "./types.ts";
import * as deviceList from "./device-list.ts";

// Reference $$ once so the import isn't dropped — used elsewhere via the
// state.ts re-export, but TS's verbatimModuleSyntax keeps unused value
// imports as runtime imports. Touching the binding here keeps imports tidy.
void $$;

// ── Interface discovery ─────────────────────────────────────────────

export async function refreshInterfaces(): Promise<void> {
  try {
    const interfaces = await api.listInterfaces();
    const ethList = (interfaces || []).filter((i) => i.is_ethernet);
    // Pick the first truly-connected adapter. "Connected" means link up AND
    // at least one real IPv4 — APIPA (169.254.x.x) addresses don't count,
    // since Windows assigns them when no real network is reachable.
    const eth = ethList.find(
      (i) => i.is_up && i.ips.some((ip) => !ip.address.startsWith("169.254."))
    );

    if (eth) {
      state.activeInterface = eth;
      $("#iface-name").textContent = eth.display_name || eth.name;
      renderSubnetList();
      // Don't wipe the CAM/PTU dropdown here — refreshInterfaces is
      // called from the manual refresh button and during reconnect
      // flows, where wiping the dropdown would lose any populated
      // node entries until the next render.
      updateCameraIpDropdown(lastSubnetResults.get());
      // Recovery — reset the dedup so the next failure toasts again.
      lastAdapterWarningAt = 0;
    } else if (ethList.length > 0) {
      // Adapter is known to Windows but has no IP. Treat this the same
      // as "no ethernet detected" from the user's perspective — the
      // actionable state is identical (click Reset adapter).
      const stale = ethList[0]!;
      state.activeInterface = stale;
      $("#iface-name").textContent =
        (stale.display_name || stale.name) + " (Disconnected)";
      renderSubnetList();
      warnNoEthernet();
    } else {
      state.activeInterface = null;
      $("#iface-name").textContent = "None found";
      warnNoEthernet();
    }
  } catch (e) {
    console.error("Failed to list interfaces:", e);
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
    "No Ethernet detected — check Ethernet connection and/or reset Ethernet adapter",
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
  api.onEvent<InterfaceInfo>("interface-status-changed", (iface) => {
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
    // Capture the CAM/PTU selections BEFORE updateCameraIpDropdown
    // wipes them below — otherwise handleHardDisconnect would
    // snapshot an empty PTU value and auto-resume on replug wouldn't
    // restore it. (camera_ip has a state.config fallback because it
    // persists; ptu_ip is session-only so the dropdown value is the
    // sole source of truth.)
    handleHardDisconnect("Ethernet disconnected");
    state.activeInterface = null;
    $("#iface-name").textContent = "None found";
    // Preserve the backend's DeviceRegistry across a "no adapter"
    // blip so a quick replug restores the UI without waiting for a
    // full re-scan. renderArpDeviceList self-hides when not connected.
    renderArpDeviceList();
    renderSubnetList();
    updateCameraIpDropdown(null);
    hideDiscoveryStatus();
    return;
  }

  // Adapter present but down or APIPA-only. Snapshot first, before
  // dropdown clear wipes PTU selection.
  state.activeInterface = iface;
  handleHardDisconnect("Ethernet disconnected");
  $("#iface-name").textContent =
    (iface.display_name || iface.name) + " (Disconnected)";
  // Preserve the backend's DeviceRegistry — a quick replug of the
  // same cable should restore the Nodes list instantly instead of
  // waiting 6+ seconds for ARP + port scan to rediscover what was
  // there. renderArpDeviceList returns early when the link is down.
  renderArpDeviceList();
  renderSubnetList();
  updateCameraIpDropdown(null);
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
  // Preserve the existing CAM/PTU dropdown — the backend registry
  // hasn't changed, so wiping the dropdown to null would just make
  // cached/discovered nodes vanish until the next render cycle (the
  // original cause of the "nodes disappear from dropdown during
  // discovery" bug).
  updateCameraIpDropdown(lastSubnetResults.get());
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

export function renderSubnetList(): void {
  const subnetList = $("#subnet-list");
  if (!state.activeInterface) return;

  const adoptedIpSet = new Set(adoptedSubnets.values());
  // Hide APIPA addresses — Windows leaves them as a secondary after
  // any brief DHCP failure and they can't carry usable traffic, so
  // showing them as if they were a selectable subnet just confuses
  // users (seen on multiple Getac installs in the field).
  const sortedIps = [...state.activeInterface.ips]
    .filter((ip) => !isApipa(ip.address))
    .sort((a, b) => {
      const aAuto = adoptedIpSet.has(a.address) ? 1 : 0;
      const bAuto = adoptedIpSet.has(b.address) ? 1 : 0;
      return aAuto - bAuto;
    });
  let html = sortedIps
    .map((ip) => {
      const isAuto = adoptedIpSet.has(ip.address);
      if (isAuto) {
        return `
        <div class="status-row subnet-row subnet-row-auto" data-subnet="${ip.subnet}">
          <span class="status-label">IP:</span>
          <span class="auto-ip-group">
            <span class="badge-auto">(auto)</span>
            <span class="status-value">${ip.address}/${ip.prefix}</span>
          </span>
        </div>`;
      }
      return `
      <div class="status-row subnet-row" data-subnet="${ip.subnet}">
        <span class="status-label">IP:</span>
        <span class="status-value">${ip.address}/${ip.prefix}</span>
      </div>`;
    })
    .join("");

  // Add auto-adopted subnets (skip if already shown in interface IPs)
  const renderedIps = new Set(state.activeInterface.ips.map((ip) => ip.address));
  for (const [subnet, adoptedIp] of adoptedSubnets) {
    if (renderedIps.has(adoptedIp)) continue;
    html += `
      <div class="status-row subnet-row subnet-row-auto" data-subnet="${subnet}">
        <span class="status-label">IP:</span>
        <span class="auto-ip-group">
          <span class="badge-auto">(auto)</span>
          <span class="status-value">${adoptedIp}/24</span>
        </span>
      </div>`;
  }

  subnetList.innerHTML = html;

  // Wire up remove buttons
  subnetList
    .querySelectorAll<HTMLButtonElement>(".btn-remove-ip")
    .forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const subnet = btn.dataset["removeSubnet"];
        if (!subnet) return;
        try {
          await api.removeAdoptedSubnet(subnet);
          adoptedSubnets.delete(subnet);
          renderSubnetList();
          showToast("Removed adopted IP");
        } catch (err) {
          showToast("Failed to remove: " + formatError(err), true);
        }
      });
    });
}

// ── Camera / PTU IP dropdown ────────────────────────────────────────

// Once-per-session flags so the alias-based auto-select runs exactly
// when the dropdown first has a populated option for the target IP
// — and never again after that. Prevents the auto-default from
// re-applying every render and overriding a user's later manual
// pick (or their deliberate clear back to "-- Select --").
let camDropdownAutoApplied = false;
let ptuDropdownAutoApplied = false;

/** Look up the device IP that the Naming dialog has been assigned a
 *  given role alias for. Aliases are persisted server-side via
 *  set_device_alias and hydrated into the registry from the device
 *  cache on cold start, so this round-trips a role designation
 *  across program restarts. */
function findDeviceIpByAlias(alias: string): string | undefined {
  return deviceList.getDevices().find((r) => r.alias === alias)?.ip;
}

export function updateCameraIpDropdown(
  filteredSubnets: SubnetRenderResult[] | null
): void {
  const select = $<HTMLSelectElement>("#camera-ip");
  const currentVal = select.value;

  let options = '<option value="">-- Select --</option>';

  // Host IPs (skip APIPA — same reasoning as renderSubnetList)
  if (state.activeInterface) {
    const usableIps = state.activeInterface.ips.filter((ip) => !isApipa(ip.address));
    if (usableIps.length > 0) {
      options += '<optgroup label="Host">';
      usableIps.forEach((ip) => {
        options += `<option value="${ip.address}">${ip.address}</option>`;
      });
      options += "</optgroup>";
    }
  }

  // Node IPs (from ARP-discovered + scan results). Each dropdown entry
  // carries its alias inline — sourced from the DeviceRegistry snapshot
  // by the render path in devices.js — so we don't need a separate
  // alias Map here.
  if (filteredSubnets) {
    let hasNodes = false;
    let nodeOptions = "";
    filteredSubnets.forEach((sr) => {
      sr.devices.forEach((d) => {
        hasNodes = true;
        const label = d.alias ? `${d.ip} (${d.alias})` : d.ip;
        nodeOptions += `<option value="${d.ip}">${label}</option>`;
      });
    });
    if (hasNodes) {
      options += `<optgroup label="Nodes">${nodeOptions}</optgroup>`;
    }
  }

  select.innerHTML = options;

  if (currentVal) {
    select.value = currentVal;
  } else if (!camDropdownAutoApplied) {
    // Cold-start auto-select. Prefer the IP saved in config (user's
    // last Start Stream / CAM-role pick) and fall back to whatever
    // device is currently aliased CAM in the Naming dialog. Either
    // way the dropdown returns to the user's last intent across
    // program restarts instead of starting empty.
    const targetIp =
      state.config?.stream.camera_ip || findDeviceIpByAlias("CAM");
    if (
      targetIp &&
      Array.from(select.options).some((o) => o.value === targetIp)
    ) {
      select.value = targetIp;
      selectedDevice.set(targetIp);
      camDropdownAutoApplied = true;
    }
  }

  // Update PTU dropdown with the same options
  const ptuSelect = $<HTMLSelectElement>("#ptu-ip");
  const ptuVal = ptuSelect.value;
  ptuSelect.innerHTML = options;
  if (ptuVal) {
    ptuSelect.value = ptuVal;
  } else if (!ptuDropdownAutoApplied) {
    // PTU has no equivalent in StreamConfig (deliberately session-
    // only there), so the alias is the only persisted breadcrumb.
    const targetIp = findDeviceIpByAlias("PTU");
    if (
      targetIp &&
      Array.from(ptuSelect.options).some((o) => o.value === targetIp)
    ) {
      ptuSelect.value = targetIp;
      ptuDropdownAutoApplied = true;
    }
  }
}

export function setupCameraIpDropdown(): void {
  $<HTMLSelectElement>("#camera-ip").addEventListener("change", (e) => {
    const target = e.target as HTMLSelectElement;
    selectedDevice.set(target.value || null);
    const ip = selectedDevice.get();
    if (state.config && ip) {
      state.config.stream.camera_ip = ip;
    }
  });

  // PTU IP is session-only — the user picks it each launch from the
  // Nodes dropdown. Backend StreamConfig deliberately has no ptu_ip
  // field (asymmetric with camera_ip), since auto-discovery rebuilds
  // the candidate list every session. If we ever want PTU persistence,
  // add `ptu_ip: String` to StreamConfig and read it back on launch
  // before populating the dropdown.
}

// ── IP Configuration dialog ─────────────────────────────────────────

/** Interfaces loaded when dialog opens — used by add/remove handlers. */
let dialogInterfaces: InterfaceInfo[] = [];

export function setupIpConfigDialog(): void {
  const dialog = $<HTMLDialogElement>("#ip-config-dialog");

  // ── Open dialog ──────────────────────────────────────────────────
  $<HTMLButtonElement>("#btn-ip-config").addEventListener("click", async () => {
    const select = $<HTMLSelectElement>("#static-iface");
    select.innerHTML = '<option value="">Loading…</option>';

    await showModalWithVideo(dialog);

    try {
      dialogInterfaces = ((await api.listInterfaces()) || []).filter((i) => i.is_ethernet);
      select.innerHTML = dialogInterfaces
        .map((i) => {
          const ip = i.ips.length > 0 ? i.ips[0]!.address : "no IP";
          return `<option value="${i.name}">${i.display_name || i.name} (${ip})</option>`;
        })
        .join("");
      populateDialogFields();
      await syncModeFromInterface();
    } catch (_) {
      select.innerHTML = '<option value="">Failed to load</option>';
    }
  });

  // Re-populate when interface selection changes
  $<HTMLSelectElement>("#static-iface").addEventListener("change", () => {
    populateDialogFields();
    void syncModeFromInterface();
  });

  // Mode toggle: hide/show the static-only fields. Applying happens via
  // the existing Apply button — see branch below.
  $<HTMLInputElement>("#ip-mode-dhcp").addEventListener("change", updateModeVisibility);
  $<HTMLInputElement>("#ip-mode-static").addEventListener("change", updateModeVisibility);

  // ── Add secondary IP ─────────────────────────────────────────────
  $<HTMLButtonElement>("#btn-add-sec-ip").addEventListener("click", async () => {
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

  // ── Apply (DHCP or primary IP, branched by mode) ─────────────────
  $<HTMLButtonElement>("#ip-config-apply").addEventListener("click", async () => {
    const iface = $<HTMLSelectElement>("#static-iface").value;
    if (!iface) {
      showToast("Select an interface", true);
      return;
    }

    const spinner = $<HTMLElement>("#ip-config-spinner");
    const dhcpMode = $<HTMLInputElement>("#ip-mode-dhcp").checked;

    if (dhcpMode) {
      spinner.style.display = "";
      try {
        await api.setDhcp(iface);
        showToast("Switched to DHCP");
        dialog.close();
        await refreshInterfaces();
      } catch (e) {
        showToast("Failed: " + formatError(e), true);
      }
      spinner.style.display = "none";
      return;
    }

    const ip = $<HTMLInputElement>("#static-ip").value.trim();
    const mask = $<HTMLInputElement>("#static-mask").value.trim();
    const gw = $<HTMLInputElement>("#static-gateway").value.trim() || null;
    if (!ip || !mask) {
      showToast("Fill in address and mask", true);
      return;
    }
    spinner.style.display = "";
    try {
      await api.setStaticIp(iface, ip, mask, gw);
      showToast("Primary IP updated");
      dialog.close();
      await refreshInterfaces();
    } catch (e) {
      showToast("Failed: " + formatError(e), true);
    }
    spinner.style.display = "none";
  });
}

/** Hide or show the static-only fields based on which radio is selected. */
function updateModeVisibility(): void {
  const isStatic = $<HTMLInputElement>("#ip-mode-static").checked;
  $<HTMLElement>("#ip-static-section").style.display = isStatic ? "" : "none";
}

/** Read the current DHCP state for the selected interface and set the
 *  radio accordingly. Errors are non-fatal — the radio falls back to its
 *  prior position (defaulting to Static for fresh opens). */
async function syncModeFromInterface(): Promise<void> {
  const name = $<HTMLSelectElement>("#static-iface").value;
  if (!name) return;
  try {
    const isDhcp = await api.getDhcpState(name);
    $<HTMLInputElement>("#ip-mode-dhcp").checked = isDhcp;
    $<HTMLInputElement>("#ip-mode-static").checked = !isDhcp;
  } catch (_) {
    // Leave the radio at its current position on error.
  }
  updateModeVisibility();
}

/** Fill primary IP fields and secondary IP list from the selected interface. */
function populateDialogFields(): void {
  const name = $<HTMLSelectElement>("#static-iface").value;
  const iface = dialogInterfaces.find((i) => i.name === name);
  if (!iface) return;

  // Find the first non-auto-adopted, non-APIPA IP as primary. Without
  // the APIPA filter, an adapter with a stale 169.254.* secondary IP
  // ahead of the real DHCP IP would surface APIPA as the "primary" in
  // the dialog — and the user could overwrite their real config by
  // hitting Apply.
  const adoptedIps = new Set(adoptedSubnets.values());
  const primary =
    iface.ips.find((ip) => !adoptedIps.has(ip.address) && !isApipa(ip.address)) ||
    iface.ips.find((ip) => !adoptedIps.has(ip.address)) ||
    iface.ips[0];
  $<HTMLInputElement>("#static-ip").value = primary ? primary.address : "";
  $<HTMLInputElement>("#static-mask").value = primary ? prefixToMask(primary.prefix) : "255.255.255.0";
  $<HTMLInputElement>("#static-gateway").value = "";

  // Secondary = all IPs except the primary
  renderSecondaryIps(iface, primary);
}

/** Render the secondary IP list with remove buttons. */
function renderSecondaryIps(
  iface: InterfaceInfo,
  primary: { address: string } | undefined
): void {
  const list = $("#secondary-ip-list");
  const secondaries = iface.ips.filter((ip) => !primary || ip.address !== primary.address);

  if (secondaries.length === 0) {
    list.innerHTML = '<p class="placeholder-text" style="padding:8px">No secondary IPs</p>';
    return;
  }

  // Only the specific IPs we auto-adopted carry the "(auto)" badge.
  // adoptedSubnets is keyed by subnet → IP we added on that subnet; a
  // user-set static IP on the same /24 is a different value and must
  // not get tagged "auto" just because the subnet is in the map.
  const adoptedIpSet = new Set(adoptedSubnets.values());
  list.innerHTML = secondaries
    .map((ip) => {
      const isAuto = adoptedIpSet.has(ip.address);
      const badge = isAuto ? '<span class="badge-auto">(auto)</span>' : "";
      return `<div class="secondary-ip-item">
        <span>${ip.address}/${ip.prefix} ${badge}</span>
        <button class="btn-remove-ip" data-remove-sec-ip="${ip.address}" title="Remove">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
        </button>
      </div>`;
    })
    .join("");

  // Wire remove buttons
  list
    .querySelectorAll<HTMLButtonElement>("[data-remove-sec-ip]")
    .forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ip = btn.dataset["removeSecIp"];
        if (!ip) return;
        const ifaceName = $<HTMLSelectElement>("#static-iface").value;
        const spinner = $<HTMLElement>("#ip-config-spinner");
        spinner.style.display = "";
        try {
          await api.removeSecondaryIp(ifaceName, ip);
          // Also remove from adopted map if it was auto-adopted
          for (const [subnet, adoptedIp] of adoptedSubnets) {
            if (adoptedIp === ip) {
              adoptedSubnets.delete(subnet);
              break;
            }
          }
          showToast(`Removed ${ip}`);
          await reloadDialogInterfaces();
        } catch (e) {
          showToast("Failed: " + formatError(e), true);
        }
        spinner.style.display = "none";
      });
    });
}

/** Reload interfaces and refresh dialog fields without closing. */
async function reloadDialogInterfaces(): Promise<void> {
  try {
    dialogInterfaces = ((await api.listInterfaces()) || []).filter((i) => i.is_ethernet);
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
