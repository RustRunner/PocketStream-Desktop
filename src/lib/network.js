/**
 * PocketStream Desktop — Network interfaces, subnets, IP config
 */

import * as api from "./tauri-api.js";
import { $, $$, state, adoptedSubnets, nodeAliases, arpDevices, tcpScanResults, showToast } from "./state.js";
import { resetDiscoveryStatus } from "./devices.js";

// ── Interface discovery ─────────────────────────────────────────────

export async function refreshInterfaces() {
  try {
    const interfaces = await api.listInterfaces();
    if (!interfaces || interfaces.length === 0) {
      $("#iface-name").textContent = "None found";
      return;
    }

    const eth =
      interfaces.find((i) => i.is_up && i.is_ethernet && i.ips.length > 0);

    if (eth) {
      state.activeInterface = eth;
      $("#iface-name").textContent = eth.display_name || eth.name;
      renderSubnetList();
      // Don't wipe the CAM/PTU dropdown here — refreshInterfaces is
      // called from the manual refresh button and during reconnect
      // flows, where wiping the dropdown would lose any populated
      // node entries until the next render.
      updateCameraIpDropdown(state.lastSubnetResults || null);
    } else {
      $("#iface-name").textContent = "None found";
    }
  } catch (e) {
    console.error("Failed to list interfaces:", e);
    $("#iface-name").textContent = "Error";
  }
}

// ── Interface status watcher ────────────────────────────────────────
// Backend polls pnet every 3s (zero network traffic) and emits this
// event when the active Ethernet interface changes state.

export function setupInterfaceWatcher() {
  api.onEvent("interface-status-changed", (iface) => {
    const wasDown = !state.activeInterface || state.activeInterface.ips.length === 0;
    state.activeInterface = iface;

    if (!iface.is_up || iface.ips.length === 0) {
      // ── Disconnected ─────────────────────────────────────────────
      $("#iface-name").textContent =
        (iface.display_name || iface.name) + " (Disconnected)";

      // Clear stale nodes — they're unreachable now
      arpDevices.clear();
      tcpScanResults.clear();
      $("#device-list").innerHTML = "";
      renderSubnetList();
      updateCameraIpDropdown(null);
    } else {
      // ── Connected (or reconnected) ───────────────────────────────
      $("#iface-name").textContent = iface.display_name || iface.name;

      // Refresh the subnet list since adopted IPs may have appeared
      // (load_adopted_from_config completing during cold start triggers
      // this event with the new IP set).
      renderSubnetList();

      // Preserve the existing CAM/PTU dropdown — arpDevices and
      // tcpScanResults haven't changed, so wiping the dropdown to
      // null would just make cached/discovered nodes vanish until the
      // next render cycle (the original cause of the "nodes disappear
      // from dropdown during discovery" bug).
      updateCameraIpDropdown(state.lastSubnetResults || null);

      // If we just came back from disconnected, kick off ARP discovery
      if (wasDown) {
        resetDiscoveryStatus();
        api.startArpDiscovery(iface.name).catch(() => {});
      }
    }
  });
}

// ── Subnet list rendering ───────────────────────────────────────────

export function renderSubnetList() {
  const subnetList = $("#subnet-list");
  if (!state.activeInterface) return;

  const adoptedIpSet = new Set(adoptedSubnets.values());
  const sortedIps = [...state.activeInterface.ips].sort((a, b) => {
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
  subnetList.querySelectorAll(".btn-remove-ip").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const subnet = btn.dataset.removeSubnet;
      try {
        await api.removeAdoptedSubnet(subnet);
        adoptedSubnets.delete(subnet);
        renderSubnetList();
        showToast("Removed adopted IP");
      } catch (err) {
        showToast("Failed to remove: " + err, true);
      }
    });
  });
}

// ── Camera / PTU IP dropdown ────────────────────────────────────────

export function updateCameraIpDropdown(filteredSubnets) {
  const select = $("#camera-ip");
  const currentVal = select.value;

  let options = '<option value="">-- Select --</option>';

  // Host IPs
  if (state.activeInterface) {
    options += '<optgroup label="Host">';
    state.activeInterface.ips.forEach((ip) => {
      options += `<option value="${ip.address}">${ip.address}</option>`;
    });
    options += '</optgroup>';
  }

  // Node IPs (from ARP-discovered + scan results)
  if (filteredSubnets) {
    let hasNodes = false;
    let nodeOptions = "";
    filteredSubnets.forEach((sr) => {
      sr.devices.forEach((d) => {
        hasNodes = true;
        const alias = nodeAliases.get(d.ip);
        const label = alias ? `${d.ip} (${alias})` : d.ip;
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
  }

  // Update PTU dropdown with the same options
  const ptuSelect = $("#ptu-ip");
  const ptuVal = ptuSelect.value;
  ptuSelect.innerHTML = options;
  if (ptuVal) {
    ptuSelect.value = ptuVal;
  }
}

export function setupCameraIpDropdown() {
  $("#camera-ip").addEventListener("change", (e) => {
    state.selectedDevice = e.target.value || null;
    if (state.config && state.selectedDevice) {
      state.config.stream.camera_ip = state.selectedDevice;
    }
  });

  $("#ptu-ip").addEventListener("change", (e) => {
    if (state.config) {
      state.config.stream.ptu_ip = e.target.value || "";
    }
  });
}

// ── IP Configuration dialog ─────────────────────────────────────────

/** Interfaces loaded when dialog opens — used by add/remove handlers. */
let dialogInterfaces = [];

export function setupIpConfigDialog() {
  const dialog = $("#ip-config-dialog");

  // ── Open dialog ──────────────────────────────────────────────────
  $("#btn-ip-config").addEventListener("click", async () => {
    const select = $("#static-iface");
    select.innerHTML = '<option value="">Loading…</option>';

    api.setVideoVisible(false).catch(() => {});
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true).catch(() => {}), { once: true });

    try {
      dialogInterfaces = (await api.listInterfaces() || []).filter((i) => i.is_ethernet);
      select.innerHTML = dialogInterfaces
        .map((i) => {
          const ip = i.ips.length > 0 ? i.ips[0].address : "no IP";
          return `<option value="${i.name}">${i.display_name || i.name} (${ip})</option>`;
        })
        .join("");
      populateDialogFields();
    } catch (_) {
      select.innerHTML = '<option value="">Failed to load</option>';
    }
  });

  // Re-populate when interface selection changes
  $("#static-iface").addEventListener("change", populateDialogFields);

  // ── Add secondary IP ─────────────────────────────────────────────
  $("#btn-add-sec-ip").addEventListener("click", async () => {
    const iface = $("#static-iface").value;
    const ip = $("#add-sec-ip").value.trim();
    const mask = $("#add-sec-mask").value.trim();
    if (!iface || !ip || !mask) {
      showToast("Enter an IP and mask", true);
      return;
    }
    const spinner = $("#ip-config-spinner");
    spinner.style.display = "";
    try {
      await api.addSecondaryIp(iface, ip, mask);
      $("#add-sec-ip").value = "";
      showToast("Secondary IP added");
      await reloadDialogInterfaces();
    } catch (e) {
      showToast("Failed: " + e, true);
    }
    spinner.style.display = "none";
  });

  // ── Cancel ───────────────────────────────────────────────────────
  $("#ip-config-cancel").addEventListener("click", () => dialog.close());

  // ── Apply (primary IP only) ──────────────────────────────────────
  $("#ip-config-apply").addEventListener("click", async () => {
    const iface = $("#static-iface").value;
    const ip = $("#static-ip").value.trim();
    const mask = $("#static-mask").value.trim();
    const gw = $("#static-gateway").value.trim() || null;

    if (!iface || !ip || !mask) {
      showToast("Fill in address and mask", true);
      return;
    }

    const spinner = $("#ip-config-spinner");
    spinner.style.display = "";
    try {
      await api.setStaticIp(iface, ip, mask, gw);
      showToast("Primary IP updated");
      dialog.close();
      await refreshInterfaces();
    } catch (e) {
      showToast("Failed: " + e, true);
    }
    spinner.style.display = "none";
  });
}

/** Fill primary IP fields and secondary IP list from the selected interface. */
function populateDialogFields() {
  const name = $("#static-iface").value;
  const iface = dialogInterfaces.find((i) => i.name === name);
  if (!iface) return;

  // Find the first non-auto-adopted IP as primary
  const adoptedIps = new Set(adoptedSubnets.values());
  const primary = iface.ips.find((ip) => !adoptedIps.has(ip.address)) || iface.ips[0];
  $("#static-ip").value = primary ? primary.address : "";
  $("#static-mask").value = primary ? prefixToMask(primary.prefix) : "255.255.255.0";
  $("#static-gateway").value = "";

  // Secondary = all IPs except the primary
  renderSecondaryIps(iface, primary);
}

/** Render the secondary IP list with remove buttons. */
function renderSecondaryIps(iface, primary) {
  const list = $("#secondary-ip-list");
  const secondaries = iface.ips.filter((ip) => !primary || ip.address !== primary.address);

  if (secondaries.length === 0) {
    list.innerHTML = '<p class="placeholder-text" style="padding:8px">No secondary IPs</p>';
    return;
  }

  list.innerHTML = secondaries
    .map((ip) => {
      const isAuto = adoptedSubnets.has(ip.subnet);
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
  list.querySelectorAll("[data-remove-sec-ip]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.removeSecIp;
      const ifaceName = $("#static-iface").value;
      const spinner = $("#ip-config-spinner");
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
        showToast("Failed: " + e, true);
      }
      spinner.style.display = "none";
    });
  });
}

/** Reload interfaces and refresh dialog fields without closing. */
async function reloadDialogInterfaces() {
  try {
    dialogInterfaces = (await api.listInterfaces() || []).filter((i) => i.is_ethernet);
    populateDialogFields();
    // Also refresh the host card
    await refreshInterfaces();
  } catch (_) {}
}

/** Convert CIDR prefix to dotted mask (e.g. 24 → "255.255.255.0"). */
function prefixToMask(prefix) {
  const bits = prefix >= 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return [bits >>> 24, (bits >>> 16) & 0xFF, (bits >>> 8) & 0xFF, bits & 0xFF].join(".");
}
