/**
 * PocketStream Desktop — Network interfaces, subnets, IP config
 */

import * as api from "./tauri-api.js";
import { $, $$, state, adoptedSubnets, nodeAliases, showToast } from "./state.js";

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
      updateCameraIpDropdown(null);
    } else {
      $("#iface-name").textContent = "None found";
    }
  } catch (e) {
    console.error("Failed to list interfaces:", e);
    $("#iface-name").textContent = "Error";
  }
}

// ── Subnet list rendering ───────────────────────────────────────────

export function renderSubnetList() {
  const subnetList = $("#subnet-list");
  if (!state.activeInterface) return;

  let html = state.activeInterface.ips
    .map(
      (ip) => `
      <div class="status-row subnet-row" data-subnet="${ip.subnet}">
        <span class="status-label">IP:</span>
        <span class="status-value">${ip.address}/${ip.prefix}</span>
      </div>`
    )
    .join("");

  // Add auto-adopted subnets
  for (const [subnet, adoptedIp] of adoptedSubnets) {
    html += `
      <div class="status-row subnet-row subnet-row-auto" data-subnet="${subnet}">
        <span class="status-label">IP:</span>
        <span class="status-value">${adoptedIp}/24 <span class="badge-auto">(auto)</span></span>
        <button class="btn-remove-ip" data-remove-subnet="${subnet}" title="Remove adopted IP">&times;</button>
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

    api.setVideoVisible(false);
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true), { once: true });

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
    try {
      await api.addSecondaryIp(iface, ip, mask);
      $("#add-sec-ip").value = "";
      showToast("Secondary IP added");
      await reloadDialogInterfaces();
    } catch (e) {
      showToast("Failed: " + e, true);
    }
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

    try {
      await api.setStaticIp(iface, ip, mask, gw);
      showToast("Primary IP updated");
      dialog.close();
      await refreshInterfaces();
    } catch (e) {
      showToast("Failed: " + e, true);
    }
  });
}

/** Fill primary IP fields and secondary IP list from the selected interface. */
function populateDialogFields() {
  const name = $("#static-iface").value;
  const iface = dialogInterfaces.find((i) => i.name === name);
  if (!iface) return;

  // Primary = first IP
  const primary = iface.ips[0];
  $("#static-ip").value = primary ? primary.address : "";
  $("#static-mask").value = primary ? prefixToMask(primary.prefix) : "255.255.255.0";
  $("#static-gateway").value = "";

  // Secondary = all remaining IPs
  renderSecondaryIps(iface);
}

/** Render the secondary IP list with remove buttons. */
function renderSecondaryIps(iface) {
  const list = $("#secondary-ip-list");
  const secondaries = iface.ips.slice(1);

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
        <button class="btn-remove-ip" data-remove-sec-ip="${ip.address}" title="Remove">×</button>
      </div>`;
    })
    .join("");

  // Wire remove buttons
  list.querySelectorAll("[data-remove-sec-ip]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.removeSecIp;
      const ifaceName = $("#static-iface").value;
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
