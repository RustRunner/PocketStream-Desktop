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

export function setupIpConfigDialog() {
  const dialog = $("#ip-config-dialog");
  let activeMode = "static";

  // Open dialog
  $("#btn-ip-config").addEventListener("click", async () => {
    try {
      const interfaces = await api.listInterfaces();
      const select = $("#static-iface");
      select.innerHTML = (interfaces || [])
        .filter((i) => i.is_ethernet)
        .map((i) => `<option value="${i.name}">${i.display_name || i.name} (${i.ip || "no IP"})</option>`)
        .join("");
    } catch (_) {}

    api.setVideoVisible(false);
    dialog.showModal();
    dialog.addEventListener("close", () => api.setVideoVisible(true), { once: true });
  });

  // Mode toggle within dialog
  $$("[data-ip-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("[data-ip-mode]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeMode = btn.dataset.ipMode;

      $$("#ip-config-static, #ip-config-dhcp-client, #ip-config-dhcp-server").forEach(
        (s) => (s.style.display = "none")
      );
      $(`#ip-config-${activeMode}`).style.display = "";
    });
  });

  $("#ip-config-cancel").addEventListener("click", () => dialog.close());

  $("#ip-config-apply").addEventListener("click", async () => {
    if (activeMode === "static") {
      const iface = $("#static-iface").value;
      const ip = $("#static-ip").value;
      const mask = $("#static-mask").value;
      const gw = $("#static-gateway").value || null;

      if (!iface || !ip || !mask) {
        showToast("Please fill in all required fields", true);
        return;
      }

      try {
        await api.setStaticIp(iface, ip, mask, gw);
        $("#ip-mode").textContent = "Static";
        showToast("Static IP assigned");
        dialog.close();
        await refreshInterfaces();
      } catch (e) {
        showToast("Failed: " + e, true);
      }
    } else if (activeMode === "dhcp-client") {
      $("#ip-mode").textContent = "DHCP Client";
      showToast("DHCP Client — coming soon");
      dialog.close();
    } else if (activeMode === "dhcp-server") {
      $("#ip-mode").textContent = "DHCP Server";
      showToast("DHCP Server — coming soon");
      dialog.close();
    }
  });
}
