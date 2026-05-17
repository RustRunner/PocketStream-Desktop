/**
 * "Add/Remove Nodes" dialog.
 *
 * Unified node manager: adds user-pinned manual nodes (which feed
 * the registry in Static-Manual mode and persist across mode toggles)
 * and removes any node from the registry — manual or discovered.
 *
 * Triggered by clicking the "Nodes" card title.
 */

import * as api from "./tauri-api.ts";
import { $, state, log, escapeHtml, showToast } from "./state.ts";
import * as deviceList from "./device-list.ts";
import { showModalWithVideo } from "./streaming.js";
import { formatError } from "./errors.ts";

interface NodeEntry {
  mac: string;
  ip: string;
  subnet: string;
  alias: string;
  isManual: boolean;
}

/** Render the current node list into the dialog. Called on open and
 *  after any add/remove so the list reflects the latest state without
 *  the user having to close and re-open. */
function renderDialogList(): void {
  const entries: NodeEntry[] = deviceList.getDevices().map((r) => ({
    mac: r.mac,
    ip: r.ip,
    subnet: r.subnet,
    alias: r.alias || "",
    isManual: r.mac.startsWith("manual:"),
  }));
  entries.sort((a, b) => {
    if (a.subnet !== b.subnet) return a.subnet.localeCompare(b.subnet);
    return a.ip.localeCompare(b.ip, undefined, { numeric: true });
  });

  const listEl = $("#cache-dialog-list");
  const emptyEl = $<HTMLElement>("#cache-dialog-empty");
  const clearAllBtn = $<HTMLButtonElement>("#cache-clear-all");

  if (entries.length === 0) {
    listEl.innerHTML = "";
    emptyEl.style.display = "";
    clearAllBtn.disabled = true;
    return;
  }

  emptyEl.style.display = "none";
  clearAllBtn.disabled = false;
  listEl.innerHTML = entries
    .map((e) => {
      const name = e.alias || "(unnamed)";
      const pinBadge = e.isManual
        ? '<span class="cache-item-pin" title="Manually pinned">pin</span>'
        : "";
      return `
          <div class="cache-item" data-mac="${escapeHtml(e.mac)}" data-ip="${escapeHtml(e.ip)}">
            <div class="cache-item-info">
              <div class="cache-item-name">${escapeHtml(name)}${pinBadge}</div>
              <div class="cache-item-detail">
                <span class="cache-item-ip">${escapeHtml(e.ip)}</span>
                <span class="cache-item-subnet">${escapeHtml(e.subnet)}</span>
              </div>
            </div>
            <button class="cache-forget-btn icon-btn small" data-mac="${escapeHtml(e.mac)}" data-ip="${escapeHtml(e.ip)}" data-manual="${e.isManual ? "1" : ""}" title="Remove">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
            </button>
          </div>`;
    })
    .join("");

  // Per-row remove. Manual entries go through removeManualNode (drops
  // the pin from config); everything else goes through forgetDevice
  // (drops from the cache file). The latter survives mode toggles too.
  listEl
    .querySelectorAll<HTMLButtonElement>(".cache-forget-btn")
    .forEach((btn) => {
      btn.addEventListener("click", async () => {
        const mac = btn.dataset["mac"];
        const ip = btn.dataset["ip"];
        const manual = btn.dataset["manual"] === "1";
        try {
          if (manual && ip) {
            await api.removeManualNode(ip);
          } else if (mac) {
            await api.forgetDevice(mac);
          }
        } catch (e) {
          log(`Failed to remove node: ${formatError(e)}`);
        }
        renderDialogList();
      });
    });
}

/** Open the dialog and render the current state. */
async function openCacheDialog(): Promise<void> {
  const dialog = $<HTMLDialogElement>("#cache-dialog");
  if (!dialog) return;

  // Clear the input fields each time the dialog opens so a previous
  // typo doesn't sit there until the user notices it.
  $<HTMLInputElement>("#add-node-ip").value = "";
  $<HTMLInputElement>("#add-node-alias").value = "";

  renderDialogList();
  if (dialog.open) dialog.close();
  await showModalWithVideo(dialog);
}

/** Handle the Add Node button: validate, persist, refresh the list. */
async function handleAddNode(): Promise<void> {
  const ip = $<HTMLInputElement>("#add-node-ip").value.trim();
  const alias = $<HTMLInputElement>("#add-node-alias").value.trim();

  if (!ip) {
    showToast("Enter an IP address", true);
    return;
  }
  // Lightweight IPv4 shape check — backend re-validates, so this is
  // just for a friendlier error before the round-trip.
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    showToast("Invalid IP format", true);
    return;
  }

  // Routability check — informational, doesn't block. Lets the user
  // pre-add nodes for a subnet they're about to configure (e.g.,
  // typing 192.168.1.50 before adding a secondary IP on .100). If
  // the host has no IP on that /24, the dot will stay red until the
  // user adds a matching secondary in IP Config.
  if (!hostHasRouteToIp(ip)) {
    showToast(
      "Heads up: host has no IP on " + nodeSubnet(ip) + " yet — dot will stay red until you add a matching secondary"
    );
  }

  try {
    await api.addManualNode(ip, alias);
    $<HTMLInputElement>("#add-node-ip").value = "";
    $<HTMLInputElement>("#add-node-alias").value = "";
    renderDialogList();
  } catch (e) {
    showToast("Failed to add: " + formatError(e), true);
  }
}

/** Compute the /24 subnet for a node IP, used purely for the
 *  routability warning. Returns the input on parse failure so the
 *  toast still makes sense. */
function nodeSubnet(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

/** True when the host adapter has at least one IP on the same /24
 *  as the target. Conservative — only checks the active interface
 *  (the badge / Apply flow's source of truth). */
function hostHasRouteToIp(targetIp: string): boolean {
  const iface = state.activeInterface;
  if (!iface) return false;
  const parts = targetIp.split(".");
  if (parts.length !== 4) return false;
  const targetPrefix = `${parts[0]}.${parts[1]}.${parts[2]}.`;
  return iface.ips.some((ip) => ip.address.startsWith(targetPrefix));
}

/** Clear All: drops every cached device AND every manual pin. The
 *  user is expected to confirm via the action's destructive styling. */
async function clearAll(): Promise<void> {
  // Pull mac/ip pairs once — clearing mid-iteration would change
  // what deviceList.getDevices() returns and skip entries.
  const targets = deviceList.getDevices().map((r) => ({
    mac: r.mac,
    ip: r.ip,
    isManual: r.mac.startsWith("manual:"),
  }));
  for (const t of targets) {
    try {
      if (t.isManual) {
        await api.removeManualNode(t.ip);
      } else {
        await api.forgetDevice(t.mac);
      }
    } catch (e) {
      log(`Failed to clear ${t.mac}: ${formatError(e)}`);
    }
  }
  // Drop any manual pins not currently in the registry (defensive —
  // a Static-Auto session with persisted pins from a prior Manual
  // session can leave orphans in config that the registry walk above
  // wouldn't have seen).
  try {
    await api.clearManualNodes();
  } catch (e) {
    log(`Failed to clear manual nodes: ${formatError(e)}`);
  }
  renderDialogList();
}

export function setupCacheDialog(): void {
  // Card-footer Configure button — mirrors the Hosts card's IP Config
  // button (same placement, same `text-btn` style).
  $<HTMLButtonElement>("#btn-nodes-config").addEventListener("click", openCacheDialog);
  // Title click is a secondary entry point. Kept so users with the
  // pre-button muscle memory still land in the right place.
  const titleEl = $("#nodes-title");
  if (titleEl) {
    titleEl.addEventListener("click", openCacheDialog);
  }

  const dialog = $<HTMLDialogElement>("#cache-dialog");
  if (!dialog) return;

  $<HTMLButtonElement>("#cache-close").addEventListener("click", () => dialog.close());
  $<HTMLButtonElement>("#cache-clear-all").addEventListener("click", clearAll);
  $<HTMLButtonElement>("#btn-add-node").addEventListener("click", handleAddNode);

  // Enter key in either input field also commits the add — typical
  // form ergonomics for a tight 2-field row.
  $<HTMLInputElement>("#add-node-ip").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleAddNode();
  });
  $<HTMLInputElement>("#add-node-alias").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleAddNode();
  });

  // Re-render when the device list changes (subscribe-based, so an
  // add/remove via Tauri events reflects without manual polling).
  deviceList.subscribe(() => {
    if (dialog.open) renderDialogList();
  });
}
