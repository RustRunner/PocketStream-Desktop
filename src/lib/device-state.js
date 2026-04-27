/**
 * Frontend-only helpers used by the discovery + scan flows.
 *
 * Used to also own the verifyingDevices / offlineDevices / cachedOnlyMacs
 * Sets and a render-callback registry; both are gone now that the
 * backend's DeviceRegistry is the single source of truth and per-device
 * status (live / verifying / offline / cached_only) lives on each
 * record. Renders are driven by `device-list.js`'s subscribe accessor.
 *
 * Nothing in this file touches the DOM. Everything is module-local
 * state plus small pure helpers; safe to import from anywhere.
 */

import { state, adoptedSubnets } from "./state.js";

// ── Scanned-IP tracking (deduplicates port scans this session) ────

const scannedIps = new Set();

export function isIpScanned(ip) {
  return scannedIps.has(ip);
}

/** Mark `ip` as scanned. Pass `clear=true` to allow it to be re-scanned
 *  if the device ever returns (called when a cached entry is forgotten). */
export function markIpScanned(ip, clear = false) {
  if (clear) {
    scannedIps.delete(ip);
  } else {
    scannedIps.add(ip);
  }
}

/** Reset all scanned-IP tracking. Used on manual refresh / reconnect
 *  paths so the next discovery cycle starts fresh. */
export function clearScannedIps() {
  scannedIps.clear();
}

// ── Routing helper ────────────────────────────────────────────────

/** Check if we have an IP on the same /24 subnet (native or adopted). */
export function hasRouteToSubnet(subnet) {
  // Check adopted subnets first
  if (adoptedSubnets.has(subnet)) return true;
  // Check native interface IPs
  if (!state.activeInterface) return false;
  return state.activeInterface.ips.some((ip) => {
    const parts = ip.address.split(".");
    if (parts.length !== 4) return false;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24` === subnet;
  });
}
