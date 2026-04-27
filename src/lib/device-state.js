/**
 * Shared state and pure helpers used by both the discovery/scan path
 * (devices.js) and the persistent cache path (device-cache.js). Lives
 * here to break the previous circular import — both modules were each
 * other's transitive dependency through these symbols.
 *
 * Nothing in this file touches the DOM. Everything is module-local
 * state plus small pure helpers; safe to import from anywhere.
 */

import { state, adoptedSubnets } from "./state.js";

// ── Cache-verification status ─────────────────────────────────────
// The render path reads these to decide which devices get "verifying"
// vs "offline" badges. The cache module mutates them as targeted
// scans complete or fail.

/** IPs of cached devices that haven't been verified by a fresh scan yet. */
export const verifyingDevices = new Set();

/** IPs of cached devices whose verification scan failed (no open ports
 *  or network error). Stay in the list so the user can still see what
 *  was last known, but are visually marked as not-currently-reachable. */
export const offlineDevices = new Set();

/** MACs hydrated from the on-disk cache but not (yet) confirmed by a
 *  live ARP discovery in this session. The render path scopes these
 *  to currently-routable subnets — stale ghosts from a previous network
 *  stay in the cache file and reappear when the subnet becomes
 *  routable again. */
export const cachedOnlyMacs = new Set();

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

// ── Render-callback registry ──────────────────────────────────────
// device-cache.js used to import renderArpDeviceList directly from
// devices.js (which was the other half of the circular import). It now
// publishes a "devices changed" event via this registry; the rendering
// module subscribes to it at startup. Keeps the cache module DOM-free.

let onDevicesChangedCb = () => {};

/** Register the function that should be called whenever the cache
 *  module mutates verifying / offline state in a way that affects how
 *  devices should render. devices.js calls this with renderArpDeviceList
 *  during init. */
export function setOnDevicesChanged(fn) {
  if (typeof fn === "function") {
    onDevicesChangedCb = fn;
  }
}

/** Trigger the registered render callback. Internal use by device-cache.js
 *  when verification flips a device to verified/offline. */
export function notifyDevicesChanged() {
  onDevicesChangedCb();
}
