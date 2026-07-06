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

import { state, adoptedSubnets } from "./state.ts";
import type { DeviceRecord } from "./types.ts";

// ── Scanned-IP tracking (deduplicates port scans this session) ────

const scannedIps = new Set<string>();

export function isIpScanned(ip: string): boolean {
  return scannedIps.has(ip);
}

/** Mark `ip` as scanned. Pass `clear=true` to allow it to be re-scanned
 *  if the device ever returns (called when a cached entry is forgotten). */
export function markIpScanned(ip: string, clear = false): void {
  if (clear) {
    scannedIps.delete(ip);
  } else {
    scannedIps.add(ip);
  }
}

/** Reset all scanned-IP tracking. Used on manual refresh / reconnect
 *  paths so the next discovery cycle starts fresh. */
export function clearScannedIps(): void {
  scannedIps.clear();
}

// ── Routing helper ────────────────────────────────────────────────

/** Parse a dotted-quad IPv4 string to a uint32. Returns null if it's
 *  not a well-formed IPv4 address. */
function ipv4ToInt(addr: string): number | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = n * 256 + octet;
  }
  return n >>> 0;
}

/** Network mask (as uint32) for a CIDR prefix length. */
function maskForPrefix(prefix: number): number {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xffffffff;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/** Split "a.b.c.d/p" into [address-as-int, prefix]. Returns null on
 *  malformed input. */
function parseCidr(cidr: string): [number, number] | null {
  const slash = cidr.indexOf("/");
  if (slash < 0) return null;
  const addr = ipv4ToInt(cidr.slice(0, slash));
  const prefix = Number(cidr.slice(slash + 1));
  if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return null;
  }
  return [addr, prefix];
}

/** True if a host address lies within `subnet`, using the subnet's
 *  prefix. */
function addrInSubnet(hostAddr: number, subnet: string): boolean {
  const parsed = parseCidr(subnet);
  if (!parsed) return false;
  const [subnetAddr, subnetPrefix] = parsed;
  const mask = maskForPrefix(subnetPrefix);
  return ((hostAddr & mask) >>> 0) === ((subnetAddr & mask) >>> 0);
}

/** True if a host address (with its own prefix) shares an on-link
 *  network with the target subnet. Because CIDR blocks either nest or
 *  are disjoint, comparing both at the coarser of the two prefixes is
 *  exactly the on-link containment test — it handles a host on a wider
 *  network (e.g. /16) that still reaches the device's /24. */
function sharesNetwork(hostAddr: number, hostPrefix: number, subnet: string): boolean {
  const parsed = parseCidr(subnet);
  if (!parsed) return false;
  const [subnetAddr, subnetPrefix] = parsed;
  const mask = maskForPrefix(Math.min(hostPrefix, subnetPrefix));
  return ((hostAddr & mask) >>> 0) === ((subnetAddr & mask) >>> 0);
}

/** Check whether the host currently has an on-link route to `subnet`
 *  (a CIDR like "192.168.1.0/24"), via either an adopted secondary IP
 *  bound for it or a live interface IP — honoring the real prefixes on
 *  both sides rather than assuming /24. */
export function hasRouteToSubnet(subnet: string): boolean {
  // Adopted secondary IP explicitly bound for this subnet. Cross-check
  // that the recorded IP actually falls inside the subnet before
  // trusting the entry, so a stale/mismatched map row can't fake a route.
  const adoptedIp = adoptedSubnets.get(subnet);
  if (adoptedIp) {
    const n = ipv4ToInt(adoptedIp);
    if (n !== null && addrInSubnet(n, subnet)) return true;
  }
  // Live interface IPs, each carrying its own prefix.
  if (!state.activeInterface) return false;
  return state.activeInterface.ips.some((ip) => {
    const n = ipv4ToInt(ip.address);
    return n !== null && sharesNetwork(n, ip.prefix, subnet);
  });
}

// ── Device visibility ─────────────────────────────────────────────

/** IPs that belong to the host itself — the active interface's
 *  addresses plus any adopted secondary IPs. A registry row at one of
 *  these is us, not a discovered node, and is never shown. */
function ownHostIps(): Set<string> {
  const ips = new Set<string>();
  if (state.activeInterface) {
    for (const ip of state.activeInterface.ips) ips.add(ip.address);
  }
  for (const ip of adoptedSubnets.values()) ips.add(ip);
  return ips;
}

/** Filter a registry snapshot down to the nodes worth showing the user.
 *  Shared by the Nodes panel and the Add/Remove Nodes dialog so the two
 *  never disagree about what counts as a node:
 *    - the host's own IPs are dropped
 *    - manual pins always qualify (they carry no scan result yet)
 *    - everything else needs at least one discovered open port
 *
 *  `panelStrict` layers on the Nodes-panel-only exclusions that the
 *  manager dialog must NOT apply (the dialog has to keep listing these
 *  so the user can remove them):
 *    - cached-only entries on subnets we can't currently route to
 *    - ghost records whose MAC matches our own adapter (stale gratuitous
 *      ARP captured while binding a secondary IP)
 */
export function visibleDevices(
  records: DeviceRecord[],
  panelStrict = false
): DeviceRecord[] {
  const ownIps = ownHostIps();
  const ownMac = state.activeInterface?.mac?.toLowerCase() || null;
  return records.filter((r) => {
    if (ownIps.has(r.ip)) return false;
    if (panelStrict) {
      if (r.status === "cached_only" && !hasRouteToSubnet(r.subnet)) return false;
      if (ownMac && r.mac.toLowerCase() === ownMac) return false;
    }
    if (r.mac.startsWith("manual:")) return true;
    return r.open_ports.length > 0;
  });
}
