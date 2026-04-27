/**
 * Frontend mirror of the backend's canonical device registry.
 *
 * Single source of truth: the backend. This module just maintains a
 * subscribe-able snapshot of `Vec<DeviceRecord>` that the render path
 * (and anything else that cares) reads from. Updates arrive via the
 * `device-list-changed` event; cold start hydrates via getDeviceList().
 *
 * Replaces the old patchwork of arpDevices + tcpScanResults +
 * nodeAliases Maps and verifyingDevices/offlineDevices/cachedOnlyMacs
 * Sets. All those derived facts now live as fields on a DeviceRecord.
 *
 * This module is *read-only* for callers — it never mutates the list
 * itself in response to UI actions. Writers go through tauri-api.js
 * IPC calls (reportScanResult, setDeviceAlias, setDeviceStatus,
 * forgetDevice); the backend updates the registry, emits a new
 * device-list-changed snapshot, and this module's subscriber picks
 * up the change. That round-trip is the whole point — frontend never
 * gets to disagree with the backend about what the device list is.
 *
 * DeviceRecord shape (defined in src-tauri/src/network/device_registry.rs):
 *   { mac, ip, subnet, open_ports: u16[], alias: string,
 *     status: "live" | "verifying" | "offline" | "cached_only",
 *     first_seen: string, last_seen: string }
 */

import * as api from "./tauri-api.js";
import { log } from "./state.js";
import { formatError } from "./errors.js";

// ── Subscribe/notify accessor ─────────────────────────────────────

let value = [];
const subscribers = new Set();

function setSnapshot(next) {
  // Reference equality is enough — backend always sends a fresh array.
  if (value === next) return;
  value = Array.isArray(next) ? next : [];
  for (const cb of subscribers) {
    try {
      cb(value);
    } catch (e) {
      log(`device-list subscriber threw: ${formatError(e)}`);
    }
  }
}

/** Current snapshot. Reference is replaced on every update — do not
 *  mutate the returned array. */
export function getDevices() {
  return value;
}

/** Register a callback fired with the latest snapshot whenever it
 *  changes. Returns an unsubscribe function. */
export function subscribe(callback) {
  subscribers.add(callback);
  return () => subscribers.delete(callback);
}

// ── Lookup helpers (read-only views over the snapshot) ───────────

/** Find a record by IP. Returns undefined if not present. */
export function deviceByIp(ip) {
  if (!ip) return undefined;
  return value.find((r) => r.ip === ip);
}

/** Find a record by MAC. Returns undefined if not present. */
export function deviceByMac(mac) {
  if (!mac) return undefined;
  return value.find((r) => r.mac === mac);
}

/** Group records by subnet, preserving the registry's sort order. */
export function devicesBySubnet() {
  const groups = new Map();
  for (const record of value) {
    if (!groups.has(record.subnet)) {
      groups.set(record.subnet, []);
    }
    groups.get(record.subnet).push(record);
  }
  return groups;
}

// ── Lifecycle ─────────────────────────────────────────────────────

/** Hydrate the snapshot from the backend and start listening for
 *  push updates. Call once during app startup, before any subscriber
 *  expects data to be available. */
export async function start() {
  api.onEvent("device-list-changed", (snapshot) => {
    setSnapshot(snapshot);
  });

  try {
    const initial = await api.getDeviceList();
    setSnapshot(initial);
    log(`device-list: hydrated ${value.length} record(s) from backend`);
  } catch (e) {
    log(`device-list: initial hydrate failed: ${formatError(e)}`);
  }
}
