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
 */

import * as api from "./tauri-api.ts";
import { log } from "./state.ts";
import { formatError } from "./errors.ts";
import type { DeviceRecord } from "./types.ts";

// ── Subscribe/notify accessor ─────────────────────────────────────

type Subscriber = (snapshot: DeviceRecord[]) => void;

let value: DeviceRecord[] = [];
const subscribers = new Set<Subscriber>();

function setSnapshot(next: unknown): void {
  // Reference equality is enough — backend always sends a fresh array.
  if (value === next) return;
  value = Array.isArray(next) ? (next as DeviceRecord[]) : [];
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
export function getDevices(): DeviceRecord[] {
  return value;
}

/** Register a callback fired with the latest snapshot whenever it
 *  changes. Returns an unsubscribe function. */
export function subscribe(callback: Subscriber): () => void {
  subscribers.add(callback);
  return () => {
    subscribers.delete(callback);
  };
}

// ── Lookup helpers (read-only views over the snapshot) ───────────

/** Find a record by IP. Returns undefined if not present. */
export function deviceByIp(ip: string | null | undefined): DeviceRecord | undefined {
  if (!ip) return undefined;
  return value.find((r) => r.ip === ip);
}

/** Find a record by MAC. Returns undefined if not present. */
export function deviceByMac(mac: string | null | undefined): DeviceRecord | undefined {
  if (!mac) return undefined;
  return value.find((r) => r.mac === mac);
}

/** Group records by subnet, preserving the registry's sort order. */
export function devicesBySubnet(): Map<string, DeviceRecord[]> {
  const groups = new Map<string, DeviceRecord[]>();
  for (const record of value) {
    const bucket = groups.get(record.subnet);
    if (bucket) {
      bucket.push(record);
    } else {
      groups.set(record.subnet, [record]);
    }
  }
  return groups;
}

// ── Lifecycle ─────────────────────────────────────────────────────

/** Hydrate the snapshot from the backend and start listening for
 *  push updates. Call once during app startup, before any subscriber
 *  expects data to be available. */
export async function start(): Promise<void> {
  // If a push update arrives while we await the cold-start fetch below,
  // it carries the backend's newest snapshot — the initial fetch may
  // predate it. Track that so we don't overwrite the fresher event.
  // Registration itself is awaited: Tauri's listen() is async, and a
  // snapshot emitted before it completes would be dropped entirely,
  // leaving the UI stale until the next backend emit. Awaiting closes
  // that pre-registration window before the fetch begins.
  let eventLanded = false;
  await api.onEvent<DeviceRecord[]>("device-list-changed", (snapshot) => {
    eventLanded = true;
    setSnapshot(snapshot);
  });

  try {
    const initial = await api.getDeviceList();
    if (eventLanded) {
      log("device-list: live event beat initial hydrate; keeping event snapshot");
    } else {
      setSnapshot(initial);
      log(`device-list: hydrated ${value.length} record(s) from backend`);
    }
  } catch (e) {
    log(`device-list: initial hydrate failed: ${formatError(e)}`);
  }
}
