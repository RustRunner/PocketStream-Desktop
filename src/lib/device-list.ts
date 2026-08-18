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
 * This module never changes records speculatively in response to UI
 * actions. Writers go through backend IPC; the usual update path is a
 * device-list-changed event. Alias writes additionally return their
 * authoritative post-write snapshot so a no-op/stale action (which has
 * no event to emit) still reconciles immediately. The frontend therefore
 * never has to guess what the backend accepted.
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

// ── Authoritative mutations ─────────────────────────────────────────

/** Serialize role writes and replace the mirror only with the snapshot
 *  returned by the backend after that write. Serializing prevents two
 *  quick picks on different rows from applying their response snapshots
 *  out of order. */
let aliasWriteTail: Promise<void> = Promise.resolve();

export function setAlias(ip: string, alias: string): Promise<void> {
  const write = aliasWriteTail.then(async () => {
    const snapshot = await api.setDeviceAlias(ip, alias);
    setSnapshot(snapshot);

    // `set_alias` deliberately leaves an unknown IP untouched so a stale
    // UI action cannot demote the real CAM/PTU holder. Treat that safe
    // backend no-op as an actionable UI error after reconciling the stale
    // row away, rather than reporting success that did not apply.
    const applied = snapshot.some((record) => record.ip === ip && record.alias === alias);
    if (!applied) {
      throw new Error(`Device ${ip} is no longer available; refresh Nodes and try again`);
    }
  });

  // Keep the queue live after a rejected write while returning the real
  // rejection to this caller.
  aliasWriteTail = write.catch(() => undefined);
  return write;
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
