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
import { log, state } from "./state.ts";
import { formatError } from "./errors.ts";
import { selectedDevice, sessionCamTarget, type DeviceTarget } from "./store.ts";
import type { DeviceRecord } from "./types.ts";

// ── Subscribe/notify accessor ─────────────────────────────────────

type Subscriber = (snapshot: DeviceRecord[]) => void;

let value: DeviceRecord[] = [];
const subscribers = new Set<Subscriber>();

function setSnapshot(next: unknown): void {
  // Reference equality is enough — backend always sends a fresh array.
  if (value === next) return;
  value = Array.isArray(next) ? (next as DeviceRecord[]) : [];
  void followManualBinding();
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

/** Keys are MAC identities or the original manual key, never IPs. */
export function deviceByKey(key: string | null | undefined): DeviceRecord | undefined {
  if (!key) return undefined;
  return value.find((r) => r.mac.toLowerCase() === key.toLowerCase());
}

export const deviceByMac = deviceByKey;

export function targetFor(record: DeviceRecord): DeviceTarget {
  return { key: record.mac, expectedMac: record.mac.startsWith("manual:") ? null : record.mac };
}

/** A missing selected identity never resolves to another record at its address. */
export function resolveTarget(target: DeviceTarget | null): DeviceRecord | undefined {
  if (!target) return undefined;
  const bound = target.key.startsWith("manual:")
    ? state.config?.manual_nodes.find((n) => `manual:${n.ip}` === target.key)?.expected_mac
    : null;
  const expected = target.expectedMac ?? bound;
  const record = deviceByKey(expected ?? target.key);
  if (!record) return undefined;
  if (expected && record.mac.toLowerCase() !== expected.toLowerCase()) return undefined;
  return record;
}

/** Follow a manual key only through the MAC saved by the backend after
 *  fresh proof. Never infer the binding from another record at its IP. */
async function followManualBinding(): Promise<void> {
  const pending = [selectedDevice, sessionCamTarget].map((store) => ({ store, target: store.get() }))
    .filter(({ target }) => target?.key.startsWith("manual:") && !deviceByKey(target.key));
  if (!pending.length) return;
  try {
    const config = await api.getConfig();
    if (state.config) state.config.manual_nodes = config.manual_nodes;
    for (const { store, target } of pending) {
      if (!target || store.get() !== target) continue;
      const record = resolveTarget(target);
      if (record) store.set(targetFor(record));
    }
  } catch (e) {
    log(`manual identity refresh failed: ${formatError(e)}`);
  }
}

export function endpointFor(target: DeviceTarget | null): string | null {
  return resolveTarget(target)?.ip ?? null;
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

export function setAlias(key: string, alias: string): Promise<void> {
  const write = aliasWriteTail.then(async () => {
    const snapshot = await api.setDeviceAlias(key, alias);
    setSnapshot(snapshot);

    // `set_alias` deliberately leaves an unknown key untouched so a stale
    // UI action cannot demote the real CAM/PTU holder. Treat that safe
    // backend no-op as an actionable UI error after reconciling the stale
    // row away, rather than reporting success that did not apply.
    const applied = snapshot.some((record) => record.mac === key && record.alias === alias);
    if (!applied) {
      throw new Error(`Device ${key} is no longer available; refresh Nodes and try again`);
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
