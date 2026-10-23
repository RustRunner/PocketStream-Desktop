/** Current PC address ownership is separate from a node's MAC/presence. */
import * as api from "./tauri-api.ts";
import type { HostIpOwner } from "./types.ts";

let owners: HostIpOwner[] = [];
let revision = 0;
let refreshRequest = 0;
let starting: Promise<void> | null = null;
const subscribers = new Set<() => void>();

export function forIp(ip: string): { adapters: string[]; message: string } | null {
  const adapters = [...new Set(owners.filter((owner) => owner.address === ip).map((owner) => owner.adapter_name))].sort();
  return adapters.length ? {
    adapters,
    message: `IP conflict: ${ip} is also assigned to this PC (${adapters.join(", ")}). Change the device's IP or the PC's address to restore full access.`,
  } : null;
}

export function subscribe(callback: () => void): () => void {
  subscribers.add(callback);
  return () => subscribers.delete(callback);
}

function accept(next: HostIpOwner[]): void {
  owners = Array.isArray(next) ? next : [];
  revision++;
  for (const callback of subscribers) callback();
}

export async function refresh(): Promise<void> {
  const requested = revision, request = ++refreshRequest;
  const snapshot = await api.getHostIpOwners();
  // A later event or newer request must not be overwritten by an old reply.
  if (revision === requested && request === refreshRequest) accept(snapshot);
}

export function start(): Promise<void> {
  starting ??= (async () => {
    await api.onEvent<HostIpOwner[]>("host-ip-owners-changed", accept);
    await refresh();
  })();
  return starting;
}
