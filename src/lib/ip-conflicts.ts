/** Current PC address ownership is separate from a node's MAC/presence. */
import * as api from "./tauri-api.ts";
import type { HostIpOwner } from "./types.ts";

let owners: HostIpOwner[] = [];
let revision = 0;
let refreshRequest = 0;
let starting: Promise<void> | null = null;
const subscribers = new Set<() => void>();

export function forIp(ip: string): { adapters: string[]; retainedAdapters: string[]; message: string } | null {
  const matches = owners.filter((owner) => owner.address === ip);
  const adapters = [...new Set(matches.map((owner) => owner.adapter_name))].sort();
  const retainedAdapters = [...new Set(matches.filter((owner) => owner.retained_route).map((owner) => owner.adapter_name))].sort();
  return adapters.length ? {
    adapters,
    retainedAdapters,
    message: retainedAdapters.length
      ? `IP conflict: ${ip} is still reserved by this PC (${adapters.join(", ")}). Turning off Wi-Fi alone may not release the address. Fully disable ${retainedAdapters.join(", ")} in Windows Network Connections, or change the PC's address.`
      : `IP conflict: ${ip} is also assigned to this PC (${adapters.join(", ")}). Change the device's IP or the PC's address to restore full access.`,
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
