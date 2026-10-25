import type { BindScope, FirewallOutcome } from "./types.ts";

export function formatBindScope(scope: BindScope | undefined): string {
  if (!scope) return "No active listener";
  switch (scope.kind) {
    case "unknown": return `Binding unknown: ${scope.reason}`;
    case "interface": return `Bound on ${scope.alias}: ${scope.address} (IPv4)`;
    case "all_addresses": return `Bound on all IPv4 addresses: ${scope.addresses.map(a => `${a.address} (${a.alias})`).join(", ") || "no local addresses observed"}`;
  }
}

export function formatFirewallOutcome(outcome: FirewallOutcome | undefined): string {
  if (!outcome || outcome.state === "inactive") return "Windows rule inactive";
  if (outcome.state === "unavailable") return `Windows rule unavailable: ${outcome.reason}`;
  if (outcome.state === "failed") return `Windows rule failed (${outcome.stage}): ${outcome.reason}${outcome.uncertain ? "; reconciliation required" : ""}`;
  return `Windows rule applied${outcome.observed_block_rules.length ? `; preserved Windows block rules: ${outcome.observed_block_rules.join(", ")}` : ""}`;
}

/** Render one measured output copy and, for fan-out of two or more clients,
 * the explicitly estimated aggregate offered payload rate. */
export function formatRestreamBitrate(kbps: number, clients: number): string {
  const single = Math.max(0, Number.isFinite(kbps) ? kbps : 0);
  const formatted = `${single.toFixed(1)} kbps`;
  return clients >= 2
    ? `${formatted} / ~${(single * clients).toFixed(1)} kbps aggregate`
    : formatted;
}
