import type { BindScope, FirewallOutcome } from "./types.ts";

export function formatBindScope(scope: BindScope | undefined): string {
  if (!scope) return "No active listener";
  switch (scope.kind) {
    case "unknown": return `Binding unknown: ${scope.reason}`;
    case "interface": return `Bound on ${scope.alias}: ${scope.address} (IPv4)`;
    case "all_addresses": return `Bound on all IPv4 addresses: ${scope.addresses.map(a => `${a.address} (${a.alias})`).join(", ") || "no local addresses observed"}`;
  }
}

export interface PolicyPresentation {
  classification: "applied" | "warning" | "inactive";
  text: string;
  detail: string;
  shortReason: string;
}

/** Last policy observation only; this does not measure remote connectivity. */
export function presentFirewallPolicy(outcome: FirewallOutcome | undefined): PolicyPresentation {
  const compact = (text: string) => text.length > 150 ? `${text.slice(0, 147)}…` : text;
  const refresh = "Stop, resolve the reported problem as needed, then start the server to refresh this observation.";
  const administrator = "Restart PocketStream from the installed administrator shortcut to manage the Windows rule.";
  if (!outcome) {
    const text = "Windows rule outcome unavailable";
    return { classification: "warning", text, detail: `${text}. ${refresh}`, shortReason: text };
  }
  if (outcome.state === "inactive") {
    return { classification: "inactive", text: "Windows rule inactive", detail: `Windows rule inactive. ${refresh}`, shortReason: "Windows rule inactive" };
  }
  if (outcome.state === "applied") {
    if (outcome.observed_block_rules.length) {
      return {
        classification: "warning", text: "Applied; possible Block-rule conflict",
        shortReason: "Windows rule observation reports a possible Block-rule conflict.",
        detail: `Applied${outcome.verified_shape ? " (last verified)" : "; shape verification missing"}. Observed Block rules: ${outcome.observed_block_rules.join(", ")}. Review Block rules for pocketstream-desktop.exe in Windows Defender Firewall with Advanced Security → Inbound Rules. Check whether they are enabled and apply to this output before changing them. Stop and start the server to refresh this observation.`,
      };
    }
    const text = outcome.verified_shape ? "Applied (last verified)" : "Applied; shape verification missing";
    return { classification: outcome.verified_shape ? "applied" : "warning", text,
      detail: `${text}. This is the last Windows rule observation. ${refresh}`, shortReason: text };
  }
  const description = outcome.state === "failed"
    ? `Windows rule failed (${outcome.stage}): ${outcome.reason}`
    : `Windows rule unavailable: ${outcome.reason}`;
  let guidance = refresh;
  if (outcome.state === "failed" && outcome.uncertain) {
    guidance = "Windows rule state is uncertain. Stop the server to attempt rule retirement, then start again. If uncertainty remains, restart PocketStream and resolve any startup reconciliation error.";
  } else if ((outcome.state === "failed" && outcome.stage === "access") || /administrator|elevat|access denied/i.test(outcome.reason)) {
    guidance = administrator;
  } else if (outcome.state === "failed" && ["input", "inventory", "ownership", "trusted_modules"].includes(outcome.stage)) {
    guidance = `Review the reported conflict or installation. ${refresh}`;
  }
  return { classification: "warning", text: compact(description), detail: `${description}. ${guidance}`, shortReason: compact(description) };
}

export function formatFirewallOutcome(outcome: FirewallOutcome | undefined): string {
  return presentFirewallPolicy(outcome).detail;
}

export function formatFirewallRetry(seconds: number | null | undefined): string {
  if (seconds == null) return "";
  return seconds > 0 ? `Retrying in ${Math.ceil(seconds)} s` : "Retry requested / in progress";
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
