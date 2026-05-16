/**
 * PocketStream Desktop — Shared state & utilities
 */

import type { AppSettings, InterfaceInfo } from "./types.ts";
import { logToFile } from "./tauri-api.ts";

// ── Shared mutable state ────────────────────────────────────────────

/** Top-level mutable state shared across modules. Field shapes match
 *  the matching Rust IPC types. New cross-module state should land in
 *  `store.js` with a subscribe/notify accessor instead of being added
 *  here — this object is kept around for the legacy fields that haven't
 *  been migrated yet. */
export interface AppState {
  config: AppSettings | null;
  activeInterface: InterfaceInfo | null;
  isStreaming: boolean;
  isRtspRunning: boolean;
  isRecording: boolean;
  /** Set by streaming.js when the connection drops mid-session. The
   *  video child window is hidden and the "Stream Lost..." overlay is
   *  shown until the next successful health-check or manual stop. */
  streamLost?: boolean;
}

export const state: AppState = {
  config: null,
  activeInterface: null,
  isStreaming: false,
  isRtspRunning: false,
  isRecording: false,
};
// `selectedDevice` and `lastSubnetResults` previously lived here; they
// are now in src/lib/store.js with subscribe/notify accessors. New
// shared mutable state should land in store.js, not here.
//
// Device records (formerly arpDevices, tcpScanResults, nodeAliases)
// now live entirely on the backend's DeviceRegistry; the frontend
// reads them via src/lib/device-list.js's subscribe accessor.

/** Subnet -> adopted secondary IP string. Mirrored from the backend's
 *  `subnet-adopted` events; used by the routing helper and the subnet
 *  list renderer. */
export const adoptedSubnets: Map<string, string> = new Map();

// ── DOM helpers ─────────────────────────────────────────────────────

/** querySelector with a generic element type. Defaults to HTMLElement
 *  for the common case; pass a more specific type when you need
 *  `.value` / `.checked` / etc. — e.g., `$<HTMLInputElement>("#x")`.
 *
 *  Returns the cast as non-null for ergonomics: every consumer in this
 *  codebase queries by an ID that is statically present in index.html,
 *  so a null return would just push a check to every site without
 *  catching real bugs. If a selector starts producing null at runtime,
 *  the resulting `Cannot read properties of null` is the real signal
 *  and the right fix is at that call site, not here. */
export const $ = <E extends Element = HTMLElement>(sel: string): E =>
  document.querySelector(sel) as E;

export const $$ = <E extends Element = HTMLElement>(sel: string): NodeListOf<E> =>
  document.querySelectorAll(sel) as NodeListOf<E>;

// ── Utilities ───────────────────────────────────────────────────────

export function log(msg: string): void {
  console.log(`[PocketStream] ${msg}`);
  // Mirror to the backend log file too — without this, diagnostic
  // breadcrumbs left around stream-lifecycle paths (debounce
  // suppression, stall recovery attempts, click-ignored notices)
  // only land in DevTools and are invisible when a user sends in
  // pocketstream.log to investigate a drop.
  logToFile("info", msg);
}

/** Escape HTML special characters to prevent injection via innerHTML. */
export function escapeHtml(str: unknown): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function showToast(message: string, isError = false): void {
  // Write toast messages to the log file for diagnostics
  logToFile(isError ? "error" : "info", `toast: ${message}`);

  const existing = document.querySelector(".toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = `toast ${isError ? "toast-error" : ""}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    background: ${isError ? "var(--md-error)" : "var(--md-surface-variant)"};
    color: ${isError ? "var(--md-on-error)" : "var(--md-on-surface)"};
    padding: 12px 24px;
    border-radius: var(--md-radius-sm);
    font-size: 14px;
    z-index: 1000;
    box-shadow: var(--md-elevation-2);
    animation: toast-in 200ms ease-out;
  `;

  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 200ms";
    setTimeout(() => toast.remove(), 200);
  }, 3000);
}

export function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

// ── Toast animation keyframe (side effect) ──────────────────────────

const style = document.createElement("style");
style.textContent = `
  @keyframes toast-in {
    from { opacity: 0; transform: translateX(-50%) translateY(10px); }
    to { opacity: 1; transform: translateX(-50%) translateY(0); }
  }
`;
document.head.appendChild(style);
