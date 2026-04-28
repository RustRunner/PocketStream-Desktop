/**
 * PocketStream Desktop — Shared state & utilities
 */

const invoke = window.__TAURI__?.core?.invoke;

// ── Shared mutable state ────────────────────────────────────────────

export const state = {
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
export const adoptedSubnets = new Map();

// ── DOM helpers ─────────────────────────────────────────────────────

export const $ = (sel) => document.querySelector(sel);
export const $$ = (sel) => document.querySelectorAll(sel);

// ── Utilities ───────────────────────────────────────────────────────

export function log(msg) {
  console.log(`[PocketStream] ${msg}`);
}

/** Escape HTML special characters to prevent injection via innerHTML. */
export function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function showToast(message, isError = false) {
  // Write toast messages to the log file for diagnostics
  if (invoke) {
    invoke("log_frontend", {
      level: isError ? "error" : "info",
      message: `toast: ${message}`,
    }).catch(() => {});
  }

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

export function formatUptime(secs) {
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
