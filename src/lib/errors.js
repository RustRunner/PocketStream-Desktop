/**
 * Error helpers for typed AppError responses from the Rust backend.
 *
 * Backend errors serialize as { kind: "<variant>", message: "<display>" }
 * via `AppError::serialize` in `src-tauri/src/error.rs`. Plain `+ e` or
 * `${e}` would render that as "[object Object]" — every toast/log site
 * must funnel through `formatError(e)` to stay readable.
 *
 * `errorKind(e)` returns the discriminator for branching (e.g., to open
 * the Npcap install dialog when `kind === "NpcapMissing"`). Returns null
 * for legacy string errors or anything without a `kind` field.
 */

export function formatError(e) {
  if (e == null) return "Unknown error";
  if (typeof e === "string") return e;
  if (typeof e === "object" && typeof e.message === "string") {
    return e.message;
  }
  return String(e);
}

export function errorKind(e) {
  if (e && typeof e === "object" && typeof e.kind === "string") {
    return e.kind;
  }
  return null;
}
