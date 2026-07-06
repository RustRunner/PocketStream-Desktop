/**
 * Error helpers for typed AppError responses from the Rust backend.
 *
 * Backend errors serialize as { kind: "<variant>", message: "<display>" }
 * via `AppError::serialize` in `src-tauri/src/error.rs`. Plain `+ e` or
 * `${e}` would render that as "[object Object]" — every toast/log site
 * must funnel through `formatError(e)` to stay readable.
 *
 * `errorKind(e)` returns the discriminator for branching (e.g., to react
 * to `kind === "DiscoveryUnavailable"`). Returns null for legacy string
 * errors or anything without a `kind` field.
 */

import type { TypedAppError } from "./types.ts";

/** The shapes that may show up in a catch — IPC, async stack errors,
 *  and JS Error objects all flow through here. */
export type Caught = unknown;

/** Best-effort coercion to a human-readable string. Handles typed
 *  AppError, plain strings, native Error, and anything else. */
export function formatError(e: Caught): string {
  if (e == null) return "Unknown error";
  if (typeof e === "string") return e;
  if (typeof e === "object" && e !== null && "message" in e) {
    const msg = (e as { message: unknown }).message;
    if (typeof msg === "string") return msg;
  }
  return String(e);
}

/** Discriminator from a typed AppError, or null if the value isn't one
 *  (legacy string error, native Error, etc.). Use this to branch on
 *  specific failure classes — e.g., react to
 *  `errorKind(e) === "DiscoveryUnavailable"`. */
export function errorKind(e: Caught): TypedAppError["kind"] | null {
  if (e && typeof e === "object" && "kind" in e) {
    const kind = (e as { kind: unknown }).kind;
    if (typeof kind === "string") {
      // The cast is the boundary between "any string from the wire"
      // and "the union we type the rest of the codebase on." If a
      // future Rust variant ships before the TS enum is updated,
      // callers fall through their switch to the default branch
      // and the toast still renders via formatError.
      return kind as TypedAppError["kind"];
    }
  }
  return null;
}
