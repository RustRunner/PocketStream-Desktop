/**
 * Ambient declarations for Tauri's runtime-injected globals.
 *
 * The codebase deliberately uses `window.__TAURI__` directly rather
 * than importing `@tauri-apps/api`, because:
 * 1. `withGlobalTauri: true` in tauri.conf.json already exposes the
 *    runtime; pulling in `@tauri-apps/api` would duplicate it.
 * 2. The dev build runs in a plain browser via `vite dev` where the
 *    Tauri runtime isn't injected — every access here is `?.`-guarded
 *    and falls back to a no-op. Importing the package would change
 *    that contract (it would throw on import outside Tauri).
 *
 * Only the surface actually used in the app is declared here. Add new
 * fields as the code grows; keep them narrow rather than widening to
 * the full @tauri-apps/api shape.
 */

declare global {
  interface Window {
    __TAURI__?: TauriRuntime;
  }
}

/** Top-level shape of the runtime injected by Tauri when
 *  `withGlobalTauri: true`. Every nested namespace is optional so
 *  feature-detection (`?.`) keeps working in non-Tauri contexts. */
export interface TauriRuntime {
  core?: TauriCore;
  event?: TauriEvent;
  app?: TauriApp;
  window?: TauriWindow;
  updater?: TauriUpdater;
}

export interface TauriCore {
  invoke: <T = unknown>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

export interface TauriEventPayload<T = unknown> {
  event: string;
  payload: T;
}

export type UnlistenFn = () => void;

export interface TauriEvent {
  listen: <T = unknown>(
    event: string,
    handler: (event: TauriEventPayload<T>) => void
  ) => Promise<UnlistenFn>;
}

export interface TauriApp {
  getVersion?: () => Promise<string>;
}

/** Minimal window surface — only `getCurrentWindow().close()` etc.
 *  is accessed today. Widen as needed. */
export interface TauriWindow {
  getCurrentWindow?: () => CurrentWindow;
}

export interface CurrentWindow {
  close: () => Promise<void>;
  minimize: () => Promise<void>;
  toggleMaximize: () => Promise<void>;
}

/** Shape of `window.__TAURI__.updater` used by main.js. The plugin's
 *  full surface is broader; only the bits actually consumed are typed. */
export interface TauriUpdater {
  check: () => Promise<TauriUpdate | null>;
}

export interface TauriUpdate {
  version: string;
  body?: string;
  date?: string;
  downloadAndInstall: (
    onProgress?: (event: TauriUpdateProgressEvent) => void
  ) => Promise<void>;
}

export type TauriUpdateProgressEvent =
  | { event: "Started"; data: { contentLength?: number } }
  | { event: "Progress"; data: { chunkLength: number } }
  | { event: "Finished" };

export {};
