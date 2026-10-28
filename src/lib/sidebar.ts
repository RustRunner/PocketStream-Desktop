import { $, state } from "./state.ts";
import * as api from "./tauri-api.ts";
import { getVideoAreaBounds, syncVideoVisibility } from "./streaming.ts";

/** Keep the header handle, panel and native video in sync through reversals. */
export function setupSidebarToggle(): void {
  const app = $("#app");
  const sidebar = $("#sidebar");
  const button = $<HTMLButtonElement>("#menu-toggle");
  let revision = 0;
  let settleTimer: ReturnType<typeof setTimeout> | null = null;

  button.addEventListener("click", () => {
    const expanded = sidebar.classList.contains("collapsed");
    sidebar.classList.toggle("collapsed", !expanded);
    sidebar.inert = !expanded;
    app.classList.toggle("sidebar-open", expanded);
    button.setAttribute("aria-expanded", String(expanded));
    const label = expanded ? "Close settings" : "Open settings";
    button.setAttribute("aria-label", label);
    button.title = label;

    const current = ++revision;
    if (settleTimer !== null) clearTimeout(settleTimer);
    settleTimer = null;
    if (!state.isStreaming) return;

    // The native child must not cover the moving panel or an open dialog.
    void api.setVideoVisible(false).catch(() => {});
    settleTimer = setTimeout(async () => {
      settleTimer = null;
      if (current !== revision) return;
      try {
        const bounds = getVideoAreaBounds();
        await api.updateVideoPosition(bounds.x, bounds.y, bounds.width, bounds.height);
        if (current === revision) await syncVideoVisibility();
      } catch (_) {}
    }, 250);
  });
}
