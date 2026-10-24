// Run in a real local main webview with the production plugin initializer/ACL.
// No application network handler is registered by this isolated fixture.
(async () => {
  const tauri = window.__TAURI__;
  const report = (level, message) => tauri.core.invoke("log_frontend", { level, message });
  try {
    const version = await tauri.app.getVersion();
    if (!version) throw Error("missing native version");
    const unlisten = await tauri.event.listen("acl-smoke", () => {});
    await unlisten();
    const win = tauri.window.getCurrentWindow();
    let resized = 0;
    const stopResize = await win.onResized(() => { resized++; });
    await win.isMaximized();
    await win.toggleMaximize();
    await win.toggleMaximize();
    await win.minimize();
    await report("restore", "version/event/window commands dispatched");
    await new Promise(resolve => setTimeout(resolve, 100));
    await stopResize();
    if (!resized) throw Error("native resize event was not observed");
    await report("address", "address-removal confirmation bridge");
    if (await window.confirm("ACL smoke: remove the saved host address? (Cancel only)") !== false) {
      throw Error("address confirmation did not return native Cancel");
    }
    await report("dhcp", "DHCP confirmation bridge");
    if (await window.confirm("ACL smoke: switch to DHCP? (Cancel only)") !== false) {
      throw Error("DHCP confirmation did not return native Cancel");
    }
    if (!tauri.updater?.check) throw Error("updater initializer unavailable");
    try {
      await tauri.updater.check({ timeout: 5000 });
      await report("updater", "native update check completed; no update installed");
    } catch (error) {
      if (/not allowed|command .*not found/i.test(String(error))) throw error;
      // A transport/service failure proves dispatch, but does not qualify
      // successful access to the configured update endpoint.
      await report("updater-unavailable", String(error));
    }
    await report("complete", "version, listen/unlisten, window controls, two native Cancel confirmations; updater initializer present");
    await win.close();
  } catch (error) {
    await report("failed", String(error));
  }
})();
