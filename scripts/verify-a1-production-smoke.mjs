// CDP drives the unchanged production page and its real DOM handlers. Do not
// replace window.confirm, invoke, modules, app state, assets or backend handlers.
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const contextPath = process.argv[2];
const context = JSON.parse(fs.readFileSync(contextPath, "utf8").replace(/^\uFEFF/, ""));
const readyOnly = process.argv[3] === "--ready-only";
const closeOnly = process.argv[3] === "--close-only";
const directory = path.dirname(contextPath);
const result = { production_ui: true, replaced_assets_or_handlers: false, settings: "pending", primary_address_controls: "pending", dhcp_confirmation: "pending", errors: [] };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let socket;
let next = 0;
const pending = new Map();
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++next;
    const timeout = setTimeout(() => { pending.delete(id); reject(Error(`${method} timed out`)); }, 15000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const reply = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (reply.exceptionDetails) throw Error(reply.exceptionDetails.text + ": " + (reply.exceptionDetails.exception?.description ?? ""));
  return reply.result.value;
}
async function until(expression, label, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await evaluate(expression)) return; await pause(150); }
  throw Error(`Timed out: ${label}`);
}
async function cancelNative(expected) {
  const { stdout } = await exec(context.powershell, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", context.native_helper,
    "-Mode", "CancelDialog", "-OwnerPid", String(context.pid), "-ExpectedText", expected, "-Executable", context.executable], { timeout: 16000, windowsHide: true });
  const observed = JSON.parse(stdout.trim().replace(/^\uFEFF/, ""));
  if (!observed.observed || observed.action !== "Cancel" || !observed.text.includes(expected)) throw Error("Native confirmation mismatch");
  return observed;
}
try {
  let target;
  const deadline = Date.now() + 25000;
  while (!target && Date.now() < deadline) {
    try {
      const pages = await (await fetch(`http://127.0.0.1:${context.port}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
      target = pages.find(page => page.type === "page" && /^http:\/\/tauri\.localhost\/?/.test(page.url));
    } catch {}
    if (!target) await pause(200);
  }
  if (!target) throw Error("Real application WebView2 target unavailable");
  socket = new WebSocket(target.webSocketDebuggerUrl);
  socket.addEventListener("message", event => {
    const reply = JSON.parse(String(event.data));
    if (!reply.id) return;
    const request = pending.get(reply.id);
    if (!request) return;
    clearTimeout(request.timeout); pending.delete(reply.id);
    if (reply.error) request.reject(Error(reply.error.message)); else request.resolve(reply.result);
  });
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  await send("Runtime.enable");
  await until(`window.__TAURI__?.core?.invoke && document.querySelector('#save-settings')`, "production initializer");
  const startup = await evaluate(`Promise.all([window.__TAURI__.core.invoke('get_config'), window.__TAURI__.core.invoke('get_startup_notices')]).then(([c,n]) => ({ mode:c.network_mode, primary:c.primary_addresses?.[${JSON.stringify(context.adapter_mac)}], output:c.rtsp_server.enabled, notices:n.length }))`);
  if (startup.mode !== "static_manual" || startup.output || startup.notices || startup.primary !== context.expected_cidr) {
    throw Error("Controlled profile was not accepted exactly; abort before workflow actions: " + JSON.stringify(startup));
  }
  result.startup_profile = startup;
  await until(`document.readyState === 'complete' && document.querySelector('#iface-name')?.textContent !== '--' && document.querySelector('#rtsp-port')?.value === '554'`, "real app initialization");
  result.page = await evaluate(`({ url: location.href, settings_button: !!document.querySelector('#save-settings'), restream_enabled: document.querySelector('#restream-server-enable').checked, interface: document.querySelector('#iface-name').textContent })`);
  if (result.page.restream_enabled) throw Error("Listener enablement must stay off in this UI phase");
  if (readyOnly || closeOnly) {
    result.ready = true;
  } else {
  console.log("Production settings: save through #save-settings, verify native persistence, restore through the same handler");
  await evaluate(`document.querySelector('#rtsp-port').value = '13554'; document.querySelector('#save-settings').click();`);
  await until(`window.__TAURI__.core.invoke('get_config').then(c => c.stream.rtsp_port === 13554 && !c.rtsp_server.enabled)`, "settings native readback");
  await until(`document.querySelector('.toast')?.textContent.includes('Settings saved')`, "production settings completion");
  await evaluate(`document.querySelector('#rtsp-port').value = '554'; document.querySelector('#save-settings').click();`);
  await until(`window.__TAURI__.core.invoke('get_config').then(c => c.stream.rtsp_port === 554 && !c.rtsp_server.enabled)`, "restored settings readback");
  result.settings = { status: "passed", action: "Save Settings", field: "stream.rtsp_port", values: [554, 13554, 554], readback: "real get_config IPC" };

  console.log("Production address controls: Configure retains the editable primary without a removal control");
  await evaluate(`document.querySelector('#btn-ip-config').click();`);
  await until(`document.querySelector('#ip-config-dialog').open && document.querySelector('#static-iface').value === ${JSON.stringify(context.alias)} && document.querySelector('#static-ip').value === ${JSON.stringify(context.expected_address)}`, "live selected adapter fields");
  const primaryControls = await evaluate(`({ removal: !!document.querySelector('#btn-remove-primary-ip'), editable: !document.querySelector('#static-ip').disabled, listed_as_secondary: document.querySelector('#secondary-ip-list').textContent.includes(${JSON.stringify(context.expected_address)}) })`);
  if (primaryControls.removal || !primaryControls.editable || primaryControls.listed_as_secondary) throw Error("Primary address controls did not match the protected-primary layout");
  result.primary_address_controls = { status: "passed", path: "Configure > Primary IP", observed: "primary remains editable and has no removal action" };

  console.log("Production DHCP: actual radio/Close handler, backend warning, native Cancel");
  await evaluate(`document.querySelector('#ip-mode-dhcp').click(); document.querySelector('#ip-config-close').click();`);
  const dhcp = await cancelNative("Switching to DHCP removes manually configured addresses");
  await until(`document.querySelector('#ip-config-dialog').open && document.querySelector('#ip-mode-static-manual').checked && !document.querySelector('#ip-config-close').disabled`, "DHCP Cancel restores original mode and controls");
  const mode = await evaluate(`window.__TAURI__.core.invoke('get_network_mode')`);
  if (mode !== "static_manual") throw Error("DHCP Cancel changed the backend mode");
  result.dhcp_confirmation = { status: "passed", path: "Configure > DHCP > Close", native: dhcp, observed_mode: mode };
  await evaluate(`document.querySelector('#ip-config-close').click();`);
  await until(`!document.querySelector('#ip-config-dialog').open`, "unchanged dialog closes without a write");
  const shot = await send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(directory, "production-ui.png"), Buffer.from(shot.data, "base64"));
  console.log("Production settings, primary address controls and native DHCP Cancel passed; discovery/playback/PTU remain separate gates");
  }
} catch (error) {
  result.errors.push(String(error)); process.exitCode = 1;
  console.error(String(error));
} finally {
  if (!readyOnly && socket?.readyState === WebSocket.OPEN) {
    try {
      await evaluate(`document.querySelector('#btn-close').click();`);
      result.close_requested = "production #btn-close handler";
    } catch (error) { result.close_request_error = String(error); }
  }
  fs.writeFileSync(path.join(directory, readyOnly ? "ready-result.json" : closeOnly ? "close-result.json" : "ui-result.json"), JSON.stringify(result, null, 2) + "\n");
  socket?.close();
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(Error("smoke ended")); }
}
