const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const source = name => fs.readFileSync(path.join(__dirname, "..", name), "utf8");
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
const inactive = { active: false, adapter_name: null, outcome: null, candidate_count: 0 };
const active = { active: true, adapter_name: "Ethernet", outcome: { scope: "selected_interface", source_id: 12 }, candidate_count: 0 };

function load(text, deps, globals = {}) {
  const exports = {};
  vm.runInNewContext(ts.transpileModule(text, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, {
    exports, require(name) { assert(name in deps, name); return deps[name]; }, ...globals,
  });
  return exports;
}

// Run the real startup callback, capture store, notice controller and modal
// helper. Only unrelated controls, IPC and DOM are faked; no wall-clock timer.
function fixture(mode = "static_auto") {
  const elements = new Map(), events = new Map(), queries = [], visibility = [], logs = [];
  let boot, shows = 0;
  const $ = id => {
    if (!elements.has(id)) elements.set(id, {
      open: false, textContent: "", style: {}, listeners: {},
      addEventListener(name, fn) { this.listeners[name] = fn; },
      showModal() { this.open = true; shows++; },
      close() { this.open = false; const fn = this.listeners.close; delete this.listeners.close; fn?.(); },
    });
    return elements.get(id);
  };
  const config = { network_mode: mode, stream: {}, credentials: {}, rtsp_server: {} };
  const state = { config, activeInterface: null, isStreaming: false, streamLost: false };
  const hidden = deferred(), notices = deferred();
  const api = {
    getConfig: async () => config,
    getStartupNotices: () => notices.promise,
    onEvent: async (name, fn) => { events.set(name, fn); return () => {}; },
    getCaptureState: () => { const q = deferred(); queries.push(q); return q.promise; },
    setVideoVisible: value => { visibility.push(value); return hidden.promise; },
  };
  const shared = { $, $$: () => [], state, log: message => logs.push(message) };
  const blank = {}, noop = () => {};
  const deviceDeps = {
    "./tauri-api.ts": api, "./state.ts": shared, "./errors.ts": { formatError: String },
    "./network.ts": blank, "./device-state.ts": blank, "./device-list.ts": blank,
    "./ip-conflicts.ts": { forIp: () => null, subscribe: () => () => {}, start: async () => {} },
    "./streaming.ts": blank, "./ptz.ts": blank, "./store.ts": blank,
  };
  const devices = load(source("src/lib/devices.ts"), deviceDeps);
  const ast = ts.createSourceFile("streaming.ts", source("src/lib/streaming.ts"), ts.ScriptTarget.Latest, true);
  const modalSource = "let openModalCount = 0;\n" + ast.statements.filter(s =>
    ts.isFunctionDeclaration(s) && ["syncVideoVisibility", "showModalWithVideo"].includes(s.name?.text)
  ).map(s => s.getText(ast)).join("\n") + "\nexports.modalCount = () => openModalCount;";
  const modal = load(modalSource, {}, { api, state });
  const streaming = new Proxy(modal, { get: (target, name) => target[name] ?? noop });
  const deps = {
    "./lib/tauri-api.ts": api, "./lib/state.ts": shared, "./lib/devices.ts": devices,
    "./lib/errors.ts": { formatError: String }, "./lib/streaming.ts": streaming,
  };
  for (const name of ["network", "device-cache", "device-list", "markdown-lite", "ptz", "sidebar"])
    deps[`./lib/${name}.ts`] = new Proxy({}, { get: () => noop });
  const exports = load(source("src/main.ts") + `
    setupMenuAndAbout = setupWindowControls = setupProtocolToggle = setupSettingsSave =
      setupRefreshButton = setupResetAdapterButton = applyRtspPath = updateProtocolVisibility = () => {};
    exports.notice = { setupListeningNotice, armListeningNotice, listeningNoticeModeApplied, cancelListeningNotice };
  `, deps, {
    window: { addEventListener() {} },
    document: { addEventListener(name, fn) { if (name === "DOMContentLoaded") boot = fn; } },
  });
  return {
    $, state, devices, modal, queries, logs, visibility, notice: exports.notice,
    boot: () => boot(), shows: () => shows, releaseVideo: hidden.resolve,
    publish: value => events.get("capture-active")(value),
    async answer(value) { await flush(); for (const q of queries.splice(0)) q.resolve(value); await flush(); },
  };
}

test("Static-Auto startup opens before pending capture, notices or video IPC", async () => {
  const f = fixture();
  void f.boot();
  await flush();
  assert.equal(f.$("#listening-notice-dialog").open, true);
  assert.equal(f.shows(), 1);
  assert.equal(f.modal.modalCount(), 1);
  assert.equal(f.$("#listening-notice-title").textContent, "Static–Auto device discovery");
  assert.equal(f.visibility[0], false);
  // The listener never becomes ready; the launch notice still requires OK.
  for (const q of f.queries.splice(0)) q.reject(Error("capture unavailable"));
  await flush();
  assert.equal(f.$("#listening-notice-dialog").open, true);
  let prevented = false;
  f.$("#listening-notice-dialog").listeners.cancel({ preventDefault() { prevented = true; } });
  assert(prevented);
  f.$("#listening-notice-ok").listeners.click();
  assert.equal(f.modal.modalCount(), 0);
  f.publish(active); f.publish(inactive); f.publish(active);
  await flush();
  assert.equal(f.shows(), 1, "later capture/reconnect cannot repeat the launch notice");
});

for (const mode of ["dhcp", "static_manual"]) test(`No launch notice in ${mode}`, async () => {
  const f = fixture(mode);
  void f.boot(); await flush();
  f.publish(active); await flush();
  assert.equal(f.shows(), 0);
});

test("Mode change still waits for capture and video; cancellation releases its reservation", async () => {
  const f = fixture("static_manual");
  f.notice.setupListeningNotice(); await f.answer(inactive);
  f.state.config.network_mode = "static_auto";
  f.notice.listeningNoticeModeApplied("static_manual", "static_auto");
  await flush(); assert.equal(f.shows(), 0);
  await f.answer(active);
  assert.equal(f.shows(), 0, "mode change must hide existing native video first");
  assert.equal(f.modal.modalCount(), 1);
  f.state.config.network_mode = "dhcp";
  f.notice.listeningNoticeModeApplied("static_auto", "dhcp");
  f.releaseVideo(); await flush();
  assert.equal(f.shows(), 0);
  assert.equal(f.modal.modalCount(), 0);
});

test("Ready mode change opens once; Refresh/reconnect/watchdog never arm a notice", async () => {
  const f = fixture("dhcp");
  f.notice.setupListeningNotice(); await f.answer(active); f.releaseVideo();
  f.state.config.network_mode = "static_auto";
  f.notice.listeningNoticeModeApplied("dhcp", "static_auto");
  await f.answer(active);
  assert.equal(f.shows(), 1);
  assert.match(f.$("#listening-notice-title").textContent, /now listening.*Ethernet/);
  f.$("#listening-notice-ok").listeners.click(); await flush();
  for (const trigger of ["refresh", "reconnect", "watchdog"]) {
    f.notice.armListeningNotice(trigger, true); await f.answer(active);
  }
  assert.equal(f.shows(), 1);
});
