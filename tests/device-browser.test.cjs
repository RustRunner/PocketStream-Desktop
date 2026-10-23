const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

function load(file, context) {
  const source = fs.readFileSync(path.join(__dirname, "../src/lib", file), "utf8");
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, { exports, ...context });
  return exports;
}

function fixture(tauri = true) {
  const calls = [], opened = [], toasts = [];
  const record = { mac: "40:cd:3a:03:8f:3f", ip: "192.168.1.204", subnet: "192.168.1.0/24",
    alias: "CAM", status: "live", open_ports: [80, 554] };
  const row = { dataset: { key: record.mac }, addEventListener() {} };
  let click;
  const link = { dataset: { browse: record.ip }, closest: () => row,
    addEventListener: (event, fn) => { if (event === "click") click = fn; } };
  const list = { innerHTML: "", querySelectorAll: selector =>
    selector === ".device-item" ? [row] : selector.includes("data-browse") ? [link] : [] };
  let fail = false;
  let present = true;
  let conflict = null;
  let liveConflict = null;
  let refreshes = 0;
  const deps = {
    "./tauri-api.ts": { openDeviceBrowser: async (ip, target) => {
      calls.push({ ip, ...target });
      if (fail) throw Error("Device identity changed");
      if (liveConflict) throw Error(liveConflict.message);
    } },
    "./state.ts": { $: () => list, escapeHtml: String, showToast: (...args) => toasts.push(args), log() {} },
    "./network.ts": {}, "./streaming.ts": {}, "./ptz.ts": {},
    "./device-state.ts": { visibleDevices: rows => rows, presenceLabel: () => "Active" },
    "./ip-conflicts.ts": { forIp: () => conflict, refresh: async () => {
      refreshes++; conflict = liveConflict; api.renderArpDeviceList();
    } },
    "./device-list.ts": { getDevices: () => [record], deviceByKey: key => present && key === record.mac ? record : undefined,
      targetFor: row => ({ key: row.mac, expectedMac: row.mac }) },
    "./store.ts": { selectedDevice: { get: () => null } },
    "./errors.ts": { formatError: String },
  };
  const api = load("devices.ts", { window: { __TAURI__: tauri ? {} : undefined, open: url => opened.push(url) },
    require(name) { assert(name in deps, name); return deps[name]; } });
  api.renderArpDeviceList();
  return { calls, opened, toasts, record, fail: () => { fail = true; }, remove: () => { present = false; },
    list, conflict: (next) => { conflict = next; liveConflict = next; api.renderArpDeviceList(); },
    liveConflict: next => { liveConflict = next; }, refreshes: () => refreshes,
    click: async () => { click({ preventDefault() {} }); for (let i = 0; i < 5; i++) await Promise.resolve(); } };
}

test("Node browser link sends the clicked device identity with its address", async () => {
  const f = fixture();
  await f.click();
  assert.deepEqual(f.calls, [{ ip: f.record.ip, key: f.record.mac, expectedMac: f.record.mac }]);
  assert.deepEqual(f.opened, []);
});

test("A rejected device browser request reports the error without an unbound fallback", async () => {
  const f = fixture();
  f.fail();
  await f.click();
  assert.deepEqual(f.opened, []);
  assert.match(f.toasts[0][0], /Device identity changed/);
  assert.equal(f.toasts[0][1], true);
});

test("A removed node cannot open a stale browser link", async () => {
  const f = fixture();
  f.remove();
  await f.click();
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.opened, []);
});

test("An active PC IP conflict stays visible and the current backend check explains the fix", async () => {
  const f = fixture();
  const conflict = { adapters: ["Wi-Fi 2"], message: "IP conflict: change the device or PC address" };
  f.conflict(conflict);
  assert.match(f.list.innerHTML, /device-ip conflicting/);
  assert.match(f.list.innerHTML, /IP conflict with PC: Wi-Fi 2/);
  assert(f.list.innerHTML.includes(f.record.mac));
  await f.click();
  assert.equal(f.calls.length, 1, "the backend checks current ownership even when the badge is orange");
  assert.deepEqual(f.opened, []);
  assert(f.toasts[0][0].includes(conflict.message));
  assert.equal(f.refreshes(), 1);
  f.conflict(null);
  assert(!f.list.innerHTML.includes("IP conflict with PC"));
  await f.click();
  assert.equal(f.calls.length, 2, "normal browser access resumes after the conflict is resolved");
});

test("Turning Wi-Fi off permits a fresh browser request even before the orange badge refreshes", async () => {
  const f = fixture();
  f.conflict({ adapters: ["Wi-Fi 2"], message: "IP conflict: change the device or PC address" });
  f.liveConflict(null);
  assert.match(f.list.innerHTML, /device-ip conflicting/);
  await f.click();
  assert.equal(f.calls.length, 1);
  assert.deepEqual(f.toasts, []);
  assert.equal(f.refreshes(), 1);
  assert(!f.list.innerHTML.includes("IP conflict with PC"));
});

test("Re-enabling Wi-Fi is checked before opening even if the badge has not caught up", async () => {
  const f = fixture();
  f.liveConflict({ adapters: ["Wi-Fi 2"], message: "IP conflict: change the device or PC address" });
  assert(!f.list.innerHTML.includes("IP conflict with PC"));
  await f.click();
  assert.equal(f.calls.length, 1);
  assert.deepEqual(f.opened, []);
  assert.match(f.toasts[0][0], /IP conflict/);
  assert.match(f.list.innerHTML, /IP conflict with PC: Wi-Fi 2/);
});

test("Device browser IPC preserves the expected MAC field", async () => {
  const calls = [];
  const api = load("tauri-api.ts", { window: { __TAURI__: { core: { invoke: async (...args) => calls.push(args) } } }, console });
  await api.openDeviceBrowser("192.168.1.204", { key: "camera-key", expectedMac: "aa:bb:cc:dd:ee:ff" });
  assert.equal(JSON.stringify(calls), JSON.stringify([["open_device_browser", {
    target: { ip: "192.168.1.204", key: "camera-key", expected_mac: "aa:bb:cc:dd:ee:ff" },
  }]]));
});
