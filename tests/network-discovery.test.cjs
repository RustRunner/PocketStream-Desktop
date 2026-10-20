const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

const source = fs.readFileSync(path.join(__dirname, "../src/lib/network.ts"), "utf8");
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

function fixture(mode = "static_auto") {
  const events = new Map(), elements = new Map();
  const calls = { discovery: 0, reconnect: 0, reset: 0, cancelNotice: 0 };
  const iface = { name: "Ethernet", display_name: "Ethernet", mac: "00:22:20:3a:e3:b3",
    is_up: true, ips: [{ address: "192.168.1.100", prefix: 24, subnet: "192.168.1.0/24" }] };
  const selection = { selected_mac: iface.mac, interface_index: 13, adapter: iface };
  const state = { config: { network_mode: mode }, activeInterface: { ...iface, is_up: false }, activeAdoptionId: null };
  const $ = id => {
    if (!elements.has(id)) elements.set(id, { textContent: "", style: {}, addEventListener() {} });
    return elements.get(id);
  };
  const noop = () => {};
  const api = {
    onEvent: async (name, fn) => { events.set(name, fn); return noop; },
    getAdapterSelection: async () => selection,
    getAdoptionState: async () => null,
    getNetworkMode: async () => mode,
    startArpDiscovery: async () => { calls.discovery++; throw Error("provider timed out"); },
  };
  const deps = {
    "./tauri-api.ts": api,
    "./state.ts": { $, $$: () => [], state, adoptedSubnets: new Map(), adoptionMeta: new Map(), log: noop, showToast: noop },
    "./devices.js": { renderArpDeviceList: noop, resetDiscoveryStatus: () => calls.reset++ },
    "./streaming.js": { handleReconnect: async () => { calls.reconnect++; }, handleHardDisconnect: noop },
    "./store.ts": {}, "./errors.ts": { formatError: String }, "./device-list.ts": {},
  };
  const exports = {};
  vm.runInNewContext(ts.transpileModule(source + "\nrenderSubnetList = () => {};", {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, { exports, require(name) { assert(name in deps, name); return deps[name]; } });
  exports.setupInterfaceWatcher(() => calls.cancelNotice++);
  events.get("adapter-selection-changed")(selection);
  return { api, exports, state, iface, calls, up: () => events.get("interface-status-changed")(iface),
    publishNative: () => {
      events.get("adapter-selection-changed")(selection);
      events.get("interface-status-changed")(iface);
    },
  };
}

test("Native recovery replaces stale APIPA state and fences a pending provider failure", async () => {
  const f = fixture();
  f.state.activeInterface = { ...f.iface, is_up: false,
    ips: [{ address: "169.254.10.2", prefix: 16, subnet: "169.254.0.0/16" }] };
  let rejectQuery;
  f.api.getAdapterSelection = () => new Promise((resolve, reject) => { rejectQuery = reject; });
  const pending = f.exports.refreshInterfaces();
  f.publishNative();
  rejectQuery(Error("older provider query timed out"));
  await pending; await flush();
  assert.equal(f.state.activeInterface.ips[0].address, "192.168.1.100");
  assert.equal(f.state.activeInterface.is_up, true);
  assert.equal(f.calls.reconnect, 1);
  assert.equal(f.calls.discovery, 0);
});

for (const mode of ["static_auto", "dhcp", "static_manual"]) {
  test(`Reconnect in ${mode} preserves stream desire while backend owns discovery`, async () => {
    const f = fixture(mode);
    f.up(); await flush();
    assert.equal(f.calls.discovery, 0, "no duplicate, silently failing frontend start");
    assert.equal(f.calls.reconnect, 1);
    assert.equal(f.calls.cancelNotice, 1);
    assert.equal(f.state.activeInterface.is_up, true);
    f.up(); await flush();
    assert.equal(f.calls.reconnect, 1, "unchanged up event does not repeat stream resume");
  });
}

test("Interface query before the up event does not determine discovery ownership", async () => {
  const f = fixture();
  await f.exports.refreshInterfaces();
  f.up(); await flush();
  assert.equal(f.state.activeInterface.is_up, true);
  assert.equal(f.calls.discovery, 0);
  assert.equal(f.calls.reconnect, 0);
});

test("A failed interface query cannot make the next up event start discovery through IPC", async () => {
  const f = fixture();
  f.api.getAdapterSelection = async () => { throw Error("provider timed out"); };
  await f.exports.refreshInterfaces();
  assert.equal(f.state.activeInterface, null);
  f.up(); await flush();
  assert.equal(f.calls.discovery, 0);
  assert.equal(f.calls.reconnect, 1);
});
