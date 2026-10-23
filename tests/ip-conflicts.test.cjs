const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");
const source = fs.readFileSync(path.join(__dirname, "../src/lib/ip-conflicts.ts"), "utf8");
const owner = (address, adapter_name, retained_route = false) => ({ address, adapter_name, retained_route });
const flush = async () => { for (let i=0; i<5; i++) await Promise.resolve(); };

function fixture(snapshot) {
  let event;
  const exports = {};
  const api = { onEvent: async (name, callback) => {
    assert.equal(name, "host-ip-owners-changed"); event = callback;
  }, getHostIpOwners: async () => snapshot };
  vm.runInNewContext(ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, { exports, require(name) { assert.equal(name, "./tauri-api.ts"); return api; } });
  return { ...exports, publish: (owners) => event(owners), snapshot: next => { snapshot = next; } };
}

test("Only an exact PC address match warns, and DHCP changes clear the warning", async () => {
  const f = fixture([owner("192.168.1.204", "Wi-Fi 2"), owner("192.168.1.204", "VPN"),
    owner("192.168.1.204", "Wi-Fi 2"), owner("192.168.1.100", "Ethernet")]);
  let changes=0; f.subscribe(() => changes++);
  await f.start();
  assert.equal(f.forIp("192.168.1.205"), null);
  assert.equal(f.forIp("192.168.1.204").adapters.join(", "), "VPN, Wi-Fi 2");
  assert.match(f.forIp("192.168.1.204").message, /Change the device's IP or the PC's address/);
  f.publish([owner("192.168.1.205", "Wi-Fi 2")]);
  assert.equal(f.forIp("192.168.1.204"), null);
  assert(f.forIp("192.168.1.205"));
  assert.equal(changes, 2);
});

test("A retained radio-off address warns until fully disabling the adapter releases it", async () => {
  const f = fixture([owner("192.168.1.204", "Wi-Fi 2", true)]);
  await f.start();
  assert.equal(f.forIp("192.168.1.204").retainedAdapters.join(", "), "Wi-Fi 2");
  assert.match(f.forIp("192.168.1.204").message, /still reserved by this PC/);
  assert.match(f.forIp("192.168.1.204").message, /Fully disable Wi-Fi 2 in Windows Network Connections/);
  f.publish([]);
  assert.equal(f.forIp("192.168.1.204"), null);
  f.publish([owner("192.168.1.204", "Wi-Fi 2")]);
  assert.equal(f.forIp("192.168.1.204").retainedAdapters.length, 0);
  assert.match(f.forIp("192.168.1.204").message, /also assigned to this PC/);
});

test("A host address event wins over a stale initial snapshot", async () => {
  let resolve;
  const f = fixture(new Promise(r => { resolve=r; }));
  const pending = f.start(); await flush();
  f.publish([owner("192.168.1.205", "Wi-Fi 2")]);
  resolve([owner("192.168.1.204", "Wi-Fi 2")]); await pending;
  assert.equal(f.forIp("192.168.1.204"), null);
  assert(f.forIp("192.168.1.205"));
});

test("An explicit refresh clears a disabled Wi-Fi warning and cannot be overwritten by an older request", async () => {
  const f = fixture([owner("192.168.1.204", "Wi-Fi 2")]);
  await f.start();
  assert(f.forIp("192.168.1.204"));
  let resolve;
  f.snapshot(new Promise(r => { resolve = r; }));
  const old = f.refresh();
  f.snapshot([]);
  await f.refresh();
  assert.equal(f.forIp("192.168.1.204"), null);
  resolve([owner("192.168.1.204", "Wi-Fi 2")]); await old;
  assert.equal(f.forIp("192.168.1.204"), null);
});

test("A failed explicit read retains the warning until a successful observation clears it", async () => {
  const f = fixture([owner("192.168.1.204", "Wi-Fi 2")]);
  await f.start();
  f.snapshot(Promise.reject(Error("native adapter read failed")));
  await assert.rejects(f.refresh(), /native adapter read failed/);
  assert(f.forIp("192.168.1.204"));
  f.publish([]);
  assert.equal(f.forIp("192.168.1.204"), null);
});
