const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");
const source = fs.readFileSync(path.join(__dirname, "../src/lib/ip-conflicts.ts"), "utf8");
const owner = (address, adapter_name) => ({ address, adapter_name });
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
  return { ...exports, publish: (owners) => event(owners) };
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

test("A host address event wins over a stale initial snapshot", async () => {
  let resolve;
  const f = fixture(new Promise(r => { resolve=r; }));
  const pending = f.start(); await flush();
  f.publish([owner("192.168.1.205", "Wi-Fi 2")]);
  resolve([owner("192.168.1.204", "Wi-Fi 2")]); await pending;
  assert.equal(f.forIp("192.168.1.204"), null);
  assert(f.forIp("192.168.1.205"));
});
