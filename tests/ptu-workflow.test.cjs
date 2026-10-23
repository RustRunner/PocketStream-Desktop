const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");

// Execute the actual module and UI handlers; only IPC, DOM and time are fakes.
// No app, adapter, camera, user configuration or real timer is accessed.
const source = fs.readFileSync(path.join(__dirname, "../src/lib/ptz.ts"), "utf8");
const compiled = ts.transpileModule(source + `
exports.testHooks = {
  queryPtuSpeed, capturePtuOperation, waitForPtuTarget, ptuCmd, enqueuePtuCmd,
  speed: () => [ptuSpeedBig, ptuSpeedSmall, ptuSpeedQueried],
  seedPreset: () => ptuPresets.set(1, {pan: "0", tilt: "0", zoom: 42}),
  hasPreset: () => ptuPresets.has(1),
  zoomHooks: (park, request) => { zoomParkWide = park; zoomRequest = request; },
};
`, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;

const A = { key: "aa:bb:cc:dd:ee:01", expectedMac: "aa:bb:cc:dd:ee:01" };
const B = { key: "aa:bb:cc:dd:ee:02", expectedMac: "aa:bb:cc:dd:ee:02" };
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

function button(dataset) {
  const handlers = {};
  return {
    dataset,
    addEventListener(event, handler) { handlers[event] = handler; },
    fire(event) { return handlers[event]?.({ preventDefault() {} }); },
  };
}

function fixture({ sameIp = false, hold = () => false, failHalt = false } = {}) {
  let current = A, camera = A, timerId = 0;
  const calls = [], pending = [], timers = new Map(), subscribers = [], zooms = [];
  const home = button({ ptz: "home" }), right = button({ ptz: "right" });
  const preset = button({ preset: "1" });
  const endpoint = (target) => target
    ? target.key === A.key || sameIp ? "192.0.2.20" : "192.0.2.21"
    : null;
  const api = {
    async ptuSend(ip, cmd, target) {
      const call = { ip, cmd, target: structuredClone(target) };
      calls.push(call);
      if (cmd === "PS=0&TS=0" && failHalt) {
        failHalt = false;
        throw Error("transient refusal");
      }
      if (hold(cmd)) return new Promise(resolve => pending.push({ call, resolve }));
      return cmd === "PU&TU&PL&TL"
        ? { PU: "300", TU: "200", PL: "3", TL: "2" }
        : { PP: "0", TP: "0" };
    },
  };
  const deps = {
    "./tauri-api.ts": api,
    "./state.ts": { $: () => null, state: {}, log() {}, showToast() {} },
    "./errors.ts": { formatError: String },
    "./network.ts": {
      getActivePtuIp: () => endpoint(current), getActivePtuTarget: () => current,
      getActiveCamIp: () => endpoint(camera), getActiveCamTarget: () => camera,
    },
    "./store.ts": { selectedDevice: { subscribe() {} } },
    "./device-list.ts": {
      endpointFor: endpoint,
      subscribe(fn) { subscribers.push(fn); return () => {}; },
    },
  };
  const exports = {};
  vm.runInNewContext(compiled, {
    exports,
    require(name) { assert(name in deps, name); return deps[name]; },
    document: {
      querySelectorAll(selector) {
        return selector.includes("data-ptz") ? [home, right] : [preset];
      },
    },
    setTimeout(fn, ms) { timers.set(++timerId, { fn, ms }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  });
  exports.setupPtzControls();
  exports.testHooks.zoomHooks(
    () => zooms.push({ camera, value: 0 }),
    value => zooms.push({ camera, value }),
  );
  return {
    exports, hooks: exports.testHooks, calls, pending, timers, home, right, preset, zooms,
    // No notification isolates continuation checks from the subscription.
    change(target = B, notify = false) {
      current = target;
      if (notify) subscribers.forEach(fn => fn());
    },
    changeCamera(target = B) { camera = target; },
    release(cmd, data = { PP: "0", TP: "0" }) {
      const index = pending.findIndex(p => p.call.cmd === cmd);
      assert(index >= 0, `no pending ${cmd}`);
      pending.splice(index, 1)[0].resolve(data);
    },
    fireTimer(ms) {
      const entry = [...timers].find(([, t]) => t.ms === ms);
      assert(entry, `no ${ms}ms timer`);
      timers.delete(entry[0]);
      return entry[1].fn();
    },
  };
}

for (const sameIp of [false, true]) {
  const label = sameIp ? "same-IP replacement" : "different-IP replacement";

  test(`Home timer cancels after ${label}, even after farewell halt`, async () => {
    const f = fixture({ sameIp });
    const home = f.home.fire("click");
    await flush();
    assert.equal(f.calls[0].target.key, A.key);
    f.change();
    f.exports.haltPtuUnit("192.0.2.20", A);
    await flush();
    f.fireTimer(250);
    await home;
    assert.deepEqual(f.calls.map(c => c.cmd), [
      "C=I&PS=100&TS=100&PP=0&TP=0", "PS=0&TS=0",
    ]);
    assert(f.calls.every(c => c.target.key === A.key));
  });

  for (const action of ["Home", "preset"]) {
    test(`${action} ACK cannot start follow-ups on ${label}`, async () => {
      const f = fixture({ sameIp, hold: cmd => cmd.startsWith("C=I") });
      f.hooks.seedPreset();
      if (action === "preset") f.preset.fire("pointerdown");
      const handler = action === "Home" ? f.home.fire("click") : f.preset.fire("pointerup");
      const goto = f.calls[0].cmd;
      f.change();
      f.changeCamera();
      f.release(goto);
      await handler;
      await flush();
      assert.equal(f.calls.length, 1);
      assert.equal(f.calls[0].target.key, A.key);
      assert.equal(f.zooms.length, 0);
      assert.equal(f.timers.size, 0);
    });
  }

  test(`poll response cannot send velocity mode to ${label}`, async () => {
    const f = fixture({ sameIp, hold: cmd => cmd === "PP&TP" });
    const home = f.home.fire("click");
    await flush();
    f.fireTimer(250);
    await flush();
    f.change();
    f.release("PP&TP");
    await home;
    assert.equal(f.calls.length, 2);
    assert(f.calls.every(c => c.target.key === A.key && c.cmd !== "C=V"));
  });

  test(`speed ACK cannot update limits or initialize ${label}`, async () => {
    const f = fixture({ sameIp, hold: cmd => cmd === "PU&TU&PL&TL" });
    const query = f.hooks.queryPtuSpeed();
    f.change();
    f.release("PU&TU&PL&TL", { PU: "900", TU: "800", PL: "10" });
    await query;
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].target.key, A.key);
    assert.deepEqual(Array.from(f.hooks.speed()), [100, 10, false]);
  });
}

test("unchanged Home and preset complete polling and return to velocity mode on A", async () => {
  for (const action of ["Home", "preset"]) {
    const f = fixture();
    f.hooks.seedPreset();
    if (action === "preset") f.preset.fire("pointerdown");
    const handler = action === "Home" ? f.home.fire("click") : f.preset.fire("pointerup");
    await flush();
    f.fireTimer(250);
    await handler;
    await flush();
    assert.deepEqual(f.calls.map(c => c.cmd), [
      "C=I&PS=100&TS=100&PP=0&TP=0", "PP&TP", "C=V",
    ]);
    assert(f.calls.every(c => c.target.key === A.key && c.ip === "192.0.2.20"));
    assert.equal(f.zooms.length, 1);
  }
});

test("unchanged speed initialization publishes limits and sends C=V on A", async () => {
  const f = fixture();
  await f.hooks.queryPtuSpeed();
  assert.deepEqual(f.calls.map(c => c.cmd), ["PU&TU&PL&TL", "C=V"]);
  assert(f.calls.every(c => c.target.key === A.key));
  assert.deepEqual(Array.from(f.hooks.speed()), [200, 20, true]);
});

test("subscription detects same-IP identity replacement and initializes B separately", async () => {
  const f = fixture({ sameIp: true });
  f.change(A, true);
  await flush();
  f.change(B, true);
  await flush();
  assert.deepEqual(f.calls.map(c => [c.cmd, c.target.key]), [
    ["PU&TU&PL&TL", A.key], ["C=V", A.key],
    ["PU&TU&PL&TL", B.key], ["C=V", B.key],
  ]);
});

test("A to B to A does not revive an old operation", async () => {
  const f = fixture();
  const operation = f.hooks.capturePtuOperation();
  f.change(B, true);
  f.change(A, true);
  await flush();
  const count = f.calls.length;
  assert.equal(await f.hooks.ptuCmd("PP&TP", operation), null);
  assert.equal(f.calls.length, count);
});

test("stale work waiting behind another command is dropped at dequeue", async () => {
  const f = fixture({ hold: cmd => cmd === "BLOCK" });
  const first = f.hooks.enqueuePtuCmd("BLOCK");
  const stale = f.hooks.ptuCmd("C=V");
  f.change();
  f.release("BLOCK");
  await first;
  assert.equal(await stale, null);
  assert.equal(f.calls.length, 1);
});

test("farewell halt retries on original identity and retires waiting workflows", async () => {
  const f = fixture({ sameIp: true, failHalt: true });
  const operation = f.hooks.capturePtuOperation();
  f.change();
  f.exports.haltPtuUnit("192.0.2.20", A);
  await flush();
  assert.equal(f.calls.length, 2);
  assert(f.calls.every(c => c.cmd === "PS=0&TS=0" && c.target.key === A.key));
  assert.equal(await f.hooks.ptuCmd("C=V", operation), null);
});

test("preset hold timer and save response cannot cross a role change", async () => {
  for (const boundary of ["timer", "response"]) {
    const f = fixture({ hold: cmd => cmd === "PP&TP" });
    f.preset.fire("pointerdown");
    if (boundary === "timer") f.change();
    const save = f.fireTimer(800);
    if (boundary === "response") {
      f.change();
      f.release("PP&TP");
    }
    await save;
    assert.equal(f.hooks.hasPreset(), false);
    assert(f.calls.every(c => c.target.key === A.key));
    assert.equal(f.calls.length, boundary === "timer" ? 0 : 1);
  }
});

test("D-pad release cannot stop a replacement PTU", async () => {
  const f = fixture({ sameIp: true });
  await f.hooks.queryPtuSpeed();
  f.right.fire("pointerdown");
  await flush();
  const count = f.calls.length;
  f.change();
  f.right.fire("pointerup");
  await flush();
  assert.equal(f.calls.length, count);
  assert(f.calls.every(c => c.target.key === A.key));
});

test("CAM replacement during Home ACK suppresses delayed zoom", async () => {
  const f = fixture({ sameIp: true, hold: cmd => cmd.startsWith("C=I") });
  const home = f.home.fire("click");
  f.changeCamera();
  f.release(f.calls[0].cmd);
  await flush();
  f.fireTimer(250);
  await home;
  assert.equal(f.zooms.length, 0);
  assert.deepEqual(f.calls.map(c => c.cmd), [
    "C=I&PS=100&TS=100&PP=0&TP=0", "PP&TP", "C=V",
  ]);
});
