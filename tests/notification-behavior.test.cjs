const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const ts = require("typescript");
const source = name => fs.readFileSync(path.join(__dirname, "..", name), "utf8");
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

// Actual modules/controllers; fake only DOM, IPC and timers. No new framework.
function fixture() {
  const ids = new Map(), events = new Map(), timers = [], logs = [], visibility = [];
  let now = 20000;
  class Element {
    constructor(tag = "div") {
      Object.assign(this, { tag, className: "", textContent: "", innerHTML: "", style: {}, children: [], listeners: {} });
      this.classList = {
        contains: c => this.className.split(" ").includes(c),
        toggle: (c, on = !this.classList.contains(c)) => {
          this.className = [...new Set([...this.className.split(" ").filter(x => x && x !== c), ...(on ? [c] : [])])].join(" ");
        },
        add: c => this.classList.toggle(c, true), remove: c => this.classList.toggle(c, false),
      };
    }
    appendChild(child) { child.parent = this; this.children.push(child); return child; }
    get textContent() { return (this._text || '') + (this.children || []).map(c => c.textContent).join(''); }
    set textContent(value) { this._text=String(value);this.children=[]; }
    setAttribute(name,value) { this.attributes ??= {};this.attributes[name]=value; }
    append(...children) { children.forEach(c => this.appendChild(c)); }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    fire(name) { return this.listeners[name]?.({ preventDefault() {} }); }
    querySelector(selector) {
      for (const child of this.children) {
        const matches = selector.startsWith(".")
          ? child.classList.contains(selector.slice(1).split(":")[0]) && (!selector.includes(":not") || !child.classList.contains("update-toast"))
          : child.tag === selector;
        if (matches) return child;
        const nested = child.querySelector(selector); if (nested) return nested;
      }
      return null;
    }
  }
  const body = new Element(), head = new Element();
  const document = {
    body, head, createElement: tag => new Element(tag),
    querySelector(selector) {
      if (!selector.startsWith("#")) return body.querySelector(selector);
      if (!ids.has(selector)) ids.set(selector, new Element());
      return ids.get(selector);
    }, querySelectorAll: () => [],
  };
  const api = {
    logToFile: (level, message) => logs.push({ level, message }),
    onEvent: async (name, callback) => { events.set(name, callback); return () => {}; },
    setVideoVisible: async value => { visibility.push(value); },
    retryPlayback: async () => {}, getCaptureState: async () => null,
    takeScreenshot: async () => "C:\\Pictures\\PocketStream\\capture.jpg",
    startRecording: async () => {}, stopRecording: async () => "C:\\Videos\\PocketStream\\recording.mp4",
  };
  const globals = { document, console: { log() {} }, Date: class extends Date { static now() { return now; } },
    setTimeout: fn => { timers.push(fn); return timers.length; }, clearTimeout() {} };
  function load(text, deps = {}, extra = {}) {
    const exports = {};
    vm.runInNewContext(ts.transpileModule(text, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    }).outputText, { exports, require(name) { assert(name in deps, name); return deps[name]; }, ...globals, ...extra });
    return exports;
  }
  const shared = load(source("src/lib/state.ts"), { "./tauri-api.ts": api });
  const blank = {}, noop = () => {};
  const deps = {
    "./tauri-api.ts": api, "./state.ts": shared, "./errors.ts": { formatError: String },
    "./store.ts": blank, "./device-state.ts": blank,
    "./device-list.ts": { subscribe: noop, getDevices: () => [] }, "./ptz.ts": blank,
    "./devices.js": { renderArpDeviceList: noop, hideDiscoveryStatus: noop },
    "./streaming.js": { handleHardDisconnect: noop }, "qrcode": blank,
  };
  const network = load(source("src/lib/network.ts"), deps);
  deps["./network.ts"] = network;
  const streaming = load(source("src/lib/streaming.ts"), deps);
  deps["./streaming.ts"] = streaming;
  const updaterAst = ts.createSourceFile("main.ts", source("src/main.ts"), ts.ScriptTarget.Latest, true);
  const updater = load(updaterAst.statements.filter(s => ts.isFunctionDeclaration(s)
    && s.name?.text === "showUpdateToast").map(s => s.getText(updaterAst)).join("\n")
    + "\nexports.showUpdateToast = showUpdateToast;", {}, { api, formatError: String });
  return { api, shared, network, streaming, updater, load, deps, events, logs, visibility,
    $: shared.$, toast: () => body.querySelector(".toast"), update: () => body.querySelector(".update-toast"),
    advance: ms => { now += ms; }, runTimers: () => timers.splice(0).forEach(fn => fn()) };
}

test("User actions retain success and error toasts alongside diagnostics", () => {
  const f = fixture();
  f.shared.showToast("Settings saved"); assert.equal(f.toast().textContent, "Settings saved");
  f.shared.showToast("Enter a valid address", true);
  const error = f.toast(); assert.equal(error.textContent, "Enter a valid address");
  f.shared.showToast("Address updated"); assert.equal(f.toast().textContent, "Address updated");
  assert(f.logs.some(x => x.message.includes("Settings saved")));
});

test("Screenshot and recording buttons show the saved file paths", async () => {
  const f = fixture(); f.streaming.setupStreamControls();
  await f.$("#btn-screenshot").fire("click");
  assert.equal(f.toast().textContent, "Screenshot saved: C:\\Pictures\\PocketStream\\capture.jpg");
  await f.$("#btn-record").fire("click");
  assert.equal(f.toast().textContent, "Recording started");
  f.advance(1000); await f.$("#btn-record").fire("click");
  assert.equal(f.toast().textContent, "Recording saved: C:\\Videos\\PocketStream\\recording.mp4");
});

test("Update toast keeps Install and survives routine and error notifications", async () => {
  const f = fixture(); let installs = 0;
  f.updater.showUpdateToast({ version: "test-version", downloadAndInstall: async () => { installs++; } });
  const update = f.update();
  f.shared.showToast("Playback requested"); f.shared.showToast("Action failed", true);
  assert.equal(f.update(), update);
  await update.children.find(c => c.textContent === "Install").fire("click");
  assert.equal(installs, 1);
  assert.equal(update.children[0].textContent, "Update installed. Restart to apply.");
});

test("Update toast retains the Later action", () => {
  const f = fixture();
  f.updater.showUpdateToast({ version: "test-version" });
  f.update().children.find(c => c.textContent === "Later").fire("click");
  f.runTimers(); assert.equal(f.update(), null);
});

function status(overrides = {}) {
  return { playback_desired: true, playback_state: "recovering", playback_next_retry_secs: 24,
    playback_fault: { reason: "Network error: Selected Ethernet adapter unavailable" },
    rtsp_desired: false, audio_present: false, audio_codec: null, recording: false,
    recording_report: null, ...overrides };
}

test("Recovery shows one message with cycling dots, no button/countdown/toast, and preserves video state", async () => {
  const f = fixture(); let retries = 0;
  f.api.retryPlayback = async () => { retries++; };
  f.streaming.startStatusListener();
  const publish = f.events.get("stream-status"); publish(status()); await flush();
  const overlay = f.$("#video-area").querySelector(".stream-lost-overlay");
  assert.equal(overlay.querySelector(".playback-reason").textContent,
    "Network Error: Check link. Retrying.");
  assert.equal(f.toast(), null); assert(overlay.classList.contains("visible"));
  assert.equal(f.visibility.at(-1), false);
  assert.equal(overlay.querySelector("button"), null);
  assert.equal(retries, 0); assert(overlay.classList.contains("visible"));
  for (const dots of ["..", "...", "."]) {
    f.advance(1000); publish(status());
    assert.equal(overlay.querySelector(".playback-reason").textContent, `Network Error: Check link. Retrying${dots}`);
    assert.equal(overlay.querySelector(".playback-dots").textContent, dots);
    assert.equal(overlay.querySelector(".playback-dots").attributes['aria-hidden'], 'true');
    assert.equal(overlay.querySelector(".playback-reason")._text, 'Network Error: Check link. Retrying');
  }
  publish(status({ playback_next_retry_secs: 0 }));
  assert.equal(overlay.querySelector(".playback-reason").textContent, "Network Error: Check link. Retrying.");
  publish(status({ playback_state: "starting", playback_next_retry_secs: null }));
  assert.equal(overlay.querySelector(".playback-reason").textContent, "Network Error: Check link. Retrying.");
  assert.equal(overlay.children.filter(c => c.tag === "span").length, 1);
  publish(status({ playback_state: "playing", playback_fault: null, playback_next_retry_secs: null }));
  await flush(); assert.equal(f.toast(), null); assert(!overlay.classList.contains("visible"));
  assert.equal(f.visibility.at(-1), true);
  f.advance(2000); publish(status());
  assert.equal(overlay.querySelector(".playback-reason").textContent, "Network Error: Check link. Retrying.", "new outage starts at one dot");
});

test("Connecting and permanent failure labels remain without a manual Retry button", async () => {
  const f = fixture(); f.streaming.startStatusListener();
  const publish = f.events.get("stream-status");
  for (const [playback_state, playback_fault, expected] of [
    ["starting", null, "Connecting"], ["failed", { reason: "Invalid credentials" }, "Playback failed: Invalid credentials"],
    ["recovering", null, "Network Error: Check link. Retrying."],
  ]) {
    publish(status({ playback_state, playback_fault, playback_next_retry_secs: null }));
    assert.equal(f.$("#video-area").querySelector(".playback-reason").textContent, expected);
    assert.equal(f.$("#video-area").querySelector("button"), null);
  }
  assert.equal(f.toast(), null);
});

test("Recording interruption reports remain actionable and deduplicated", () => {
  const f = fixture(); f.streaming.startStatusListener();
  const report = status({ recording_report: "recording stopped: stream lost", recording_finalized_path: "saved.mp4" });
  f.events.get("stream-status")(report);
  const toast = f.toast(); assert.match(toast.textContent, /recording stopped: stream lost: saved.mp4/);
  f.events.get("stream-status")(report); assert.equal(f.toast(), toast);
});

test("No-Ethernet status stays in the Host card and diagnostics without a toast", () => {
  const f = fixture(); f.network.warnNoEthernet();
  assert.equal(f.toast(), null); assert(f.logs.some(x => x.message.includes("No Ethernet detected")));
});

test("Quiet discovery and auto-adoption retries are diagnostic only", () => {
  const f = fixture(); const devices = f.load(source("src/lib/devices.ts"), f.deps);
  devices.setupArpListeners();
  f.events.get("discovery-degraded")({ reason: "quiet", missed_packets: 0 });
  f.events.get("adoption-failed")({ subnet: "192.0.2.0/24", error: "retry pending" });
  assert.equal(f.toast(), null);
  assert(f.logs.some(x => x.message.includes("Discovery degraded")));
  assert(f.logs.some(x => x.message.includes("Auto-adopt failed")));
});

test("Degraded capture never occupies Nodes card space and still publishes capture state", async () => {
  const f = fixture(); const devices = f.load(source("src/lib/devices.ts"), f.deps);
  await devices.refreshCaptureState();
  let observed; devices.subscribeCaptureState(value => { observed = value; });
  for (const outcome of [{ scope: "scoped_by_name", source_id: 1 },
    { scope: "unscoped_fallback", reason: "no source matched" }]) {
    f.events.get("capture-active")({ active: true, outcome, adapter_name: "Ethernet", candidate_count: 2 });
    assert.equal(f.$("#capture-scope-status").hidden, true);
    assert.equal(f.$("#capture-scope-status").textContent, "");
    assert.equal(observed.active, true); assert.equal(observed.candidate_count, 2);
  }
});

test("Host card hides completed removals but retains pending removals and saved addresses", () => {
  const f = fixture();
  const row = { address: "172.26.95.99", prefix: 24, adapter_mac: "00:22:20:3a:e3:b3",
    desired: "removed", applied: false, last_error: null };
  const meta = f.shared.adoptionMeta; meta.set("172.26.95.0/24", row);
  f.network.renderSubnetList(); assert(!f.$("#subnet-list").innerHTML.includes("172.26.95.99"));
  meta.set("172.26.95.0/24", { ...row, last_error: "OS rejected removal" });
  f.network.renderSubnetList(); assert(f.$("#subnet-list").innerHTML.includes("172.26.95.99"));
  meta.set("172.26.95.0/24", { ...row, desired: "present" });
  meta.set("169.254.10.0/24", { ...row, address: "169.254.10.2", desired: "present" });
  f.network.renderSubnetList(); const html = f.$("#subnet-list").innerHTML;
  assert(html.includes("172.26.95.99") && html.includes("169.254.10.2"));
});

async function nodeRemovalFixture(kind) {
  const f = fixture(), calls = [];
  const first = { mac: "40:cd:3a:03:8f:3f", ip: "192.168.1.204", subnet: "192.168.1.0/24",
    alias: "", open_ports: [554], status: "cached_only", first_seen: "before", last_seen: "before" };
  let records = kind === "all" ? [first, { ...first, mac: "40:cd:3a:03:8f:40", ip: "192.168.1.205" }] : [first];
  let pins = kind === "cached" ? [] : [{ ip: first.ip, alias: "", expected_mac: first.mac }];
  f.shared.state.config = { network_mode: "static_auto", manual_nodes: pins };
  f.shared.state.activeInterface = { name: "Ethernet", mac: "00:22:20:3a:e3:b3", is_up: true,
    ips: [{ address: "192.168.1.100", prefix: 24, subnet: first.subnet }] };
  f.api.getConfig = async () => ({ ...f.shared.state.config, manual_nodes: [...pins] });
  f.api.getDeviceList = async () => [...records];
  const publish = () => f.events.get("device-list-changed")([...records]);
  f.api.forgetDevice = async mac => {
    calls.push(["forget", mac]); records = records.filter(r => r.mac !== mac); publish();
  };
  f.api.removeManualNode = async (ip, expectedMac) => {
    calls.push(["manual", ip, expectedMac]);
    pins = pins.filter(n => n.ip !== ip || n.expected_mac !== expectedMac);
    records = records.filter(r => r.mac !== expectedMac && r.mac !== `manual:${ip}`); publish();
  };
  f.api.clearManualNodes = async () => { calls.push(["clear-pins"]); pins = []; };
  let finishScan;
  f.api.scanNetwork = () => new Promise(resolve => { finishScan = resolve; });
  f.api.reportScanResult = async (key, ports) => {
    const row = records.find(r => r.mac === key);
    if (row) { row.open_ports = ports; publish(); }
  };
  f.deps["./store.ts"] = f.load(source("src/lib/store.ts"));
  f.deps["./device-state.ts"] = f.load(source("src/lib/device-state.ts"), f.deps);
  const mirror = f.load(source("src/lib/device-list.ts"), f.deps);
  f.deps["./device-list.ts"] = mirror;
  const card = f.$("#device-list"); card.querySelectorAll = () => [];
  const cacheList = f.$("#cache-dialog-list"); let buttons = [], nextButton = 0;
  cacheList.querySelectorAll = selector => {
    assert.equal(selector, ".cache-forget-btn");
    buttons = [...cacheList.innerHTML.matchAll(/<button class="cache-forget-btn[^\"]*" data-mac="([^\"]*)" data-ip="([^\"]*)" data-manual="([^\"]*)"/g)].map(match => {
      const btn = f.$(`#node-remove-${++nextButton}`);
      btn.dataset = { mac: match[1], ip: match[2], manual: match[3] }; return btn;
    });
    return buttons;
  };
  f.deps["./streaming.js"] = { showModalWithVideo: async dialog => { dialog.open = true; } };
  const devices = f.load(source("src/lib/devices.ts") + "\nexports.scanForTest = scanDevicePorts;", f.deps);
  const cache = f.load(source("src/lib/device-cache.ts"), f.deps);
  devices.setupArpListeners(); cache.setupCacheDialog(); await mirror.start();
  await f.$("#btn-nodes-config").fire("click");
  assert(card.innerHTML.includes(first.ip)); assert(cacheList.innerHTML.includes(first.ip));
  const scan = devices.scanForTest(first.mac, first.ip);
  assert(finishScan, "the real scan handler has an outstanding reply");
  return { f, first, calls, card, cacheList, mirror, scan,
    remove: () => kind === "all" ? f.$("#cache-clear-all").fire("click") : buttons[0].fire("click"),
    finish: () => finishScan([{ reachable: true, open_ports: [554] }]),
    rediscover: () => { records = [first]; publish(); },
  };
}

for (const kind of ["cached", "manual", "all"]) {
  test(`Nodes ${kind} removal clears the card immediately while the last port scan is pending`, async () => {
    const t = await nodeRemovalFixture(kind); await t.remove();
    const cardAfterRemoval = t.card.innerHTML;
    assert.equal(t.mirror.getDevices().length, 0, "authoritative event retired the records");
    assert.equal(t.cacheList.innerHTML, "", "Configure is already empty");
    assert.equal(t.f.$("#cache-dialog-empty").style.display, "");
    t.finish(); await t.scan;
    assert.equal(cardAfterRemoval, "", "the card must clear even while the scan reply is outstanding");
    assert(!t.card.innerHTML.includes(t.first.ip), "late capabilities cannot repaint the deleted node");
    assert(!t.f.logs.some(x => x.message.includes("subscriber threw")));
    if (kind === "cached") assert.deepEqual(t.calls, [["forget", t.first.mac]]);
    if (kind === "manual") assert.deepEqual(t.calls, [["manual", t.first.ip, t.first.mac]]);
    if (kind === "all") assert.deepEqual(t.calls, [["manual", t.first.ip, t.first.mac], ["forget", "40:cd:3a:03:8f:40"], ["clear-pins"]]);
    t.rediscover(); assert(t.card.innerHTML.includes(t.first.ip), "fresh backend discovery is still visible");
  });
}

for (const result of ["ports", "empty", "error"]) {
  test(`Manual mode stops Discovery and retires a delayed ${result} scan without retries or lost history`, async () => {
    const f = fixture(), timers = new Map(), scans = [], reports = [];
    let timerId = 0;
    const record = { mac: "40:cd:3a:03:8f:3f", ip: "192.168.1.204", subnet: "192.168.1.0/24",
      alias: "CAM", open_ports: [554], status: "live", first_seen: "before", last_seen: "before" };
    f.shared.state.config = { network_mode: "static_auto" };
    f.shared.state.activeInterface = { name: "Ethernet", mac: "00:22:20:3a:e3:b3", is_up: true,
      ips: [{ address: "192.168.1.100", prefix: 24, subnet: record.subnet }] };
    f.api.getDeviceList = async () => [record];
    f.api.scanNetwork = () => new Promise((resolve, reject) => scans.push({ resolve, reject }));
    f.api.reportScanResult = async (...args) => { reports.push(args); };
    f.deps["./store.ts"] = f.load(source("src/lib/store.ts"));
    f.deps["./device-state.ts"] = f.load(source("src/lib/device-state.ts"), f.deps);
    const mirror = f.load(source("src/lib/device-list.ts"), f.deps);
    f.deps["./device-list.ts"] = mirror;
    f.$("#device-list").querySelectorAll = () => [];
    const devices = f.load(source("src/lib/devices.ts") + "\nexports.scanForTest = scanDevicePorts;", f.deps, {
      setTimeout(fn, ms) { timers.set(++timerId, { fn, ms }); return timerId; },
      clearTimeout(id) { timers.delete(id); },
    });
    devices.setupArpListeners(); await mirror.start();
    const history = JSON.stringify(mirror.getDevices());
    const scan = devices.scanForTest(record.mac, record.ip);
    f.events.get("arp-device-discovered")({ ip: "192.168.1.205", mac: "40:cd:3a:03:8f:40" });
    assert.equal(scans.length, 1); assert(timers.size > 0, "settle work is pending before mode change");
    f.shared.state.config.network_mode = "static_manual"; devices.hideDiscoveryStatus();
    assert.equal(timers.size, 0, "Manual discards the old settle/grace work");
    f.events.get("arp-device-discovered")({ ip: "192.168.1.205", mac: "40:cd:3a:03:8f:40" });
    if (result === "ports") devices.resetDiscoveryStatus(); // Queued NIC reconnect in Manual.
    if (result === "error") scans[0].reject(Error("prior scan cancelled by transition"));
    else scans[0].resolve([{ reachable: true, open_ports: result === "ports" ? [80, 554] : [] }]);
    await scan; await flush();
    assert.equal(scans.length, 1); assert.equal(reports.length, 0);
    assert.equal(timers.size, 0, "no old scan retry or startup grace survives in Manual");
    assert(f.$("#discovery-status").classList.contains("hidden"));
    assert(!f.$("#btn-refresh-nodes").classList.contains("discovery-active"));
    assert.equal(JSON.stringify(mirror.getDevices()), history);
    f.shared.state.config.network_mode = "static_auto"; devices.resetDiscoveryStatus();
    assert.equal(scans.length, 2, "returning to Auto can scan the retained identity again");
    assert(f.$("#btn-refresh-nodes").classList.contains("discovery-active"));
    scans[1].resolve([{ reachable: true, open_ports: [554] }]); await flush();
    assert.equal(reports.length, 1); assert.equal(JSON.stringify(mirror.getDevices()), history);
  });
}
