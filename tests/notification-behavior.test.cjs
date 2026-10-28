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
      Object.assign(this, { tag, className: "", textContent: "", innerHTML: "", style: {}, dataset: {}, children: [], listeners: {} });
      this.classList = {
        contains: c => this.className.split(" ").includes(c),
        toggle: (c, on = !this.classList.contains(c)) => {
          this.className = [...new Set([...this.className.split(" ").filter(x => x && x !== c), ...(on ? [c] : [])])].join(" ");
        },
        add: c => this.classList.toggle(c, true), remove: c => this.classList.toggle(c, false),
      };
    }
    replaceChildren(...children) { this.children = []; this.append(...children); }
    appendChild(child) { child.parent = this; this.children.push(child); return child; }
    get textContent() { return (this._text || '') + (this.children || []).map(c => c.textContent).join(''); }
    set textContent(value) { this._text=String(value);this.children=[]; }
    setAttribute(name,value) { this.attributes ??= {};this.attributes[name]=value; }
    getBoundingClientRect() { return this.bounds ?? { top: 0, height: 0 }; }
    append(...children) { children.forEach(c => this.appendChild(c)); }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    fire(name, event = {}) { return this.listeners[name]?.({ preventDefault() {}, ...event }); }
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
    listBindInterfaces: async () => [],
    takeScreenshot: async () => "C:\\Pictures\\PocketStream\\capture.jpg",
    startRecording: async () => {}, stopRecording: async () => "C:\\Videos\\PocketStream\\recording.mp4",
  };
  const globals = { document, window: { innerHeight: 1000 }, console: { log() {}, warn() {} }, Date: class extends Date { static now() { return now; } },
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
    "./ip-conflicts.ts": { forIp: () => null, subscribe: () => () => {}, start: async () => {} },
    "./device-list.ts": { subscribe: noop, getDevices: () => [] }, "./ptz.ts": blank,
    "./devices.js": { renderArpDeviceList: noop, hideDiscoveryStatus: noop },
    "./streaming.js": { handleHardDisconnect: noop }, "qrcode": blank,
  };
  deps["./restream-format.ts"] = load(source("src/lib/restream-format.ts"));
  deps["./restream-settings.ts"] = load(source("src/lib/restream-settings.ts"));
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

test("Screenshot and recording can be pressed again while their previous toast is visible", async () => {
  const f = fixture(); let shots = 0, starts = 0, stops = 0;
  f.api.takeScreenshot = async () => `shot-${++shots}.jpg`;
  f.api.startRecording = async () => { starts++; };
  f.api.stopRecording = async () => { stops++; return 'recording.mp4'; };
  f.streaming.setupStreamControls();
  await f.$('#btn-screenshot').fire('click');
  const first = f.toast();
  assert.match(first.style.cssText, /pointer-events:\s*none/);
  await f.$('#btn-screenshot').fire('click');
  assert.equal(shots, 2); assert.notEqual(f.toast(), first);
  await f.$('#btn-record').fire('click');
  f.advance(1000); await f.$('#btn-record').fire('click');
  f.advance(1000); await f.$('#btn-record').fire('click');
  assert.equal(starts, 2); assert.equal(stops, 1);
  assert.equal(f.toast().textContent, 'Recording started');
});

test("Transient notices clear both controls and the native video without stealing clicks", () => {
  const f = fixture();
  f.shared.showToast('Settings saved');
  assert.match(f.toast().style.cssText, /bottom:\s*80px/);
  f.shared.state.isStreaming = true;
  f.$('#video-area').bounds = { top: 400, height: 500 };
  f.shared.showToast('Recording started');
  assert.match(f.toast().style.cssText, /bottom:\s*612px/);
  assert.match(f.toast().style.cssText, /pointer-events:\s*none/);
});

test("Changing the camera adapter retires an older re-stream interface enumeration", async () => {
  const f = fixture(), requests = [];
  f.shared.state.config = { restream_protocol: 'rtsp',
    rtsp_server: { bind_interface: 'Wi-Fi', bind_interface_id: 'wifi' },
    srt_server: { bind_interface: '', bind_interface_id: null } };
  f.api.listBindInterfaces = () => new Promise(resolve => requests.push(resolve));
  f.streaming.startStatusListener();
  f.events.get('binding-topology-changed')();
  f.events.get('adapter-selection-changed')();
  assert.equal(requests.length, 2);
  requests[1]([{ id: 'wifi', alias: 'Wi-Fi', kind: 'wifi', address: '192.0.2.2' }]);
  await flush();
  requests[0]([{ id: 'camera', alias: 'Ethernet', kind: 'ethernet', address: '192.168.0.100' }]);
  await flush();
  const select = f.$('#restream-bind-interface');
  assert.deepEqual(select.children.map(option => option.value), ['', 'wifi']);
  assert.equal(select.value, 'wifi'); assert.equal(select.disabled, false);
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
    selected_protocol: "rtsp", desired: false, audio_present: false, audio_codec: null, recording: false,
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

test("Nodes title leaves the modal closed while Configure still opens it", async () => {
  const t = await nodeRemovalFixture('cached');
  const dialog = t.f.$('#cache-dialog'); dialog.open = false;
  await t.f.$('#nodes-title').fire('click');
  assert.equal(dialog.open, false);
  await t.f.$('#btn-nodes-config').fire('click');
  assert.equal(dialog.open, true);
  t.finish(); await t.scan;
});

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
    assert.equal(scans.length, 1, "new ARP activity cannot duplicate the running scan");
    f.shared.state.config.network_mode = "static_manual"; devices.hideDiscoveryStatus();
    assert.equal(timers.size, 0, "Manual discards the old progress work");
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
    assert.equal(reports.length, 0, "scan completion is published by the backend without a renderer echo");
    assert.equal(JSON.stringify(mirror.getDevices()), history);
  });
}

async function progressiveScanFixture() {
  const f = fixture(), scans = [], timers = new Map();
  let timerId = 0;
  f.shared.state.config = { network_mode: "static_auto" };
  f.shared.state.activeInterface = { name: "Ethernet", mac: "00:22:20:3a:e3:b3", is_up: true,
    ips: [{ address: "192.168.0.100", prefix: 24, subnet: "192.168.0.0/24" }] };
  f.api.getDeviceList = async () => [];
  f.api.scanNetwork = cidr => new Promise(resolve => scans.push({ cidr, resolve }));
  f.deps["./store.ts"] = f.load(source("src/lib/store.ts"));
  f.deps["./device-state.ts"] = f.load(source("src/lib/device-state.ts"), f.deps);
  const mirror = f.load(source("src/lib/device-list.ts"), f.deps);
  f.deps["./device-list.ts"] = mirror;
  f.deps["./network.ts"] = { ...f.network, refreshNetworkEvent() {} };
  f.$("#device-list").querySelectorAll = () => [];
  const devices = f.load(source("src/lib/devices.ts"), f.deps, {
    setTimeout(fn, ms) { timers.set(++timerId, { fn, ms }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  });
  devices.setupArpListeners(); await mirror.start();
  return { f, scans, timers, devices,
    publish: records => f.events.get("device-list-changed")(records),
    adopt: (subnet, adopted_ip) => f.events.get("subnet-adopted")({ subnet, adopted_ip,
      restored: false, adapter_mac: f.shared.state.activeInterface.mac }),
    finish: async () => { scans.forEach(s => s.resolve([{ reachable: true, open_ports: [80, 554] }])); await flush(); },
  };
}

const scanPeer = (ip, mac, status = "live") => ({ mac, ip,
  subnet: ip.split(".").slice(0, 3).join(".") + ".0/24", status,
  alias: "", open_ports: [], first_seen: "before", last_seen: "now",
});

test("Discovery rows and node numbers survive subnet sorting, late peers and IP changes", async () => {
  const t = await progressiveScanFixture();
  const first = { ...scanPeer('192.168.1.74', '08:df:ec:22:01:77'), first_seen: '2026-10-27T19:01:59Z' };
  const camera = { ...scanPeer('172.31.169.84', '40:cd:3a:03:28:e2'), first_seen: '2026-10-27T19:02:13Z' };
  const ptu = { ...scanPeer('192.168.1.202', 'fc:68:3e:22:05:28'), first_seen: '2026-10-27T19:02:31Z' };
  const rows = () => [...t.f.$('#device-list').innerHTML.matchAll(/data-key="([^"]+)" data-ip="([^"]+)"[\s\S]*?<option selected disabled hidden>([^<]+)<\/option>/g)].map(m => [m[1], m[2], m[3]]);
  t.publish([first]);
  t.publish([camera, first]);
  t.publish([camera, first, ptu]);
  assert.deepEqual(rows(), [[first.mac, first.ip, 'Node 1'], [camera.mac, camera.ip, 'Node 2'], [ptu.mac, ptu.ip, 'Node 3']]);
  t.publish([{ ...ptu, status: 'offline' }, { ...camera, ip: '172.31.169.85', open_ports: [554] }]);
  assert.deepEqual(rows(), [[camera.mac, '172.31.169.85', 'Node 2'], [ptu.mac, ptu.ip, 'Node 3']]);
  t.publish([ptu, camera, first]);
  assert.equal(rows()[0][0], first.mac);
  t.publish([]); t.publish([ptu]);
  assert.equal(rows()[0][2], 'Node 1', 'clearing all history starts fresh numbering');
  await t.finish();
});

test("An initial device batch uses discovery timestamps rather than backend IP order", async () => {
  const t = await progressiveScanFixture();
  const first = { ...scanPeer('192.168.1.74', '08:df:ec:22:01:77'), first_seen: '2026-10-27T19:01:59Z' };
  const camera = { ...scanPeer('172.31.169.84', '40:cd:3a:03:28:e2'), first_seen: '2026-10-27T19:02:13Z' };
  t.publish([camera, first]);
  const html = t.f.$('#device-list').innerHTML;
  assert(html.indexOf(first.ip) < html.indexOf(camera.ip));
  await t.finish();
});

test("Auto adoption label survives a peer expiring and returning, until the binding is removed", async () => {
  const t = await progressiveScanFixture();
  const ptu = scanPeer("192.168.1.202", "fc:68:3e:22:05:28");
  t.publish([ptu]); t.adopt(ptu.subnet, "192.168.1.100");
  const labels = t.f.network.sessionAdoptedSubnets;
  assert(labels.has(ptu.subnet));
  t.publish([{ ...ptu, status: "offline" }]);
  assert(labels.has(ptu.subnet), "peer presence does not own the host binding label");
  t.publish([ptu]); assert(labels.has(ptu.subnet));
  t.f.events.get("subnet-removed")({ subnet: ptu.subnet, adopted_ip: "192.168.1.100", reason: "manual" });
  assert(!labels.has(ptu.subnet));
  await t.finish();
});

test("Each adopted subnet scans immediately while another adoption or device scan is unfinished", async () => {
  const t = await progressiveScanFixture();
  const camera = scanPeer("172.31.169.84", "40:cd:3a:03:28:e2");
  const ptu = scanPeer("192.168.1.202", "fc:68:3e:22:05:28");
  t.publish([camera, ptu]); assert.equal(t.scans.length, 0, "foreign IPs wait for a route");
  t.adopt(camera.subnet, "172.31.169.100");
  assert.deepEqual(t.scans.map(s => s.cidr), ["172.31.169.84/32"], "no settle timer must expire");
  t.f.events.get("arp-device-discovered")({ ip: "10.9.1.20", mac: "aa:bb:cc:dd:ee:04" });
  t.publish([camera, ptu]);
  assert.equal(t.scans.length, 1, "unrelated activity cannot restart or delay this scan");
  t.adopt(ptu.subnet, "192.168.1.100");
  assert.deepEqual(t.scans.map(s => s.cidr), ["172.31.169.84/32", "192.168.1.202/32"], "second scan starts before the first replies");
  await t.finish();
});

test("A route arriving before identity verification starts the scan on the first live snapshot", async () => {
  const t = await progressiveScanFixture();
  const camera = scanPeer("172.31.169.84", "40:cd:3a:03:28:e2", "cached_only");
  t.publish([camera]); t.adopt(camera.subnet, "172.31.169.100");
  assert.equal(t.scans.length, 0, "cached history is not a verified scan target");
  t.publish([{ ...camera, status: "live" }]);
  assert.equal(t.scans.length, 1);
  t.publish([{ ...camera, status: "live", open_ports: [554] }]);
  assert.equal(t.scans.length, 1, "capability and repeated presence snapshots are deduplicated");
  await t.finish();
});

test("A new IP for the same live identity scans immediately on its existing subnet", async () => {
  const t = await progressiveScanFixture();
  const camera = scanPeer("192.168.0.50", "40:cd:3a:03:28:e2");
  t.publish([camera]);
  t.publish([{ ...camera, ip: "192.168.0.51" }]);
  assert.deepEqual(t.scans.map(s => s.cidr), ["192.168.0.50/32", "192.168.0.51/32"]);
  await t.finish();
});

test("A device joining a ready subnet scans without waiting for unrelated ARP traffic", async () => {
  const t = await progressiveScanFixture();
  const first = scanPeer("192.168.0.50", "40:cd:3a:03:28:e2");
  const second = scanPeer("192.168.0.51", "fc:68:3e:22:05:28");
  t.publish([first]);
  t.f.events.get("arp-device-discovered")({ ip: second.ip, mac: second.mac });
  t.publish([first, second]);
  assert.deepEqual(t.scans.map(s => s.cidr), ["192.168.0.50/32", "192.168.0.51/32"]);
  assert(![...t.timers.values()].some(timer => timer.ms === 6000), "no global discovery settle delay remains");
  await t.finish();
});

async function cameraRoleFixture({ alias = "", persisted = false, protocol = "rtsp" } = {}) {
  const f = fixture(), calls = [], key = "40:cd:3a:03:8f:3f";
  let records = [{ mac: key, ip: "192.168.1.204", subnet: "192.168.1.0/24", alias,
    status: "live", open_ports: [554], first_seen: "before", last_seen: "before" }];
  f.shared.state.config = { network_mode: "static_manual", manual_nodes: [], rtsp_server: {},
    stream: { protocol, camera_mac: persisted ? key : null, camera_ip: persisted ? records[0].ip : "", audio_muted: false } };
  f.shared.state.activeInterface = { name: "Ethernet", mac: "00:22:20:3a:e3:b3", is_up: true,
    ips: [{ address: "192.168.1.100", prefix: 24, subnet: records[0].subnet }] };
  f.api.getDeviceList = async () => records;
  f.api.getConfig = async () => f.shared.state.config;
  f.api.setDeviceAlias = async (target, next) => {
    calls.push(["role", target, next]);
    records = records.map(row => ({ ...row, alias: row.mac === target ? next : row.alias === next ? "" : row.alias }));
    return records;
  };
  f.api.updateStreamSettings = async settings => { calls.push(["settings", { ...settings }]); };
  f.api.createVideoWindow = async () => { calls.push(["window"]); return "123"; };
  f.api.startStream = async () => { calls.push(["preview"]); };
  f.api.stopStream = async () => { calls.push(["stop"]); };
  f.api.listVpnInterfaces = async () => [];
  f.api.startRestreamServer = async () => { calls.push(["relay"]); return { server_url: "rtsp://127.0.0.1:8554/test", display_url: "rtsp://127.0.0.1:8554/test" }; };
  f.api.stopRestreamServer = async () => { calls.push(["stop-relay"]); };
  const store = f.load(source("src/lib/store.ts")); f.deps["./store.ts"] = store;
  f.deps["./device-state.ts"] = f.load(source("src/lib/device-state.ts"), f.deps);
  const mirror = f.load(source("src/lib/device-list.ts"), f.deps); f.deps["./device-list.ts"] = mirror;
  const network = f.load(source("src/lib/network.ts"), f.deps); f.deps["./network.ts"] = network;
  const streaming = f.load(source("src/lib/streaming.ts"), f.deps, { window: { devicePixelRatio: 1 } });
  f.deps["./streaming.ts"] = streaming;
  const devices = f.load(source("src/lib/devices.ts"), f.deps);
  const card = f.$("#device-list");
  card.querySelectorAll = selector => {
    if (selector === ".device-item") return [...card.innerHTML.matchAll(/class="device-item[^\"]*" data-key="([^\"]*)"/g)].map(match => {
      const row = f.$(`#row-${match[1]}`); row.dataset = { key: match[1] }; return row;
    });
    if (selector === ".node-role-select") return [...card.innerHTML.matchAll(/class="node-role-select" data-role-key="([^\"]*)"/g)].map(match => {
      const select = f.$(`#role-${match[1]}`); select.dataset = { roleKey: match[1] }; select.isConnected = true; return select;
    });
    return [];
  };
  f.$("#video-area").getBoundingClientRect = () => ({ x: 0, y: 0, width: 640, height: 480 });
  f.$("#restream-server-enable").checked = true;
  streaming.setupStreamControls(); streaming.setupRestreamControls();
  devices.setupArpListeners(); await mirror.start();
  return { f, calls, store, mirror, network, streaming, key,
    click: () => f.$(`#row-${key}`).fire("click", { target: { closest: () => null } }),
    async role(action) { const select = f.$(`#role-${key}`); select.value = action; select.fire("change"); await flush(); },
    async replace(rows) { records = rows; f.events.get("device-list-changed")(rows); await flush(); },
  };
}

test("Clicking an unassigned node cannot select a video target or start preview/re-stream", async () => {
  const t = await cameraRoleFixture(); await t.click();
  assert.equal(t.store.selectedDevice.get().key, t.key); assert.equal(t.store.sessionCamTarget.get(), null);
  assert.equal(t.network.getActiveCamTarget(), null);
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-restream").fire("click");
  assert(!t.calls.some(([kind]) => ["settings", "window", "preview", "relay"].includes(kind)));
  assert.match(t.f.toast().textContent, /CAM/); assert.equal(t.f.$("#btn-toggle-stream").disabled, false);
});

for (const alias of ["", "PTU"]) test(`Saved ${alias || "unassigned"} target cannot bypass the CAM requirement`, async () => {
  const t = await cameraRoleFixture({ alias, persisted: true });
  t.store.sessionCamTarget.set({ key: t.key, expectedMac: t.key });
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-restream").fire("click");
  assert.equal(t.network.getActiveCamTarget(), null);
  assert(!t.calls.some(([kind]) => ["settings", "window", "preview", "relay"].includes(kind)));
});

test("The CAM dropdown enables both starts and Clear stops preview and blocks subsequent starts", async () => {
  const t = await cameraRoleFixture(); await t.role("cam");
  assert.equal(t.network.getActiveCamTarget().key, t.key);
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-restream").fire("click");
  assert.equal(t.calls.filter(([kind]) => kind === "preview").length, 1);
  assert.equal(t.calls.filter(([kind]) => kind === "relay").length, 1);
  await t.role("clear");
  assert.equal(t.f.shared.state.isStreaming, false); assert.equal(t.network.getActiveCamTarget(), null);
  assert.equal(t.f.shared.state.isRestreamDesired, false);
  assert.equal(t.calls.filter(([kind]) => kind === "stop-relay").length, 1);
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-restream").fire("click");
  assert.equal(t.calls.filter(([kind]) => kind === "preview").length, 1);
  assert.equal(t.calls.filter(([kind]) => kind === "relay").length, 1);
  assert.equal(t.calls.filter(([kind]) => kind === "stop").length, 1);
});

test("Missing identities and duplicate CAM roles cannot redirect a saved video selection", async () => {
  const t = await cameraRoleFixture({ alias: "CAM", persisted: true });
  const first = t.mirror.getDevices()[0], other = { ...first, mac: "40:cd:3a:03:8f:40" };
  t.store.sessionCamTarget.set({ key: t.key, expectedMac: t.key });
  await t.replace([first, other]); assert.equal(t.network.getActiveCamTarget(), null);
  await t.replace([other]); assert.equal(t.network.getActiveCamTarget(), null);
  await t.f.$("#btn-toggle-stream").fire("click"); assert(!t.calls.some(([kind]) => kind === "preview"));
});

test("UDP input can start preview and re-stream without a CAM node", async () => {
  const t = await cameraRoleFixture({ protocol: "udp" });
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-stream").fire("click");
  await t.f.$("#btn-toggle-restream").fire("click");
  assert.equal(t.calls.filter(([kind]) => kind === "preview").length, 1);
  assert.equal(t.calls.filter(([kind]) => kind === "relay").length, 1);
  assert(!t.calls.some(([kind]) => kind === "settings"));
});

for (const alias of ["", "PTU"]) test(`Clicking another ${alias || "unassigned"} node preserves the assigned CAM target`, async () => {
  const t = await cameraRoleFixture({ alias: "CAM", persisted: true });
  const first = t.mirror.getDevices()[0], other = { ...first, mac: "40:cd:3a:03:8f:40", ip: "192.168.1.205", alias };
  await t.replace([first, other]);
  await t.f.$(`#row-${other.mac}`).fire("click", { target: { closest: () => null } });
  assert.equal(t.store.selectedDevice.get().key, other.mac);
  assert.equal(t.network.getActiveCamTarget().key, first.mac);
  await t.f.$("#btn-toggle-stream").fire("click");
  assert.equal(t.calls.find(([kind]) => kind === "settings")[1].camera_mac, first.mac);
});

test("An IP-only manual target still requires CAM and follows only its saved binding", async () => {
  const t = await cameraRoleFixture(), first = t.mirror.getDevices()[0];
  const manual = { ...first, mac: `manual:${first.ip}` };
  t.f.shared.state.config.stream.camera_ip = first.ip;
  t.store.sessionCamTarget.set({ key: manual.mac, expectedMac: null });
  await t.replace([manual]); assert.equal(t.network.getActiveCamTarget(), null);
  t.f.shared.state.config.manual_nodes = [{ ip: first.ip, expected_mac: first.mac }];
  await t.replace([{ ...first, alias: "CAM" }]);
  assert.equal(t.network.getActiveCamTarget().expectedMac, first.mac);
  await t.f.$("#btn-toggle-stream").fire("click"); assert(t.calls.some(([kind]) => kind === "preview"));
});

test("Losing CAM during the settings save blocks video creation and the start command", async () => {
  const t = await cameraRoleFixture({ alias: "CAM" }); let release;
  t.f.api.updateStreamSettings = () => new Promise(resolve => { release = resolve; });
  const start = t.f.$("#btn-toggle-stream").fire("click");
  await t.replace(t.mirror.getDevices().map(row => ({ ...row, alias: "" })));
  release(); await start;
  assert(!t.calls.some(([kind]) => ["window", "preview"].includes(kind)));
  assert.equal(t.f.shared.state.isStreaming, false); assert.match(t.f.toast().textContent, /CAM assignment changed/);
});

test("A failed re-stream stop leaves CAM assigned and reports an actionable error", async () => {
  const t = await cameraRoleFixture({ alias: "CAM" });
  await t.f.$("#btn-toggle-restream").fire("click");
  t.f.api.stopRestreamServer = async () => { throw Error("stop refused"); };
  await t.role("clear");
  assert.equal(t.mirror.getDevices()[0].alias, "CAM"); assert.equal(t.f.shared.state.isRestreamDesired, true);
  assert.equal(t.f.$(`#role-${t.key}`).selectedIndex, 0);
  assert(!t.calls.some(([kind]) => kind === "role")); assert.match(t.f.toast().textContent, /CAM role unchanged/);
});

test("Reassigning CAM stops the old preview/re-stream and directs the next start to the new identity", async () => {
  const t = await cameraRoleFixture({ alias: "CAM", persisted: true });
  const first = t.mirror.getDevices()[0], other = { ...first, mac: "40:cd:3a:03:8f:40", ip: "192.168.1.205", alias: "" };
  await t.replace([first, other]);
  await t.f.$("#btn-toggle-stream").fire("click"); await t.f.$("#btn-toggle-restream").fire("click");
  const select = t.f.$(`#role-${other.mac}`); select.value = "cam"; select.fire("change"); await flush();
  assert.equal(t.f.shared.state.isStreaming, false); assert.equal(t.f.shared.state.isRestreamDesired, false);
  assert.equal(t.calls.filter(([kind]) => kind === "stop").length, 1);
  assert.equal(t.calls.filter(([kind]) => kind === "stop-relay").length, 1);
  assert.equal(t.mirror.deviceByKey(first.mac).alias, ""); assert.equal(t.network.getActiveCamTarget().key, other.mac);
  await t.f.$("#btn-toggle-stream").fire("click");
  assert.equal(t.calls.filter(([kind]) => kind === "settings").at(-1)[1].camera_mac, other.mac);
});

test("Explicitly reselecting the existing CAM replaces a missing saved selection without stopping streams", async () => {
  const t = await cameraRoleFixture({ alias: "CAM", persisted: true });
  const missing = "40:cd:3a:03:8f:40";
  t.f.shared.state.config.stream.camera_mac = missing;
  t.store.sessionCamTarget.set({ key: missing, expectedMac: missing });
  assert.equal(t.network.getActiveCamTarget(), null);
  await t.role("cam");
  assert.equal(t.network.getActiveCamTarget()?.key, t.key);
  assert.equal(t.f.shared.state.config.stream.camera_mac, t.key);
  assert(!t.calls.some(([kind]) => kind === "stop" || kind === "stop-relay"));
});
