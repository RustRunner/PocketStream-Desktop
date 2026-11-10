const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const source = name => fs.readFileSync(path.join(__dirname, '../..', name), 'utf8');

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
  const protocolButtons = ['rtsp', 'srt'].map(protocol => {
    const button = new Element('button'); button.dataset.restreamProtocol = protocol; return button;
  });
  const document = {
    body, head, createElement: tag => new Element(tag),
    querySelector(selector) {
      if (!selector.startsWith("#")) return body.querySelector(selector);
      if (!ids.has(selector)) ids.set(selector, new Element());
      return ids.get(selector);
    }, querySelectorAll: selector => selector === '[data-restream-protocol]' ? protocolButtons : [],
  };
  const api = {
    logToFile: (level, message) => logs.push({ level, message }),
    onEvent: async (name, callback) => { events.set(name, callback); return () => {}; },
    setVideoVisible: async value => { visibility.push(value); },
    retryPlayback: async () => {}, getCaptureState: async () => null,
    listBindInterfaces: async () => [],
    startRestreamServer: async () => { throw Error('Start fixture result required'); },
    stopRestreamServer: async () => {},
    switchRestreamProtocol: async () => { throw Error('Switch fixture result required'); },
    applyRestreamSettings: async () => { throw Error('Settings fixture result required'); },
    getConfig: async () => { throw Error('Config fixture result required'); },
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
  return { api, shared, network, streaming, updater, load, deps, events, logs, visibility, protocolButtons,
    $: shared.$, toast: () => body.querySelector(".toast"), update: () => body.querySelector(".update-toast"),
    advance: ms => { now += ms; }, runTimers: () => timers.splice(0).forEach(fn => fn()) };
}

module.exports = { fixture };
