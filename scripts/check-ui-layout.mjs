// Real DOM/CSS and sidebar/toast handlers in an isolated headless browser.
// Native video actions are stubbed; no installed app or device is touched.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import ts from 'typescript';

if (typeof WebSocket === 'undefined') throw new Error('The optional browser layout check requires Node.js 22 or newer');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'src-tauri/target/ui-layout');
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify({ passed: false, started_utc: new Date().toISOString() }) + '\n');
const browser = [process.env.BROWSER_EXECUTABLE,
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/chromium', '/usr/bin/google-chrome',
].find(candidate => candidate && fs.existsSync(candidate));
if (!browser) throw new Error('Set BROWSER_EXECUTABLE to an Edge/Chrome/Chromium executable for layout checks');
const profile = fs.mkdtempSync(path.join(output, 'profile-'));
const compile = name => ts.transpileModule(fs.readFileSync(path.join(root, name), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const bootstrap = `
const native = { logToFile() {}, setVideoVisible: async () => {}, updateVideoPosition: async () => {} };
function load(code, deps) { const exports = {}; new Function('exports', 'require', code)(exports, name => deps[name]); return exports; }
const shared = load(${JSON.stringify(compile('src/lib/state.ts'))}, { './tauri-api.ts': native });
const sidebar = load(${JSON.stringify(compile('src/lib/sidebar.ts'))}, {
  './state.ts': shared, './tauri-api.ts': native,
  './streaming.ts': { getVideoAreaBounds: () => ({ x: 0, y: 0, width: 1, height: 1 }), syncVideoVisibility: async () => {} },
});
sidebar.setupSidebarToggle();
const policyFormat = load(${JSON.stringify(compile('src/lib/restream-format.ts'))}, {});
const streaming = load(${JSON.stringify(compile('src/lib/streaming.ts'))}, {
  'qrcode': {}, './tauri-api.ts': native, './state.ts': shared, './errors.ts': { formatError: String },
  './device-list.ts': {}, './network.ts': {}, './restream-format.ts': policyFormat,
  './restream-settings.ts': load(${JSON.stringify(compile('src/lib/restream-settings.ts'))}, {}),
});
window.layout = { shared, streaming, clicks: { screenshot: 0, record: 0 } };
for (const name of ['screenshot', 'record']) {
  const button = document.querySelector('#btn-' + name); button.disabled = false;
  button.addEventListener('click', () => { window.layout.clicks[name]++; });
}
`;
let html = fs.readFileSync(path.join(root, 'index.html'), 'utf8')
  .replace(/<script\b[^>]*src="\/src\/main\.ts"[^>]*><\/script>/, '')
  .replace(/(src|href)="\/(src\/[^\"]+)"/g, (_, attr, file) => `${attr}="${pathToFileURL(path.join(root, file)).href}"`);
html = html.replace('</body>', () => `<script>${bootstrap.replaceAll('</script', '<\\/script')}</script></body>`);
html = html.replace('</head>', `<script>window.layoutErrors = []; window.addEventListener('error', event => window.layoutErrors.push(event.message));</script></head>`);
const page = path.join(output, 'fixture.html');
fs.writeFileSync(page, html);
const log = fs.openSync(path.join(output, 'browser.log'), 'w');
const child = spawn(browser, ['--headless=new', '--disable-gpu', '--disable-background-networking',
  '--host-resolver-rules=MAP * ~NOTFOUND', '--no-first-run', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, pathToFileURL(page).href,
], { windowsHide: true, stdio: ['ignore', log, log] });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let socket, next = 0;
const pending = new Map();
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++next;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 10000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const reply = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (reply.exceptionDetails) throw new Error(reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text);
  return reply.result.value;
}
async function click(selector) {
  const point = await evaluate(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...point, button: 'left', clickCount: 1 });
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...point, button: 'left', clickCount: 1 });
}
const geometry = `(() => {
  const toggle = document.querySelector('#menu-toggle'), panel = document.querySelector('#sidebar');
  const b = toggle.getBoundingClientRect(), p = panel.getBoundingClientRect();
  return { left: b.left, buttonRight: b.right, buttonWidth: b.width, right: p.right, width: p.width, expanded: toggle.getAttribute('aria-expanded'),
    rotation: getComputedStyle(toggle.querySelector('svg')).transform, inert: panel.inert };
})()`;
const observations = [];
try {
  const deadline = Date.now() + 15000;
  let target;
  while (!target && Date.now() < deadline) {
    try {
      const port = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split(/\r?\n/)[0];
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
      target = pages.find(p => p.url === pathToFileURL(page).href);
    } catch {}
    if (!target) await pause(100);
  }
  if (!target) throw new Error('Isolated layout browser did not become ready');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  socket.addEventListener('message', event => {
    const reply = JSON.parse(String(event.data)), request = pending.get(reply.id);
    if (!request) return;
    clearTimeout(request.timeout); pending.delete(reply.id);
    if (reply.error) request.reject(new Error(reply.error.message)); else request.resolve(reply.result);
  });
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  await send('Runtime.enable');
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }] });
  const readyUntil = Date.now() + 5000;
  while (!(await evaluate('!!window.layout')) && Date.now() < readyUntil) await pause(100);
  assert(await evaluate('!!window.layout'), `real renderer modules initialized: ${JSON.stringify(await evaluate('window.layoutErrors'))}`);
  for (const [width, height] of [[1280, 800], [960, 600]]) {
    await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
    await pause(100);
    const closed = await evaluate(geometry);
    assert.equal(closed.expanded, 'false'); assert(closed.inert);
    assert(Math.abs(closed.left - 16) < 1);
    await click('#menu-toggle'); await pause(80);
    const moving = await evaluate(geometry);
    const expandedTravel = closed.width - closed.left - closed.buttonWidth - 8;
    assert(Math.abs(moving.left - closed.left - expandedTravel * moving.right / moving.width) < 2, 'handle and panel animate together');
    await pause(220);
    const open = await evaluate(geometry);
    assert.equal(open.expanded, 'true'); assert(!open.inert);
    assert(Math.abs(open.right - open.buttonRight - 8) < 1, 'expanded handle stays 8px inside the panel edge');
    assert.match(open.rotation, /^matrix\(-1, 0, 0, -1,/);
    const titleClear = await evaluate(`document.querySelector('#menu-toggle').getBoundingClientRect().right < document.querySelector('.app-bar-center').getBoundingClientRect().left`);
    assert(titleClear, 'expanded handle must not overlap the centered app title');
    await evaluate('layout.shared.state.isStreaming = true; layout.shared.showToast(' + JSON.stringify('Screenshot saved: C:\\Pictures\\PocketStream\\capture.jpg') + ');');
    const noticeGeometry = `(() => { const t = document.querySelector('.toast'), r = t.getBoundingClientRect(), v = document.querySelector('#video-area').getBoundingClientRect(); return { bottom: r.bottom, videoTop: v.top, left: r.left, right: r.right, pointer: getComputedStyle(t).pointerEvents }; })()`;
    const entering = await evaluate(noticeGeometry);
    assert(entering.bottom <= entering.videoTop - 1, 'notice enters without overlapping the native video');
    await pause(230);
    const notice = await evaluate(noticeGeometry);
    assert(notice.bottom <= notice.videoTop - 11, `notice settles above the native video: ${JSON.stringify(notice)}`);
    assert(notice.left >= 0 && notice.right <= width, 'notice stays inside the window');
    assert.equal(notice.pointer, 'none');
    const before = await evaluate('({...layout.clicks})');
    await click('#btn-screenshot'); await click('#btn-screenshot'); await click('#btn-record'); await click('#btn-record');
    const after = await evaluate('({...layout.clicks})');
    assert.equal(after.screenshot - before.screenshot, 2); assert.equal(after.record - before.record, 2);
    assert(await evaluate(`!!document.querySelector('.toast')`), 'repeat clicks happen while the notice remains visible');
    assert(await evaluate(`!document.querySelector('#btn-remove-primary-ip')`));
    const nodesLayout = await evaluate(`(() => {
      const card = document.querySelector('#card-devices'), body = card.querySelector('.card-body');
      const list = document.querySelector('#device-list'), scope = document.querySelector('#capture-scope-status');
      list.innerHTML = '<div class="subnet-group">' + Array.from({ length: 24 }, (_, index) =>
        '<div class="device-item"><div class="device-name-row"><span class="device-dot dot-green"></span>' +
        '<select class="node-role-select" title="Assign role"><option>Node ' + (index + 1) + '</option><option>CAM</option><option>PTU</option></select></div>' +
        '<div class="device-detail-row"><a class="device-ip" href="#">192.0.2.' + (index + 1) + '</a><span class="device-ports">80, 554</span></div></div>'
      ).join('') + '</div>';
      const cases = [false, true].map(withNotice => {
        scope.hidden = !withNotice;
        scope.textContent = withNotice ? 'Discovery is limited to the selected adapter.' : '';
        body.scrollTop = 0;
        const scrollers = [body, ...body.querySelectorAll('*')].filter(element =>
          /auto|scroll/.test(getComputedStyle(element).overflowY) && element.scrollHeight > element.clientHeight + 1
        ).map(element => element === body ? 'card-body' : element.id || element.className);
        body.scrollTop = body.scrollHeight;
        const last = list.querySelector('.device-item:last-child .node-role-select');
        last.focus();
        const rect = last.getBoundingClientRect(), bounds = body.getBoundingClientRect();
        const header = card.querySelector('.card-header').getBoundingClientRect(), footer = card.querySelector('.card-footer').getBoundingClientRect();
        return { withNotice, scrollers, lastVisible: rect.top >= bounds.top && rect.bottom <= bounds.bottom,
          lastFocusable: document.activeElement === last, noHorizontalOverflow: body.scrollWidth <= body.clientWidth + 1,
          controlsVisible: header.top >= 0 && header.bottom <= bounds.top && footer.top >= bounds.bottom && footer.bottom <= innerHeight };
      });
      scope.hidden = true; scope.textContent = ''; body.scrollTop = 0;
      return cases;
    })()`);
    fs.writeFileSync(path.join(output, `nodes-${width}.json`), JSON.stringify(nodesLayout, null, 2) + '\n');
    for (const item of nodesLayout) {
      assert.deepEqual(item.scrollers, ['card-body'], `Nodes has one vertical scroll area: ${JSON.stringify(item)}`);
      assert(item.lastVisible && item.lastFocusable, 'the last node is visible and keyboard accessible');
      assert(item.controlsVisible && item.noHorizontalOverflow, 'Nodes header/footer stay visible without horizontal scrolling');
    }
    assert(await evaluate(`['restream-bind-scope', 'restream-firewall-state', 'restream-scope-row', 'restream-firewall-row'].every(id => !document.querySelector('#card-restream #' + id))`));
    const policyLayout = await evaluate(`(() => {
      const blocks = ['Disabled other-protocol Block ' + 'native-name'.repeat(40), 'unrelated-interface-rule'];
      const applied = { state: 'applied', rule_name: 'owned', action: 'updated', verified_shape: true, observed_block_rules: blocks };
      const failure = { state: 'failed', stage: 'native_timeout', uncertain: false, reason: 'Long reported reason '.repeat(40) };
      const render = (desired, firewall) => {
        layout.shared.state.isRestreamDesired = desired;
        layout.streaming.updateRestreamUI('rtsp://192.0.2.2:8554/***', { firewall, relay_state: 'listening' });
      };
      const visible = id => getComputedStyle(document.querySelector('#' + id)).display !== 'none';
      render(true, applied);
      const conflict = { reason: visible('restream-error-row'), detail: document.querySelector('#restream-error').title };
      const overflow = () => {
        const card = document.querySelector('#card-restream').getBoundingClientRect();
        return ['restream-error'].map(id => {
          const value = document.querySelector('#' + id), rect = value.getBoundingClientRect();
          return { id, left: rect.left, right: rect.right, cardLeft: card.left, cardRight: card.right, scroll: value.scrollWidth, width: value.clientWidth };
        });
      };
      const conflictGeometry = overflow();
      render(true, failure); const failedGeometry = overflow();
      render(false, failure); const stopped = { reason: visible('restream-error-row') };
      render(false, { state: 'inactive' }); const inactive = { reason: visible('restream-error-row') };
      render(true, applied);
      const readable = ['restream-error'].map(id => {
        const value = document.querySelector('#' + id);
        value.scrollIntoView({ block: 'start' });
        const rect = value.getBoundingClientRect(), body = value.closest('.card-body').getBoundingClientRect();
        return { id, inView: rect.top < body.bottom && rect.bottom > body.top, detail: value.title.length >= value.textContent.length };
      });
      const pageOverflow = document.documentElement.scrollWidth > innerWidth;
      render(true, { ...applied, observed_block_rules: [] });
      document.querySelector('#card-restream .card-body').scrollTop = 0;
      const healthy = { reason: visible('restream-error-row'), status: document.querySelector('#restream-status').textContent };
      return { conflict, conflictGeometry, failedGeometry, stopped, inactive, readable, healthy, pageOverflow };
    })()`);
    assert(policyLayout.conflict.reason);
    assert.match(policyLayout.conflict.detail, /Disabled other-protocol Block.*unrelated-interface-rule/);
    assert.match(policyLayout.conflict.detail, /whether they are enabled and apply/);
    for (const item of [...policyLayout.conflictGeometry, ...policyLayout.failedGeometry]) {
      assert(item.left >= item.cardLeft && item.right <= item.cardRight + 1, `policy value stays in card: ${JSON.stringify(item)}`);
      assert(item.scroll <= item.width + 1, `long Reason text wraps: ${JSON.stringify(item)}`);
    }
    assert.deepEqual(policyLayout.stopped, { reason: true });
    assert.deepEqual(policyLayout.inactive, { reason: false });
    assert.deepEqual(policyLayout.healthy, { reason: false, status: 'Listening' });
    assert(!policyLayout.pageOverflow, 'Reason cannot widen the viewport');
    assert(policyLayout.readable.every(row => row.inView && row.detail), 'Reason scrolls into view with its full detail available');
    assert(await evaluate(`!!document.querySelector('#card-restream .card-header #btn-show-qr')`));
    assert(await evaluate(`!document.querySelector('#nodes-title').matches('.clickable-title, [role="button"]')`));
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(output, `expanded-${width}.png`), Buffer.from(shot.data, 'base64'));
    await click('#menu-toggle'); await pause(300);
    assert.equal((await evaluate(geometry)).expanded, 'false');
    const closedShot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(output, `collapsed-${width}.png`), Buffer.from(closedShot.data, 'base64'));
    observations.push({ width, height, closed, moving, open, notice, nodesLayout, policyLayout, clicks: after });
  }
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('#menu-toggle')).transitionDuration`), '0s');
  fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify({ passed: true, observations }, null, 2) + '\n');
  console.log('Browser layout passed: single Nodes scrollbar, re-stream warnings, panel tracking/rotation, accessible state, toast clearance and real repeated clicks at 1280x800 and 960x600');
} finally {
  if (socket?.readyState === WebSocket.OPEN) await send('Browser.close').catch(() => {});
  socket?.close();
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(new Error('Layout check ended')); }
  pending.clear();
  if (child.exitCode === null) child.kill();
  fs.closeSync(log);
}
