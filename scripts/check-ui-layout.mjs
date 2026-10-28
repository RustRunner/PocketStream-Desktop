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
window.layout = { shared, clicks: { screenshot: 0, record: 0 } };
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
    assert(await evaluate(`!document.querySelector('#btn-remove-primary-ip, #restream-bind-scope, #restream-firewall-state')`));
    assert(await evaluate(`!!document.querySelector('#card-restream .card-header #btn-show-qr')`));
    assert(await evaluate(`!document.querySelector('#nodes-title').matches('.clickable-title, [role="button"]')`));
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(output, `expanded-${width}.png`), Buffer.from(shot.data, 'base64'));
    await click('#menu-toggle'); await pause(300);
    assert.equal((await evaluate(geometry)).expanded, 'false');
    const closedShot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(output, `collapsed-${width}.png`), Buffer.from(closedShot.data, 'base64'));
    observations.push({ width, height, closed, moving, open, notice, clicks: after });
  }
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('#menu-toggle')).transitionDuration`), '0s');
  fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify({ passed: true, observations }, null, 2) + '\n');
  console.log('Browser layout passed: panel tracking/rotation, accessible state, toast clearance and real repeated clicks at 1280x800 and 960x600');
} finally {
  if (socket?.readyState === WebSocket.OPEN) await send('Browser.close').catch(() => {});
  socket?.close();
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(new Error('Layout check ended')); }
  pending.clear();
  if (child.exitCode === null) child.kill();
  fs.closeSync(log);
}
