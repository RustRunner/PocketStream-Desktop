const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { test } = require('node:test');

function fixture(streaming = false) {
  const elements = new Map(), timers = new Map(), calls = [];
  let nextTimer = 0, finishPosition = null;
  const state = { isStreaming: streaming };
  const $ = id => {
    if (!elements.has(id)) {
      const classes = new Set(id === '#sidebar' ? ['collapsed'] : []);
      elements.set(id, {
        inert: id === '#sidebar', attributes: {},
        classList: { contains: c => classes.has(c), toggle: (c, on) => on ? classes.add(c) : classes.delete(c) },
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener(type, callback) { this[type] = callback; },
      });
    }
    return elements.get(id);
  };
  const deps = {
    './state.ts': { $, state },
    './tauri-api.ts': {
      setVideoVisible: async visible => { calls.push(['visible', visible]); },
      updateVideoPosition: async (...bounds) => { calls.push(['bounds', ...bounds]); if (finishPosition) await finishPosition; },
    },
    './streaming.ts': {
      getVideoAreaBounds: () => ({ x: 100, y: 200, width: 600, height: 400 }),
      syncVideoVisibility: async () => { calls.push(['sync']); },
    },
  };
  const exports = {};
  vm.runInNewContext(ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/lib/sidebar.ts'), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, { exports, require: name => deps[name],
    setTimeout: fn => { timers.set(++nextTimer, fn); return nextTimer; },
    clearTimeout: id => timers.delete(id),
  });
  exports.setupSidebarToggle();
  return { $, state, calls, timers, click: () => $('#menu-toggle').click(),
    settle: () => { const [id, fn] = timers.entries().next().value; timers.delete(id); return fn(); },
    delayPosition: () => { let resolve; finishPosition = new Promise(r => { resolve = r; }); return resolve; },
  };
}

test('Sidebar toggle opens and closes the panel with matching accessible state', () => {
  const f = fixture();
  f.click();
  assert(!f.$('#sidebar').classList.contains('collapsed'));
  assert(f.$('#app').classList.contains('sidebar-open'));
  assert.equal(f.$('#sidebar').inert, false);
  assert.equal(f.$('#menu-toggle').attributes['aria-expanded'], 'true');
  assert.equal(f.$('#menu-toggle').attributes['aria-label'], 'Close settings');
  f.click();
  assert(f.$('#sidebar').classList.contains('collapsed'));
  assert(!f.$('#app').classList.contains('sidebar-open'));
  assert.equal(f.$('#sidebar').inert, true);
  assert.equal(f.$('#menu-toggle').attributes['aria-expanded'], 'false');
  assert.equal(f.$('#menu-toggle').title, 'Open settings');
  assert.deepEqual(f.calls, []);
});

test('Rapid sidebar reversals reposition native video only after the final animation', async () => {
  const f = fixture(true);
  f.click(); f.click(); f.click();
  assert.equal(f.timers.size, 1);
  assert.deepEqual(f.calls, [['visible', false], ['visible', false], ['visible', false]]);
  await f.settle();
  assert.deepEqual(f.calls.slice(3), [['bounds', 100, 200, 600, 400], ['sync']]);
});

test('A delayed native resize cannot show video over a newer sidebar animation', async () => {
  const f = fixture(true), release = f.delayPosition();
  f.click();
  const oldResize = f.settle();
  f.click(); release(); await oldResize;
  assert.equal(f.calls.filter(([kind]) => kind === 'sync').length, 0);
  await f.settle();
  assert.equal(f.calls.filter(([kind]) => kind === 'sync').length, 1);
  assert.equal(f.$('#menu-toggle').attributes['aria-expanded'], 'false');
});
