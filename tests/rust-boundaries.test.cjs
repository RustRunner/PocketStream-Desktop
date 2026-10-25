const { test } = require('node:test');
const assert = require('node:assert/strict');

test('Rust boundary guard catches explicit, inferred and grouped managed-state dependencies', async () => {
  const { violations } = await import('../scripts/check-rust-boundaries.mjs');
  for (const source of ['app.state::<Arc<Config>>()', 'app.state()', 'app.try_state()', 'app.try_state::<Config>()']) {
    assert.equal(violations(source).lookups, 1, source);
  }
  for (const source of ['use tauri::Manager;', 'use tauri::{Emitter, Manager};', 'tauri::State<Config>', 'tauri::AppHandle']) {
    assert.equal(violations(source).imports, true, source);
  }
  assert.deepEqual(violations('// app.state()\nself.state.lock().await'), { lookups: 0, imports: false });
});
