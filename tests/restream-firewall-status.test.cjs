const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('./helpers/streaming-fixture.cjs');
const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve(); };
const applied = (overrides = {}) => ({ state: 'applied', rule_name: 'owned', action: 'unchanged', verified_shape: true, observed_block_rules: [], ...overrides });
const failed = (stage = 'readback', uncertain = false) => ({ state: 'failed', stage, reason: 'Reported reason <img src=x onerror=bad()>', uncertain });
const scope = { kind: 'interface', id: 'uplink', alias: 'Uplink', address: '192.0.2.2', family: 'ipv4', topology_revision: 1 };
const info = (firewall = applied(), protocol = 'rtsp') => ({ protocol, bind_scope: scope, firewall, server_url: `${protocol}://192.0.2.2:8554/test`, display_url: `${protocol}://192.0.2.2:8554/***` });
const status = (overrides = {}) => ({ ...info(), selected_protocol: 'rtsp', active_protocol: 'rtsp', desired: true,
  relay_state: 'listening', server_running: true, firewall_next_retry_secs: null, playback_desired: false, playback_state: 'stopped',
  audio_present: false, audio_codec: null, recording: false, uptime_secs: 2, bandwidth_kbps: 0, connected_clients: 0, client_limit: 10,
  relay_error: null, recording_report: null, ...overrides });
const notices = f => f.logs.filter(entry => entry.message.startsWith('toast: '));
function card() {
  const f = fixture();
  f.shared.state.config = { restream_protocol: 'rtsp', stream: { protocol: 'udp' },
    rtsp_server: { enabled: true, bind_interface: '', bind_interface_id: null },
    srt_server: { bind_interface: '', bind_interface_id: null, passphrase: { state: 'unencrypted', value: null } } };
  f.$('#restream-server-enable').checked = true;
  f.streaming.setupRestreamControls();
  f.streaming.startStatusListener();
  f.publish = f.events.get('stream-status');
  return f;
}

test('pure policy presentation covers verification, conflicts, absent outcomes and repair guidance', () => {
  const { presentFirewallPolicy: present, formatFirewallRetry: retry } = fixture().deps['./restream-format.ts'];
  assert.equal(present(applied()).classification, 'applied');
  assert.equal(present(applied()).text, 'Applied (last verified)');
  assert.equal(present(applied({ verified_shape: false })).classification, 'warning');
  assert.match(present(applied({ verified_shape: false })).text, /verification missing/);
  assert.equal(present(undefined).classification, 'warning');
  assert.equal(present({ state: 'inactive' }).classification, 'inactive');
  const conflicts = present(applied({ observed_block_rules: ['Disabled TCP other-output rule', 'native-<script>name'] }));
  assert.equal(conflicts.classification, 'warning');
  assert.match(conflicts.text, /possible Block-rule conflict/);
  assert.match(conflicts.detail, /Disabled TCP other-output rule, native-<script>name/);
  assert.match(conflicts.detail, /whether they are enabled and apply to this output/);
  assert.match(conflicts.detail, /Stop and start the server/);
  assert.match(present({ state: 'unavailable', reason: 'Administrator access required' }).detail, /installed administrator shortcut/);
  assert.match(present(failed('access')).detail, /installed administrator shortcut/);
  assert.match(present(failed('native_timeout', true)).detail, /Stop the server to attempt rule retirement.*If uncertainty remains, restart/);
  assert.doesNotMatch(present(failed('native_timeout')).detail, /state is uncertain/);
  for (const stage of ['input', 'inventory', 'ownership', 'trusted_modules', 'prepare', 'blocks', 'native_report']) {
    const p = present(failed(stage));
    assert.equal(p.classification, 'warning'); assert(p.detail.includes(stage)); assert(p.detail.includes('Reported reason'));
  }
  for (const p of [present(applied()), conflicts, present(failed()), present(undefined)]) {
    assert.doesNotMatch(p.text + p.detail, /other devices (?:are blocked|can connect)|reachable|reachability|reinstall.*remov/i);
  }
  assert.equal(retry(3), 'Retrying in 3 s');
  assert.equal(retry(0), 'Retry requested / in progress');
  assert.equal(retry(null), ''); assert.equal(retry(undefined), '');
});

test('card renders local listener and policy separately; stopped non-inactive evidence stays visible', () => {
  const f = card();
  for (const [firewall, text] of [[applied(), 'Listening'], [applied({ observed_block_rules: ['disabled unrelated UDP'] }), 'Listening — check Windows rules'],
    [applied({ verified_shape: false }), 'Listening — firewall warning'], [failed(), 'Listening — firewall warning'],
    [{ state: 'inactive' }, 'Listening — firewall warning'], [undefined, 'Listening — firewall warning']]) {
    f.publish(status({ firewall, firewall_next_retry_secs: 8 }));
    assert.equal(f.$('#restream-status').textContent, text);
    assert.equal(f.$('#restream-scope-row').style.display, 'contents');
    assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
    assert.match(f.$('#restream-bind-scope').textContent, /Bound on Uplink/);
    assert.match(f.$('#restream-firewall-state').textContent, /Retrying in 8 s/);
  }
  f.publish(status({ firewall: failed(), firewall_next_retry_secs: 0 }));
  assert.match(f.$('#restream-firewall-state').textContent, /Retry requested \/ in progress/);
  assert(f.$('#restream-firewall-state').title.includes('<img src=x onerror=bad()>'));
  assert.equal(f.$('#restream-firewall-state').innerHTML, '');
  for (const [relay_state, text] of [['starting', 'Starting'], ['recovering', 'Reconnecting'], ['failed', 'Failed']]) {
    f.publish(status({ relay_state, firewall: failed() })); assert.equal(f.$('#restream-status').textContent, text);
  }
  for (const firewall of [failed('disable', true), { state: 'unavailable', reason: 'Startup reconciliation failed' }, applied()]) {
    f.publish(status({ desired: false, relay_state: 'stopped', server_running: false, firewall }));
    assert.equal(f.$('#restream-status').textContent, 'Offline');
    assert.equal(f.$('#restream-scope-row').style.display, 'none');
    assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
    f.streaming.updateRestreamUI(null); // Stop completion must not erase its latest status.
    assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
  }
  for (const firewall of [{ state: 'inactive' }, undefined]) {
    f.publish(status({ desired: false, firewall }));
    assert.equal(f.$('#restream-firewall-row').style.display, 'none');
  }
});

test('hydration, repeated snapshots, countdowns and recovery do not manufacture transition toasts', () => {
  const f = card();
  f.publish(status({ firewall: failed(), firewall_next_retry_secs: 5 }));
  assert.equal(notices(f).length, 0);
  for (const n of [4, 3, 0, null]) f.publish(status({ firewall: failed('blocks'), firewall_next_retry_secs: n }));
  assert.equal(notices(f).length, 0);
  f.publish(status()); assert.equal(notices(f).length, 1); assert.equal(f.toast().textContent, 'Windows rule applied.');
  for (const relay_state of ['starting', 'recovering', 'failed']) f.publish(status({ relay_state, firewall: { state: 'inactive' } }));
  f.publish(status()); assert.equal(notices(f).length, 1);
  f.publish(status({ firewall: applied({ observed_block_rules: ['disabled unrelated rule'] }) }));
  assert.equal(f.toast().textContent, 'Windows rule observation reports a possible Block-rule conflict.');
  assert.equal(notices(f).at(-1).level, 'error');
  f.publish(status({ firewall: failed('ownership') })); assert.equal(notices(f).length, 2);
  f.publish(status()); f.publish(status()); assert.equal(notices(f).length, 3);
  f.publish(status({ desired: false })); f.publish(status({ firewall: failed() })); assert.equal(notices(f).length, 3);
});

test('Start completion owns reply-first, status-first and successful retry before stale reply', async () => {
  for (const ordering of ['reply-first', 'status-first', 'retry-before-reply']) {
    const f = card(); let resolve;
    f.publish(status({ desired: false, firewall: { state: 'inactive' } }));
    f.api.startRestreamServer = () => new Promise(r => { resolve = r; });
    const start = f.$('#btn-toggle-restream').fire('click');
    assert.equal(notices(f).length, 0);
    if (ordering !== 'reply-first') f.publish(status({ firewall: failed(), firewall_next_retry_secs: 2 }));
    if (ordering === 'retry-before-reply') f.publish(status());
    resolve(info(failed())); await start;
    assert.equal(notices(f).length, 1);
    if (ordering === 'retry-before-reply') {
      assert.equal(f.toast().textContent, 'Re-stream server started.');
      assert.equal(f.$('#restream-status').textContent, 'Listening');
      assert.equal(f.$('#restream-firewall-state').textContent, 'Applied (last verified)');
      f.publish(status()); assert.equal(notices(f).length, 1);
    } else {
      assert.match(f.toast().textContent, /^Re-stream server started; Windows rule warning:/);
      assert.equal(f.toast().textContent.includes('Retry requested'), ordering === 'status-first');
      if (ordering === 'reply-first') assert.equal(f.$('#restream-status').textContent, 'Starting', 'RestreamServerInfo has no listener state');
      f.publish(status()); assert.equal(notices(f).length, 2); assert.equal(f.toast().textContent, 'Windows rule applied.');
    }
  }
});

test('a clean Start reply without listener fields remains Starting and seeds the policy baseline', async () => {
  const f = card(); f.api.startRestreamServer = async () => info();
  await f.$('#btn-toggle-restream').fire('click');
  assert.equal(f.$('#restream-status').textContent, 'Starting');
  assert.equal(f.toast().textContent, 'Re-stream server started.');
  f.publish(status()); assert.equal(notices(f).length, 1);
  f.publish(status({ firewall: failed('native_timeout') })); assert.equal(notices(f).length, 2);
});

test('a stale Start reply cannot restore desired state or a policy baseline after a newer Stop', async () => {
  const f = card(); let resolve;
  f.api.startRestreamServer = () => new Promise(r => { resolve = r; });
  const work = f.$('#btn-toggle-restream').fire('click');
  f.publish(status({ desired: false, relay_state: 'stopped', firewall: failed('disable', true) }));
  resolve(info(failed())); await work;
  assert.equal(f.shared.state.isRestreamDesired, false);
  assert.equal(f.$('#restream-status').textContent, 'Offline');
  assert.match(f.$('#restream-firewall-state').textContent, /disable/);
  f.publish(status());
  assert.equal(notices(f).length, 1, 'a stopped baseline stays reset');
});

test('a late command reply preserves a newer listener on another endpoint', async () => {
  const f = card(); let resolve;
  f.api.startRestreamServer = () => new Promise(r => { resolve = r; });
  const work = f.$('#btn-toggle-restream').fire('click');
  const newer = status({ server_url: 'rtsp://192.0.2.9/new', display_url: 'rtsp://192.0.2.9/***' });
  f.publish(newer); resolve(info(failed())); await work;
  assert.equal(f.$('#restream-url').textContent, newer.display_url);
  assert.equal(f.$('#restream-status').textContent, 'Listening');
  f.publish(newer); assert.equal(notices(f).length, 1);
  f.api.stopRestreamServer = () => new Promise(r => { resolve = r; });
  const stop = f.$('#btn-toggle-restream').fire('click');
  f.publish(status({ desired: false })); f.publish({ ...newer }); resolve(); await stop;
  assert.equal(f.shared.state.isRestreamDesired, true);
  assert.equal(f.$('#restream-status').textContent, 'Listening');
});

test('settings and bind transactions suppress intermediate policy transitions', async () => {
  for (const operation of ['settings', 'bind']) {
    const f = card(); await flush(); f.publish(status());
    let finish, work;
    if (operation === 'settings') assert(f.streaming.beginRestreamSettingsSave());
    else {
      f.api.applyRestreamSettings = () => new Promise(resolve => { finish = resolve; });
      f.$('#restream-bind-interface').value = ''; f.$('#restream-bind-interface').selectedOptions = [];
      work = f.$('#restream-bind-interface').fire('change');
    }
    f.publish(status({ firewall: failed() })); f.publish(status({ relay_state: 'recovering', firewall: { state: 'inactive' } })); f.publish(status());
    assert.equal(notices(f).length, 0);
    if (work) { finish({ desired: true, selected_protocol: 'rtsp', server_info: info() }); await work; }
    else f.streaming.finishRestreamSettingsSave();
    f.publish(status()); assert.equal(notices(f).length, 0);
    f.publish(status({ firewall: failed() })); assert.equal(notices(f).length, 1);
  }
});

test('protocol transaction keeps controls busy and suppresses policy toasts through its reply', async () => {
  const f = card(); f.publish(status()); let finish;
  f.api.switchRestreamProtocol = () => new Promise(resolve => { finish = resolve; });
  const work = f.protocolButtons[1].fire('click');
  f.publish(status({ selected_protocol: 'srt', active_protocol: 'srt', firewall: failed() }));
  f.publish(status({ selected_protocol: 'srt', active_protocol: 'srt' }));
  assert.equal(notices(f).length, 0);
  for (const selector of ['#restream-server-enable', '#btn-toggle-restream', '#restream-bind-interface', '#save-settings']) {
    assert.equal(f.$(selector).disabled, true, selector);
  }
  assert(f.protocolButtons.every(button => button.disabled));
  assert.equal(f.$('#restream-spinner').style.display, '');
  finish({ desired: true, selected_protocol: 'srt', server_info: info(applied(), 'srt') }); await work;
  assert.equal(f.$('#restream-server-enable').disabled, false);
  assert.equal(f.$('#btn-toggle-restream').disabled, false);
  assert(f.protocolButtons.every(button => !button.disabled));
  assert.equal(f.$('#restream-spinner').style.display, 'none');
  assert.equal(notices(f).length, 1); assert.match(f.toast().textContent, /switched to SRT/);
  f.publish(status({ selected_protocol: 'srt', active_protocol: 'srt' })); assert.equal(notices(f).length, 1);
});

test('Stop remains busy through retirement and retains its reported failure at completion', async () => {
  const f = card(); f.publish(status()); let finish;
  f.api.stopRestreamServer = () => new Promise(resolve => { finish = resolve; });
  const work = f.$('#btn-toggle-restream').fire('click');
  f.publish(status({ desired: false, firewall: failed('disable', true) }));
  assert.equal(f.$('#restream-status').textContent, 'Offline');
  assert.equal(f.$('#restream-spinner').style.display, '');
  assert.equal(f.$('#btn-toggle-restream').disabled, true);
  assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
  finish(); await work;
  assert.match(f.$('#restream-firewall-state').textContent, /disable/);
  assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
  assert.equal(f.$('#restream-scope-row').style.display, 'none');
  assert.equal(notices(f).length, 1); assert.equal(f.toast().textContent, 'Re-stream server stopped');
});
