const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('./helpers/streaming-fixture.cjs');

const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve(); };
const plain = value => JSON.parse(JSON.stringify(value));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const applied = () => ({ state: 'applied', rule_name: 'owned', action: 'unchanged', verified_shape: true, observed_block_rules: [] });
const failed = stage => ({ state: 'failed', stage, reason: 'injected policy failure', uncertain: true });
const info = protocol => ({ protocol,
  bind_scope: { kind: 'interface', id: 'uplink', alias: 'Uplink', address: '192.0.2.2', family: 'ipv4', topology_revision: 1 },
  firewall: applied(), server_url: `${protocol}://192.0.2.2/test`, display_url: `${protocol}://192.0.2.2/***` });
const result = (protocol, desired = false) => ({ selected_protocol: protocol, desired, server_info: desired ? info(protocol) : null });
const status = (protocol, desired = false, overrides = {}) => ({ ...info(protocol), selected_protocol: protocol,
  active_protocol: desired ? protocol : null, desired, relay_state: desired ? 'listening' : 'stopped', server_running: desired,
  playing: false, playback_desired: false, playback_state: 'stopped', playback_fault: null, playback_recovery_attempt: 0,
  playback_next_retry_secs: null, recording_report: null, recording_finalized_path: null, relay_error: null, recovery_attempt: 0,
  recording: false, uptime_secs: 0, bandwidth_kbps: 0, connected_clients: 0, client_limit: 10, error: null,
  audio_present: false, audio_codec: null, firewall_next_retry_secs: null, ...overrides });
const config = (enabled = false, protocol = 'rtsp') => ({ selected_adapter_mac: null, restream_protocol: protocol,
  stream: { protocol: 'udp', rtsp_port: 554, rtsp_path: '/live', udp_port: 8600, camera_ip: '', camera_mac: null, audio_muted: false },
  rtsp_server: { enabled, port: 8554, token: '0123456789abcdef', bind_interface: 'RTSP uplink', bind_interface_id: '01234567-89ab-cdef-0123-456789abcdef' },
  srt_server: { port: 8890, latency_ms: 125, stream_id: 'canonical', passphrase: { state: 'available', value: 'strongPass1' },
    bind_interface: 'SRT uplink', bind_interface_id: '12345678-89ab-cdef-0123-456789abcdef' },
  credentials: { username: '', password: '' }, adopted_subnets: {}, adopted_meta: {}, zoom_positions: {},
  network_mode: 'dhcp', manual_nodes: [] });
const notices = f => f.logs.filter(entry => entry.message.startsWith('toast: '));

async function controls({ enabled = false, protocol = 'rtsp', desired = false, relayState } = {}) {
  const f = fixture();
  f.shared.state.config = config(enabled, protocol);
  f.writes = []; f.reads = 0; f.starts = 0; f.stops = 0; f.switches = [];
  f.settingsReply = async () => result(f.shared.state.config.restream_protocol);
  f.configReply = async () => structuredClone(f.shared.state.config);
  f.startReply = async () => info(protocol);
  f.stopReply = async () => {};
  f.switchReply = async selected => result(selected, desired);
  f.api.applyRestreamSettings = update => { f.writes.push(plain(update)); return f.settingsReply(update); };
  f.api.getConfig = () => { f.reads++; return f.configReply(); };
  f.api.startRestreamServer = () => { f.starts++; return f.startReply(); };
  f.api.stopRestreamServer = () => { f.stops++; return f.stopReply(); };
  f.api.switchRestreamProtocol = selected => { f.switches.push(selected); return f.switchReply(selected); };
  f.streaming.setupRestreamControls();
  f.streaming.syncRestreamSettingsUI();
  f.streaming.startStatusListener();
  f.publish = f.events.get('stream-status');
  f.publish(status(protocol, desired, relayState ? { relay_state: relayState, server_running: false } : {}));
  await flush();
  return f;
}

function busy(f) {
  for (const selector of ['#restream-server-enable', '#btn-toggle-restream', '#restream-bind-interface', '#save-settings']) {
    assert.equal(f.$(selector).disabled, true, selector);
  }
  assert(f.protocolButtons.every(button => button.disabled));
  assert.equal(f.$('#restream-spinner').style.display, '');
}
function ready(f) {
  for (const selector of ['#restream-server-enable', '#restream-bind-interface', '#save-settings']) {
    assert.equal(f.$(selector).disabled, false, selector);
  }
  assert(f.protocolButtons.every(button => !button.disabled));
  assert.equal(f.$('#restream-spinner').style.display, 'none');
  assert.equal(f.$('#btn-toggle-restream').disabled, !f.shared.state.isRestreamDesired && !f.shared.state.config.rtsp_server.enabled);
}
function flip(f, enabled) {
  f.$('#restream-server-enable').checked = enabled;
  return f.$('#restream-server-enable').fire('change');
}
async function refuseEnable(f) {
  const accepted = f.shared.state.config.rtsp_server.enabled;
  const count = f.writes.length;
  await flip(f, !accepted);
  assert.equal(f.$('#restream-server-enable').checked, accepted);
  assert.equal(f.writes.length, count);
  busy(f);
}

async function editDrafts(f, secret = 'replace') {
  const fields = { '#rtsp-server-port': '9554', '#rtsp-token': 'fedcba9876543210', '#srt-server-port': '9990',
    '#srt-latency-ms': '777', '#srt-stream-id': 'draft stream', '#camera-user': 'draft user', '#camera-pass': 'draft password',
    '#udp-port': '9600', '#restream-bind-interface': 'draft bind selection' };
  for (const [selector, value] of Object.entries(fields)) f.$(selector).value = value;
  const passphrase = f.$('#srt-passphrase');
  passphrase.value = secret === 'replace' ? 'replacement1' : '';
  passphrase.fire('input');
  if (secret === 'confirmed-clear') {
    const dialog = f.$('#srt-clear-passphrase-dialog'), closed = [];
    dialog.addEventListener = (event, callback) => { assert.equal(event, 'close'); closed.push(callback); };
    dialog.showModal = () => { dialog.open = true; };
    dialog.close = value => { dialog.returnValue = value; dialog.open = false; closed.splice(0).forEach(callback => callback()); };
    const confirmation = f.streaming.confirmSrtPassphraseClearIfNeeded();
    await flush(); assert.equal(dialog.open, true);
    f.$('#srt-clear-passphrase-confirm').fire('click');
    assert.equal(await confirmation, true);
  }
  const snapshot = () => ({ values: Object.fromEntries([...Object.keys(fields), '#srt-passphrase'].map(selector => [selector, f.$(selector).value])),
    secretStatus: f.$('#srt-passphrase-state').textContent, copyDisabled: f.$('#srt-copy-passphrase').disabled });
  const before = snapshot();
  return () => {
    assert.deepEqual(snapshot(), before, 'Enable must preserve all drafts and secret presentation');
    if (secret === 'unconfirmed-clear') {
      assert.throws(() => f.streaming.readRestreamSettingsUpdate(), /Enter a replacement SRT passphrase/);
    } else {
      assert.deepEqual(plain(f.streaming.readRestreamSettingsUpdate().srt_server.passphrase),
        secret === 'replace' ? { action: 'replace', value: 'replacement1' } : { action: 'clear' });
    }
  };
}

test('Enable while stopped writes only canonical enabled; drafts survive acknowledgement and Start needs no Save', async () => {
  const f = await controls(), write = deferred();
  const original = structuredClone(f.shared.state.config);
  const assertDrafts = await editDrafts(f);
  f.settingsReply = () => write.promise;
  const work = flip(f, true);
  busy(f);
  assert.equal(f.$('#restream-server-enable').checked, true);
  assert.deepEqual(f.shared.state.config, original);
  const { enabled, ...rtsp } = original.rtsp_server;
  assert.deepEqual(f.writes, [{ enabled: true, rtsp_server: rtsp,
    srt_server: { ...original.srt_server, passphrase: { action: 'keep' } } }]);
  await f.$('#btn-toggle-restream').fire('click');
  await f.protocolButtons[1].fire('click');
  await f.$('#restream-bind-interface').fire('change');
  assert.equal(f.streaming.beginRestreamSettingsSave(), false);
  assert.equal(f.starts, 0); assert.equal(f.stops, 0); assert.deepEqual(f.switches, []);
  assert.equal(f.writes.length, 1); busy(f);
  write.resolve(result('rtsp')); await work;
  assert.equal(f.shared.state.config.rtsp_server.enabled, true);
  assert.equal(f.$('#restream-server-enable').checked, true);
  assert.equal(f.shared.state.isRestreamDesired, false);
  assert.equal(f.reads, 0); assert.equal(f.starts, 0); assert.equal(f.stops, 0);
  assertDrafts(); ready(f);
  assert.equal(f.toast().textContent, 'Re-stream server enabled');
  f.startReply = async () => {
    assert.equal(f.shared.state.config.rtsp_server.enabled, true);
    return info('rtsp');
  };
  await f.$('#btn-toggle-restream').fire('click');
  assert.equal(f.starts, 1); assert.equal(f.writes.length, 1);
  assert.match(f.toast().textContent, /Re-stream server started/);
});

for (const protocol of ['rtsp', 'srt']) {
  for (const relayState of ['listening', 'streaming', 'recovering', 'failed']) {
    test(`Disable ${protocol} desired ${relayState} awaits its transaction despite stopped status`, async () => {
      const f = await controls({ enabled: true, protocol, desired: true, relayState }), write = deferred();
      f.settingsReply = () => write.promise;
      const work = flip(f, false);
      busy(f);
      f.publish(status(protocol, false, { firewall: failed('disable') }));
      assert.equal(f.$('#restream-status').textContent, 'Offline');
      busy(f); assert.equal(notices(f).length, 0);
      assert.equal(f.shared.state.config.rtsp_server.enabled, true);
      write.resolve(result(protocol)); await work;
      assert.equal(f.shared.state.config.rtsp_server.enabled, false);
      assert.equal(f.$('#restream-server-enable').checked, false);
      assert.equal(f.shared.state.isRestreamDesired, false);
      assert.equal(f.$('#restream-status').textContent, 'Offline');
      assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
      assert.match(f.$('#restream-firewall-state').textContent, /disable/);
      assert.equal(f.toast().textContent, 'Re-stream server disabled and stopped');
      assert.equal(notices(f).length, 1);
      assert.equal(f.writes.length, 1); assert.equal(f.writes[0].enabled, false);
      assert.equal(f.stops, 0); assert.equal(f.starts, 0); assert.equal(f.reads, 0);
      ready(f);
    });
  }

  test(`Disable and re-enable stopped ${protocol} persists without starting either output`, async () => {
    const f = await controls({ enabled: true, protocol });
    await flip(f, false);
    assert.equal(f.toast().textContent, 'Re-stream server disabled');
    assert.equal(f.shared.state.config.rtsp_server.enabled, false); ready(f);
    await flip(f, true);
    assert.equal(f.toast().textContent, 'Re-stream server enabled');
    assert.equal(f.shared.state.config.rtsp_server.enabled, true); ready(f);
    assert.deepEqual(f.writes.map(update => update.enabled), [false, true]);
    assert.equal(f.starts, 0); assert.equal(f.stops, 0); assert.equal(f.reads, 0);
  });
}

for (const secret of ['replace', 'unconfirmed-clear', 'confirmed-clear']) {
  test(`Enable success preserves ${secret} secret intent`, async () => {
    const f = await controls();
    const assertDrafts = await editDrafts(f, secret);
    await flip(f, true);
    assertDrafts(); ready(f);
    assert.deepEqual(f.writes[0].srt_server.passphrase, { action: 'keep' });
  });

  for (const accepted of [false, true]) {
    for (const canonical of [false, true, 'read-error']) {
      test(`Enable ${accepted ? 'off' : 'on'} failure with ${canonical} reload preserves ${secret}`, async () => {
        const f = await controls({ enabled: accepted }), write = deferred(), reload = deferred();
        const previous = f.shared.state.config, previousSnapshot = structuredClone(previous);
        const assertDrafts = await editDrafts(f, secret);
        f.settingsReply = () => write.promise; f.configReply = () => reload.promise;
        const work = flip(f, !accepted);
        busy(f); write.reject(Error('injected settings write failure')); await flush();
        assert.equal(f.reads, 1); busy(f);
        await refuseEnable(f);
        assert.equal(notices(f).length, 0);
        if (canonical === 'read-error') reload.reject(Error('injected reload failure'));
        else {
          const refreshed = config(canonical);
          refreshed.rtsp_server.port = 7554; refreshed.srt_server.latency_ms = 500;
          reload.resolve(refreshed);
        }
        await work;
        const expected = canonical === 'read-error' ? accepted : canonical;
        assert.equal(f.shared.state.config.rtsp_server.enabled, expected);
        assert.equal(f.$('#restream-server-enable').checked, expected);
        assertDrafts(); ready(f);
        assert.equal(f.writes.length, 1); assert.equal(f.reads, 1);
        assert.equal(f.stops, 0); assert.equal(f.starts, 0);
        assert.equal(notices(f).length, 1); assert.equal(notices(f)[0].level, 'error');
        assert.match(f.toast().textContent, new RegExp(`Failed to turn the re-stream server ${accepted ? 'off' : 'on'}:.*injected settings write failure`));
        if (canonical === 'read-error') {
          assert.equal(f.shared.state.config, previous);
          assert.deepEqual(previous, previousSnapshot);
          assert.match(f.toast().textContent, /Settings could not be reloaded; showing the last confirmed Enable value\./);
          assert(f.logs.some(entry => /Failed to reload re-stream Enable:.*injected reload failure/.test(entry.message)));
        } else {
          assert.notEqual(f.shared.state.config, previous);
          assert.equal(f.shared.state.config.rtsp_server.port, 7554);
          assert.doesNotMatch(f.toast().textContent, /last confirmed/);
        }
      });
    }
  }
}

test('Enable is unavailable before initial config and canonical initialization restores availability', async () => {
  const f = fixture(); let writes = 0;
  f.api.applyRestreamSettings = async () => { writes++; };
  f.streaming.setupRestreamControls();
  assert.equal(f.$('#restream-server-enable').disabled, true);
  assert.equal(f.$('#btn-toggle-restream').disabled, true);
  await flip(f, true);
  assert.equal(writes, 0); assert.equal(f.$('#restream-server-enable').checked, false);
  assert.equal(f.$('#restream-spinner').style.display, 'none');
  f.shared.state.config = config(true);
  f.streaming.syncRestreamSettingsUI(); await flush();
  assert.equal(f.$('#restream-server-enable').checked, true); ready(f);
});

for (const operation of ['start', 'stop', 'bind', 'save']) {
  test(`Pending ${operation} refuses Enable without releasing the owning latch`, async () => {
    const f = await controls({ enabled: true, desired: operation === 'stop' }), reply = deferred();
    let work;
    if (operation === 'start') { f.startReply = () => reply.promise; work = f.$('#btn-toggle-restream').fire('click'); }
    if (operation === 'stop') { f.stopReply = () => reply.promise; work = f.$('#btn-toggle-restream').fire('click'); }
    if (operation === 'bind') {
      f.settingsReply = () => reply.promise;
      f.$('#restream-bind-interface').value = ''; f.$('#restream-bind-interface').selectedOptions = [];
      work = f.$('#restream-bind-interface').fire('change');
    }
    if (operation === 'save') assert.equal(f.streaming.beginRestreamSettingsSave(), true);
    // The fixture invokes listeners even on disabled elements.
    assert.equal(f.$('#restream-server-enable').disabled, true);
    await flip(f, false);
    assert.equal(f.$('#restream-server-enable').checked, true);
    assert.equal(f.$('#restream-server-enable').disabled, true);
    assert.equal(f.$('#btn-toggle-restream').disabled, true);
    assert.equal(f.$('#save-settings').disabled, true);
    assert.equal(f.$('#restream-spinner').style.display, '');
    assert(f.protocolButtons.every(button => button.disabled));
    assert.equal(f.streaming.beginRestreamSettingsSave(), false);
    assert.equal(f.writes.length, operation === 'bind' ? 1 : 0);
    assert.equal(notices(f).length, 0);
    if (operation === 'save') f.streaming.finishRestreamSettingsSave();
    else { reply.resolve(operation === 'start' ? info('rtsp') : result('rtsp')); await work; }
    await flush(); ready(f);
  });
}

test('A refused second Enable event is repainted after acknowledgement and a subsequent Save reads true', async () => {
  const f = await controls(), write = deferred();
  f.settingsReply = () => write.promise;
  const work = flip(f, true);
  await refuseEnable(f);
  assert.equal(f.$('#restream-server-enable').checked, false);
  write.resolve(result('rtsp')); await work;
  assert.equal(f.shared.state.config.rtsp_server.enabled, true);
  assert.equal(f.$('#restream-server-enable').checked, true); ready(f);
  assert.equal(f.streaming.beginRestreamSettingsSave(), true);
  const save = f.streaming.readRestreamSettingsUpdate();
  assert.equal(save.enabled, true);
  f.settingsReply = async () => result('rtsp');
  await f.api.applyRestreamSettings(save);
  f.streaming.finishRestreamSettingsSave();
  assert.deepEqual(f.writes.map(update => update.enabled), [true, true]);
  assert.equal(f.reads, 0); ready(f);
});

for (const desired of [false, true]) {
  for (const completion of ['success', 'reload-success', 'reload-error']) {
    test(`Protocol switch ${desired ? 'live' : 'stopped'} holds controls through matching status and ${completion}`, async () => {
      const f = await controls({ enabled: true, desired }), reply = deferred(), reload = deferred();
      f.switchReply = () => reply.promise; f.configReply = () => reload.promise;
      const work = f.protocolButtons[1].fire('click');
      f.publish(status('srt', false));
      busy(f);
      f.publish(status('srt', desired, { firewall: failed('readback') }));
      busy(f); await refuseEnable(f);
      f.publish(status('srt', desired));
      assert.equal(f.shared.state.config.restream_protocol, 'srt');
      assert.equal(f.protocolButtons[1].classList.contains('active'), true);
      assert.equal(notices(f).length, 0); assert.equal(f.writes.length, 0);
      if (completion === 'success') reply.resolve(result('srt', desired));
      else {
        reply.reject(Error('injected switch failure')); await flush();
        assert.equal(f.reads, 1); busy(f);
        await refuseEnable(f);
        f.publish(status('srt', desired, { firewall: failed('ownership') }));
        f.publish(status('srt', desired));
        assert.equal(notices(f).length, 0); busy(f);
        if (completion === 'reload-error') reload.reject(Error('injected switch reload failure'));
        else reload.resolve(config(true, 'srt'));
      }
      await work; await flush(); ready(f);
      assert.equal(notices(f).length, 1);
      assert.match(f.toast().textContent, completion === 'success' ? /switched to SRT/ : /Failed to switch.*injected switch failure/);
      const assertDrafts = await editDrafts(f);
      await flip(f, false); await flush();
      assert.equal(f.writes.length, 1);
      assert.equal(f.shared.state.config.rtsp_server.enabled, false);
      assert.equal(f.$('#restream-server-enable').checked, false);
      assert.equal(f.shared.state.config.restream_protocol, 'srt');
      assert.equal(f.shared.state.isRestreamDesired, false);
      assert.equal(f.$('#restream-status').textContent, 'Offline');
      assert.equal(f.$('#btn-toggle-restream').disabled, true);
      assertDrafts(); ready(f);
      assert.equal(notices(f).length, 2);
      assert.equal(f.switches.length, 1);
      assert.equal(f.reads, completion === 'success' ? 0 : 1);
    });
  }
}

test('Start availability follows accepted settings; desired outputs remain Stop even with accepted false', async () => {
  const f = await controls();
  f.$('#restream-server-enable').checked = true;
  f.streaming.syncRestreamStartButton();
  assert.equal(f.$('#btn-toggle-restream').disabled, true);
  f.shared.state.config.rtsp_server.enabled = true;
  f.$('#restream-server-enable').checked = false;
  f.streaming.syncRestreamStartButton();
  assert.equal(f.$('#btn-toggle-restream').disabled, false);
  f.shared.state.config.rtsp_server.enabled = false;
  f.publish(status('rtsp', true, { relay_state: 'recovering', server_running: false }));
  assert.equal(f.$('#btn-toggle-restream').textContent, 'Stop Server');
  assert.equal(f.$('#btn-toggle-restream').disabled, false);
  await f.$('#btn-toggle-restream').fire('click');
  assert.equal(f.stops, 1); assert.equal(f.$('#btn-toggle-restream').disabled, true);
});

test('Disable response resets policy baseline before stopped status and preserves cached retirement failure', async () => {
  const f = await controls({ enabled: true, desired: true }), write = deferred();
  f.settingsReply = () => write.promise;
  const work = flip(f, false);
  f.publish(status('rtsp', true, { firewall: failed('disable') }));
  assert.equal(notices(f).length, 0);
  write.resolve(result('rtsp')); await work;
  assert.equal(f.$('#restream-status').textContent, 'Offline');
  assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
  assert.match(f.$('#restream-firewall-state').textContent, /disable/);
  assert.equal(f.toast().textContent, 'Re-stream server disabled and stopped');
  // No stopped status has arrived. The next stable observation hydrates a new
  // baseline; only the following genuine warning transition should notify.
  f.publish(status('rtsp', true));
  assert.equal(notices(f).length, 1);
  f.publish(status('rtsp', true, { firewall: failed('blocks') }));
  assert.equal(notices(f).length, 2);
  f.publish(status('rtsp', false, { firewall: failed('disable') }));
  assert.equal(f.$('#restream-firewall-row').style.display, 'contents');
  assert.equal(f.$('#restream-status').textContent, 'Offline');
});
