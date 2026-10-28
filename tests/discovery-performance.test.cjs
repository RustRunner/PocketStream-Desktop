const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const root = path.resolve(__dirname, '..');
const baseline = JSON.parse(fs.readFileSync(path.join(root, 'benchmarks/discovery-baseline.json'), 'utf8'));
const reference = JSON.parse(fs.readFileSync(path.join(root, baseline.reference.fixture), 'utf8')).lines;
const modulePromise = import('../scripts/check-discovery-performance.mjs');
const check = async (lines = reference, start = baseline.reference.link_up_local) =>
  (await modulePromise).evaluateDiscovery(lines.join('\n'), baseline, start);
function shift(line, seconds) {
  const time = new Date(Date.parse(line.slice(0, 19).replace(' ', 'T') + 'Z') + seconds * 1000);
  return time.toISOString().slice(0, 19).replace('T', ' ') + line.slice(19);
}

test('Recorded good connection remains the fixed discovery performance reference', async () => {
  const result = await check();
  assert.equal(result.passed, true, result.errors.join('\n'));
  assert.equal(result.version, '0.6.14'); // Measurement provenance, not the accepted release number.
  assert.equal(result.all_devices_ready_seconds, 51);
  assert.deepEqual(result.devices.map(d => d.seconds.discovered), [3, 7, 49]);
  assert.deepEqual(result.devices.map(d => d.seconds.scan_finished), [21, 48, 51]);
  assert.deepEqual(result.devices.map(d => d.scan_dispatch_seconds), [0, 0, 0]);
  assert.equal(result.adoptions, 2);
});

test('Five-second timing allowance has a boundary; a slower PTU cannot hide behind the camera', async () => {
  const delayed = seconds => reference.map(line => line.includes('192.168.1.202') ? shift(line, seconds) : line);
  const boundary = await check(delayed(5));
  assert.equal(boundary.passed, true, boundary.errors.join('\n'));
  const slow = await check(delayed(6));
  assert.equal(slow.passed, false);
  assert(slow.errors.some(e => e.includes('ptu.scan_finished: 57s exceeds 56s')));
});

test('A global scan settle delay fails even if total discovery stays within its allowance', async () => {
  const lines = reference.map(line => line.includes('Port scan') && line.includes('172.31.169.84') ? shift(line, 3) : line);
  const result = await check(lines);
  assert.equal(result.passed, false);
  assert(result.errors.some(e => e.includes('camera: scan dispatch 3s')));
});

test('Missing PTU and missing camera ports fail rather than producing a partial success', async () => {
  const missing = await check(reference.filter(line => !line.includes('192.168.1.202')));
  assert.equal(missing.passed, false);
  assert.equal(missing.all_devices_ready_seconds, null);
  assert(missing.errors.includes('ptu.discovered: missing'));
  const ports = await check(reference.map(line => line.replace('ports=22,80,554,8080;', 'ports=22,80,8080;')));
  assert.equal(ports.passed, false);
  assert(ports.errors.some(e => e.startsWith('camera: required ports missing')));
});

test('An earlier fast connection cannot satisfy a later incomplete connection', async () => {
  const earlier = reference.map(line => shift(line, -600));
  const incomplete = reference.filter(line => !line.includes('192.168.1.202'));
  const result = await check([...earlier, ...incomplete]);
  assert.equal(result.passed, false);
  assert(result.errors.includes('ptu.discovered: missing'));
});

test('Unapplied adoption, absent frontend publication, and repeat adoption loops fail', async () => {
  const unapplied = await check(reference.filter(line => !line.includes('event=binding_change')));
  assert(unapplied.errors.includes('camera: missing applied host binding'));
  const unpublished = await check(reference.filter(line => !line.includes('[frontend] Subnet adopted:')));
  assert(unpublished.errors.includes('ptu: missing frontend adoption event'));
  const duplicate = shift(reference.find(line => line.includes('event=adoption_ready')), 30);
  const looping = await check([...reference, duplicate]);
  assert.equal(looping.passed, false);
  assert(looping.errors.includes('Expected exactly 2 adoptions; found 3'));
});

test('Reliability requires a full observation window without link drops, offline flaps, errors or restarts', async () => {
  const transition = reference.find(line => line.includes('event=node_transition'));
  const down = reference.find(line => line.includes('event=ethernet_link'));
  const startup = reference.find(line => line.includes('PocketStream Desktop v'));
  const result = await check([...reference,
    shift(transition.replace('from=null to="live"', 'from="live" to="offline"'), 60),
    shift(down.replace('link_up=true', 'link_up=false'), 80),
    '2026-10-27 19:31:00 [WARN] pocketstream_desktop - fixture warning',
    shift(startup, 120),
  ]);
  assert.equal(result.passed, false);
  for (const prefix of ['Link drops:', 'Offline transitions:', 'Warnings/errors:', 'Application restarted']) {
    assert(result.errors.some(e => e.startsWith(prefix)), prefix);
  }
  const short = await check(reference.filter(line => line.slice(0, 19) < '2026-10-27 19:32:00'));
  assert(short.errors.some(e => e.startsWith('Incomplete observation')));
});

test('A selected-adapter link-up is required and later deliberate disconnects are outside the test window', async () => {
  const link = reference.find(line => line.includes('event=ethernet_link'));
  const wrong = await check(reference.map(line => line === link ? line.replace(baseline.environment.adapter_mac, 'aa:bb:cc:dd:ee:ff') : line));
  assert.equal(wrong.passed, false);
  const later = await check([...reference, shift(link.replace('link_up=true', 'link_up=false'), 200)]);
  assert.equal(later.passed, true, later.errors.join('\n'));
  const ambiguous = await check([...reference, link]);
  assert.equal(ambiguous.passed, false);
});

test('Performance CLI labels reference replay and refuses an unspecified hardware attempt', () => {
  const run = args => spawnSync(process.execPath, ['scripts/check-discovery-performance.mjs', ...args], { cwd: root, encoding: 'utf8' });
  const replay = run(['--reference']);
  assert.equal(replay.status, 0, replay.stderr);
  assert.match(replay.stdout, /not a new hardware measurement/);
  const missing = run([]);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /--link-up/);
});

test('Missing or invalid baseline budgets cannot silently disable performance checks', async () => {
  const { evaluateDiscovery } = await modulePromise;
  for (const field of ['timing_allowance_seconds', 'scan_dispatch_budget_seconds', 'max_offline_transitions']) {
    const changed = structuredClone(baseline);
    delete changed[field];
    assert.throws(() => evaluateDiscovery(reference.join('\n'), changed, baseline.reference.link_up_local), /Invalid baseline limit/);
  }
  const changed = structuredClone(baseline);
  delete changed.devices[2].observed_seconds.scan_finished;
  assert.throws(() => evaluateDiscovery(reference.join('\n'), changed, baseline.reference.link_up_local), /Invalid baseline milestone/);
});
