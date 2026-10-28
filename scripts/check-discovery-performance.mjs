// Compare real connection logs with the fixed, reviewed hardware baseline.
// Reference replay validates the checker; it is not a new hardware measurement.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const baselinePath = path.join(root, 'benchmarks/discovery-baseline.json');
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const mac = value => value?.replaceAll('-', ':').toLowerCase();

function timestamp(value) {
  if (!/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(value)) throw new Error('Use a local log timestamp: YYYY-MM-DD HH:mm:ss');
  // Treat the local calendar as an arithmetic clock. No host timezone/DST
  // conversion is involved; a run crossing a clock adjustment is invalid.
  const time = Date.parse(value.replace(' ', 'T') + 'Z');
  if (!Number.isFinite(time)) throw new Error('Invalid log timestamp');
  return time;
}

export function evaluateDiscovery(logText, baseline, linkUpLocal) {
  if (baseline.schema_version !== 1) throw new Error('Unsupported discovery baseline schema');
  const milestones = ['discovered', 'frontend_discovered', 'adopted', 'scan_started', 'scan_finished'];
  for (const field of ['timing_allowance_seconds', 'scan_dispatch_budget_seconds', 'observation_window_seconds', 'required_adoptions', 'max_link_drops', 'max_offline_transitions', 'max_warnings_or_errors']) {
    if (!Number.isFinite(baseline[field]) || baseline[field] < 0) throw new Error(`Invalid baseline limit: ${field}`);
  }
  if (baseline.observation_window_seconds <= 0 || !Array.isArray(baseline.devices) || !baseline.devices.length) throw new Error('Invalid baseline observation window or devices');
  for (const device of baseline.devices) {
    for (const field of milestones) {
      if (!Number.isFinite(device.observed_seconds?.[field]) || device.observed_seconds[field] < 0) throw new Error(`Invalid baseline milestone: ${device.key}.${field}`);
    }
    if (!Array.isArray(device.required_ports)) throw new Error(`Invalid baseline ports: ${device.key}`);
  }
  const start = timestamp(linkUpLocal), end = start + baseline.observation_window_seconds * 1000;
  const records = logText.replace(/^\uFEFF/, '').split(/\r?\n/).filter(line => /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d /.test(line))
    .map(line => ({ line, time: timestamp(line.slice(0, 19)) }));
  const errors = [];
  const within = records.filter(r => r.time >= start && r.time <= end);
  const onAdapter = r => mac(r.line.match(/adapter_mac="([^"]+)"/)?.[1]) === mac(baseline.environment.adapter_mac);
  const ups = within.filter(r => r.time === start && onAdapter(r) && /event=ethernet_link .*link_up=true\b/.test(r.line));
  if (ups.length !== 1) errors.push('The requested link-up timestamp must identify exactly one selected-adapter link-up event');
  if (!records.some(r => r.time >= end)) errors.push(`Incomplete observation: keep recording for at least ${baseline.observation_window_seconds}s after link-up`);
  const versions = records.filter(r => r.time <= start && /PocketStream Desktop v[^ ]+ starting/.test(r.line));
  const version = versions.at(-1)?.line.match(/PocketStream Desktop v([^ ]+) starting/)?.[1] ?? null;
  if (!version) errors.push('Missing app startup/version context before the selected connection');
  if (within.some(r => r.time > start && /PocketStream Desktop v[^ ]+ starting/.test(r.line))) errors.push('Application restarted during the observation window');
  const elapsed = record => record ? (record.time - start) / 1000 : null;
  const first = pattern => within.find(r => pattern.test(r.line));
  const adoptions = within.filter(r => /event=adoption_ready /.test(r.line));
  const linkDrops = within.filter(r => onAdapter(r) && /event=ethernet_link .*link_up=false\b/.test(r.line)).length;
  const offline = within.filter(r => onAdapter(r) && /event=node_transition .*to="offline"/.test(r.line)).length;
  const warnings = within.filter(r => /\[(WARN|ERROR)\]/.test(r.line)).length;
  if (linkDrops > baseline.max_link_drops) errors.push(`Link drops: ${linkDrops} > ${baseline.max_link_drops}`);
  if (offline > baseline.max_offline_transitions) errors.push(`Offline transitions: ${offline} > ${baseline.max_offline_transitions}`);
  if (warnings > baseline.max_warnings_or_errors) errors.push(`Warnings/errors: ${warnings} > ${baseline.max_warnings_or_errors}`);
  if (adoptions.length !== baseline.required_adoptions) errors.push(`Expected exactly ${baseline.required_adoptions} adoptions; found ${adoptions.length}`);

  const devices = baseline.devices.map(device => {
    const ip = escape(device.ip), identity = escape(device.mac), subnet = escape(device.subnet);
    const seen = first(new RegExp(` - ARP: ${ip} \\(${identity}\\)`, 'i'));
    const frontend = first(new RegExp(`\\[frontend\\] ARP: discovered ${ip} \\(${identity}\\)`, 'i'));
    const adopted = first(new RegExp(`event=adoption_ready subnet="${subnet}" `));
    const applied = within.find(r => onAdapter(r) && r.line.includes(`subnet="${device.subnet}"`) && /event=binding_change .*desired=Present applied=true\b/.test(r.line));
    if (!applied) errors.push(`${device.key}: missing applied host binding`);
    if (!first(new RegExp(`\\[frontend\\] Subnet adopted: ${subnet} -> `))) errors.push(`${device.key}: missing frontend adoption event`);
    const starts = within.filter(r => new RegExp(`\\[frontend\\] Port scan started: ${ip} \\(`).test(r.line));
    const completions = within.filter(r => new RegExp(`\\[frontend\\] Port scan finished: ${ip};`).test(r.line));
    const portsOf = r => (r.line.match(/ports=([^;]+);/)?.[1] ?? '').split(',').filter(p => /^\d+$/.test(p)).map(Number);
    const finished = completions.find(r => device.required_ports.every(p => portsOf(r).includes(p)));
    if (!finished && completions.length) errors.push(`${device.key}: required ports missing (${device.required_ports.join(', ')})`);
    const seconds = { discovered: elapsed(seen), frontend_discovered: elapsed(frontend), adopted: elapsed(adopted), scan_started: elapsed(starts[0]), scan_finished: elapsed(finished) };
    for (const name of milestones) {
      const observed = device.observed_seconds[name];
      const actual = seconds[name], maximum = observed + baseline.timing_allowance_seconds;
      if (actual === null) errors.push(`${device.key}.${name}: missing`);
      else if (actual > maximum) errors.push(`${device.key}.${name}: ${actual}s exceeds ${maximum}s (${observed}s reference + ${baseline.timing_allowance_seconds}s allowance)`);
    }
    const routeReady = seconds.discovered === null || seconds.adopted === null ? null : Math.max(seconds.discovered, seconds.adopted);
    const dispatch = routeReady === null || seconds.scan_started === null ? null : seconds.scan_started - routeReady;
    if (dispatch !== null && (dispatch < 0 || dispatch > baseline.scan_dispatch_budget_seconds)) errors.push(`${device.key}: scan dispatch ${dispatch}s outside 0..${baseline.scan_dispatch_budget_seconds}s after device/route readiness`);
    if (seconds.scan_finished !== null && seconds.scan_started !== null && seconds.scan_finished < seconds.scan_started) errors.push(`${device.key}: scan completion precedes its start`);
    if (seconds.frontend_discovered !== null && seconds.discovered !== null && seconds.frontend_discovered < seconds.discovered) errors.push(`${device.key}: frontend discovery precedes backend observation`);
    if (starts.length > 3) errors.push(`${device.key}: ${starts.length} scan attempts exceed the three-attempt retry bound`);
    return { key: device.key, ip: device.ip, seconds, scan_dispatch_seconds: dispatch, ports: finished ? portsOf(finished) : [], scan_attempts: starts.length };
  });
  const completionTimes = devices.map(d => d.seconds.scan_finished);
  return { baseline: baseline.id, version, link_up_local: linkUpLocal, window_seconds: baseline.observation_window_seconds,
    all_devices_ready_seconds: completionTimes.every(t => t !== null) ? Math.max(...completionTimes) : null,
    devices, adoptions: adoptions.length, link_drops: linkDrops, offline_transitions: offline, warnings_or_errors: warnings,
    passed: errors.length === 0, errors };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {};
    for (let i = 2; i < process.argv.length; i++) {
      const arg = process.argv[i];
      if (arg === '--reference') options.reference = true;
      else if (['--log', '--link-up', '--output'].includes(arg) && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) options[arg.slice(2)] = process.argv[++i];
      else throw new Error(`Unknown or incomplete argument: ${arg}`);
    }
    if (options.reference ? options.log || options['link-up'] : !options.log || !options['link-up']) throw new Error('Use --reference OR --log <file> --link-up "YYYY-MM-DD HH:mm:ss"; optionally --output <json>');
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    const text = options.reference ? JSON.parse(fs.readFileSync(path.join(root, baseline.reference.fixture), 'utf8')).lines.join('\n') : fs.readFileSync(options.log, 'utf8');
    const report = evaluateDiscovery(text, baseline, options.reference ? baseline.reference.link_up_local : options['link-up']);
    report.mode = options.reference ? 'reference-replay-only' : 'recorded-hardware-run';
    if (options.output) {
      fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
      fs.writeFileSync(options.output, JSON.stringify(report, null, 2) + '\n');
    }
    console.log(`${options.reference ? 'Reference replay (not a new hardware measurement)' : 'Hardware log comparison'}: ${report.passed ? 'PASS' : 'FAIL'} against ${report.baseline}`);
    for (const device of report.devices) console.log(`${device.key}: discovered=${device.seconds.discovered}s adopted=${device.seconds.adopted}s scan started=${device.seconds.scan_started}s ports ready=${device.seconds.scan_finished}s`);
    for (const error of report.errors) console.error(error);
    process.exitCode = report.passed ? 0 : 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
