// Reuse the exact hardware-qualified executable when only installer inputs
// changed. Refuse any application input drift. Never launch an application.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const [hostRecord, packagingRecord, directory] = process.argv.slice(2);
if (!hostRecord || !packagingRecord || !directory) throw new Error('Specify qualified-host record, current-packaging record, and new output directory');
const read = name => JSON.parse(fs.readFileSync(path.resolve(repo, name)));
const host = read(hostRecord), packaging = read(packagingRecord);
const out = path.resolve(repo, directory);
if (fs.existsSync(out)) throw new Error('Preserve existing evidence; choose a new output directory');
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const ref = file => ({ path: path.relative(repo, file).replaceAll('\\', '/'), sha256: hash(file), bytes: fs.statSync(file).size });
const resolve = reference => {
  const file = path.join(repo, reference.path);
  if (hash(file) !== reference.sha256) throw new Error(`Reference drift: ${reference.path}`);
  return file;
};
const allowed = new Set(['src-tauri/installer/vc-runtime.nsh', 'src-tauri/installer/provenance.json',
  'src-tauri/installer/transaction.nsh', 'src-tauri/installer/installer.nsi',
  'src-tauri/installer/uninstall-bootstrap.ps1']);
const prior = new Map(host.source_inputs.map(f => [f.path, f.sha256]));
const changes = [];
const source_inputs = [];
for (const input of packaging.source_inputs) {
  const current = ref(path.join(repo, input.path));
  if (current.sha256 !== input.sha256 && !allowed.has(input.path)) throw new Error(`Current non-installer input changed: ${input.path}`);
  source_inputs.push(current);
  if (prior.get(input.path) !== current.sha256) {
    if (!allowed.has(input.path)) throw new Error(`Application or non-approved input changed: ${input.path}`);
    changes.push(input.path);
  }
}
if (prior.size !== packaging.source_inputs.length) throw new Error('Unexpected source inventory change');
const staged = resolve(host.artifacts.staged), embedded = resolve(host.artifacts.embedded);
const originalScript = resolve(packaging.artifacts.generated_script);
const metadata = read(packaging.artifacts.compiler_metadata.path);
const liveScript = metadata.args.at(-1);
if (!liveScript || hash(liveScript) !== packaging.artifacts.generated_script.sha256) {
  throw new Error('Generated support directory no longer matches the frozen script');
}
fs.mkdirSync(out, { recursive: true });
const scriptPath = path.join(out, 'installer.nsi');
let script = fs.readFileSync(originalScript, 'utf8');
const template = fs.readFileSync(path.join(repo, 'src-tauri/installer/installer.nsi'), 'utf8');
const success = /^Function \.onInstSuccess\r?\n[\s\S]*?^FunctionEnd/gm;
const currentSuccess = template.match(success);
if (currentSuccess?.length !== 1 || script.match(success)?.length !== 1) throw new Error('Ambiguous installer success callback');
script = script.replace(success, () => currentSuccess[0]);
for (const [name, value] of [['MAINBINARYSRCPATH', embedded], ['OUTFILE', path.join(out, 'setup.exe')]]) {
  const pattern = new RegExp(`^!define ${name} "[^"\\r\\n]*"$`, 'm');
  if (!pattern.test(script)) throw new Error(`Missing generated define: ${name}`);
  script = script.replace(pattern, () => `!define ${name} "${value}"`);
}
fs.writeFileSync(scriptPath, script);
const support = [];
for (const name of fs.readdirSync(path.dirname(liveScript)).filter(n => n.endsWith('.nsh') || n === 'license_file')) {
  const dest = path.join(out, name);
  fs.copyFileSync(path.join(path.dirname(liveScript), name), dest);
  support.push(ref(dest));
}
const env = { ...process.env };
for (const key of Object.keys(env)) if (/^TAURI_SIGNING_/i.test(key)) delete env[key];
const steps = [];
function run(name, program, args) {
  const start = new Date().toISOString();
  const result = spawnSync(program, args, { cwd: repo, env, encoding: 'utf8', windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
  fs.writeFileSync(path.join(out, name + '.log'), (result.stdout || '') + (result.stderr || ''));
  steps.push({ name, program, args, started_utc: start, finished_utc: new Date().toISOString(), status: result.status, error: result.error?.message || null });
  fs.writeFileSync(path.join(out, 'run.json'), JSON.stringify({ steps, application_launched: false, host_installation: false, signing: false }, null, 2) + '\n');
  if (result.error || result.status !== 0) throw new Error(`${name} failed; retained ${out}`);
  process.stdout.write(`${name}: passed\n`);
}
run('compile-contract', process.execPath, ['scripts/check-installer.mjs', scriptPath, '--compile-trace']);
const packagePath = path.join(out, `package-${hash(path.join(out, 'setup.exe'))}.exe`);
fs.copyFileSync(path.join(out, 'setup.exe'), packagePath);
const extract = path.join(out, 'package');
run('extract', 'C:/Program Files/7-Zip/7z.exe', ['x', '-y', `-o${extract}`, '--', packagePath]);
const actualEmbedded = path.join(extract, 'pocketstream-desktop.exe');
if (hash(actualEmbedded) !== host.artifacts.embedded.sha256) throw new Error('Repackaged host identity changed');
const artifacts = {
  staged: host.artifacts.staged,
  package: ref(packagePath),
  embedded: ref(actualEmbedded),
  staged_manifest: host.artifacts.staged_manifest,
  embedded_manifest: host.artifacts.embedded_manifest,
  generated_script: ref(scriptPath),
  compiled_trace: ref(path.join(out, 'installer.compile.log')),
  compiler_metadata: ref(path.join(out, 'compile-inspection.json')),
};
const sdk = 'C:/Program Files (x86)/Windows Kits/10/bin';
const mt = fs.readdirSync(sdk).sort().reverse().map(n => `${sdk}/${n}/x64/mt.exe`).find(n => fs.existsSync(n));
if (!mt) throw new Error('Manifest tool unavailable');
const manifest = path.join(out, 'installer.manifest');
run('installer-manifest', mt, ['-nologo', `-inputresource:${packagePath};#1`, `-out:${manifest}`]);
if (!/level="requireAdministrator"/.test(fs.readFileSync(manifest, 'utf8'))) throw new Error('Installer elevation changed');
artifacts.installer_manifest = ref(manifest);
const effective_source_sha256 = crypto.createHash('sha256').update(source_inputs.map(f => `${f.sha256}  ${f.path}\n`).join('')).digest('hex');
const record = { ...packaging, recorded_at_utc: new Date().toISOString(), source_inputs, effective_source_sha256,
  status: 'Retained exact hardware-observed host; installer-only repack; native qualification pending',
  artifacts, marker_difference: host.marker_difference,
  retained_host: { source_record: hostRecord, staged_sha256: host.artifacts.staged.sha256,
    embedded_sha256: host.artifacts.embedded.sha256, application_inputs_unchanged: true,
    only_changed_inputs: changes, support_files: support },
  code_signing: false, updater_artifacts: false, a4_complete: false };
fs.writeFileSync(path.join(out, 'candidate.json'), JSON.stringify(record, null, 2) + '\n');
