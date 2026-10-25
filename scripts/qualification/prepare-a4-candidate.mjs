// Local qualification only: no application launch, installation, signing or upload.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const mode = process.argv[2];
const output = path.resolve(repo, process.argv[3] || 'src-tauri/target/privilege-a4/candidate');
if (!['checks', 'build'].includes(mode) || fs.existsSync(output)) {
  throw new Error('Use checks|build and a new evidence directory; earlier runs are preserved.');
}
fs.mkdirSync(output, { recursive: true });
const env = { ...process.env };
for (const key of Object.keys(env)) {
  if (/^POCKETSTREAM_/i.test(key) || /^TAURI_SIGNING_/i.test(key)) delete env[key];
}
env.GSTREAMER_1_0_ROOT_MSVC_X86_64 = 'C:/Program Files/gstreamer/1.0/msvc_x86_64';
const pathKey = Object.keys(env).find(key => key.toLowerCase() === 'path') || 'Path';
env[pathKey] = `${env.GSTREAMER_1_0_ROOT_MSVC_X86_64}/bin;${env[pathKey] || ''}`;
const report = { version: 1, mode, started_utc: new Date().toISOString(), steps: [],
  signing: false, application_launched: false, installation_executed: false };
const write = (name, data) => fs.writeFileSync(path.join(output, name), JSON.stringify(data, null, 2) + '\n');
function run(name, program, args, cwd = repo, extraEnv = {}) {
  const started_utc = new Date().toISOString();
  const result = spawnSync(program, args, { cwd, env: { ...env, ...extraEnv },
    encoding: 'utf8', windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
  fs.writeFileSync(path.join(output, name + '.log'), (result.stdout || '') + (result.stderr || ''));
  report.steps.push({ name, program, args, started_utc, finished_utc: new Date().toISOString(),
    status: result.status, error: result.error?.message || null });
  write('run.json', report);
  if (result.error || result.status !== 0) throw new Error(`${name} failed; see ${output}`);
  process.stdout.write(`${name}: passed\n`);
  return result.stdout;
}
const node = process.execPath;
const cargo = path.join(process.env.USERPROFILE, '.cargo/bin/cargo.exe');
if (mode === 'checks') {
  run('typecheck', node, ['node_modules/typescript/bin/tsc', '--noEmit']);
  const tests = fs.readdirSync(path.join(repo, 'tests')).filter(n => n.endsWith('.test.cjs')).map(n => `tests/${n}`);
  run('frontend-tests', node, ['--test', ...tests]);
  run('frontend-build', node, ['node_modules/vite/bin/vite.js', 'build']);
  for (const script of ['check-dom-selectors', 'check-restream-card', 'check-restream-ui', 'check-ipc-allowlist', 'check-installer']) {
    run(script, node, [`scripts/${script}.mjs`]);
  }
  run('rust-tests', cargo, ['test', '--lib', '--locked', '--offline'], path.join(repo, 'src-tauri'));
  run('fmt', cargo, ['fmt', '--check'], path.join(repo, 'src-tauri'));
  run('clippy', cargo, ['clippy', '--all-targets', '--no-deps', '--locked', '--offline', '--', '-D', 'warnings'], path.join(repo, 'src-tauri'));
} else {
  run('installer-prerequisite', 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts/prepare-installer-prerequisites.ps1']);
  run('package-build', node, ['node_modules/@tauri-apps/cli/tauri.js', 'build', '--bundles', 'nsis',
    '--no-sign', '--ci', '--config', '{"bundle":{"createUpdaterArtifacts":false}}', '--', '--locked', '--offline'],
  repo, { POCKETSTREAM_RELEASE: '1' });
  run('generated-contract', node, ['scripts/check-installer.mjs', 'src-tauri/target/release/nsis/x64/installer.nsi', '--compile-trace']);
  const hash = data => crypto.createHash('sha256').update(data).digest('hex');
  const reference = filename => ({ path: path.relative(repo, filename).replaceAll('\\', '/'),
    sha256: hash(fs.readFileSync(filename)), bytes: fs.statSync(filename).size });
  const retain = (filename, name) => {
    const dest = path.join(output, name);
    fs.copyFileSync(filename, dest);
    return reference(dest);
  };
  const stagedPath = path.join(repo, 'src-tauri/target/release/pocketstream-desktop.exe');
  const staged = retain(stagedPath, `staged-${hash(fs.readFileSync(stagedPath))}.exe`);
  const packageRoot = path.join(repo, 'src-tauri/target/release/bundle/nsis');
  const config = JSON.parse(fs.readFileSync(path.join(repo, 'src-tauri/tauri.conf.json')));
  const packagePath = path.join(packageRoot, `${config.productName}_${config.version}_x64-setup.exe`);
  if (!fs.existsSync(packagePath) || fs.statSync(packagePath).mtimeMs < Date.parse(report.started_utc)) {
    throw new Error('This build did not produce the expected exact package');
  }
  const packageRef = retain(packagePath, `package-${hash(fs.readFileSync(packagePath))}.exe`);
  const extracted = path.join(output, 'package');
  run('package-extraction', 'C:/Program Files/7-Zip/7z.exe', ['x', '-y', `-o${extracted}`, '--', path.join(repo, packageRef.path)]);
  const embedded = reference(path.join(extracted, 'pocketstream-desktop.exe'));
  const a = fs.readFileSync(path.join(repo, staged.path));
  const b = fs.readFileSync(path.join(repo, embedded.path));
  if (a.length !== b.length) throw new Error('Embedded/staged size differs');
  const offsets = [];
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) offsets.push(i);
  if (offsets.length !== 3 || a.toString('ascii', offsets[0], offsets[0] + 3) !== 'UNK' ||
      b.toString('ascii', offsets[0], offsets[0] + 3) !== 'NSS') throw new Error('Unexpected embedded/staged difference');
  const artifacts = { staged, package: packageRef, embedded };
  const sdk = 'C:/Program Files (x86)/Windows Kits/10/bin';
  const mt = fs.readdirSync(sdk).sort().reverse().map(n => `${sdk}/${n}/x64/mt.exe`).find(n => fs.existsSync(n));
  if (!mt) throw new Error('Windows SDK mt.exe missing');
  for (const [name, ref] of Object.entries({ staged, embedded, installer: packageRef })) {
    const dest = path.join(output, `${name}.manifest`);
    run(`${name}-manifest`, mt, ['-nologo', `-inputresource:${path.join(repo, ref.path)};#1`, `-out:${dest}`]);
    const manifest = fs.readFileSync(dest, 'utf8');
    if (!/level="requireAdministrator"/.test(manifest) || !/Microsoft.Windows.Common-Controls/.test(manifest)) {
      throw new Error('Release manifest contract failed');
    }
    artifacts[`${name}_manifest`] = reference(dest);
  }
  for (const [key, filename, name] of [
    ['generated_script', 'installer.nsi', 'installer.generated.nsi'],
    ['compiled_trace', 'installer.compile.log', 'installer.compile.log'],
    ['compiler_metadata', 'compile-inspection.json', 'compile-inspection.json'],
  ]) artifacts[key] = retain(path.join(repo, 'src-tauri/target/release/nsis/x64', filename), name);
  const baseline = JSON.parse(fs.readFileSync(path.join(repo, 'docs/runtime-evidence/privilege-v2-final-qualification.json')));
  const additional = ['scripts/prepare-installer-prerequisites.ps1', 'src-tauri/installer/vc-runtime.nsh', 'src-tauri/installer/uninstall-bootstrap.ps1'];
  const source_inputs = [...new Set([...baseline.source_inputs.map(f => f.path), ...additional])]
    .map(f => reference(path.join(repo, f))).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const effective_source_sha256 = hash(source_inputs.map(f => `${f.sha256}  ${f.path}\n`).join(''));
  write('candidate.json', { version: 1, recorded_at_utc: new Date().toISOString(),
    status: 'unsigned rebuilt candidate; qualification pending', source_count: source_inputs.length,
    effective_source_sha256, source_inputs, artifacts,
    marker_difference: { differing_bytes: 3, offsets, staged: 'UNK', embedded: 'NSS' },
    release_manifest: 'requireAdministrator; Common Controls v6', commands: 46,
    code_signing: false, updater_artifacts: false, a4_complete: false,
    previous_evidence: 'docs/runtime-evidence/privilege-v2-final-qualification.json' });
}
report.finished_utc = new Date().toISOString();
write('run.json', report);
