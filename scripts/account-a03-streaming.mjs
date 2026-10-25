// Scenario identity accounting supplements totals. No fixture execution.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const dir = 'docs/runtime-evidence/a03-streaming';
const slice = Number(process.argv[2]);
function read(file) {
  const bytes = fs.readFileSync(file);
  return bytes.toString(bytes[0] === 255 && bytes[1] === 254 ? 'utf16le' : 'utf8').replace(/^\uFEFF/, '');
}
const inventory = file => read(file).split(/\r?\n/).filter(line => line.endsWith(': test')).map(line => line.slice(0, -6));
const baseline = inventory(`${dir}/baseline-rust-inventory.txt`);
const current = inventory(`${dir}/slice-${slice}-rust-inventory.txt`);
if (baseline.length !== 814) throw Error(`Unexpected starting inventory: ${baseline.length}`);
const kept = baseline.filter(test => current.includes(test));
const missing = baseline.filter(test => !current.includes(test));
const introduced = current.filter(test => !baseline.includes(test));
const moved = [];
for (const before of [...missing]) {
  const name = before.split('::').at(-1);
  const matches = introduced.filter(test => test.split('::').at(-1) === name);
  if (matches.length === 1) {
    moved.push({ before, after: matches[0] });
    missing.splice(missing.indexOf(before), 1);
    introduced.splice(introduced.indexOf(matches[0]), 1);
  }
}
const ignored = [];
const files = execFileSync('rg', ['--files', 'src-tauri/src', 'src-tauri/tests'], { encoding: 'utf8' }).trim().split(/\r?\n/).filter(f => f.endsWith('.rs'));
for (const file of files) {
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/#\[ignore\s*=\s*"([^"]+)"\][\s\S]*?\bfn\s+(\w+)\s*\(/g)) {
    ignored.push({ file: file.replaceAll('\\', '/'), name: match[2], reason: match[1] });
  }
}
const frozenIgnored = JSON.parse(read('docs/runtime-evidence/a03-revision3/ignored-tests.json'));
const canonical = list => JSON.stringify(list.map(x => `${x.file}|${x.name}|${x.reason}`).sort());
const ignoredUnchanged = canonical(ignored) === canonical(frozenIgnored);
fs.writeFileSync(`${dir}/slice-${slice}-scenario-accounting.json`, JSON.stringify({ baseline_count: baseline.length, current_count: current.length, kept, moved, added: introduced, missing, ignored_unchanged: ignoredUnchanged, ignored }, null, 2) + '\n');
console.log(JSON.stringify({ kept: kept.length, moved: moved.length, added: introduced.length, missing: missing.length, ignoredUnchanged }));
if (missing.length || !ignoredUnchanged) process.exitCode = 1;
