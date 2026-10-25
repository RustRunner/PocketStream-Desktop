// Compare the actual reviewed starting commit to the extracted implementation.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const baseline = '6f8a727c33de7e722040aeb97ab7aff6538ba277';
const git = args => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
const old = file => git(['show', `${baseline}:${file}`]).replaceAll('\r\n', '\n');
const now = file => fs.readFileSync(file, 'utf8').replaceAll('\r\n', '\n');
const paths = git(['ls-tree', '-r', '--name-only', baseline]).trim().split('\n');
const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(`${dir}/${entry.name}`) : [`${dir}/${entry.name}`]);
const sourcePaths = paths.filter(p => p.startsWith('src-tauri/src/') && p.endsWith('.rs'));
const currentPaths = walk('src-tauri/src').filter(p => p.endsWith('.rs'));
const previousSource = sourcePaths.map(old).join('\n');
const currentSource = currentPaths.map(now).join('\n');
const normalized = source => source.replace(/\/\/[^\n]*/g, '').replace(/\s+/g, '');
function declaration(source, name) {
  const match = source.match(new RegExp(`(?:pub(?:\\([^)]*\\))? )?struct ${name} \\{([\\s\\S]*?)^\\}`, 'm'));
  if (!match) throw Error(`Missing ${name}`);
  return match[1];
}
function fields(source, name) {
  return [...declaration(source, name).matchAll(/^\s*(?:pub(?:\([^)]*\))? )?(\w+): (.+),$/gm)]
    .map(match => ({ name: match[1], type: match[2].replace(/\s+/g, '') }));
}
const contracts = ['StreamStatus', 'RestreamServerInfo', 'RestreamOperationResult'].map(name => ({
  name,
  fields: fields(currentSource, name),
  unchanged: normalized(declaration(previousSource, name)) === normalized(declaration(currentSource, name)),
}));
const beforeState = fields(old('src-tauri/src/streaming/mod.rs'), 'StreamState').sort((a, b) => a.name.localeCompare(b.name));
const afterState = [...fields(now('src-tauri/src/streaming/playback.rs'), 'PlaybackData'), ...fields(now('src-tauri/src/streaming/relay_service.rs'), 'RelayData')].sort((a, b) => a.name.localeCompare(b.name));
const events = source => [...new Set([...source.matchAll(/\bemit(?:_serialized)?\s*\([^";]{0,250}"([a-z][a-z0-9]*(?:-[a-z0-9]+)+)"/g)].map(match => match[1]))].sort();
const beforeEvents = events(previousSource);
const afterEvents = events(currentSource);
function commands(source) {
  return [...source.matchAll(/#\[tauri::command(?:\([^\]]*\))?\]\s*pub (?:async )?fn (\w+)[^{]+\{/g)]
    .map(match => ({ name: match[1], signature: normalized(match[0].slice(0, -1)) })).sort((a, b) => a.name.localeCompare(b.name));
}
const beforeCommands = commands(previousSource);
const afterCommands = commands(currentSource);
const previousRecord = JSON.parse(now('docs/runtime-evidence/a03-revision3/contracts-preserved.json'));
const protectedPaths = new Set([
  ...previousRecord.retained.map(entry => entry.path),
  ...paths.filter(p => p.startsWith('src-tauri/src/network/') || p.startsWith('docs/runtime-evidence/privilege-v2')),
  'docs/runtime-evidence/a03-revision3-implementation.md',
  'src-tauri/Cargo.lock', 'src-tauri/Cargo.toml', 'src-tauri/build.rs',
]);
const retained = [...protectedPaths].sort().map(path => ({ path, unchanged: old(path) === now(path) }));
const exitTail = source => source.slice(source.indexOf('            if let tauri::RunEvent::ExitRequested'));
const errorLiterals = source => [...new Set([...source.matchAll(/AppError::(?:Stream|Validation|Network)\(\s*(?:format!\(\s*)?("(?:\\.|[^"\\])*")/g)].map(match => match[1]))].sort();
const beforeErrors = errorLiterals(previousSource);
const afterErrors = new Set(errorLiterals(currentSource));
const missingErrors = beforeErrors.filter(error => !afterErrors.has(error));
const production = source => source.split('\n#[cfg(test)]\nmod tests {')[0];
const mediaInputs = ['rtsp_server.rs', 'srt_server.rs', 'recorder.rs', 'audio.rs'].map(file => {
  const path = `src-tauri/src/streaming/${file}`;
  return { path, production_unchanged: production(old(path)) === production(now(path)) };
});
const playbackPipeline = 'src-tauri/src/streaming/rtsp_client.rs';
mediaInputs.push({ path: playbackPipeline, production_unchanged_except_redaction_dependency:
  production(old(playbackPipeline)).replaceAll('super::StreamManager::redact_url', 'super::source::redact_url') === production(now(playbackPipeline)) });
const result = {
  baseline,
  commands: { baseline_count: beforeCommands.length, current_count: afterCommands.length, unchanged: JSON.stringify(beforeCommands) === JSON.stringify(afterCommands) },
  events: { baseline: beforeEvents, current: afterEvents, unchanged: JSON.stringify(beforeEvents) === JSON.stringify(afterEvents) },
  contracts,
  state_representations: { baseline: beforeState, current: afterState, unchanged: JSON.stringify(beforeState) === JSON.stringify(afterState) },
  retained,
  environment_configuration: { path: '.cargo/config.toml', tracked: false, sha256: createHash('sha256').update(fs.readFileSync('.cargo/config.toml')).digest('hex') },
  exit_order_unchanged: exitTail(old('src-tauri/src/lib.rs')) === exitTail(now('src-tauri/src/lib.rs')),
  baseline_error_literals: beforeErrors.length,
  missing_error_literals: missingErrors,
  media_inputs: mediaInputs,
};
fs.writeFileSync('docs/runtime-evidence/a03-streaming/contracts-preserved.json', JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ commands: result.commands, events: beforeEvents.length, status_fields: contracts[0].fields.length, state_fields: beforeState.length,
  state_unchanged: result.state_representations.unchanged, changed_protected_paths: retained.filter(p => !p.unchanged), missingErrors, exit_order_unchanged: result.exit_order_unchanged }));
if (beforeCommands.length !== 46 || !result.commands.unchanged || beforeEvents.length !== 16 || !result.events.unchanged || contracts.some(c => !c.unchanged) ||
  contracts[0].fields.length !== 27 || !result.state_representations.unchanged || retained.some(p => !p.unchanged) || !result.exit_order_unchanged || missingErrors.length ||
  mediaInputs.some(input => !(input.production_unchanged ?? input.production_unchanged_except_redaction_dependency))) process.exitCode = 1;
