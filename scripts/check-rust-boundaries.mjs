// A03 dependency guard. This is a review aid, not a Rust ownership proof.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const permanent = new Set([
  'lib.rs', 'bridge.rs', 'ipc_acl_tests.rs',
  'network/watcher.rs', 'network/ip_conflict.rs', 'streaming/video_embed.rs',
]);
// A03 network and streaming extraction is closed. The remaining adapters above
// are narrowly permanent; no owner or facade has a temporary exception.

export function violations(source) {
  // Strip comments so examples do not create exceptions. Match inferred calls
  // as well as turbofish, qualified State and grouped Tauri imports.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const lookups = [...code.matchAll(/\.\s*(?:try_)?state\s*(?:::<[^;]*?>\s*)?\(\s*\)/g)].length;
  const imports = /\btauri\s*::\s*(?:Manager|State|AppHandle)|\buse\s+tauri\s*::\s*\*|\buse\s+tauri\s*::\s*\{[^}]*\b(?:Manager|State|AppHandle)\b/s.test(code);
  return { lookups, imports };
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const src = path.join(root, 'src-tauri/src');
  const errors = [];
  for (const file of walk(src).filter(f => f.endsWith('.rs'))) {
    const relative = path.relative(src, file).replaceAll('\\', '/');
    const { lookups, imports } = violations(fs.readFileSync(file, 'utf8'));
    if (permanent.has(relative) || relative.startsWith('commands/')) continue;
    if (lookups || imports) {
      errors.push(`${relative}: owner depends on Tauri managed state/handle (${lookups} lookups)`);
    }
  }
  if (errors.length) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else console.log('Rust dependency boundaries passed (0 temporary paths; permanent composition/OS adapters separate).');
}
