import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

export const pluginPermissions = [
  "core:event:allow-listen", "core:event:allow-unlisten", "core:app:allow-version",
  "core:window:allow-minimize", "core:window:allow-toggle-maximize",
  "core:window:allow-close", "core:window:allow-is-maximized",
  "dialog:allow-confirm", "updater:default",
];

// Tokenize the small Rust list convention, skipping comments (including nested
// block comments) and treating strings as tokens. A commented-out registration
// or a macro name inside a string cannot satisfy the contract.
function rustTokens(source) {
  const tokens = [];
  for (let i = 0; i < source.length;) {
    if (/\s/.test(source[i])) { i++; continue; }
    if (source.startsWith("//", i)) {
      const end = source.indexOf("\n", i); i = end < 0 ? source.length : end; continue;
    }
    if (source.startsWith("/*", i)) {
      let depth = 1; i += 2;
      while (i < source.length && depth) {
        if (source.startsWith("/*", i)) { depth++; i += 2; }
        else if (source.startsWith("*/", i)) { depth--; i += 2; }
        else i++;
      }
      if (depth) throw Error("unterminated Rust comment");
      continue;
    }
    const raw = source.slice(i).match(/^r(#+)?"/);
    if (raw) {
      const end = source.indexOf('"' + (raw[1] ?? ""), i + raw[0].length);
      if (end < 0) throw Error("unterminated Rust raw string");
      tokens.push({ string: source.slice(i + raw[0].length, end) });
      i = end + 1 + (raw[1]?.length ?? 0); continue;
    }
    if (source[i] === '"') {
      const literal = source.slice(i).match(/^"(?:\\.|[^"\\])*"/s)?.[0];
      if (!literal) throw Error("unterminated Rust string");
      // Only the command strings are interpreted; other Rust strings can use
      // Rust-specific escapes that are irrelevant to the list parser.
      tokens.push({ string: literal.slice(1, -1) }); i += literal.length; continue;
    }
    const word = source.slice(i).match(/^[A-Za-z_][A-Za-z_0-9]*/)?.[0];
    tokens.push(word ?? source[i]); i += word?.length ?? 1;
  }
  return tokens;
}

function listAfter(tokens, marker) {
  const starts = tokens.flatMap((_, i) => marker.every((x, j) => tokens[i + j] === x) ? [i + marker.length] : []);
  if (starts.length !== 1) throw Error(`expected one ${marker.join(" ")}, found ${starts.length}`);
  const start = starts[0], end = tokens.indexOf("]", start);
  if (end < 0) throw Error("unterminated Rust command list");
  return tokens.slice(start, end);
}

function permissionRecords(source) {
  const records = [];
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line === "[[permission]]") { records.push({}); continue; }
    const field = line.match(/^(identifier|description|commands\.(?:allow|deny))\s*=\s*(.+)$/);
    if (!field || !records.length) throw Error(`unsupported generated permission syntax: ${line}`);
    const record = records.at(-1);
    if (Object.hasOwn(record, field[1])) throw Error(`duplicate permission field ${field[1]}`);
    record[field[1]] = JSON.parse(field[2]);
  }
  return records;
}

function filesUnder(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const name = path.join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(name) : [name];
  });
}

export function checkIpcAllowlist(root, { expectedCount = 46 } = {}) {
  const errors = [], read = file => fs.readFileSync(path.join(root, file), "utf8");
  const fail = message => errors.push(message);
  const same = (label, actual, expected) => {
    if (new Set(actual).size !== actual.length) fail(`${label}: duplicate entries`);
    const extras = actual.filter(x => !expected.includes(x));
    const missing = expected.filter(x => !actual.includes(x));
    if (extras.length) fail(`${label}: unexpected ${extras.join(", ")}`);
    if (missing.length) fail(`${label}: missing ${missing.join(", ")}`);
  };
  let commands = [], registrations = [], wrappers = new Map();
  try {
    const build = rustTokens(read("src-tauri/build.rs"));
    const constant = build.findIndex((t, i) => t === "const" && build[i + 1] === "COMMANDS");
    if (constant < 0) throw Error("build.rs: missing const COMMANDS");
    const assignment = build.indexOf("=", constant);
    const values = listAfter(build.slice(assignment), ["=", "&", "["]);
    for (const token of values) {
      if (token === ",") continue;
      if (!token.string || !/^[a-z][a-z0-9_]*$/.test(token.string)) throw Error("COMMANDS must contain literal snake_case names");
      commands.push(token.string);
    }
    if (commands.length !== expectedCount) fail(`COMMANDS: expected ${expectedCount} commands, found ${commands.length}`);
    const source = rustTokens(read("src-tauri/src/lib.rs"));
    const handler = listAfter(source, ["tauri", ":", ":", "generate_handler", "!", "["]);
    for (let i = 0; i < handler.length;) {
      if (handler[i] === ",") { i++; continue; }
      if (handler[i] !== "commands" || handler[i + 1] !== ":" || handler[i + 2] !== ":" || typeof handler[i + 3] !== "string") {
        throw Error("generate_handler!: use literal commands::<name> registrations");
      }
      registrations.push(handler[i + 3]); i += 4;
    }
    same("generate_handler!", registrations, commands);
    const capability = JSON.parse(read("src-tauri/capabilities/default.json"));
    if (capability.local === false || capability.remote || JSON.stringify(capability.windows) !== '["main"]' || capability.webviews) {
      fail("default capability must apply only to the local main window, with no remote origins");
    }
    same("main capability", capability.permissions, [...commands.map(c => "allow-" + c.replaceAll("_", "-")), ...pluginPermissions]);
    const capabilities = filesUnder(path.join(root, "src-tauri/capabilities"));
    same("capability files", capabilities.map(f => path.relative(root, f).replaceAll("\\", "/")), ["src-tauri/capabilities/default.json"]);

    const permissions = filesUnder(path.join(root, "src-tauri/permissions"));
    same("permission files", permissions.map(f => path.relative(path.join(root, "src-tauri/permissions"), f).replaceAll("\\", "/")), commands.map(c => `autogenerated/${c}.toml`));
    for (const command of commands) {
      const file = `src-tauri/permissions/autogenerated/${command}.toml`;
      try {
        const records = permissionRecords(read(file));
        if (records.length !== 2) throw Error("expected exactly allow and deny records");
        for (const [index, action] of ["allow", "deny"].entries()) {
          const record = records[index];
          if (record.identifier !== `${action}-${command.replaceAll("_", "-")}` || typeof record.description !== "string" ||
              JSON.stringify(record[`commands.${action}`]) !== JSON.stringify([command]) ||
              Object.keys(record).sort().join(",") !== [`commands.${action}`, "description", "identifier"].sort().join(",")) {
            throw Error(`exact ${action} identifier/commands payload differs`);
          }
        }
      } catch (error) { fail(`${file}: ${error.message}`); }
    }

    // Native registration is a separate inventory. Notification remains for
    // Rust-side use; it does not give the renderer notification permissions.
    const plugins = [];
    for (let i = 0; i < source.length - 3; i++) {
      if (source[i] === "." && source[i + 1] === "plugin" && source[i + 2] === "(" &&
          typeof source[i + 3] === "string" && source[i + 3].startsWith("tauri_plugin_")) {
        plugins.push(source[i + 3].slice("tauri_plugin_".length));
      }
    }
    same("Rust plugin registrations", plugins, ["dialog", "notification", "updater"]);
    wrappers = inspectWrappers(root, commands, fail);
  } catch (error) { fail(error.message); }
  return { errors, commands, registrations, wrapperCount: wrappers.size, pluginPermissions };
}

function inspectWrappers(root, commands, fail) {
  const configFile = path.join(root, "tsconfig.json");
  const config = ts.readConfigFile(configFile, ts.sys.readFile);
  if (config.error) throw Error(ts.flattenDiagnosticMessageText(config.error.messageText, "\n"));
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  if (parsed.errors.length) throw Error(ts.flattenDiagnosticMessageText(parsed.errors[0].messageText, "\n"));
  const program = ts.createProgram(parsed.fileNames, parsed.options), checker = program.getTypeChecker();
  const api = program.getSourceFile(path.join(root, "src/lib/tauri-api.ts"));
  if (!api) throw Error("missing src/lib/tauri-api.ts in TypeScript program");
  const diagnostic = (node, message) => {
    const file = node.getSourceFile(), pos = file.getLineAndCharacterOfPosition(node.getStart());
    fail(`${path.relative(root, file.fileName)}:${pos.line + 1}:${pos.character + 1}: ${message}`);
  };
  const symbolAt = node => {
    const symbol = checker.getSymbolAtLocation(node);
    return symbol?.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  };
  const visit = (node, fn) => { fn(node); ts.forEachChild(node, child => visit(child, fn)); };
  const unwrap = node => {
    while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node))) node = node.expression;
    return node;
  };
  const enclosing = (node, predicate) => { for (let n = node.parent; n; n = n.parent) if (predicate(n)) return n; };
  const invoke = api.statements.filter(ts.isVariableStatement).flatMap(s => [...s.declarationList.declarations])
    .find(d => ts.isIdentifier(d.name) && d.name.text === "invoke");
  if (!invoke) throw Error("wrapper module must declare its private invoke boundary");
  const invokeSymbol = symbolAt(invoke.name), wrappers = new Map(), symbols = new Map();
  const apiSymbol = checker.getSymbolAtLocation(api);
  for (const fn of api.statements.filter(ts.isFunctionDeclaration)) {
    if (!fn.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) || !fn.body) continue;
    const calls = [];
    visit(fn.body, node => {
      if (ts.isCallExpression(node) && symbolAt(unwrap(node.expression)) === invokeSymbol) {
        const name = node.arguments[0];
        if (!name || !ts.isStringLiteral(name)) diagnostic(node, "invoke requires a literal command name");
        else calls.push(name.text);
      }
    });
    if (fn.name.text === "onEvent") {
      if (calls.length) diagnostic(fn, "onEvent must remain an event helper");
    } else if (calls.length !== 1) diagnostic(fn, "exported command wrapper must contain exactly one literal invoke");
    else wrappers.set(fn.name.text, calls[0]);
    symbols.set(symbolAt(fn.name), fn.name.text);
  }
  const referenced = new Set();
  const resolve = (raw, seen = new Set()) => {
    const node = unwrap(raw);
    if (!node) return;
    if (ts.isPropertyAccessExpression(node)) {
      const base = resolve(node.expression, seen);
      if (base === "namespace") return symbols.has(symbolAt(node.name)) ? symbols.get(symbolAt(node.name)) : undefined;
      return;
    }
    if (!ts.isIdentifier(node)) return;
    const symbol = symbolAt(node);
    if (!symbol || seen.has(symbol)) return;
    if (symbol === apiSymbol) return "namespace";
    if (symbols.has(symbol)) return symbols.get(symbol);
    seen.add(symbol);
    const declaration = symbol.valueDeclaration;
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.parent.flags & ts.NodeFlags.Const) {
      return resolve(declaration.initializer, seen);
    }
  };
  const isAliasInitializer = node => {
    let parent = node.parent;
    while (parent && unwrap(parent) === node) parent = parent.parent;
    return parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name) &&
      parent.parent.flags & ts.NodeFlags.Const && unwrap(parent.initializer) === node;
  };
  for (const file of program.getSourceFiles()) {
    if (file.isDeclarationFile || !path.relative(root, file.fileName).replaceAll("\\", "/").startsWith("src/")) continue;
    visit(file, node => {
      if (enclosing(node, n => ts.isTypeNode(n) || ts.isImportDeclaration(n))) return;
      if (ts.isImportDeclaration(node) && /@tauri-apps\/api\/(?:core|tauri)/.test(node.moduleSpecifier.text ?? "")) {
        diagnostic(node, "raw invoke import; use tauri-api.ts wrappers");
      }
      if (file === api) {
        if (ts.isIdentifier(node) && symbolAt(node) === invokeSymbol && node !== invoke.name) {
          if (!ts.isCallExpression(node.parent) || node.parent.expression !== node ||
              !enclosing(node, n => ts.isFunctionDeclaration(n) && symbols.has(symbolAt(n.name)))) {
            diagnostic(node, "invoke reference escaped a command wrapper; call it directly with a literal name");
          }
        }
      }
      const property = ts.isPropertyAccessExpression(node) ? node.name.text :
        ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression) ? node.argumentExpression.text : null;
      if (property === "invoke" || property === "core" || ts.isIdentifier(node) && node.text === "__TAURI_INTERNALS__") {
        if (enclosing(node, ts.isVariableDeclaration) !== invoke || file !== api) diagnostic(node, "raw/unresolved invoke access; use tauri-api.ts wrappers");
      }
      if (file === api) return;
      if (ts.isElementAccessExpression(node) && resolve(node.expression) === "namespace") {
        diagnostic(node, "computed wrapper access is unsupported; use a named import or namespace.property");
      }
      if (!ts.isIdentifier(node) && !ts.isPropertyAccessExpression(node)) return;
      if (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) return;
      if (ts.isVariableDeclaration(node.parent) && node.parent.name === node) return;
      if (ts.isBindingElement(node.parent) || ts.isExportSpecifier(node.parent)) {
        if (resolve(node)) diagnostic(node, "wrapper indirection is unsupported; use named imports or const aliases");
        return;
      }
      const value = resolve(node);
      if (!value || isAliasInitializer(node)) return;
      if (ts.isVariableDeclaration(node.parent) && node.parent.initializer === node) {
        diagnostic(node, "wrapper aliases must be const identifiers; destructuring/mutable indirection is unsupported");
      }
      if (value === "namespace") {
        if (!(ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node)) {
          diagnostic(node, "wrapper namespace escaped; use namespace.property or a const namespace alias");
        } else if (!resolve(node.parent)) diagnostic(node.parent, "unresolved wrapper property");
      } else if (ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node) {
        diagnostic(node.parent, "wrapper .call/.bind/.apply indirection is unsupported; use a direct value reference");
      } else if (wrappers.has(value)) referenced.add(value);
    });
  }
  for (const [name, command] of wrappers) {
    if (!referenced.has(name)) fail(`unreferenced exported command wrapper: ${name} (${command})`);
    if (!commands.includes(command)) fail(`wrapper ${name}: command ${command} is not in COMMANDS`);
  }
  for (const command of commands) {
    const names = [...wrappers].filter(([, c]) => c === command);
    if (names.length !== 1) fail(`command ${command}: expected one wrapper, found ${names.length}`);
  }
  return wrappers;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = checkIpcAllowlist(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."));
  if (result.errors.length) {
    console.error(result.errors.join("\n")); process.exitCode = 1;
  } else console.log(`IPC contract: ${result.commands.length} commands, ${result.wrapperCount} referenced wrappers + event helper; ${pluginPermissions.length} plugin permissions checked separately.`);
}
