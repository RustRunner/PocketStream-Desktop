import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const htmlPath = path.join(root, "index.html");
const html = fs.readFileSync(htmlPath, "utf8");
const ids = new Map();
const idPattern = /\bid\s*=\s*["']([^"']+)["']/g;
for (const match of html.matchAll(idPattern)) {
  ids.set(match[1], (ids.get(match[1]) ?? 0) + 1);
}

const failures = [];
for (const [id, count] of ids) {
  if (count > 1) failures.push(`index.html contains duplicate id #${id} (${count} times)`);
}

function sourceFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.isFile() && entry.name.endsWith(".ts") ? [full] : [];
  });
}

for (const file of sourceFiles(path.join(root, "src"))) {
  const sourceText = fs.readFileSync(file, "utf8");
  const source = ts.createSourceFile(file, sourceText, ts.ScriptTarget.Latest, true);
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      ["$", "$opt", "$$"].includes(node.expression.text)
    ) {
      const argument = node.arguments[0];
      if (argument && (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument))) {
        for (const match of argument.text.matchAll(/#([A-Za-z][\w:-]*)/g)) {
          if (!ids.has(match[1])) {
            const position = source.getLineAndCharacterOfPosition(argument.getStart(source));
            failures.push(
              `${path.relative(root, file)}:${position.line + 1} references missing #${match[1]}`
            );
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`DOM selector contract passed (${ids.size} unique IDs)`);
