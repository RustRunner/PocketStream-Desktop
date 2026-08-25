import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = fs.readFileSync(path.join(root, "src/lib/restream-format.ts"), "utf8");
const output = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
}).outputText;
const moduleUrl = `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`;
const { formatRestreamBitrate } = await import(moduleUrl);

const cases = [
  [0, "500.0 kbps"],
  [1, "500.0 kbps"],
  [2, "500.0 kbps / ~1000.0 kbps aggregate"],
  [10, "500.0 kbps / ~5000.0 kbps aggregate"],
];
for (const [clients, expected] of cases) {
  const actual = formatRestreamBitrate(500, clients);
  if (actual !== expected) throw new Error(`${clients} clients: expected '${expected}', got '${actual}'`);
}
if (formatRestreamBitrate(500, 1).includes("aggregate")) {
  throw new Error("2 -> 1 clients must remove the aggregate estimate on the next render");
}
console.log("Re-stream bitrate rendering contract passed");
