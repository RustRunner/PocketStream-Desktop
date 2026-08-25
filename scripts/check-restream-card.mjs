import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const html = read("index.html");
const streaming = read("src/lib/streaming.ts");
const api = read("src/lib/tauri-api.ts");
const backend = read("src-tauri/src/lib.rs");

const requiredIds = [
  "card-restream",
  "restream-server-enable",
  "restream-spinner",
  "restream-status",
  "restream-error-row",
  "restream-error",
  "restream-url",
  "restream-uptime",
  "restream-clients",
  "restream-bandwidth",
  "restream-bind-interface",
  "restream-rtsp-settings",
  "restream-srt-settings",
  "srt-server-port",
  "srt-passphrase",
  "srt-passphrase-state",
  "srt-copy-passphrase",
  "srt-clear-passphrase",
  "srt-latency-ms",
  "srt-stream-id",
  "srt-clear-passphrase-dialog",
  "srt-clear-passphrase-confirm",
  "srt-clear-passphrase-cancel",
  "btn-toggle-restream",
];
const failures = requiredIds
  .filter((id) => !html.includes(`id="${id}"`))
  .map((id) => `neutral card is missing #${id}`);

for (const stale of [
  "card-rtsp",
  "rtsp-server-enable",
  "rtsp-spinner",
  "rtsp-status",
  "rtsp-url",
  "rtsp-uptime",
  "rtsp-clients",
  "rtsp-bandwidth",
  "rtsp-bind-interface",
  "btn-toggle-rtsp",
]) {
  if (html.includes(`id="${stale}"`)) failures.push(`stale card id remains: #${stale}`);
}

for (const command of [
  "start_restream_server",
  "stop_restream_server",
  "switch_restream_protocol",
  "apply_restream_settings",
]) {
  if (!api.includes(`"${command}"`) || !backend.includes(`commands::${command}`)) {
    failures.push(`neutral IPC command is not wired end-to-end: ${command}`);
  }
}
for (const stale of [
  "start_rtsp_server",
  "stop_rtsp_server",
  "update_rtsp_settings",
  "save_config",
]) {
  if (api.includes(stale) || backend.includes(`commands::${stale}`)) {
    failures.push(`stale IPC command remains registered or invoked: ${stale}`);
  }
}

const inputProtocolButtons = [...html.matchAll(/data-protocol="(rtsp|udp)"/g)].map(
  (match) => match[1]
);
if (inputProtocolButtons.join(",") !== "rtsp,udp") {
  failures.push("camera input data-protocol controls changed during the card rename");
}
const outputProtocolButtons = [
  ...html.matchAll(/data-restream-protocol="(rtsp|srt)"/g),
].map((match) => match[1]);
if (outputProtocolButtons.join(",") !== "rtsp,srt") {
  failures.push("the re-stream selector must expose exactly RTSP and SRT");
}
if (!/<input(?=[^>]*id="srt-passphrase")(?=[^>]*type="password")[^>]*>/.test(html)) {
  failures.push("the SRT passphrase must render as a masked password field");
}
if (!html.includes("Run SRT without encryption?")) {
  failures.push("the explicit unencrypted-SRT confirmation is missing");
}
if (!/id="restream-bind-interface"[^>]*\bdisabled\b/.test(html)) {
  failures.push("the asynchronous re-stream bind selector must start disabled");
}
for (const raceGuard of [
  "RestreamBindRequestGate",
  "isCurrent(request, currentRestreamProtocol())",
  "selectedRestreamBindInterface",
  "reloadCanonicalRestreamConfig",
]) {
  if (!streaming.includes(raceGuard)) {
    failures.push(`re-stream bind race guard is missing: ${raceGuard}`);
  }
}
for (const wiring of [
  "setupRestreamControls",
  "refreshRestreamBindOptions",
  "updateRestreamUI",
  "startRestreamServer",
  "stopRestreamServer",
  "switchRestreamProtocol(protocol)",
  "beginRestreamSettingsSave",
  "readRestreamSettingsUpdate",
  "resolveSrtPassphraseUpdate",
]) {
  if (!streaming.includes(wiring)) failures.push(`re-stream card wiring is missing ${wiring}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("RTSP/SRT re-stream card contract passed");
