import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function importTypeScript(relativePath) {
  const source = fs.readFileSync(path.join(root, relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(output).toString("base64")}`;
  return await import(moduleUrl);
}

const { formatRestreamBitrate } = await importTypeScript("src/lib/restream-format.ts");
const {
  RestreamBindRequestGate,
  buildRestreamBindOptions,
  buildRestreamBindUpdate,
  buildRestreamSettingsUpdate,
  resolveSrtPassphraseUpdate,
  restreamSwitchStatusIsFinal,
  selectedRestreamBindInterface,
} = await importTypeScript("src/lib/restream-settings.ts");

const bitrateCases = [
  [0, "500.0 kbps"],
  [1, "500.0 kbps"],
  [2, "500.0 kbps / ~1000.0 kbps aggregate"],
  [10, "500.0 kbps / ~5000.0 kbps aggregate"],
];
for (const [clients, expected] of bitrateCases) {
  const actual = formatRestreamBitrate(500, clients);
  if (actual !== expected) {
    throw new Error(`${clients} clients: expected '${expected}', got '${actual}'`);
  }
}
if (formatRestreamBitrate(500, 1).includes("aggregate")) {
  throw new Error("2 -> 1 clients must remove the aggregate estimate on the next render");
}

const config = {
  stream: {
    protocol: "rtsp",
    rtsp_port: 554,
    rtsp_path: "/live",
    udp_port: 8600,
    camera_ip: "",
    audio_muted: false,
  },
  restream_protocol: "rtsp",
  rtsp_server: {
    enabled: true,
    port: 8554,
    token: "0123456789abcdef",
    bind_interface: "ZeroTier RTSP",
  },
  srt_server: {
    port: 8890,
    passphrase: { state: "available", value: "strongPass1" },
    latency_ms: 125,
    stream_id: "field unit",
    bind_interface: "ZeroTier SRT",
  },
  credentials: { username: "", password: "" },
  adopted_subnets: {},
  adopted_meta: {},
  zoom_positions: {},
  network_mode: "dhcp",
  manual_nodes: [],
};

if (selectedRestreamBindInterface(config, "rtsp") !== "ZeroTier RTSP") {
  throw new Error("RTSP selection did not retain its independent bind interface");
}
if (selectedRestreamBindInterface(config, "srt") !== "ZeroTier SRT") {
  throw new Error("SRT selection did not retain its independent bind interface");
}

const formUpdate = buildRestreamSettingsUpdate(config, {
  enabled: false,
  rtspPort: 9554,
  rtspToken: "fedcba9876543210",
  srtPort: 9000,
  srtLatencyMs: 250,
  srtStreamId: "replacement",
  srtPassphrase: { action: "replace", value: "replacement1" },
});
if (
  formUpdate.rtsp_server.bind_interface !== "ZeroTier RTSP" ||
  formUpdate.srt_server.bind_interface !== "ZeroTier SRT" ||
  formUpdate.srt_server.passphrase.action !== "replace"
) {
  throw new Error("Settings Save did not submit both complete protocol sections");
}

const srtBindUpdate = buildRestreamBindUpdate(config, "srt", "ZeroTier New");
if (
  srtBindUpdate.srt_server.bind_interface !== "ZeroTier New" ||
  srtBindUpdate.rtsp_server.bind_interface !== "ZeroTier RTSP" ||
  srtBindUpdate.srt_server.passphrase.action !== "keep"
) {
  throw new Error("SRT bind selection changed inactive settings or protected-secret intent");
}

const available = { state: "available", value: "strongPass1" };
const unavailable = { state: "unavailable", value: null };
if (resolveSrtPassphraseUpdate(available, "strongPass1", false, false).action !== "keep") {
  throw new Error("an untouched available passphrase must submit Keep");
}
if (resolveSrtPassphraseUpdate(unavailable, "", false, false).action !== "keep") {
  throw new Error("an untouched unavailable passphrase must submit Keep");
}
const replacement = resolveSrtPassphraseUpdate(unavailable, "replacement1", true, false);
if (replacement.action !== "replace" || replacement.value !== "replacement1") {
  throw new Error("passphrase re-entry must submit Replace");
}
if (resolveSrtPassphraseUpdate(available, "", true, true).action !== "clear") {
  throw new Error("confirmed passwordless operation must submit Clear");
}
let emptyEditRejected = false;
try {
  resolveSrtPassphraseUpdate(available, "", true, false);
} catch {
  emptyEditRejected = true;
}
if (!emptyEditRejected) {
  throw new Error("an empty edit must not silently clear SRT encryption");
}

if (restreamSwitchStatusIsFinal("srt", true, "srt", false)) {
  throw new Error("a live switch released its latch on the intermediate stopped status");
}
if (!restreamSwitchStatusIsFinal("srt", true, "srt", true)) {
  throw new Error("a live switch did not release after its desired SRT status arrived");
}
if (!restreamSwitchStatusIsFinal("srt", false, "srt", false)) {
  throw new Error("a stopped switch did not release after its selected SRT status arrived");
}

const unavailableOptions = buildRestreamBindOptions([], "Missing VPN");
if (
  !unavailableOptions.some(
    (option) =>
      option.value === "Missing VPN" &&
      option.label === "Missing VPN (unavailable)" &&
      option.unavailable
  )
) {
  throw new Error("a saved unavailable interface must remain representable and selected");
}

// Simulate a delayed RTSP enumeration completing after a protocol switch.
// Only the SRT generation may paint, even though both calls return valid data.
const gate = new RestreamBindRequestGate();
const painted = [];
let releaseRtsp;
const rtspResponse = new Promise((resolve) => {
  releaseRtsp = resolve;
});
const rtspRequest = gate.begin("rtsp");
const lateRtspPaint = rtspResponse.then(() => {
  if (gate.isCurrent(rtspRequest, "srt")) painted.push("rtsp");
});
const srtRequest = gate.begin("srt");
if (gate.isCurrent(srtRequest, "srt")) painted.push("srt");
releaseRtsp();
await lateRtspPaint;
if (painted.join(",") !== "srt") {
  throw new Error(`late bind enumeration painted stale state: ${painted.join(",")}`);
}

console.log("Re-stream selector, secret, bind-race, and bitrate contracts passed");
