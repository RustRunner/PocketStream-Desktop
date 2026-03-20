/**
 * PocketStream Desktop — Tauri IPC API wrapper
 *
 * Provides a clean interface to all Rust backend commands.
 * Falls back to console.log in browser dev mode (no Tauri).
 */

const invoke = window.__TAURI__?.core?.invoke ?? (async (cmd, args) => {
  console.log(`[dev] invoke: ${cmd}`, args);
  return null;
});

// ── Config ──────────────────────────────────────────────────────────

export async function getConfig() {
  return await invoke("get_config");
}

export async function saveConfig(settings) {
  return await invoke("save_config", { settings });
}

// ── Network ─────────────────────────────────────────────────────────

export async function scanNetwork(subnet) {
  return await invoke("scan_network", { subnet });
}

export async function listInterfaces() {
  return await invoke("list_interfaces");
}

export async function getInterfaceInfo(name) {
  return await invoke("get_interface_info", { name });
}

export async function setStaticIp(name, ip, subnetMask, gateway = null) {
  return await invoke("set_static_ip", { name, ip, subnetMask, gateway });
}

// ── Streaming ───────────────────────────────────────────────────────

export async function startStream() {
  return await invoke("start_stream");
}

export async function stopStream() {
  return await invoke("stop_stream");
}

export async function startRtspServer() {
  return await invoke("start_rtsp_server");
}

export async function stopRtspServer() {
  return await invoke("stop_rtsp_server");
}

export async function getStreamStatus() {
  return await invoke("get_stream_status");
}


export async function takeScreenshot() {
  return await invoke("take_screenshot");
}

export async function startRecording() {
  return await invoke("start_recording");
}

export async function stopRecording() {
  return await invoke("stop_recording");
}

// ── Camera / PTZ ────────────────────────────────────────────────────

export async function discoverOnvif(subnet = null) {
  return await invoke("discover_onvif", { subnet });
}

export async function ptzMove(cameraUrl, pan, tilt, zoom) {
  return await invoke("ptz_move", { cameraUrl, pan, tilt, zoom });
}

export async function ptzStop(cameraUrl) {
  return await invoke("ptz_stop", { cameraUrl });
}

export async function ptzGotoPreset(cameraUrl, preset) {
  return await invoke("ptz_goto_preset", { cameraUrl, preset });
}

export async function ptzSetPreset(cameraUrl, preset, name) {
  return await invoke("ptz_set_preset", { cameraUrl, preset, name });
}
