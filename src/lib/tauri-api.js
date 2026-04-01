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

// ── Logging ─────────────────────────────────────────────────────────

export function logToFile(level, message) {
  invoke("log_frontend", { level, message }).catch(() => {});
}

export async function openLogFolder() {
  return await invoke("open_log_folder");
}

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

export async function listVpnInterfaces() {
  return await invoke("list_vpn_interfaces");
}

export async function getInterfaceInfo(name) {
  return await invoke("get_interface_info", { name });
}

export async function setStaticIp(name, ip, subnetMask, gateway = null) {
  return await invoke("set_static_ip", { name, ip, subnetMask, gateway });
}

export async function addSecondaryIp(name, ip, subnetMask) {
  return await invoke("add_secondary_ip", { name, ip, subnetMask });
}

export async function removeSecondaryIp(name, ip) {
  return await invoke("remove_secondary_ip", { name, ip });
}

// ── ARP Discovery ───────────────────────────────────────────────────

export async function startArpDiscovery(iface) {
  return await invoke("start_arp_discovery", { interface: iface });
}

export async function stopArpDiscovery() {
  return await invoke("stop_arp_discovery");
}

export async function getArpDevices() {
  return await invoke("get_arp_devices");
}

export async function getAdoptedSubnets() {
  return await invoke("get_adopted_subnets");
}

export async function removeAdoptedSubnet(subnet) {
  return await invoke("remove_adopted_subnet", { subnet });
}

/** Listen for a Tauri event. Returns an unlisten function. */
export function onEvent(eventName, callback) {
  const listen = window.__TAURI__?.event?.listen;
  if (listen) {
    // listen() returns a Promise<UnlistenFn>
    return listen(eventName, (event) => callback(event.payload));
  }
  console.log(`[dev] onEvent: ${eventName} (no Tauri runtime)`);
  return Promise.resolve(() => {});
}

// ── Streaming ───────────────────────────────────────────────────────

export async function startStream(windowHandle = null) {
  return await invoke("start_stream", { windowHandle: windowHandle ? parseInt(windowHandle) : null });
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

export async function createVideoWindow(x, y, width, height) {
  return await invoke("create_video_window", { x, y, width, height });
}

export async function updateVideoPosition(x, y, width, height) {
  return await invoke("update_video_position", { x, y, width, height });
}

export async function setVideoVisible(visible) {
  return await invoke("set_video_visible", { visible });
}

export async function startRecording() {
  return await invoke("start_recording");
}

export async function stopRecording() {
  return await invoke("stop_recording");
}

// ── FLIR PTU ────────────────────────────────────────────────────────

export async function ptuSend(ip, cmd) {
  return await invoke("ptu_send", { ip, cmd });
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

export async function sonyCgiZoom(ip, zoomSpeed, username, password) {
  return await invoke("sony_cgi_zoom", { ip, zoomSpeed, username, password });
}
