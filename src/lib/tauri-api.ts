/**
 * PocketStream Desktop — Tauri IPC API wrapper
 *
 * Provides a typed interface to all Rust backend commands. Wraps the
 * runtime-injected `window.__TAURI__.core.invoke` and falls back to a
 * console.log shim when running in `vite dev` outside the Tauri shell
 * (so the dev workflow doesn't crash on every IPC call).
 *
 * Each wrapper's parameters and return type match the corresponding
 * Rust command signature in `src-tauri/src/commands/`. When you change
 * a Rust handler's IPC contract, also update the wrapper here AND the
 * relevant interface in `types.ts`.
 */

import type {
  AdoptionSnapshot,
  AppSettings,
  Credentials,
  DeviceRecord,
  DeviceStatus,
  InterfaceInfo,
  NetworkMode,
  RtspServerConfig,
  RtspServerInfo,
  ScanResult,
  StreamConfig,
} from "./types.ts";

/** Strongly-typed invoke. Always async. Returns whatever the backend
 *  serializes; the per-command wrappers below pin the concrete shape. */
type Invoke = <T = unknown>(
  cmd: string,
  args?: Record<string, unknown>
) => Promise<T>;

const invoke: Invoke =
  (window.__TAURI__?.core?.invoke as Invoke | undefined) ??
  (async <T,>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    console.log(`[dev] invoke: ${cmd}`, args);
    return null as T;
  });

// ── Logging ─────────────────────────────────────────────────────────

export function logToFile(level: "info" | "warn" | "error", message: string): void {
  invoke("log_frontend", { level, message }).catch(() => {});
}

export async function openLogFolder(): Promise<void> {
  return await invoke("open_log_folder");
}

// ── Config ──────────────────────────────────────────────────────────

export async function getConfig(): Promise<AppSettings> {
  return await invoke<AppSettings>("get_config");
}

/** Salvage actions taken while loading config files (quarantines,
 *  resets) — fetched once at init and surfaced as error toasts. */
export async function getStartupNotices(): Promise<string[]> {
  return await invoke<string[]>("get_startup_notices");
}

export async function updateStreamSettings(stream: StreamConfig): Promise<void> {
  return await invoke("update_stream_settings", { stream });
}

export async function updateRtspSettings(rtspServer: RtspServerConfig): Promise<void> {
  return await invoke("update_rtsp_settings", { rtspServer });
}

export async function updateCredentials(credentials: Credentials): Promise<void> {
  return await invoke("update_credentials", { credentials });
}

/** Persist the audio mute preference and apply it to live playback. */
export async function setAudioMuted(muted: boolean): Promise<void> {
  return await invoke("set_audio_muted", { muted });
}

// ── Network ─────────────────────────────────────────────────────────

export async function scanNetwork(subnet: string): Promise<ScanResult[]> {
  return await invoke<ScanResult[]>("scan_network", { subnet });
}

export async function listInterfaces(): Promise<InterfaceInfo[]> {
  return await invoke<InterfaceInfo[]>("list_interfaces");
}

export async function listVpnInterfaces(): Promise<InterfaceInfo[]> {
  return await invoke<InterfaceInfo[]>("list_vpn_interfaces");
}

export async function setStaticIp(
  name: string,
  ip: string,
  subnetMask: string,
  gateway: string | null = null
): Promise<void> {
  return await invoke("set_static_ip", { name, ip, subnetMask, gateway });
}

export async function addSecondaryIp(
  name: string,
  ip: string,
  subnetMask: string
): Promise<void> {
  return await invoke("add_secondary_ip", { name, ip, subnetMask });
}

export async function removeSecondaryIp(name: string, ip: string): Promise<void> {
  return await invoke("remove_secondary_ip", { name, ip });
}

/**
 * Switch the interface to DHCP. Clears static IPs, enables DHCP for IPv4
 * and DNS, and renews the lease. May trigger a UAC prompt.
 */
export async function setDhcp(name: string): Promise<void> {
  return await invoke("set_dhcp", { name });
}

/**
 * Look up the MAC currently bound to `ip` from the live ARP cache.
 * Returns null if the IP doesn't respond. Used by the cache verify
 * path to confirm the responder at a cached IP is the same physical
 * device (matching MAC), not an unrelated host that happens to share
 * the address today.
 */
export async function resolveMac(ip: string): Promise<string | null> {
  return await invoke<string | null>("resolve_mac", { ip });
}

/**
 * Reset an adapter to force Windows to re-probe the driver state.
 * `soft` uses ipconfig /release /renew (no admin); `hard` uses
 * Restart-NetAdapter (triggers UAC if not already elevated).
 */
export async function refreshAdapter(
  name: string,
  mode: "soft" | "hard"
): Promise<void> {
  return await invoke("refresh_adapter", { name, mode });
}

// ── ARP Discovery ───────────────────────────────────────────────────

export async function startArpDiscovery(iface: string): Promise<void> {
  return await invoke("start_arp_discovery", { interface: iface });
}

// ── Device Registry (canonical device list) ─────────────────────────

export async function getDeviceList(): Promise<DeviceRecord[]> {
  return await invoke<DeviceRecord[]>("get_device_list");
}

export async function reportScanResult(
  ip: string,
  openPorts: number[]
): Promise<void> {
  return await invoke("report_scan_result", { ip, openPorts });
}

export async function setDeviceAlias(ip: string, alias: string): Promise<void> {
  return await invoke("set_device_alias", { ip, alias });
}

export async function setDeviceStatus(
  mac: string,
  status: DeviceStatus
): Promise<void> {
  return await invoke("set_device_status", { mac, status });
}

export async function forgetDevice(mac: string): Promise<void> {
  return await invoke("forget_device", { mac });
}

/** Evict a phantom cached device (targeted verify found no open ports).
 *  The backend no-ops for aliased CAM/PTU, manual, and Live entries, so
 *  this is safe to call unconditionally on a failed verify. Returns true
 *  if a device was actually removed. */
export async function evictPhantomDevice(ip: string): Promise<boolean> {
  return await invoke<boolean>("evict_phantom_device", { ip });
}

/** Atomic adoption snapshot: routing map + per-subnet lifecycle
 *  metadata with backend-derived staleness. Replaced the plain
 *  subnet-to-IP getter — every consumer renders badges from the same
 *  pull now, so the two can't drift. */
export async function getAdoptionState(): Promise<AdoptionSnapshot> {
  return await invoke<AdoptionSnapshot>("get_adoption_state");
}

/** Remove an auto-adopted subnet: unbinds its secondary IP from the wired
 *  port and drops it from persisted config. Rejects (with a backend message)
 *  if the subnet isn't adopted or no interface is configured. */
export async function removeAdoptedSubnet(subnet: string): Promise<void> {
  return await invoke("remove_adopted_subnet", { subnet });
}

/** Listen for a Tauri event. Returns a Promise that resolves to the
 *  unlisten function (call to stop receiving). When running outside
 *  the Tauri shell (e.g. plain `vite dev`), returns a no-op unlisten. */
export function onEvent<T = unknown>(
  eventName: string,
  callback: (payload: T) => void
): Promise<() => void> {
  const listen = window.__TAURI__?.event?.listen;
  if (listen) {
    return listen<T>(eventName, (event) => callback(event.payload));
  }
  console.log(`[dev] onEvent: ${eventName} (no Tauri runtime)`);
  return Promise.resolve(() => {});
}

// ── Streaming ───────────────────────────────────────────────────────

export async function startStream(
  windowHandle: string | number | null = null
): Promise<void> {
  return await invoke("start_stream", {
    windowHandle:
      windowHandle == null
        ? null
        : typeof windowHandle === "number"
          ? windowHandle
          : parseInt(windowHandle, 10),
  });
}

export async function stopStream(): Promise<void> {
  return await invoke("stop_stream");
}

export async function startRtspServer(): Promise<RtspServerInfo> {
  return await invoke<RtspServerInfo>("start_rtsp_server");
}

export async function stopRtspServer(): Promise<void> {
  return await invoke("stop_rtsp_server");
}

export async function takeScreenshot(): Promise<string> {
  return await invoke<string>("take_screenshot");
}

export async function createVideoWindow(
  x: number,
  y: number,
  width: number,
  height: number
): Promise<string> {
  return await invoke<string>("create_video_window", { x, y, width, height });
}

export async function updateVideoPosition(
  x: number,
  y: number,
  width: number,
  height: number
): Promise<void> {
  return await invoke("update_video_position", { x, y, width, height });
}

export async function setVideoVisible(visible: boolean): Promise<void> {
  return await invoke("set_video_visible", { visible });
}

export async function startRecording(): Promise<void> {
  return await invoke("start_recording");
}

export async function stopRecording(): Promise<string> {
  return await invoke<string>("stop_recording");
}

// ── FLIR PTU ────────────────────────────────────────────────────────

export async function ptuSend(
  ip: string,
  cmd: string
): Promise<Record<string, string>> {
  return await invoke<Record<string, string>>("ptu_send", { ip, cmd });
}

/** Open a discovered device's web UI in the system browser. Backend
 *  validates the IP against the known-device set and only ever opens
 *  `http://<ip>` — the webview no longer holds a shell-open capability. */
export async function openDeviceBrowser(ip: string): Promise<void> {
  return await invoke("open_device_browser", { ip });
}

// ── Camera / PTZ ────────────────────────────────────────────────────
//
// The generic ONVIF / multi-vendor camera surface below (discoverOnvif,
// ptzMove/Stop/GotoPreset/SetPreset, sonyCgiZoom, controlCgiProbeStatus)
// is intentionally retained but not yet wired to any UI. The live camera
// path today is FLIR PTU (ptuSend) plus EV-7520 zoom (controlCgiZoomDirect
// / setZoomPosition). These wrappers stay so a future ONVIF/multi-camera
// impl lands without a frontend churn pass; keep them in sync with their
// Rust commands during the IPC drift audit.

/** ONVIF discovery currently returns Err("not yet implemented") —
 *  the wrapper is kept so a future ONVIF impl can land without a
 *  frontend churn pass. */
export async function discoverOnvif(subnet: string | null = null): Promise<unknown> {
  return await invoke("discover_onvif", { subnet });
}

export async function ptzMove(
  cameraUrl: string,
  pan: number,
  tilt: number,
  zoom: number
): Promise<void> {
  return await invoke("ptz_move", { cameraUrl, pan, tilt, zoom });
}

export async function ptzStop(cameraUrl: string): Promise<void> {
  return await invoke("ptz_stop", { cameraUrl });
}

export async function ptzGotoPreset(cameraUrl: string, preset: number): Promise<void> {
  return await invoke("ptz_goto_preset", { cameraUrl, preset });
}

export async function ptzSetPreset(
  cameraUrl: string,
  preset: number,
  name: string
): Promise<void> {
  return await invoke("ptz_set_preset", { cameraUrl, preset, name });
}

export async function sonyCgiZoom(
  ip: string,
  zoomSpeed: number,
  username: string,
  password: string
): Promise<void> {
  return await invoke("sony_cgi_zoom", { ip, zoomSpeed, username, password });
}

export async function controlCgiZoomDirect(
  ip: string,
  position: number
): Promise<void> {
  return await invoke("control_cgi_zoom_direct", { ip, position });
}

export async function controlCgiProbeStatus(ip: string): Promise<string> {
  return await invoke<string>("control_cgi_probe_status", { ip });
}

export async function setZoomPosition(
  cameraIp: string,
  percent: number
): Promise<void> {
  return await invoke("set_zoom_position", { cameraIp, percent });
}

// ── Network mode + manual nodes ─────────────────────────────────────

export async function getNetworkMode(): Promise<NetworkMode> {
  return await invoke<NetworkMode>("get_network_mode");
}

export async function setNetworkMode(mode: NetworkMode): Promise<void> {
  return await invoke("set_network_mode", { mode });
}

export async function addManualNode(ip: string, alias: string): Promise<void> {
  return await invoke("add_manual_node", { ip, alias });
}

export async function removeManualNode(ip: string): Promise<void> {
  return await invoke("remove_manual_node", { ip });
}

export async function clearManualNodes(): Promise<void> {
  return await invoke("clear_manual_nodes");
}
