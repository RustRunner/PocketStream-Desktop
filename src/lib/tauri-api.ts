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

import type { DeviceTarget } from "./store.ts";

import type {
  AdapterSelection,
  AddressReply,
  AdoptionSnapshot,
  ModeTransition,
  ModeTransitionReply,
  AppSettings,
  CaptureState,
  Credentials,
  DeviceRecord,
  InterfaceInfo,
  HostIpOwner,
  LicenseDocumentId,
  NetworkMode,
  RestreamOperationResult,
  RestreamProtocol,
  RestreamServerInfo,
  RestreamSettingsUpdate,
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

// ── Licensing ───────────────────────────────────────────────────────

export async function getLicenseDocument(id: LicenseDocumentId): Promise<string> {
  return await invoke<string>("get_license_document", { id });
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

export async function applyRestreamSettings(
  update: RestreamSettingsUpdate
): Promise<RestreamOperationResult> {
  return await invoke<RestreamOperationResult>("apply_restream_settings", { update });
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

export async function getHostIpOwners(): Promise<HostIpOwner[]> {
  return await invoke<HostIpOwner[]>("get_host_ip_owners");
}

export async function getAdapterSelection(): Promise<AdapterSelection> {
  return await invoke<AdapterSelection>("get_adapter_selection");
}

export async function selectAdapter(mac: string): Promise<AdapterSelection> {
  return await invoke<AdapterSelection>("select_adapter", { mac });
}

export async function listVpnInterfaces(): Promise<InterfaceInfo[]> {
  return await invoke<InterfaceInfo[]>("list_vpn_interfaces");
}

export async function addSecondaryIp(
  name: string,
  ip: string,
  subnetMask: string
): Promise<AddressReply> {
  return await invoke("add_secondary_ip", { name, ip, subnetMask });
}

export async function removeSecondaryIp(name: string, ip: string, primary = false): Promise<AddressReply> {
  return await invoke("remove_secondary_ip", { name, ip, primary });
}

export async function getDhcpState(name: string): Promise<boolean> {
  return await invoke<boolean>("get_dhcp_state", { name });
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

export async function getCaptureState(): Promise<CaptureState> {
  return await invoke<CaptureState>("get_capture_state");
}

export async function startArpDiscovery(iface: string, refresh = false): Promise<void> {
  return await invoke("start_arp_discovery", { interface: iface, refresh });
}

// ── Device Registry (canonical device list) ─────────────────────────

export async function getDeviceList(): Promise<DeviceRecord[]> {
  return await invoke<DeviceRecord[]>("get_device_list");
}

export async function setDeviceAlias(key: string, alias: string): Promise<DeviceRecord[]> {
  return await invoke<DeviceRecord[]>("set_device_alias", { key, alias });
}

export async function forgetDevice(mac: string): Promise<void> {
  return await invoke("forget_device", { mac });
}

/** Atomic adoption snapshot: routing map + per-subnet lifecycle
 *  metadata with backend-derived staleness. Replaced the plain
 *  subnet-to-IP getter — every consumer renders badges from the same
 *  pull now, so the two can't drift. */
export async function getAdoptionState(): Promise<AdoptionSnapshot> {
  return await invoke<AdoptionSnapshot>("get_adoption_state");
}

/** Save removal intent before unbinding the exact saved address on its
 *  owning adapter. Failure remains pending and is retried on adapter return. */
export async function removeAdoptedSubnet(subnet: string, ifaceHint?: string): Promise<AddressReply> {
  return await invoke("remove_adopted_subnet", { subnet, ifaceHint });
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

export async function reassertPlayback(): Promise<void> {
  return await invoke("retry_playback", { manual: false });
}

export async function stopStream(): Promise<void> {
  return await invoke("stop_stream");
}

export async function startRestreamServer(): Promise<RestreamServerInfo> {
  return await invoke<RestreamServerInfo>("start_restream_server");
}

export async function stopRestreamServer(): Promise<void> {
  return await invoke("stop_restream_server");
}

export async function switchRestreamProtocol(
  protocol: RestreamProtocol
): Promise<RestreamOperationResult> {
  return await invoke<RestreamOperationResult>("switch_restream_protocol", { protocol });
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
  cmd: string,
  target: DeviceTarget
): Promise<Record<string, string>> {
  return await invoke<Record<string, string>>("ptu_send", { target: { ip, key: target.key, expected_mac: target.expectedMac }, cmd });
}

/** Open the verified Ethernet device's actual IP; PC address conflicts are
 *  reported as errors so the user can correct the network configuration. */
export async function openDeviceBrowser(ip: string, target: DeviceTarget): Promise<void> {
  return await invoke("open_device_browser", { target: { ip, key: target.key, expected_mac: target.expectedMac } });
}

// ── Camera / PTZ ────────────────────────────────────────────────────
export async function controlCgiZoomDirect(
  ip: string,
  position: number,
  target: DeviceTarget
): Promise<void> {
  return await invoke("control_cgi_zoom_direct", { target: { ip, key: target.key, expected_mac: target.expectedMac }, position });
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

export async function setNetworkMode(request: ModeTransition): Promise<ModeTransitionReply> {
  return await invoke<ModeTransitionReply>("set_network_mode", { request });
}

export async function addManualNode(ip: string, alias: string, expectedMac: string | null = null): Promise<void> {
  return await invoke("add_manual_node", { ip, alias, expectedMac });
}

export async function removeManualNode(ip: string, expectedMac: string | null): Promise<void> {
  return await invoke("remove_manual_node", { ip, expectedMac });
}

export async function clearManualNodes(): Promise<void> {
  return await invoke("clear_manual_nodes");
}
