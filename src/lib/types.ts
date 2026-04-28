/**
 * Shapes mirrored from the Rust IPC contract. Each interface here
 * corresponds to a struct in `src-tauri/src/` that is sent across the
 * Tauri boundary.
 *
 * Drift discipline: when changing a Rust struct that crosses IPC, also
 * update the matching interface here. There is no auto-generation today
 * — the trade-off is that this file is hand-maintained but stays
 * dependency-free (no `ts-rs` build step). If drift becomes a recurring
 * source of bugs, revisit by adding `ts-rs` to the workspace.
 *
 * Field naming follows the on-the-wire JSON shape (snake_case),
 * matching serde's default for Rust struct field serialization.
 */

// ── Device registry (network/device_registry.rs) ─────────────────────

/** User-visible reachability status of a device record.
 *  Wire shape uses snake_case via `#[serde(rename_all = "snake_case")]`. */
export type DeviceStatus = "live" | "verifying" | "offline" | "cached_only";

/** Unified device record. Replaces the old split between ARP map +
 *  scan-result map + alias map + cache file rows. */
export interface DeviceRecord {
  mac: string;
  ip: string;
  subnet: string;
  open_ports: number[];
  alias: string;
  status: DeviceStatus;
  /** RFC3339 timestamp */
  first_seen: string;
  /** RFC3339 timestamp */
  last_seen: string;
}

// ── Network interface (network/interface.rs) ─────────────────────────

export interface IpInfo {
  address: string;
  /** CIDR prefix length, e.g. 24 for /24 */
  prefix: number;
  subnet: string;
}

export interface InterfaceInfo {
  name: string;
  display_name: string;
  ips: IpInfo[];
  mac: string;
  is_up: boolean;
  is_ethernet: boolean;
  is_wifi: boolean;
  is_vpn: boolean;
}

// ── Network scanner (network/scanner.rs) ─────────────────────────────

export interface ScanResult {
  ip: string;
  reachable: boolean;
  open_ports: number[];
}

// ── Config (config.rs) ───────────────────────────────────────────────

export interface StreamConfig {
  /** "rtsp" or "udp" */
  protocol: string;
  rtsp_port: number;
  rtsp_path: string;
  udp_port: number;
  camera_ip: string;
}

export interface RtspServerConfig {
  enabled: boolean;
  port: number;
  token: string;
  /** Empty string means bind to all interfaces */
  bind_interface: string;
}

export interface Credentials {
  username: string;
  password: string;
}

export interface CachedDevice {
  mac: string;
  ip: string;
  subnet: string;
  open_ports: number[];
  alias: string;
  /** RFC3339 timestamp */
  last_seen: string;
}

export interface AppSettings {
  stream: StreamConfig;
  rtsp_server: RtspServerConfig;
  credentials: Credentials;
  /** subnet (e.g. "192.168.1.0/24") -> adopted secondary IP */
  adopted_subnets: Record<string, string>;
  /** camera IP -> last zoom slider position (0..100) */
  zoom_positions: Record<string, number>;
}

// ── Streaming (streaming/mod.rs) ─────────────────────────────────────

export interface StreamStatus {
  playing: boolean;
  rtsp_server_running: boolean;
  rtsp_url: string | null;
  display_url: string | null;
  recording: boolean;
  uptime_secs: number;
  bandwidth_kbps: number;
  /** Friendly error string if the pipeline reported a problem */
  error: string | null;
}

export interface RtspServerInfo {
  rtsp_url: string;
  display_url: string;
}

// ── Errors (error.rs) ────────────────────────────────────────────────

/** Wire shape of `AppError`: every variant serializes via the custom
 *  Serialize impl as `{ kind, message }`. The `kind` discriminator is
 *  a stable string that frontend code can branch on; the `message` is
 *  the human-readable Display output. */
export interface TypedAppError {
  kind:
    | "Network"
    | "NpcapMissing"
    | "Stream"
    | "Config"
    | "Camera"
    | "Io"
    | "Serde";
  message: string;
}

// ── Tauri event payloads ─────────────────────────────────────────────

/** Payload for the `device-list-changed` event emitted by
 *  DeviceListEmitter when the canonical device registry changes. */
export type DeviceListChangedPayload = DeviceRecord[];

/** Payload for the `stream-status` event emitted by the streaming
 *  status broadcaster on every change to the watch channel snapshot. */
export type StreamStatusPayload = StreamStatus;

/** Payload for the `subnet-adopted` event emitted by the network
 *  manager when a foreign-subnet auto-adoption completes. */
export interface SubnetAdoptedPayload {
  subnet: string;
  ip: string;
}

/** Payload for the `interface-status-changed` event emitted by the
 *  Windows NotifyIpInterfaceChange watcher (or pnet poller fallback). */
export interface InterfaceStatusChangedPayload {
  iface: InterfaceInfo | { name: ""; ips: [] };
  was_down: boolean;
}
