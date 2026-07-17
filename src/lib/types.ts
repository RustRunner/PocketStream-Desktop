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

// ── Network mode + manual nodes (config.rs) ──────────────────────────

/** User's chosen network mode. Drives which discovery subsystems run.
 *  Wire shape uses snake_case via `#[serde(rename_all = "snake_case")]`
 *  on the Rust enum. */
export type NetworkMode = "dhcp" | "static_auto" | "static_manual";

/** User-pinned device for `NetworkMode = "static_manual"`. Persists
 *  across mode toggles. */
export interface ManualNode {
  ip: string;
  alias: string;
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
  /** OS-reported virtual adapter (Hyper-V/WSL vEthernet, VMware/VirtualBox
   *  host adapters, most VPN tunnels). Distinct from is_vpn: a keyword-missed
   *  virtual adapter is still excluded from wired camera-port discovery. */
  is_virtual: boolean;
}

// ── Network scanner (network/scanner.rs) ─────────────────────────────

export interface ScanResult {
  ip: string;
  reachable: boolean;
  open_ports: number[];
}

// ── Config (config.rs) ───────────────────────────────────────────────

/** Camera input protocol. Mirrors the Rust `StreamProtocol` enum, which
 *  rejects any other value at the IPC boundary. */
export type StreamProtocol = "rtsp" | "udp";

export interface StreamConfig {
  protocol: StreamProtocol;
  rtsp_port: number;
  rtsp_path: string;
  udp_port: number;
  camera_ip: string;
  /** Audio mute preference; false = audio plays when a stream carries
   *  a supported track. Required so every StreamConfig literal carries
   *  it — an omitted field would deserialize to false backend-side and
   *  silently unmute. */
  audio_muted: boolean;
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

/** Backend-owned adoption lifecycle metadata, keyed like
 *  `adopted_subnets`. The frontend never writes it — the backend
 *  preserves it across saves and the UI reads adoption state via
 *  `get_adoption_state` instead. */
export interface AdoptedMeta {
  /** RFC3339 wall time the subnet was adopted. */
  adopted_at: string | null;
  /** RFC3339 wall time of the last positive device evidence, or null. */
  last_device_seen: string | null;
}

export interface AppSettings {
  stream: StreamConfig;
  rtsp_server: RtspServerConfig;
  credentials: Credentials;
  /** subnet (e.g. "192.168.1.0/24") -> adopted secondary IP */
  adopted_subnets: Record<string, string>;
  /** subnet -> lifecycle metadata; backend-owned, see AdoptedMeta */
  adopted_meta: Record<string, AdoptedMeta>;
  /** camera IP -> last zoom slider position (0..100) */
  zoom_positions: Record<string, number>;
  /** User's chosen network mode. Drives ARP/auto-adopt subsystem
   *  gating; persists across sessions. */
  network_mode: NetworkMode;
  /** User-pinned nodes for Static — Manual mode. */
  manual_nodes: ManualNode[];
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
  /** True while the playback pipeline has a linked audio branch */
  audio_present: boolean;
  /** Last recognized audio codec; may be set with audio_present=false
   *  when the codec was recognized but skipped (no decoder) */
  audio_codec: string | null;
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
    | "DiscoveryUnavailable"
    | "Stream"
    | "Config"
    | "Camera"
    | "Io"
    | "Serde";
  message: string;
}

// ── Tauri event payloads ─────────────────────────────────────────────

/** Payload for the `arp-device-discovered` event emitted by the pcap
 *  ARP listener. Mirrors `network/arp.rs::ArpDevice`. */
export interface ArpDevicePayload {
  mac: string;
  ip: string;
  subnet: string;
  /** RFC3339 timestamp */
  first_seen: string;
  /** RFC3339 timestamp */
  last_seen: string;
}

/** Lifecycle metadata for one adopted subnet as the backend derives it
 *  (see Rust `AdoptedMetaView`). `stale` is computed backend-side from
 *  the same policy the removal pass uses; the frontend only renders. */
export interface AdoptedMetaView {
  /** RFC3339; null for entries recorded before metadata existed. */
  adopted_at: string | null;
  /** RFC3339; null until positive device evidence arrives. */
  last_device_seen: string | null;
  stale: boolean;
}

/** Atomic adoption snapshot (Rust `AdoptionSnapshot`): the routing map
 *  and per-subnet metadata taken together so they can't disagree. */
export interface AdoptionSnapshot {
  adopted_subnets: Record<string, string>;
  meta: Record<string, AdoptedMetaView>;
}

/** Payload for the `subnet-adopted` event emitted by the network
 *  manager when a foreign-subnet auto-adoption completes or a
 *  persisted adoption is restored at startup. The wire field is
 *  `adopted_ip` (not `ip`) — matches the JSON the backend builds via
 *  `serde_json::json!`. Carries the metadata view inline so listeners
 *  don't need a follow-up snapshot pull. */
export interface SubnetAdoptedPayload {
  subnet: string;
  adopted_ip: string;
  adopted_at: string | null;
  last_device_seen: string | null;
  stale: boolean;
}

/** Payload for the `subnet-removed` event: an adoption left backend
 *  state, either reaped by the lifecycle check (`stale_apipa`) or
 *  removed by the user (`manual`). One listener serves both so every
 *  surface follows backend state through the same path. */
export interface SubnetRemovedPayload {
  subnet: string;
  adopted_ip: string;
  reason: "stale_apipa" | "manual";
}

/** Payload for the `device-ping-result` event emitted by the ICMP
 *  pinger on every probe completion. Drives the green/red reachability
 *  dot in the Nodes panel. */
export interface DevicePingResultPayload {
  ip: string;
  reachable: boolean;
}

/** Payload for the `subnet-adopted` failure counterpart: an auto-adopt
 *  attempt failed and was put on a retry cooldown. Diagnostic — the loop
 *  retries with backoff on its own. */
export interface AdoptionFailedPayload {
  subnet: string;
  error: string;
}

/** Payload for the `adoption-started` / `adoption-finished` events. The
 *  backend brackets every auto-adoption with these — `adoption-finished`
 *  fires on success, failure, timeout, and shutdown alike, after a short
 *  settle covering the NIC watcher's ~300 ms debounce. `adoption_id` is an
 *  opaque monotonic token so a stale finish from a superseded adoption is
 *  told apart from the active one. */
export interface AdoptionLifecyclePayload {
  adoption_id: string;
}

/** Payload for the `discovery-degraded` event: the capture backend
 *  delivered no ARP payload events within the window after the provoking
 *  ping sweep. Diagnostic only — availability is never flipped on this. */
export interface DiscoveryDegradedPayload {
  /** Machine-readable cause; currently always "no-payload-events". */
  reason: string;
  /** Worst missed-packet count the capture ring reported (0 = none). */
  missed_packets: number;
}

/** The `discovery-recovered` event (empty payload) fires once after a
 *  `discovery-degraded` when the first ARP frame finally parses. */
export type DiscoveryRecoveredPayload = Record<string, never>;

/** Document ids accepted by `get_license_document`. Mirrors the fixed
 *  allowlist in `src-tauri/src/commands/mod.rs` — ids, not paths, are
 *  the IPC contract. */
export type LicenseDocumentId =
  | "app-license"
  | "third-party-notices"
  | "rust-crates"
  | "lgpl-2.1"
  | "lgpl-2.0"
  | "gpl-2.0"
  | "mit"
  | "bsd-3-clause"
  | "zlib"
  | "libpng"
  | "libjpeg-turbo"
  | "bzip2";
