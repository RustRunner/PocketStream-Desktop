# PocketStream Desktop

**PocketStream Desktop** is a Tauri/Rust Windows application for field camera work. It discovers IP cameras on the selected Ethernet adapter, including cameras that retain an old DHCP address on another subnet, plays and records their RTSP/UDP streams, re-serves them over RTSP or SRT, and drives FLIR pan-tilt units. Cameras using APIPA (169.254.0.0/16) must first be configured with a usable non-APIPA address using their vendor's tools.

Based on [PocketStream for Android](https://github.com/RustRunner/PocketStream).

## Core Capabilities

The application supports two primary streaming modes:

**Mode A (RTSP Input):** Compatible with modern cameras including Amcrest, Hikvision, and Dahua models, requiring standard RTSP credential configuration.

**Mode B (UDP Input):** Designed for legacy hardware or cameras that push video directly to the device via UDP protocol.

Choose RTSP or SRT independently under **Output Protocol** for re-streaming. SRT input is not currently supported.

## Key Features

### Automatic Device Discovery
- ARP-based device detection on the Ethernet interface — no manual IP entry required
- Bounded packet-capture recovery, with a visible degraded status when capture uses a name match or an unscoped fallback
- Known cameras are re-discovered actively — cached devices require fresh verification on the selected Ethernet adapter by MAC, without waiting for the camera's own broadcasts
- TCP port scanning of discovered hosts (RTSP, HTTP, SSH, and common camera ports)
- Automatic subnet adoption for verified non-APIPA camera networks; committed host bindings persist across exit, adapter return and restart until explicitly removed
- Node role assignment — a single CAM and a single PTU, enforced with safe role handoff

### Video Streaming & Recording
- Low-latency RTSP and UDP playback via GStreamer
- Camera RTSP connections use the verified Ethernet adapter and source address, including when Wi-Fi has an overlapping subnet
- G.711 camera audio playback with a persistent mute control
- Screenshot capture to Pictures directory
- MP4 recording with one-click start/stop
- Stream health monitoring with user-friendly error messages

### RTSP / SRT Re-Streaming Server
- Token-protected RTSP server for sharing the camera feed over the network
- SRT listener with configurable port, latency, Stream ID and optional passphrase encryption, supporting up to 10 callers
- With Bind set to **All addresses**, the displayed URL prefers an active physical Wi-Fi address, then Ethernet; camera-adopted addresses are excluded
- Selecting an eligible Ethernet, Wi-Fi or VPN interface binds to its current address and preserves its stable GUID
- QR code generation for easy client connection
- Bandwidth and uptime monitoring

### Network Management
- Static IP assignment and secondary IP management on Ethernet interfaces
- Address removal and DHCP changes wait for the native confirmation dialog
- Auto-detection of interface status changes (zero network overhead)
- Host link status refreshes when Windows reports the change; Ethernet hardware negotiation can still take several seconds
- PC/device IP conflicts identify the owning adapter and explain how to restore browser access
- Physical and VPN binding choices, separate from the full wildcard IPv4 inventory
- Program-scoped RTSP/SRT Windows rules, preserved block policy, and separate binding/firewall status

All APIPA Nodes are hidden, including historical entries. Saved APIPA host addresses and stored node history are retained. Removing a Node does not remove a host binding. See [reliability release notes](RELEASE-NOTES.md) for binding lifetime, rollback limitations and pending hardware qualification.

If a camera shares the PC's Wi-Fi IP, turning off the Wi-Fi radio may leave Windows reserving that address. An **IP still reserved by PC** warning identifies this case. To reach the camera's web page, open Network Connections (`Win+R` → `ncpa.cpl`) and fully disable the named adapter. Give the camera an unused IP, then re-enable the adapter. PocketStream refreshes the warning automatically and checks the current address ownership and Ethernet route when opening a device page.

### PTZ Camera Control
- FLIR PTU control via directional D-pad with hold-to-move
- Automatic speed limit negotiation with the pan-tilt unit
- Homing with position convergence detection
- Four configurable presets (long-press to save, tap to recall)

## System Requirements

- Windows 11
- Ethernet (for direct camera connection)
- IP camera configured for static IP (program can detect a previous DHCP lease if it persists on the camera)
- GStreamer runtime (bundled with the application)

Device discovery uses the in-box Windows PacketMonitor API — no separate capture driver to install.

## Installation

Download the latest installer from [Releases](https://github.com/RustRunner/PocketStream-Desktop/releases). The NSIS installer includes all required GStreamer libraries. Device discovery uses the OS-native PacketMonitor API, so there is no capture driver to install.

## Updater

An updater is configured that checks GitHub releases. The GUI shows an Install/Later notification when an update is found.

## Build from Source

### Prerequisites

- [Node.js](https://nodejs.org/) 20+
- [Rust](https://rustup.rs/) toolchain
- GStreamer development libraries (place in `resources/gstreamer/`)

### Build

```bash
npm install
npx tauri build
```

The installer will be generated in `src-tauri/target/release/bundle/nsis/`.

### Tests

```bash
npm test
npm run typecheck
```

`npm test` runs every frontend regression test in `tests/`. CI and release checks run the same command.

`npm run check:ui` checks the real HTML/CSS and sidebar/toast handlers in an isolated headless Edge, Chrome, or Chromium profile. It verifies sidebar movement and rotation, reduced motion, and repeated clicks while a toast is visible at 1280×800 and the minimum 960×600 window size. It runs in CI and the full local `scripts/check.ps1` check, and requires Node.js 22+; set `BROWSER_EXECUTABLE` if the browser is installed elsewhere. Screenshots and results are written to `src-tauri/target/ui-layout/`; native video actions are stubbed, so this check does not change the installed app or network configuration.

With the frontend built and the GStreamer SDK's `bin` directory on `PATH`, run `cargo test --lib --locked` from `src-tauri/`. Windows development and test executables embed their Common Controls manifest during linking; no manual executable patch is needed. Leave `POCKETSTREAM_RELEASE` unset for development and tests. Release packaging sets it to `1` to request administrator access.

`npm run check:contracts` also checks the application IPC allowlist and pinned installer source contract. `npm run check:installer:generated` inspects and trace-compiles the generated NSIS script after a package build without executing it. The supported wrapper convention is documented with the [v2-A.1 qualification evidence](docs/runtime-evidence/privilege-v2-a1.md). Run the isolated native dialog bridge fixture with `cargo run --example acl_native_smoke --locked` from `src-tauri/`; it cancels only its own dialogs and does not initialize networking. Use a 45-second outer process bound when running this GUI fixture under automation.

The 46-command contract now includes `list_bind_interfaces`. [Earlier application/hardware smoke](docs/runtime-evidence/privilege-v2-a2.md) remains tied to its recorded artifacts. The [firewall/install/binding integration checkpoint](docs/runtime-evidence/privilege-v2-a3.md) implements program-scoped policy, fixed maintenance, guarded in-place installation, stable binding selection and truthful status. The [historical qualification](docs/runtime-evidence/privilege-v2-final-qualification.md) records 28 passing native Sandbox scenarios against its exact images. The [development checkpoint](docs/runtime-evidence/privilege-v2-development-checkpoint.md) preserves later installer fixes, attributed hardware observations, listener fixture corrections, failures and restoration. Full A4 qualification was stopped at the operator's request. The original sequencing exception and release requirements remain in the [release procedure](docs/runtime-evidence/privilege-v2-release-qualification.md). A4 and overall qualification remain incomplete. v2-B is deferred, and release builds still request administrator access: renderer/media compromise still compromises an elevated host.

#### Discovery performance baseline

[The fixed local-build 0.6.16 baseline](benchmarks/discovery-baseline.json) is the comparison point for future discovery changes, including public release v0.6.8. The local test-build numbers are retained as measurement provenance. Its hardware timings come from the successful 0.6.14 watch on October 27, 2026; the discovery implementation is unchanged in 0.6.16. [The retained diagnostic extract](tests/fixtures/discovery-reference-0.6.14.json) records the measurement provenance. These are log event timings from one run, not rendered-frame timings or a statistical percentile.

| Device | First observed | Subnet ready | Ports ready | Maximum ports-ready time |
|---|---:|---:|---:|---:|
| Camera, 172.31.169.84 | 3s | 18s | 21s | 26s |
| Unidentified peer, 192.168.1.74 | 7s | 46s | 48s (scan completed, no ports) | 53s |
| PTU, 192.168.1.202 | 49s | 46s | 51s | 56s |

Every milestone has a five-second allowance over its recorded value. Each IP's scan must start within two seconds after both the device and its route are ready. The three-minute observation must contain both successful adoptions, all required device/port results, and zero link drops, offline transitions, application restarts, or warnings/errors. A missing PTU, partial result, repeat-adoption loop, or incomplete recording fails. An isolated unanswered ARP probe does not fail if presence remains stable.

For comparable hardware checks, use the same host, 100 Mbps Ethernet link and camera/PTU unit, Static–Auto mode, and primary `192.168.0.100/24`. Remove the adopted secondary addresses through IP Configuration, retain cached identities, and let the app listen before inserting the cable. Leave it connected for at least three minutes without manual scans or extra probe tools. Supply the full app log, including its startup/version line, and the exact selected-adapter `event=ethernet_link ... link_up=true` timestamp:

```powershell
npm.cmd run check:performance -- --log "$env:LOCALAPPDATA\PocketStream\logs\pocketstream.log" --link-up "YYYY-MM-DD HH:mm:ss" --output src-tauri/target/discovery-performance.json
```

Run three comparable connection attempts when qualifying discovery/network changes; each attempt must pass rather than averaging away failures. The checker only reads logs. `npm run check:performance -- --reference` replays the committed good capture to validate the checker; it does **not** measure new software on hardware. CI also runs negative log cases, paused-clock Rust readiness budgets, and real renderer workflow tests that enforce independent scans, stable ordering and auto tags. Hardware latency still needs the connection procedure above. Keep the baseline fixed across versions; changing a limit requires an explanation and fresh comparable evidence in the review.

## Architecture

| Layer | Technology | Role |
|-------|-----------|------|
| Frontend | HTML + TypeScript (vanilla) | UI, settings, device list |
| Backend | Rust + Tauri 2 | Streaming, network ops, camera control |
| Video | GStreamer | RTSP/UDP playback, recording, RTSP/SRT re-streaming |
| Network | PacketMonitor API + pnet | ARP discovery, interface management |
| Crypto | AES-256-GCM | Credential encryption at rest |

## Licensing

Licensed under the [GNU General Public License v3.0 only](https://www.gnu.org/licenses/gpl-3.0.html) (SPDX: `GPL-3.0-only`) — see [LICENSE](LICENSE).

Third-party components:

- The Windows installer bundles the GStreamer MSVC runtime (LGPL-2.1+, plus the GPL-2.0+ x264 encoder) and supporting libraries. Complete notices and license texts ship with every install under `resources\licenses\` and are viewable in-app (About → Licenses & Notices).
- Corresponding source for all LGPL/GPL components — including the build recipes used to produce the binaries — is published at the [gst-src-1.26.11 release](https://github.com/RustRunner/PocketStream-Desktop/releases/tag/gst-src-1.26.11) and mirrored for each pinned GStreamer version.
- Notices for the Rust crates compiled into the executable are generated at release time and installed as `resources\licenses\generated\THIRD-PARTY-RUST.md`.
