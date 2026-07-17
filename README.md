# PocketStream Desktop

**PocketStream Desktop** is a Windows application for IP camera monitoring, network discovery, and RTSP re-streaming. Built with Tauri and Rust, it transforms a laptop or workstation into a portable video relay station with automatic device detection and pan-tilt-zoom control.

Based on [PocketStream for Android](https://github.com/RustRunner/PocketStream).

## Core Capabilities

The application supports two primary streaming modes:

**Mode A (RTSP Input):** Compatible with modern cameras including Amcrest, Hikvision, and Dahua models, requiring standard RTSP credential configuration.

**Mode B (UDP Input):** Designed for legacy hardware or cameras that push video directly to the device via UDP protocol.

## Key Features

### Automatic Device Discovery
- ARP-based device detection on the Ethernet interface — no manual IP entry required
- Self-healing packet capture: a session that starts deaf is restarted and escalated automatically before discovery is ever reported degraded
- Known cameras are re-discovered actively — cached devices are verified on-wire by MAC and their subnets adopted in seconds, without waiting for the camera's own broadcasts
- TCP port scanning of discovered hosts (RTSP, HTTP, SSH, and common camera ports)
- Automatic subnet adoption when cameras are on non-native networks, gated on a repeat ARP observation; stale link-local adoptions are reaped automatically
- Node role assignment — a single CAM and a single PTU, enforced with safe role handoff

### Video Streaming & Recording
- Low-latency RTSP and UDP playback via GStreamer
- G.711 camera audio playback with a persistent mute control
- Screenshot capture to Pictures directory
- MP4 recording with one-click start/stop
- Stream health monitoring with user-friendly error messages

### RTSP Re-Streaming Server
- Token-protected RTSP server for sharing the camera feed over the network
- Bind to local network IP or VPN IP
- QR code generation for easy client connection
- Bandwidth and uptime monitoring

### Network Management
- Static IP assignment and secondary IP management on Ethernet interfaces
- Auto-detection of interface status changes (zero network overhead)
- VPN interface enumeration for secure remote streaming
- Automatic Windows Firewall rule management for the RTSP server

### PTZ Camera Control
- FLIR PTU control via directional D-pad with hold-to-move
- Automatic speed limit negotiation with the pan-tilt unit
- Homing with position convergence detection
- Four configurable presets (long-press to save, tap to recall)

## System Requirements

- Windows 10/11
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

## Architecture

| Layer | Technology | Role |
|-------|-----------|------|
| Frontend | HTML + TypeScript (vanilla) | UI, settings, device list |
| Backend | Rust + Tauri 2 | Streaming, network ops, camera control |
| Video | GStreamer | RTSP/UDP playback, recording, re-streaming |
| Network | PacketMonitor API + pnet | ARP discovery, interface management |
| Crypto | AES-256-GCM | Credential encryption at rest |

## Licensing

Licensed under the [GNU General Public License v3.0 only](https://www.gnu.org/licenses/gpl-3.0.html) (SPDX: `GPL-3.0-only`) — see [LICENSE](LICENSE).

Third-party components:

- The Windows installer bundles the GStreamer MSVC runtime (LGPL-2.1+, plus the GPL-2.0+ x264 encoder) and supporting libraries. Complete notices and license texts ship with every install under `resources\licenses\` and are viewable in-app (About → Licenses & Notices).
- Corresponding source for all LGPL/GPL components — including the build recipes used to produce the binaries — is published at the [gst-src-1.26.11 release](https://github.com/RustRunner/PocketStream-Desktop/releases/tag/gst-src-1.26.11) and mirrored for each pinned GStreamer version.
- Notices for the Rust crates compiled into the executable are generated at release time and installed as `resources\licenses\generated\THIRD-PARTY-RUST.md`.
