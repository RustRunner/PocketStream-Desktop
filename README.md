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
- TCP port scanning of discovered hosts (RTSP, HTTP, SSH, and common camera ports)
- Automatic subnet adoption when cameras are on non-native networks
- Node aliasing with role assignment (CAM, PTU, or custom names)

### Video Streaming & Recording
- Low-latency RTSP and UDP playback via GStreamer
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

### PTZ Camera Control (Still in Development)
- FLIR PTU control via directional D-pad with hold-to-move
- Automatic speed limit negotiation with the pan-tilt unit
- Homing with position convergence detection
- Four configurable presets (long-press to save, tap to recall)

## System Requirements

- Windows 10/11
- Ethernet (for direct camera connection)
- IP camera configured for static IP (program can detect a previous DHCP lease if it persists on the camera)
- [Npcap](https://npcap.com/#download) (bundled installer included for device discovery)
- GStreamer runtime (bundled with the application)

## Installation

Download the latest installer from [Releases](https://github.com/RustRunner/PocketStream-Desktop/releases). The NSIS installer includes all required GStreamer libraries. Npcap is installed separately on first launch if not already present.

## Updater

An updater is configured that checks GitHub releases. The GUI shows an Install/Later notification when an update is found.

## Build from Source

### Prerequisites

- [Node.js](https://nodejs.org/) 20+
- [Rust](https://rustup.rs/) toolchain
- GStreamer development libraries (place in `resources/gstreamer/`)
- Npcap SDK

### Build

```bash
npm install
npx tauri build
```

The installer will be generated in `src-tauri/target/release/bundle/nsis/`.

## Architecture

| Layer | Technology | Role |
|-------|-----------|------|
| Frontend | HTML/JS + Material Web | UI, settings, device list |
| Backend | Rust + Tauri 2 | Streaming, network ops, camera control |
| Video | GStreamer | RTSP/UDP playback, recording, re-streaming |
| Network | pcap + pnet | ARP discovery, interface management |
| Crypto | AES-256-GCM | Credential encryption at rest |

## Licensing

Licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).

Third-party libraries used under Apache 2.0, MIT, and LGPL-2.1+ licenses.
