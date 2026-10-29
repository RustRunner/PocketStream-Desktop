# Development

[Back to the README](../README.md)

## Build from source

### Prerequisites

- Windows 11 with the [Tauri Windows prerequisites](https://v2.tauri.app/start/prerequisites/#windows).
- [Node.js](https://nodejs.org/) 20+; the browser UI checks require 22+.
- The [Rust](https://rustup.rs/) toolchain for MSVC.
- GStreamer MSVC x86_64 runtime and development packages. The October 29 local development checkpoint used SDK 1.28.1; release bundles must still match [the pinned manifest](../scripts/gstreamer-manifest.psd1) (1.26.11). Set `GSTREAMER_1_0_ROOT_MSVC_X86_64` to the SDK root and add its `bin` directory to `PATH`.

### Build

Install JavaScript dependencies from the repository root:

```powershell
npm ci
```

Before packaging, follow the preparation steps in the [release workflow](../.github/workflows/release.yml):

- Stage the GStreamer runtime and pinned SRT dependency into `src-tauri/resources/gstreamer/` with [bundle-gstreamer.ps1](../scripts/bundle-gstreamer.ps1).
- Generate Rust dependency notices with `cargo about`, as shown in the workflow.
- Prepare the pinned installer prerequisite with [prepare-installer-prerequisites.ps1](../scripts/prepare-installer-prerequisites.ps1).
- Configure the updater signing variables shown in the workflow.

With those prerequisites in place, build from the repository root:

```powershell
npx tauri build -- --locked
```

The installer is generated in `src-tauri/target/release/bundle/nsis/`. The release workflow also runs verification and creates a draft GitHub release.

## Tests

```bash
npm test
npm run typecheck
```

`npm test` runs every frontend regression test in `tests/`. CI and release checks run the same command.

`npm run check:ui` checks the real HTML/CSS and sidebar/toast handlers in an isolated headless Edge, Chrome, or Chromium profile. It verifies sidebar movement and rotation, reduced motion, and repeated clicks while a toast is visible at 1280×800 and the minimum 960×600 window size. It runs in CI and the full local `scripts/check.ps1` check, and requires Node.js 22+; set `BROWSER_EXECUTABLE` if the browser is installed elsewhere. Screenshots and results are written to `src-tauri/target/ui-layout/`; native video actions are stubbed, so this check does not change the installed app or network configuration.

With the frontend built and the GStreamer SDK's `bin` directory on `PATH`, run `cargo test --lib --locked` from `src-tauri/`. Windows development and test executables embed their Common Controls manifest during linking; no manual executable patch is needed. Leave `POCKETSTREAM_RELEASE` unset for development and tests. Release packaging sets it to `1` to request administrator access.

`npm run check:contracts` also checks the application IPC allowlist and pinned installer source contract. `npm run check:installer:generated` inspects and trace-compiles the generated NSIS script after a package build without executing it. The supported wrapper convention is documented with the [v2-A.1 qualification evidence](runtime-evidence/privilege-v2-a1.md). Run the isolated native dialog bridge fixture with `cargo run --example acl_native_smoke --locked` from `src-tauri/`; it cancels only its own dialogs and does not initialize networking. Use a 45-second outer process bound when running this GUI fixture under automation.

### Discovery performance baseline

[The fixed local-build 0.6.16 baseline](../benchmarks/discovery-baseline.json) is the comparison point for future discovery changes, including public release v0.6.8. The local test-build numbers are retained as measurement provenance. Its hardware timings come from the successful 0.6.14 watch on October 27, 2026; the discovery implementation is unchanged in 0.6.16. [The retained diagnostic extract](../tests/fixtures/discovery-reference-0.6.14.json) records the measurement provenance. These are log event timings from one run, not rendered-frame timings or a statistical percentile.

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

## Release qualification

The 46-command contract now includes `list_bind_interfaces`. [Earlier application/hardware smoke](runtime-evidence/privilege-v2-a2.md) remains tied to its recorded artifacts. The [firewall/install/binding integration checkpoint](runtime-evidence/privilege-v2-a3.md) implements program-scoped policy, fixed maintenance, guarded in-place installation, stable binding selection and truthful status. The [historical qualification](runtime-evidence/privilege-v2-final-qualification.md) records 28 passing native Sandbox scenarios against its exact images. The [development checkpoint](runtime-evidence/privilege-v2-development-checkpoint.md) preserves later installer fixes, attributed hardware observations, listener fixture corrections, failures and restoration. Full A4 qualification was stopped at the operator's request. The original sequencing exception and release requirements remain in the [release procedure](runtime-evidence/privilege-v2-release-qualification.md). A4 and overall qualification remain incomplete.

Unreleased Revision 6-B work on the local development branch adds shared runtime components behind explicit test-build features. Frozen B-S3 staging and hash/ACL readback are complete, but neither desktop session ran. Desktop/UAC cases, remaining native capture/provider/recovery/update qualification, and the pinned release closure remain pending. Production routing and manifest demotion remain gated; release builds still request administrator access, so renderer/media compromise still compromises an elevated host.

## Architecture

| Layer | Technology | Role |
|-------|-----------|------|
| Frontend | HTML + TypeScript (vanilla) | UI, settings, device list |
| Backend | Rust + Tauri 2 | Streaming, network ops, camera control |
| Video | GStreamer | RTSP/UDP playback, recording, RTSP/SRT re-streaming |
| Network | PacketMonitor API + pnet | ARP discovery, interface management |
| Crypto | AES-256-GCM | Credential encryption at rest |

See [runtime ownership](architecture/ownership.md) for the backend's component boundaries.
