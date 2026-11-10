# v0.6.10 re-stream release candidate

Date: 10 November 2026. R0 and S6-R only. Source verification, CI installer
production, installed/native qualification and public release are separate gates.
This note is the current candidate run sheet; historical results are not passes
for this artifact. Discovery/Clear/Refresh and privilege integration remain
separate work.

## Source and build identity

- Branch: `release/v0.6.10`, isolated at
  `C:\Users\joshu\PocketStream-Desktop\.worktrees\v0.6.10`, outside build outputs.
- Verified remote base: `922b41434bd16a76eedddace9cdf6bbb101e0901`, containing
  the complete firewall/topology/admission/status-retry/Enable chain and RTSP
  readiness correction. No feature subset was cherry-picked.
- Root remains `work/privilege-v2-b-r5` at `fd65b1d`; its README, DEVELOPMENT and
  images are unrelated and preserved. Existing worktrees are preserved.
- No applicable `AGENTS.md` was found in the repository, selected worktree or
  checked ancestor paths. Governing input is revision 1.4 of
  `Documents/Untracked/10NOV26-v0610-consolidated-delivery-spec.md`, with F/T/N/R/E
  and the existing [Windows release procedure](privilege-v2-release-qualification.md).
- Remote tags and releases were checked before changes: no `v0.6.10` existed.
  Existing tags must never move. A tag push is authorized only for an unpublished
  draft from the verified release commit. Publication and updater-feed edits are
  outside this task.
- Package/config/Cargo and both lockfile root versions: `0.6.10`. Used
  `scripts/bump-version.ps1`; Windows PowerShell 5.1 required a temporary copy of
  the identical UTF-8 script with a BOM. The copy was removed. Its `-NoCheck`
  deferred Cargo checking until frontend/runtime inputs were staged; the required
  Cargo check is run separately.
- Dependency change: `openssl 0.10.76 -> 0.10.80` requires
  `openssl-sys 0.9.112 -> 0.9.118`. No other dependency upgrade or new audit
  exception. npm also synchronized the root lockfile license metadata.
- Local SDK: existing isolated official GStreamer MSVC 1.26.11 development
  extraction under `src-tauri/target/privilege-v2-b/b2-integration/sdk/admin-image`.
  `pkg-config --modversion gstreamer-1.0` reports `1.26.11`; pkg-config SHA-256
  `34398823c5bb3f559e5312e7c48c87a94aa0ea6c3726dd390e90ca73a8a02970`.
  The installed development SDK is untouched.
- All 76 real bundled DLLs were independently checked against
  `scripts/gstreamer-manifest.psd1` before copying into this worktree. Runtime:
  GStreamer 1.26.11 / patched SRT 1.5.7. No runtime placeholders. Tests use this
  runtime first on PATH and isolate its plugins from system plugins.
- The minimal shipping bundle intentionally omits `videotestsrc`. A first full
  Rust attempt passed 929 tests and failed three playback fixtures for that
  missing test element. Preserved `release-rust-tests-shipping-plugins.log`.
  Extracted the test-only plugin as data with 7-Zip from the existing official
  runtime MSI, verified against SHA-256
  `31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605`.
  Plugin SHA-256:
  `66b291ab130fac7867978f2d5ac995e874f37fc3f4c3bd2f8b43fcd358665eb5`.
  It is in a separate ignored test directory, never in the shipping bundle.
  The full rerun passed at unchanged default concurrency. A separate launch
  attempt stopped on PowerShell 5.1's treatment of native stderr; its log is
  retained as `release-rust-tests-launch-error.log`.
- Local Node `24.14.0`, Rust `1.97.1`; CI uses the existing workflow toolchains
  and SHA-pinned runtime/development MSI inputs. Cargo uses the existing ignored
  target cache; no clean or deletion of historical evidence/worktrees.

## Verification

| Check | Observed result | Log / evidence |
| --- | --- | --- |
| Recorded main CI, run 42883086456 | Rechecked: Security Audit failed, other jobs passed; historical only | [Run](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42883086456) |
| Targeted dependency resolution | Only OpenSSL and its required sys crate updated | `release-cargo-check.log`, lockfile diff |
| Current `cargo audit`, same three existing explicit exceptions as CI | Passed; 0 blocking vulnerabilities. 12 unmaintained, 7 unsound and 1 yanked warnings remain; no new suppressions | `src-tauri/target/release-candidate/audit.json` |
| Locked npm installation | Passed | `release-npm-ci.log` |
| Frontend suite | Passed: 287 tests, 0 failed/skipped | `release-frontend-tests.log` |
| TypeScript | Passed | `release-typecheck.log` |
| Production frontend build, DOM/re-stream/IPC/installer/boundary contracts | Passed | `release-frontend-build.log` |
| Isolated browser UI, 1280x800 and 960x600 | Passed; native calls stubbed | `release-ui.log`, `src-tauri/target/ui-layout/` |
| Cargo check / version lock refresh | Passed | `release-cargo-check.log` |
| Full Rust suite, unchanged default concurrency | Passed: 932 tests, 0 failed, 14 ignored; 35.63s. Ignored native cases do not count as passes | `release-rust-tests.log` |
| Rust formatting / all-target Clippy, `-D warnings` | Passed | `release-fmt.log`, `release-clippy.log` |
| Third-party/source/native manifest policy | Passed: 76 locked DLLs, 23 components, 25 source assets | `release-third-party.log`, `release-source-policy.log`, `release-source-manifest.log`, `release-runtime-manifest.log` |
| Release workflow / draft / generated NSIS / installed G3 | Pending CI candidate | CI run and artifact identities to be appended here |

Routine logs above are ignored files in this worktree. CI evidence must identify
the exact pushed commit, run, draft release, installer, packaged executable and
updater signatures by SHA-256. A local build cannot replace the CI artifact.

## Installed/native run sheet

Host assignments follow the consolidated spec: Test = authorized
`DESKTOP-PI5BMJR`; Second = separately identified disposable Windows host; VM =
fresh isolated disposable Windows fixture; Peer = remote media client. Concrete
current identities, access, authorization and baseline snapshots are required
before each native run. Development PC is source/read-only only. Paused A4 and B
batches remain paused. Hardware/PTU movement requires the existing operator
procedure; no unattended motion is authorized.

Every pending row below has no new installed/native timing or log. Existing
28-case Sandbox, FLIR/PTU, G1/G2/G3 or source results remain attached to their
original hashes and do not qualify this candidate. R10 subcases retain Q's
requirements that are not covered by the headline R1-R9 scenarios.

| Case | Source requirements | Host | Candidate identity | Result / timing / evidence |
| --- | --- | --- | --- | --- |
| R1.1 / R1.2 | F hardware 1-2; Q package repair: actual 0.6.8 and 0.6.9 upgrades, both defective templates, empty Package/no AppPkgId, two repaired_template records, successful NSIS <=65s; first-ensure fallback repair | Test + Second, VM where supported | CI artifact pending | Pending fixture/access; capture predecessor and candidate hashes, baseline, journals and end state |
| R2 | F hardware 3; N: ten ensure/disable cycles with unchanged/custom ports; p50/p95/stages; Test ensure <=15s (goal 10), disable <=8s, startup <=12s, install <=35s; Second ensure <=5s/startup <=4s with capability comparison | Test + Second | CI artifact pending | Pending; unit-test durations provide no native timing credit |
| R3 | F 4-6; T/N/R: RTSP and SRT, default/custom ports, wildcard/explicit Wi-Fi, WFP permits/interface filters, OPTIONS 200 + >=150 H.264 buffers, SRT handshake/media; Stop removes filters/disables rules and prevents access | Test + Second + Peer | CI artifact pending | Pending; retain socket/rule/WFP/remote-client evidence and restore snapshots |
| R4 | F 7; R 3: authorized overriding Block survives install/ensure/Stop/uninstall; disabled/other-protocol observations remain cautious; remove fixture Block and Stop/Start restores media | Test + Second + Peer | CI artifact pending | Pending |
| R5 | F 8-9; N; R 2/4: fixed post-enable timeout proves actual write and contained/exited writer; successful settle, retained accounting/retry; double failure and failed recovery retain barrier; later qualified Stop retires exactly | Test + Second | Separately hashed qualification fault candidate plus CI normal candidate | Pending; never inject native faults on development PC; fixed test procedure is in firewall revision 3 note |
| R6 | F 10; N exit; Q startup: fixed one-shot failure settles/retries within original workflow; queued/admitted Stop/exit prevent obsolete Ensure; unresolved lease survives and reconciles next start | Test + Second | Fixed fault candidate / CI artifact | Pending |
| R7 | T hardware; R 4: 20 wildcard Start/Stop cycles per host, both protocols, unrelated churn, explicit bind camera churn, settled usable address change without duplicate rebuild; Stop/newer Start wins | Test + Second + Peer | CI artifact pending | Pending; retain listener/scope/rule/lease generations and churn records |
| R8 | N hardware; R 1: Start/Stop/retry under current real or qualified scratch contention; separate admission/native timing; User admission <=15s, saturation expires without delayed writes; early/late scratch cleanup and retained uncertainty | Test + Second | CI artifact / qualified controlled fixture | Pending; discovery contention is intentionally still present |
| R9 | E hardware: false config -> Enable -> Start without Save, both outputs; Disable while running waits/reports errors; preserve all drafts/secret intents; accepted flag persists after restart | Test + Peer | CI artifact pending | Pending; reuse matching R3 media evidence only |
| R10.1 | Q fresh/reinstall/upgrade/uninstall in interactive/passive/silent/updater modes; install without /R, correct disabled template shapes, maintenance before deletion, diagnostics on failure | Fresh VM + Test where required | CI artifact + independently hashed legacy installers | Pending fresh fixture; paused batches will not resume |
| R10.2 | Q legacy 0.6.7 migration/custom/duplicate/disabled/program-scoped rules; indistinguishable manual clone convention; foreign/unrecognized/colliding rules; repeated/partial recovery; exact preservation | Fresh VM | CI artifact / separately identified partial-provider fault build | Pending; actual partial-provider injection is distinct from a conflict or fake provider |
| R10.3 | Q strict malformed/unknown/unelevated/unprotected entry refusal, no GUI/profile/native writes; install gate/HostOwner Busy, cancel, file replacement/maintenance failure, every exit path and launch after release | Fresh VM | CI artifact pending | Pending; static/generated contracts are supporting evidence only |
| R10.4 | Q continuous ownership, legacy process/image-in-use refusal, no process kill/previous-uninstaller child, bootstrap-parent propagation, launch/finish timing and independent accounts/logon sessions | Full disposable Windows VM/Second | CI artifact pending | Pending; unsupported Sandbox cases remain pending |
| R10.5 | Q binding/settings: Wi-Fi/VPN/non-VPN virtual churn, IPv4 inventory vs native/listeners, failure -> Unknown -> recovery, stable GUID/alias/index/restart, reused/ambiguous legacy alias, failed-save migration, stale async races, QR exclusions | Test + Second + Peer | CI artifact pending | Pending; reuse R3/R7 only when artifact/config/observation matches |
| R10.6 | Q hardware: settings save/readback, both confirmation Cancels, selected-adapter proof and positive candidate ICMP, visible playback/recovery, PTU role/position/limits/presets/cold start and individually operator-confirmed directions/Home/stop, normal Close/restoration | Test + physical camera/PTU + operator | CI artifact pending | Pending hardware/operator; historical smoke does not qualify this image |
| R10.7 | Q existing resource gates: 20 cable cycles, 5 camera reboots, >=60 minutes representative playback/recording/relay, process-tree resources and notices; recovery/address/native postconditions applicable to this unchanged production path | Test + physical hardware/operator | CI artifact pending | Pending; discovery redesign/S-R2/B gates remain separate |
| R10.8 | Packaged runtime closure/import/plugin/source/G3 installed gate, generated installer trace, requireAdministrator/Common Controls manifests, staged-vs-packaged image identity, updater signature/public key and feed/version checks | CI + read-only development inspection; isolated installed update fixture | Exact CI artifact | Pending build/inspection; no public feed mutation or publication |

## Remaining gates and release state

R0 audit repair and local source validation passed. Installer built:
pending CI. Working on a tested installed configuration: not established. Ready
for public release: no. Fixture access, a Second host, fresh VM capability, Peer
and physical/operator availability must be resolved before the affected rows can
be run; unavailable cases stay pending. No failures are to be erased by a rerun.

Known product limitations are retained in [release notes](../../RELEASE-NOTES.md)
and [user instructions](../../README.md): current discovery contention/history,
non-atomic Clear, persistent host bindings, separate shared-subnet protection and
unchanged administrator privilege model. S1-S5/D/B are not included in this train.
