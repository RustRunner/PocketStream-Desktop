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
| Tagged application frontend suite | Passed: 287 tests, 0 failed/skipped | `release-frontend-tests.log` |
| TypeScript | Passed | `release-typecheck.log` |
| Production frontend build, DOM/re-stream/IPC/installer/boundary contracts | Passed | `release-frontend-build.log` |
| Isolated browser UI, 1280x800 and 960x600 | Passed; native calls stubbed | `release-ui.log`, `src-tauri/target/ui-layout/` |
| Cargo check / version lock refresh | Passed | `release-cargo-check.log` |
| Full Rust suite, unchanged default concurrency | Passed: 932 tests, 0 failed, 14 ignored; 35.63s. Ignored native cases do not count as passes | `release-rust-tests.log` |
| Rust formatting / all-target Clippy, `-D warnings` | Passed | `release-fmt.log`, `release-clippy.log` |
| Third-party/source/native manifest policy | Passed: 76 locked DLLs, 23 components, 25 source assets | `release-third-party.log`, `release-source-policy.log`, `release-source-manifest.log`, `release-runtime-manifest.log` |
| Tagged application CI | All six jobs passed, including audit, Windows 932 tests / 14 ignored and Linux 831 tests / 2 ignored | [Run 42902219995](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42902219995), `release-ci.log` |
| Release workflow / draft / generated NSIS / installed G3 | Both builds passed. Final downloaded installer/executable match the final CI installed hashes; G3 complete and draft-ready | [Final run 42908114945](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42908114945), final release evidence |
| Qualification fixture follow-up | 12 focused tooling tests and all 288 frontend tests passed locally | `release-template-regression-red.log`, `release-sandbox-contracts.log`, `release-frontend-tests-final.log` |

Routine logs above are ignored files in this worktree. A local build cannot
replace the CI artifact. The follow-up qualification-only CI run
[42905333665](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42905333665)
on `e2c29f2576e46483029e549c1cbed21799d7251e` passed five jobs but initially
failed the Windows SDK download with curl exit 18 (122,105,856 bytes missing).
The failed log is preserved as `release-qualification-ci-failed.log`. Attempt 2
passed the unchanged Windows job; the full run now has all six jobs successful.
Its log is `release-qualification-ci-pass.log`. Production/build/version sources
at that follow-up have no differences from the immutable application tag; it
changes only the qualification fixture, its regression and this evidence note.

## CI draft and downloaded artifacts

Application tag `v0.6.10` remains object `854f9be7dec1442ea5c870455711fd2f724c53ab`,
pointing to `f2a6f4f5eebc1199487d08480144431bbe3b43f7`. The first successful
[release run 42902225261](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42902225261)
created [unpublished draft 440937913](https://github.com/RustRunner/PocketStream-Desktop/releases/tag/untagged-5083b9c937598f71d3f9).
Its installer `78ab8b7d1f4e3e4555ed972636849a32da1f62b95f0c5b52004e7637aef67b7e`
and payload `1ee8f14d29447d2ece734aca685a8e7218892ac413b4174b4e7adfeeff7c96f1`
passed fresh CI installation and G3. They remain separately retained in
`ci-artifacts/`, `release-evidence/` and `artifact-identity.json`; they were never
installed on Test. This first workflow did not export the original staged
executable and generated NSIS, so its hashes and installed results stay historical.

Workflow follow-up `70288d6bdc219646fc3978d582ff7aff64152645` added those exports
and source identity. Manual rebuild checks out the immutable tag, verifies its
commit and all six version fields, requires an unpublished draft, and refuses a
published release. Five stubbed CLI guard cases passed locally; the actual
PowerShell 7 guard passed on CI. [Workflow CI 42908114229](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42908114229)
passed all six jobs. No check was removed. The [final release run 42908114945](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42908114945)
succeeded with workflow `70288d6` and application source `f2a6f4f`, confirmed in
its exported `release-source-identity.json`. It updated only the unpublished
v0.6.10 draft; neither main nor any existing tag moved.

Final downloaded artifacts are under `src-tauri/target/release-candidate/final-ci-artifacts/`.
Authenticated download: `gh release download v0.6.10 --repo RustRunner/PocketStream-Desktop --dir <new-directory>`.

| Final artifact | Product/file version; bytes | SHA-256 |
| --- | --- | --- |
| `PocketStream.Desktop_0.6.10_x64-setup.exe` | 0.6.10; 48,493,118 | `88dea7c2f016b3a17a8bfefde11635804772047a49c407b9733b37c93eca47bc` |
| Packaged `pocketstream-desktop.exe` | 0.6.10; 24,702,976 | `a1fc999c99a02ffd1ac174717a43581f1f9d26a9e18479b83e36d9bd2cf61faa` |
| Original staged CI executable | 0.6.10; 24,702,976 | `6f06fe7c69a6365d9f41f3101ad5e3b56bdb679990e4a89e073c8af397b80d57` |
| Installer `.sig` | 436 | `7ed16e3bc6501aabbe35e75aaec87299906fae4e98028cddb3f62233a2a7cddc` |
| Draft `latest.json` | 0.6.10 | `dfe1540a0fdc29383232f9ada9838a5d1a35668726042086cdba9cabefa6b09c` |
| Original generated `installer.nsi` | CI export | `ab344577ffa231cf32731a4d2fcf747d2e7db57759f317cb625705a3b23dc932` |
| Expanded installer compiler trace | CI export | `a95b02ff9400d42c05fc4932e2a8a6b808d06c0906a897e2b9fa402ab276656d` |
| Installed G3 evidence | `pass`, `draft_ready=true`, `g3_complete=true` | `edcc67b7ac9388d127acd6cb75398800f427bd34a723cc5299a7fcc840a4bd9f` |

The CI runner really installed the final installer silently into a fresh protected
root. Its installer/executable hashes equal the downloaded pair. The exact 76
GStreamer 1.26.11 / patched SRT 1.5.7 DLLs match the pinned closure; the installed
isolated pipeline, plugin/import/license checks and 26 published corresponding
source assets passed. The original staged and packaged files differ only by the
three-byte Tauri `UNK` → `NSS` marker at offsets 18,968,874–18,968,876. Both actual
NSIS source and trace contracts passed. All three PE images contain
requireAdministrator/Common Controls v6. Installer and packaged app are
Authenticode `NotSigned`. Both draft updater entries and the cryptographic
signature pass against the application public key; modified bytes are rejected.
The public v0.6.9 updater digest remains unchanged. Final source, installer,
manifest and runtime inspection data is retained in `final-release-evidence/`
and `final-ci-artifacts/source-artifact-comparison.json`.

## Installed/native run sheet

Preparation on 10 November: the existing IP-pinned SSH connection reached Test
read-only at `192.168.1.73`, Windows 11 Pro build 26200, PowerShell
`5.1.26100.9711`, account `DESKTOP-PI5BMJR\TSD-0311`, SID ending 1001, elevated
SSH session 0. BFE/MpsSvc/Winmgmt/sshd were running. The authentic v0.6.9 packaged
image was running as PID 3296 in desktop session 1; its SHA-256
`6f8e2a0d1e7c2b6db7eba6d2dc7739983b6a2b4194243a3c7f9f86ce10325a1c`
matches the independently extracted public v0.6.9 installer. Both installed
templates were observed disabled with `Package=Any` and registry `AppPkgId=Any`.
These are predecessor observations. This initial inspection was read-only.

The first CI draft's installer, signature and updater metadata were initially
copied to the new Test input directory
`C:\Users\Public\Documents\PocketStream-v0610\f2a6f4f-78ab8b7d1f4e3e45`.
Remote SHA-256 verification passed for all three at 21:37:58 UTC; the old installed
image hash and PID 3296 remained unchanged at that point. These staged inputs
were never launched; all Test installations below used the separate final input.

After the operator closed v0.6.9 normally, both real predecessor upgrades passed
on DESKTOP-PI5BMJR with the final CI installer staged separately at
`C:\Users\Public\Documents\PocketStream-v0610\f2a6f4f-88dea7c2f016b3a1`.
The before snapshots record both actual `AppPkgId=Any` fields. Each normal `/S`
upgrade exited 0, installed the exact final payload, verified the complete
disabled template shapes and absent AppPkgId, and left the three profile files
byte-identical. The v0.6.8 case used the registered silent standalone uninstall
and then the actual published v0.6.8 installer before upgrade. Neither legacy
desktop executable was launched. The profile copies remain private on Test;
native snapshots, process records and journals are exported and hash-verified
under `physical-R1-evidence/`.

| Predecessor | NSIS elapsed | Native policy total | Protected repair journal SHA-256 |
| --- | --- | --- | --- |
| v0.6.9, executable `6f8e2a0d…` | 23.714 s | 13.021 s | `51add86d5179686ce86948c3ea4af9abc0d3318d7a276a62fa1f702d64149fc1` |
| v0.6.8, executable `d16e25af6b8a9cf61caaa95dd5095833f41388eb09fd1863b044091e48ac04be` | 21.570 s | 13.284 s | `0846b6af824ba2ff605ac67f7e4552fa352f3c5ec502ced74a7cbf1c89ae981a` |

The fresh Sandbox `8B46C1B3-E356-4` used the guarded existing supported procedure,
279 current source hashes, the exact final installer and the authentic v0.6.9
predecessor. All **22 planned cases passed**: protected destination and welcome
Cancel, fresh silent/passive/updater, three reinstall modes, strict entry,
legacy migration/Block preservation, conflict/retry/collision, image in use,
both owner gates, standalone silent/passive uninstall, install after uninstall,
and actual predecessor upgrade/uninstall. The 1,229 exported files and 31 process
records are indexed under `sandbox-v0610-R10-v069-20261110T222629Z/`. Result SHA-256
`8d44ae50f07a1d47a318c94b7b7f57f0c3c3b1b8d620616ad7bd8d9bb4f4bd1c`;
export index SHA-256 `a6849f69a11f0dd1dbe3a5e40467133b055aea02548624ecde059814670bb6ec`.
Immutable inputs matched before/after. Final uninstall verified no installed
image, registration or owned rules; there is no profile. The guest was left
open for inspection as required. This is a new R10 run; paused batches stayed
paused. Interactive completion, continuous ownership, cross-account sessions,
actual partial-provider failure and signed update transport are still separate.

On Test, the operator launched the exact final installed executable in desktop
session 1 and confirmed visible live camera playback. App logs recorded native
startup reconciliation and `Playback pipeline set to Playing`. The PTU web
link at `192.168.1.202` failed the existing route guard: bound ARP proves the
PTU on Ethernet 13, while `Find-NetRoute` selects Wi-Fi 18 and `192.168.1.0/24`.
No route/interface change or automated PTU motion was performed. This is the
retained shared-subnet limitation, not successful PTU qualification. See
`test-ptu-route-and-preview-r2.json` and `test-real-desktop-state.json`.

RTSP Enable → Start without Save passed on that live camera configuration.
Peer `192.168.1.204` used the SHA-pinned GStreamer 1.26.11 client and received
OPTIONS 200 plus 150 H.264 buffers in 5.997 s from Test `192.168.1.73:8554`.
The exact process listened on `0.0.0.0:8554`; Windows showed four matching
application/port WFP permits at the IPv4/IPv6 listen and receive/accept layers.
Disabling while running persisted false, removed the listener and all four
permits, disabled both owned rules, and made the peer connection fail. Observed
policy times: startup 6.002 s, RTSP ensure 6.783 s, disable 3.230 s. Ensure and
disable each had zero admission wait; this does not prove saturated contention.
State, WFP paths, peer and timing evidence is in `media-probe/`.

SRT Enable → Start without Save used saved UDP 8890 and no passphrase despite
an unsaved port change to 18890 and a draft passphrase. Two native GStreamer
transients (EOS and a generic error) interrupted this case. Automatic recovery
took 10.803 s and 11.299 s. The recovered process listened on `0.0.0.0:8890`;
Windows showed four matching application/port WFP permits and the peer received
150 buffers in 1.746 s. Disabling while running persisted false, left the card
Offline, removed the UDP socket and permits, and left both rules disabled.
The peer received no data in the 8 s stopped probe. Disable policy took 3.052 s.
The port draft was still visible; visual preservation of the passphrase draft
was not confirmed. The passphrase was then cleared for the saved custom case.
See `srt-first-failure.json`, `srt-default-recovered-running-state.json`,
`srt-default-peer-recovered.json` and the stopped-state/probe records.

For custom SRT on 18890 and RTSP on 18554, the app was explicitly bound to Wi-Fi.
The respective UDP/TCP sockets bound to `192.168.1.73`. Each had six matching
WFP permits with application/port and local, arrival or next-hop interface
conditions. The same peer received 150 buffers for each: SRT in 1.743 s, RTSP
in 5.955 s with OPTIONS 200. SRT ensure policy took 9.902 s; RTSP took 9.954 s.
See the two `*-custom-wifi-running-state.json` and `*-custom-wifi-peer.json`
pairs. The transition to RTSP showed the SRT rule disabled and no app UDP
listener. These results are for Wi-Fi output and the tested Ethernet camera
input. They do not establish alternate-interface denial or topology churn.

At the operator's stopping point, they used Stop on the custom RTSP case and
closed the app normally. RTSP disable policy took 3.312 s; the native process
exited in 3.693 s and logged retirement before Stop completed. The exact
candidate remains installed. No app process, re-stream sockets or WFP permits
remained, and both owned rules were disabled. The 6 s peer probe to port 18554
timed out without connecting. Enable was still true on disk after Close;
application restart was not run. Saved test settings remain RTSP 18554,
SRT 18890 and explicit Wi-Fi. Evidence: `test-normal-close.json`,
`rtsp-custom-stopped-and-closed-state.json` and
`rtsp-custom-stopped-peer.json` under `media-probe/`.

Operator feedback during the RTSP case requests removing the Bound addresses
and Windows Rule display rows. This is a separate UI change to the existing
status contract. The exact qualified artifact still has those rows; its tag
and evidence were not changed to attribute results to a different UI.

Actual predecessor installers are downloaded in
`src-tauri/target/release-candidate/legacy/`:

| Installer | SHA-256 |
| --- | --- |
| Public v0.6.8 | `a6b83207d217d7e9e5aadb26a09843554bf680fc54201c5e2fa76934394b5410` |
| Public v0.6.9 | `beba0a03b8e881cd7d532d2f5ada6d8488f638949f3c14ad87c927249ef5edef` |

Their hashes match GitHub's asset digests. The v0.6.9 updater signature verifies
against the current application public key; a modified-file negative control is
rejected. The current public `latest.json` is v0.6.9, SHA-256
`e2002dce38f57c36cb4f607a9192f4d318c75d4c1d082d54085c34a91c8ab66a`.

The fixed existing post-enable timeout harness was initially compiled and listed,
without execution at that preparation checkpoint. Its bounded Test run is recorded
below; the original `prepared.json` remains the preparation record.
Prepared local debug lib-test executable SHA-256:
`07b0685b7d8042464488a74f40bbfda180608367d382c9be1d303f75a570c5a7`.
Its manifest is asInvoker/Common Controls v6; elevated isolated execution and
independent installed-image baseline remain mandatory. It and the guarded
controller were staged separately on Test and hash-checked. Source hashes,
ignored inventory and controller identity are under
`src-tauri/target/release-candidate/fault-fixture/`. This qualification-only
executable cannot replace CI production-artifact evidence.

The existing Sandbox `Verify-Templates` still accepted `Any`/`*` package fields.
A new pure-provider regression reproduced that false pass. The qualification
fixture now requires exactly empty Package, a successfully observed stored rule,
and absence of registry AppPkgId. The regression covers both roles, six package
restrictions, stored restrictions, missing records and registry failure; no
NetSecurity provider is imported or mutated. All 12 Sandbox tooling tests and
the full 288-test frontend suite pass. This validation-only follow-up is separate
from the immutable `v0.6.10` application tag; production sources are unchanged.

Host assignments: Test = authorized `DESKTOP-PI5BMJR`, previously at `192.168.1.73`
and reidentified at `192.168.141.125` for the bounded resume below; VM =
fresh Sandbox `8B46C1B3-E356-4` for supported cases; Peer = `THINKBOOK-G7`
at `192.168.1.204`, used only as a read-only media client. The operator confirmed
there is no separate authorized Windows host for Second. Unsupported Sandbox
cases require a full disposable Windows VM. The development PC was used only
for source/read-only work. Paused A4 and B batches remain paused. Hardware/PTU
movement requires the existing operator procedure.

Each partial row credits only the stated scenarios. Historical Sandbox, FLIR/PTU,
G1/G2/G3 and source results remain attached to their original artifacts. R10
retains Q's distinct requirements.

| Case | Source requirements | Host | Candidate identity | Result / timing / evidence |
| --- | --- | --- | --- | --- |
| R1.1 / R1.2 | F hardware 1-2; Q package repair: actual 0.6.8 and 0.6.9 upgrades, both defective templates, empty Package/no AppPkgId, two repaired_template records, successful NSIS <=65s; first-ensure fallback repair | Test + Second, VM where supported | Final CI artifact | Both real upgrades passed on Test in 21.570 s and 23.714 s; v0.6.9 also passed in Sandbox. First-ensure fallback and Second repeats pending |
| R2 | F hardware 3; N: ten ensure/disable cycles with unchanged/custom ports; p50/p95/stages; Test ensure <=15s (goal 10), disable <=8s, startup <=12s, install <=35s; Second ensure <=5s/startup <=4s with capability comparison | Test + Second | Final CI artifact | Partial, with failed timing samples: production startup 13.608/14.606/14.002 s exceeded 12 s; ensure 17.203/15.512/19.192/24.164 s exceeded 15 s; RTSP disable 8.790 s exceeded 8 s. Other measured disables passed. Ten cycles, percentiles, investigation and Second pending |
| R3 | F 4-6; T/N/R: RTSP and SRT, default/custom ports, wildcard/explicit Wi-Fi, WFP permits/interface filters, OPTIONS 200 + >=150 H.264 buffers, SRT handshake/media; Stop removes filters/disables rules and prevents access | Test + Second + Peer | Final CI artifact | Default wildcard and custom Wi-Fi media passed for both on Test/Peer; SRT default needed recovery. Default Disable, custom RTSP Stop and peer negative probes passed. Second and remaining binding permutations pending |
| R4 | F 7; R 3: authorized overriding Block survives install/ensure/Stop/uninstall; disabled/other-protocol observations remain cautious; remove fixture Block and Stop/Start restores media | Test + Second + Peer | Final CI artifact | Partial: Sandbox installer preservation passed. Physical overriding Block, cautious UI and removal/recovery pending |
| R5 | F 8-9; N; R 2/4: fixed post-enable timeout proves actual write and contained/exited writer; successful settle, retained accounting/retry; double failure and failed recovery retain barrier; later qualified Stop retires exactly | Test + Second | Hash-pinned fault fixture and final CI artifact | Partial: fixed RTSP executor/policy harness passed on Test, with actual enable events, contained/exited writers, verified settlement, double-failure/failed-recovery barriers, explicit disable recovery and subsequent normal ensure/disable. Application Stop, relay lease/orphan accounting, resumed ordinary native writes, SRT fault coverage and Second remain pending; details below |
| R6 | F 10; N exit; Q startup: fixed one-shot failure settles/retries within original workflow; queued/admitted Stop/exit prevent obsolete Ensure; unresolved lease survives and reconciles next start | Test + Second | Fixed fault candidate / CI artifact | Partial: the R5 harness's separate startup subcase passed: first 1 s attempt timed out, contained/exited; normal retry returned Inactive and scope write availability passed. Injected application startup, queued/admitted Stop/exit, lease persistence and Second remain pending |
| R7 | T hardware; R 4: 20 wildcard Start/Stop cycles per host, both protocols, unrelated churn, explicit bind camera churn, settled usable address change without duplicate rebuild; Stop/newer Start wins | Test + Second + Peer | CI f2a6f4f (identity above) | Pending; retain listener/scope/rule/lease generations and churn records |
| R8 | N hardware; R 1: Start/Stop/retry under current real or qualified scratch contention; separate admission/native timing; User admission <=15s, saturation expires without delayed writes; early/late scratch cleanup and retained uncertainty | Test + Second | Final CI artifact / qualified controlled fixture | Partial: ordinary Start/Disable passed with discovery active; recorded admission wait 0 on RTSP. Actual saturation, scratch cleanup and uncertainty pending |
| R9 | E hardware: false config -> Enable -> Start without Save, both outputs; Disable while running waits/reports errors; preserve all drafts/secret intents; accepted flag persists after restart | Test + Peer | Final CI artifact | Partial: accepted true/false survived restart without Start. After the operator identified a replacement camera, normal CAM selection resolved the saved-MAC refusal. RTSP port draft and SRT port/latency/replacement/removal intents survived successful Start and running Disable without Save; sockets, six correct permits per running snapshot and retirement verified. Eight follow-up captures confirm visual states. Native policy-failure/reload UI and remaining E save/confirmation paths stay pending; no replacement-camera peer-media campaign is credited |
| R10.1 | Q fresh/reinstall/upgrade/uninstall in interactive/passive/silent/updater modes; install without /R, correct disabled template shapes, maintenance before deletion, diagnostics on failure | Fresh VM + Test where required | Final CI artifact + hashed legacy installers | Partial: exact final fresh CI /S, Sandbox supported silent/passive/updater/reinstall/uninstall, real Test upgrades passed. Interactive completion and remaining failure/relaunch modes pending |
| R10.2 | Q legacy 0.6.7 migration/custom/duplicate/disabled/program-scoped rules; indistinguishable manual clone convention; foreign/unrecognized/colliding rules; repeated/partial recovery; exact preservation | Fresh VM | Final CI artifact / separately identified partial-provider fault build | Partial: supported seeded migration, preservation, conflict/retry/collision passed in Sandbox. Actual v0.6.7 installer and partial-provider injection pending |
| R10.3 | Q strict malformed/unknown/unelevated/unprotected entry refusal, no GUI/profile/native writes; install gate/HostOwner Busy, cancel, file replacement/maintenance failure, every exit path and launch after release | Fresh VM | Final CI artifact | Partial: Sandbox strict entry, welcome Cancel, supported ownership gates and maintenance conflict/retry passed. Full failure/exit/relaunch matrix pending |
| R10.4 | Q continuous ownership, legacy process/image-in-use refusal, no process kill/previous-uninstaller child, bootstrap-parent propagation, launch/finish timing and independent accounts/logon sessions | Full disposable Windows VM/Second | Final CI artifact | Partial: supported image-in-use refusal passed in Sandbox. Continuous ownership and unsupported cross-account, session and bootstrap paths pending |
| R10.5 | Q binding/settings: Wi-Fi/VPN/non-VPN virtual churn, IPv4 inventory vs native/listeners, failure -> Unknown -> recovery, stable GUID/alias/index/restart, reused/ambiguous legacy alias, failed-save migration, stale async races, QR exclusions | Test + Second + Peer | Final CI artifact | Partial: custom explicit Wi-Fi listener/scope and real settings save/readback passed. Other adapters, churn, errors, migration and restart pending |
| R10.6 | Q hardware: settings save/readback, both confirmation Cancels, selected-adapter proof and positive candidate ICMP, visible playback/recovery, PTU role/position/limits/presets/cold start and individually operator-confirmed directions/Home/stop, normal Close/restoration | Test + physical camera/PTU + operator | Final CI artifact | Partial: visible playback, normal Close and re-stream rule retirement confirmed. PTU web link blocked by current shared-subnet route; physical confirmations, positive ICMP, PTU motion and other hardware cases pending |
| R10.7 | Q existing resource gates: 20 cable cycles, 5 camera reboots, >=60 minutes representative playback/recording/relay, process-tree resources and notices; recovery/address/native postconditions applicable to this unchanged production path | Test + physical hardware/operator | CI f2a6f4f (identity above) | Pending; discovery redesign/S-R2/B gates remain separate |
| R10.8 | Packaged runtime closure/import/plugin/source/G3 installed gate, generated installer trace, requireAdministrator/Common Controls manifests, staged-vs-packaged image identity, updater signature/public key and feed/version checks | CI + read-only development inspection; isolated installed update fixture | Final CI artifact | Partial: final G3, exact runtime/source closure, generated NSIS, PE manifests, staged/packaged comparison and Tauri signature verified. Authenticode absent; true signed updater transport pending |

## Bounded R5/R9 resume — 10 November 2026

Initial execution was 11 November 02:32–03:09 UTC, followed by the operator's
replacement-camera clarification and qualification through 04:17 UTC (10 November
on Test). Release HEAD
was `dd7258644cbbcfce66226068a4426d9337e0e3a2`, with no production difference
from immutable tag commit `f2a6f4f5eebc1199487d08480144431bbe3b43f7`.
The root privilege branch and its unrelated edits/worktrees were preserved.
The exact installer `88dea7c2…` and packaged image `a1fc999c…` above were rehashed;
no installation, new production build, tag, feed change, publication or main merge
was performed. A4/B remained paused; no PTU movement or development-PC native
mutation occurred. No Second host was available or authorized.

The old Test address timed out. DNS resolved `192.168.141.125`; the previously
pinned SSH host key, actual hostname `DESKTOP-PI5BMJR`, account
`DESKTOP-PI5BMJR\TSD-0311`, SID
`S-1-5-21-3861278283-306712892-3066044081-1001` and both physical adapter
GUIDs/MACs were reverified. Test remained Windows 11 Pro build 26200 /
PowerShell `5.1.26100.9711`, elevated SSH session 0 and qualification desktop
session 1. Required services were running. An existing production PID 7784 was
closed normally before the independent disabled-rule/no-listener/no-WFP baseline.
Both stored owned rules had empty Package and no registry AppPkgId.

All local paths in this subsection are relative to
`src-tauri/target/release-candidate/R5-R9-resume-20261111T023245Z/` (`E`).
Remote paths below are relative to
`C:\Users\TSD-0311\AppData\Local\PocketStreamQualification\v0610\` (`Q`).
The initial profile backup in `Q\R5-R9-preflight-20261111T023529Z\` and the
interactive run's `baseline-profile\` remain private on Test; their contents,
including `.key`, were not exported.

**R5 / separate R6 subcase.** The executable remained SHA-256
`07b0685b7d8042464488a74f40bbfda180608367d382c9be1d303f75a570c5a7`.
All 77 recorded source-input hashes matched the tag's production sources.
The asInvoker/Common Controls manifest was inspected; execution used the verified
elevated account. The executable controller was SHA-256
`01977d08704c2bf26aa0cd9b243dccf4349f54d9825e1b8ab0d4cb55390fb0b2`.
It parsed successfully and corresponded exactly to its `.source.ps1` template
plus the reviewed Snapshot function; the template was not executed.

The one exact ignored test ran as PID 23768 in
`Q\R5-R6-RTSP-20261111T024105Z\`: 1 passed, 0 failed, 172.77 s;
controller process observation was 174.462 s, exit 0. The 13 real native attempts
are retained in `E/R5-native/fixed-fault.stdout.log`; ordered events and parsed
attempts are in `E/R5-sequence-summary.json`.

| Attempt(s) | Observed result and credited scope |
| --- | --- |
| 1–3 | Actual RTSP enable: event 2099 record 26212, Active=1 at 02:41:40.7545261Z, and `qualification_after_enable` before the 30.072 s timeout. Both writer processes were contained/exited. Safety disable returned verified Inactive, mutated=true in 7.073 s; event 26213 Active=0 at 02:41:59.5605153Z. The harness asserted ordinary admission available, followed by idempotent disable. |
| 4–5 | Same-session normal ensure returned Applied in 14.981 s, then normal disable returned Inactive in 7.472 s; the consumed fault did not recur. |
| 6–7 | Second actual enable: event 26216 Active=1 at 02:42:43.8170574Z and post-enable marker before a 30.072 s timeout. Safety disable itself timed out at 30.057 s with `qualification_disable_before_readback`. Both process trees were contained/exited. The harness asserted uncertain failure and ReconciliationRequired even though event 26217 already showed Active=0; a disabled observation did not bypass settlement accounting. |
| 8 | Fixed pre-write recovery failure exited with access-stage Failed, mutated=false, in 2.914 s. Uncertain failure and ReconciliationRequired remained asserted. |
| 9–11 | A later explicit policy disable freshly verified Inactive in 6.931 s and released the executor barrier. Subsequent ordinary ensure returned Applied in 14.621 s, then disable returned Inactive in 7.031 s. This is policy/executor recovery, not an application Stop or relay lease observation. |
| 12–13, R6 only | First startup attempt exhausted its fixed 1 s budget in 1.042 s, contained/exited. Its normal retry returned verified Inactive in 13.518 s inside the original reconciliation scope. The harness asserted `first_attempt` retention, scope write availability and final executor availability. No injected application startup/restart/exit campaign is credited. |

Every recorded native attempt had containment and observed tree exit; the four
timeouts each retained both tree PIDs. Nine rule-change events and complete
before/after rule/filter/address/route snapshots were preserved. Independent
checks at `Q\R5-ready-20261111T024021Z\` and
`Q\R5-qualified-cleanup-20261111T024717Z\` bracket the fault run with no product
process, both rules disabled and no managed WFP permits. All 60 exported R5
files matched their remote hashes. Export index SHA-256:
`b5dbd2b3bd230cce0d7619a88157ffb987263609c9d4e03d6cddfb73258a9b98`;
result SHA-256:
`0fd3102ec1ab69a2f1b8837f9a8f66d548f1a3538c75a361d48b8ac90a8fd168`.

The harness does not exercise application listeners, UI policy reporting, relay
lease ownership, abandoned requester accounting, resumed auto-adopt/address
writes, SRT fault behavior or production-image timeout behavior. Those R5/R6
subcases and Second repetitions remain pending. No generic fault framework or
new application injection surface was added.

**R9.** After qualified R5 cleanup, the exact installed production image was
relaunched as PID 19044 without Start. Actual UI Automation controls were used,
with process-scoped WebView2 `--force-renderer-accessibility` for inspection
([documented diagnostic flag](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/webview-features-flags)).
No browser/IPC stubs, persistent browser setting or altered application binary
was used. The launch discovery notice was acknowledged through its close-only
OK handler. `Inspect-20261111T025253326Z.json` records accepted Enable=On with
the config true and no RTSP/SRT socket before Start.

| R9 subcase | Result and evidence under `E/R9-native/` |
| --- | --- |
| RTSP draft / stopped Disable / Enable | Passed for unsaved port 19554 versus saved 18554; canonical SRT section and RTSP section excluding enabled stayed byte-equivalent by SHA-256. `DraftRtsp-20261111T025515686Z.json`, then `Disable-20261111T025829199Z.json`. |
| RTSP successful Start / running Disable with draft | Not completed at this first checkpoint. The Start attempt failed with `Network error: Ethernet not ready: expected MAC lacks fresh evidence at this endpoint`; no listener appeared. Its draft remained 19554, and later stopped Disable accepted false. This failed run is retained; the later replacement-camera pass is separate below. |
| SRT replacement intent | Passed for stopped Enable, rejected Start and stopped Disable: draft port 19890 and latency 777 remained visible versus saved 18890/125. Replacement-pending helper comparison and enabled Copy control persisted. `DraftSrt-20261111T030121588Z.json`; `start_became_desired=false` is explicit. |
| SRT removal intent | Passed for the same stopped/rejected-Start sequence: empty protected field, removal-pending helper and disabled Copy control persisted, without saving. `ClearSecret-20261111T030229354Z.json`. This is an unsaved removal intent, not a completed passwordless-save confirmation. |
| Visual secret draft | Six captures after Enable, rejected Start and Disable show masked replacement or empty removal field plus pending-save guidance. The two initial `*-draft.png` captures showed another region and receive no visual credit. See `E/R9-visual-review.json`; all eight originals are retained. |
| Accepted false across restart | Passed after normal Close of PID 19044 and exact production relaunch as PID 5824, without Start. The early inspector ran before controls loaded and is retained as failed tooling; `Inspect-20261111T030554986Z.json` later records loaded/enabled controls with Enable=Off, saved SRT port 18890 and latency 125. Unsaved drafts were discarded at restart, as permitted by the contract. |
| Successful SRT Start / running Disable with secret draft | Initially pending fresh expected-MAC evidence. Both SRT Start attempts logged the same readiness refusal as RTSP. These initial attempts establish preservation through refusal; later replacement-camera passes are recorded separately below. |
| Native policy-failure UI / failed canonical reload | Pending. The prescribed executable exercises executor/policy faults and has no application UI injection path. Readiness refusal does not qualify firewall-retirement failure reporting. |

At every captured draft phase the canonical SRT section SHA-256 remained
`c56f16966c4527d06ce22a6ef7175a203dfa7ef3035f8da867a9db41e6851679`,
including the saved secret, port and latency. RTSP excluding enabled remained
`09a87a33af987654cb20287c4cbca04c519fa51ff9b881c1e27b9007db344d2b`.
No Save Settings action was used. Redacted production toasts and native startup
records, including all three readiness failures, are in
`E/R9-native/production-events-redacted.log`.

Both real production restarts completed native reconciliation, but their startup
policy totals **13.608 s and 14.606 s exceeded Test's 12 s target** (runner
14.553 s and 16.025 s). These are failed R2 timing samples, not completed R2
qualification. Test was on battery; the threshold was not relaxed and no cause
or production fix is inferred. Only local qualification automation was adjusted
for transport limits, battery scheduling, actual UI patterns and redaction.
Failed tooling attempts, the resolved automatic redaction-review rejection and
two stalled read-only observers are retained under E. The observer processes
were retired only after their exact encoded source hash was checked and the
native fixture had exited. Production sources and artifact identities did not change.

**First clean checkpoint.** PID 5824 closed normally; at 03:09:09.6852322Z Test had no
product/helper/fixture process, no associated listener and no managed WFP permit.
Both ActiveStore and PersistentStore owned rules were disabled with the expected
group/program, empty Package and no registry AppPkgId. All temporary qualification
tasks were retired. The accepted final config is Enable=false, output SRT,
RTSP 18554, SRT 18890/125, explicit Wi-Fi; `.key` and the saved SRT section are
unchanged. No unresolved cleanup barrier is reported.

Remote UI/evidence root: `Q\R5-R9-interactive-20261111T023245Z\`.
Final native snapshot: `Q\R5R9-final-retirement-20261111T030859Z\`, exported as
`E/final-native-retirement/`. Final state: `E/R9-native/final-state.json`.
All 34 final exported UI/native files matched their remote hashes; index SHA-256
`938239cbae14096e0f8c7c6ccca207cf93ccd540f0356511bc64562b107338bb`,
final-state SHA-256
`6510d158689ccce7ccd003e7cc665569f266085f6cadffe964c70b6d0c2af856`.

**Replacement-camera follow-up and final stopping point.** The operator clarified
that a new camera was attached. Test was reverified over the same pinned SSH
connection. The saved CAM was `10.131.50.56 / 40:cd:3a:03:e0:0d`; the current
camera was `172.31.169.84 / 40:cd:3a:03:28:e2`. An RTSP OPTIONS probe bound to
Ethernet source `172.31.169.100`, GUID
`86193159-40f0-4a29-a389-c4c0b1945e82`, returned `RTSP/1.0 200 OK` and observed
the expected new MAC Reachable. No address configuration was changed for it.

Fresh local evidence is `E/camera-followup-20261111T032700Z/` (`F`); remote
evidence is `Q\R9-new-camera-20261111T032700Z\`. The pre-change profile was
backed up privately in that remote directory. PID 3468 was the exact installed
production image. Normal Nodes CAM selection persisted the new IP/MAC;
`F/R9-native/SelectNewCamera-20261111T035540934Z.json` records the accepted
selection. The old PTU role `fc:68:3e:22:05:2a / 192.168.1.202` was independently
unchanged in the before/after cache roles. No PTU control was selected or motion
command sent. The new CAM selection is retained; the old target was not restored.

The native role popup required a guarded pointer interaction: unique camera row,
exact visible CAM option, actual candidate/browser process ancestry and native
window ownership were checked. Earlier inaccessible/stale-element, ambiguous
button, focus/hit-test and popup-action attempts remain failed tooling records.
One stalled desktop traversal was stopped only as its named qualification task,
with the saved old camera identity checked afterward. No application process
was killed and no production/IPC workaround was introduced.

| Follow-up R9 scenario | Result and evidence under `F/R9-native/` |
| --- | --- |
| SRT replacement draft, Enable, successful Start, running Disable | Passed as a continuous sequence across `DraftSrt-20261111T035708201Z.json` and `FinishReplacement-20261111T040359605Z.json`. Start returned accepted/desired with UDP `192.168.141.125:18890`, while port draft 19890, latency 777 and replacement intent stayed unsaved. Running observation had the enabled owned rule and six permits; Disable returned disabled-and-stopped, removed the socket, disabled the rule and retired all permits. Initial verifier failures are preserved and assessed separately below. |
| SRT removal draft, Enable, successful Start, running Disable | Passed in `ClearSecret-20261111T040523943Z.json`: saved UDP 18890 used; empty protected field/removal intent, disabled Copy control and 19890/777 drafts persisted. Six running permits and complete retirement verified. No passwordless-save confirmation was exercised. |
| RTSP port draft, Enable, successful Start, running Disable | Passed across `DraftRtsp-20261111T041108586Z.json` and `FinishRtsp-20261111T041443141Z.json`. TCP `192.168.141.125:18554` used the saved value while draft 19554 survived. Six running permits and the exact expected TCP layers were observed; Disable removed the socket/permits, disabled the rule, persisted false and preserved 19554. The earlier listen-layer checker error is retained. |
| Visual secret behavior | Eight reviewed captures cover draft/Enable/successful Start/running Disable for both replacement and removal. Two extra verified-running crops were solid blue and are excluded, with originals preserved. `F/visual-review.json` identifies every credited/excluded image. No secret text is exported. |

All captured output-section hashes remained the same as the initial R9 baseline
above, including the saved SRT secret. Save Settings was never pressed. Native
running/disabled snapshots and original WFP XML are in `F/native-snapshots/`.
No replacement-camera peer media, 150-buffer result or full R3/R6 campaign is
inferred from these local R9 results.

The verifier initially assumed four permits, then lost a singleton socket's
Count through a PowerShell 5.1 conditional assignment. A pure local reproduction
showed the old value was PSCustomObject with Count=null, while an outer array
retained Count=1; `F/native-observer-array-regression.json` records that check.
The corrected qualification code checks required layers, permit action, app,
port and interface conditions, with explicit protocol checks where that layer
supports them. TCP listen-layer filters do not have an IP_PROTOCOL condition in
the [documented layer schema](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer);
the TCP listener and rule protocol are independently observed. These are tooling
corrections, not production fixes or relaxed timing limits.

Each protocol actually had six named permits: one IPv4 and one IPv6 listen
(RTSP) or resource-assignment (SRT) filter, plus two receive/accept filters per
family. Direct XML value assessment verified all 18 filters across RTSP running,
SRT replacement running and SRT removal running: exact installed NT application
path, local ports 18554/18890, protocols 6/17 where present, and every interface
LUID equal to `19985273102270464`. A read-only IP Helper query matched that LUID
to Wi-Fi index 18 / GUID `ec4b8efb-634e-4414-8afe-c5b945fb272b` / MAC
`10-51-07-F7-A6-B6`. See `F/wfp-value-assessment.json` and
`F/output-WiFi-luid.stdout.log`.

The SRT replacement run had an actual EOS at 04:02:02 UTC while it remained
desired. Automatic recovery logged listener readiness after **24.173 s** and
healthy-for-30-seconds at 04:02:57. That transient is retained in
`F/R9-native/media-events-redacted.log`; its temporary retirement/re-ensure is
not an extra operator Start or an injected R6 pass. The replacement draft still
had its original values/intent after recovery and at the later qualified Disable.

Incidental production timings remain failures against the existing Test budgets:
startup **14.002 s**; SRT ensure **17.203 s**, recovery ensure **15.512 s**,
SRT removal-case ensure **19.192 s**, RTSP ensure **24.164 s**; final RTSP
disable **8.790 s**. Other captured disables were 6.042 s during recovery,
7.427 s and 7.153 s. Earlier 13.608/14.606 s startup misses are preserved above.
No percentile or ten-cycle claim is made. These observations and the EOS need
investigation; no production cause or fix is inferred. Redacted policy/toast
records are in `F/R9-native/production-events-redacted.log`.

PID 3468 closed normally in `Close-20261111T041628127Z.json`. At
**04:17:26.1161619Z**, the final independent snapshot established no
product/helper/fixture process, no associated listener, both ActiveStore and
PersistentStore owned rules disabled, no managed WFP permits and no remaining
qualification tasks. Program/group/empty Package/no AppPkgId passed again.
Final accepted settings are Enable=false, output RTSP, saved RTSP 18554 and SRT
18890/125, explicit Wi-Fi, and the new CAM IP/MAC. `.key`, the SRT section and
RTSP fields other than enabled are unchanged; the PTU role is unchanged.

Final state is `F/R9-native/final-state.json`; native retirement is
`F/final-native-retirement/`, originally
`Q\R9-new-camera-final-retirement-20261111T041713Z\`.
All **73** follow-up indexed exports matched their Test hashes, with private
profile contents excluded. Index SHA-256:
`9143d0f4ffd96e258a3805b3310b21ef70aa4a3e9de170d4e74c161042993547`;
final-state SHA-256:
`3439dd7000ac058515dfcf6c281de476b18a6dc84aa83aaae3cd15036e811378`.
Together with the first 60 + 34 indexed exports, 167 indexed file transfers were
verified. R5 remains limited to its exact fault executable; R9 native
policy-failure/reload UI and remaining E save/confirmation paths are pending.
Production code/artifact identities remain unchanged, and no new CI candidate
or production fix is claimed.

## Bounded timing/EOS investigation — 11 November 2026 UTC

This S6-R follow-up starts from `release/v0.6.10` at `0ddd4c4`, verified against
live remote `dd72586` and immutable application tag `f2a6f4f`. Implementation is
isolated on `fix/v0610-timing-eos` in `.worktrees/v0610-timing-eos`; root privilege
edits and every existing worktree remain preserved. Live releases/tags confirmed
`v0.6.11` unused before its version preparation. Original v0.6.10 sources,
artifacts and failed samples remain historical and are not reclassified.

Evidence `I` is the new `timing-eos-20261111T044800Z/` subdirectory of E above,
in the original release worktree. The pinned SSH host/account/SID, elevation,
installed image hash, both physical adapter identities and current replacement
CAM were rechecked before fixture work. At 04:45 UTC the application was closed,
both persistent owned rules disabled, no qualification task active, and camera
`172.31.169.84 / 40:cd:3a:03:28:e2` still selected on Ethernet 13. Output Wi-Fi 18
was `192.168.141.125`. Read-only resource observations: i5-10310U, 4 cores/8 threads,
about 8 GB free RAM, reported 1505 MHz, 2% CPU load, battery 59%, Balanced plan.
These are current observations, not contemporaneous proof of a historical cause.

Recovered redacted historical events in `I/baseline-r2.stdout.log` establish zero
runtime admission wait, successful containment/tree exit, and actual ensure
actions: SRT unchanged (17.203/15.512/19.192 s), RTSP updated (24.164 s). Startup's
inventory includes two ownership checks, two fresh disabled readbacks and legacy
inventory; it is not enumeration alone. Prepare includes interface validation,
redundant exact lookup, disabled readback and, when changed, rewrite/full shape
verification. The recovery's policy totals are 21.554/24.173 s (89.2%); native
runner durations are 6.784 + 16.223 = 23.007 s (95.2%). The remaining 1.166 s
includes teardown, scheduling and listener construction; second-resolution logs
do not isolate those further. No remote-decoding recovery is established.

With app/fixture/observers stopped, `I/reads.stdout.log` measured 639 persistent
rules, no legacy candidates, exact queries 1.325–1.688 s, seven shape filters
0.256–0.339 s each, NetSecurity import 1.445 s, explicit NetAdapter import 1.362 s,
and adapter reads 0.294/0.099 s. Three paired comparisons in `I/refresh.stdout.log`
measured exact queries 1.523/1.320/1.319 s versus application-filter associations
0.335/0.248/0.248 s, returning the same exact PersistentStore rule. This confirms
avoidable repeated name-query cost without concurrent qualification observers.
Historical observer/power effects remain unquantified. Direct CIM refresh was
measured but not adopted; the implementation uses the supported, explicitly
store-selected [NetSecurity association parameter](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule).

The minimal policy change reuses the already validated rule/application-filter
identity for fresh association readbacks and removes Prepare's redundant name
query. Disappearance, ambiguity, provider error and wrong identity fail closed;
initial ownership queries, legacy migration/removal checks, Block observation,
interface identity checks, full changed-shape verification and all executor,
settlement/retirement accounting remain. Timings now split startup ownership,
shape and disable from inventory, plus explicit binding module/interface work.

EOS is investigated separately. Existing logs establish a current desired
generation, EOS before ordered teardown, zero-delay recovery and no logged
accepted downstream caller during the replacement-camera case. They do not
identify an upstream RTSP event, pipeline defect, downstream cause or lifecycle
race. Narrow EOS-only pad/bus diagnostics add fixed stages, sequence numbers and
instance/data IDs, with shutdown state. They never log object names, URLs,
credentials, passphrases or stream IDs and do not change media/recovery behavior.

All 167 original indexed exports and both v0.6.10 artifact hashes were reverified
(`I/preserved-evidence-verification.json`). Local final-source checks passed:
288 frontend tests including the 27-case pure provider fixture; type checking,
contracts/production build, both browser sizes, Cargo check, 934 Rust tests
(14 ignored, default concurrency, 36.03 s), formatting, all-target Clippy with
warnings denied, current audit using only CI's three existing exceptions,
76-DLL closure/third-party and source-release policy. Two failed Rust runs are
retained: only the fixed qualification anchors failed after the source refactor;
the final anchor check and full rerun pass. The single-line pre-write anchor
also avoids Windows CRLF assumptions. Sandbox-limited build/browser failures
and the missing PATH audit launcher are retained; approved source-only reruns
passed with the existing isolated audit binary. No native ignored test is
credited as passed.

At about 05:00 UTC Test's pinned SSH transport closed during staging. Subsequent
exact-address SSH timed out and hostname resolution failed. No candidate
installation, application launch, firewall/address mutation or fault execution
had begun. The prepared pre-candidate snapshot/profile-backup script did not run.
Access restoration was requested while independent CI candidate work continued.
The last live read at 04:45 UTC had no product/fixture process and disabled owned
rules; latest complete WFP retirement remains the 04:17 checkpoint above. A new
final-state observation must wait for connectivity; it is not inferred.

Candidate checks and installed measurements are recorded below as they complete;
R2 remains pending until its required repetitions and limits are met. Second,
paused A4/B, PTU, discovery/Clear and unrelated release gates remain unchanged.

## Remaining gates and release state

R0 audit repair and source validation passed. Installer built: yes, and the
downloaded hashes match the exact final CI installed candidate. Earlier Test
runs passed both real upgrades, live preview, default/custom remote RTSP/SRT,
and firewall retirement on Stop/Disable. The bounded resume adds only its stated
passes. The initial saved-MAC refusal was resolved with the operator's new camera;
R9 running draft/Disable checks then passed. Policy timing misses and the SRT EOS
are retained. Ready for public release: no. The remaining
gates above require more isolated Test time,
a separately authorized Second and full disposable Windows VM, and operator-led
hardware testing. The release is still a draft. No tag was moved, no public feed
changed, and no main merge was performed.

Next bounded action: investigate the recorded Test startup/ensure/disable timing
misses and SRT EOS using the preserved stages/resources, without relaxing budgets.
Any production fix needs a separate branch, a new CI-built candidate and affected
requalification. Native policy-failure UI needs an appropriate separately identified
prescribed fixture; this executable cannot provide it. Remaining R5/R6
application/SRT/ownership cases and all Second repetitions stay pending. Test is
closed and clean at the final stopping point above; public release remains incomplete.

Known product limitations are retained in [release notes](../../RELEASE-NOTES.md)
and [user instructions](../../README.md): current discovery contention/history,
non-atomic Clear, persistent host bindings, separate shared-subnet protection and
unchanged administrator privilege model. S1-S5/D/B are not included in this train.
