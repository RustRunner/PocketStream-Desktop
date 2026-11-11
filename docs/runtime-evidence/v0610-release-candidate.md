# v0.6.10 re-stream release candidate

Date: 10 November 2026. R0 and S6-R only. Source verification, CI installer
production, installed/native qualification and public release are separate gates.
This note is the current candidate run sheet; historical results are not passes
for this artifact. Discovery/Clear/Refresh and privilege integration remain
separate work.

The [11 November timing/EOS follow-up](#bounded-timingeos-investigation--11-november-2026-utc)
below identifies the separate unpublished v0.6.11 candidate. The latest
[v0.6.12 CI candidate results](#v0612-exact-ci-candidate-follow-through--11-november-2026-utc)
record the confirmed pending-reader fix and its affected Test qualification.
Public release remains blocked by the [remaining gates](#remaining-gates-and-release-state).
Earlier identities and qualification samples remain immutable historical
evidence; they do not transfer to a new image.

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

**Access restored / policy barriers.** The operator confirmed Test awake at the
same address. At 05:05:17 UTC the independent native snapshot again verified no
product process, both rules disabled and zero managed WFP permits. A fresh bound
camera OPTIONS probe returned 200 with the expected new MAC Reachable. The
profile backup is private in `Q/timing-eos-20261111T044800Z/baseline-profile/`.
The saved SRT passphrase is empty; no credential was exported.

The unchanged fixed RTSP post-enable timeout/settlement/recovery procedure ran
against the new policy source `7ed10d87d909369e0154ca66083375b2a1f2e5fe` as a
separate local debug cfg(test), no-feature harness, SHA-256
`9711391621d8011b51ab58f9b6b805eb67e5761b8b856753125970eff3a92e19` (77 source
input hashes; asInvoker/Common Controls v6 inspected). Controller SHA-256
`d5bdc4fa35feb841ffd04f0b41d5ec76043e0c8057f94b9c1456c8cb0fb3f2d3`.
It passed one exact ignored test, 13 native attempts, four contained/exited
timeouts, two actual post-enable markers, one settlement-timeout marker and nine
rule-change events; controller elapsed 156.056 s, exit 0, final disabled state.
The installed application was still exact v0.6.10 `a1fc999c…`; this is new-policy
executor/policy evidence, not new-CI application/lease/media qualification.
Evidence: `I/new-policy-r5.stdout.log`, `I/fault-prepared.json`, indexed native
export and independent post-R5 snapshot. Original fault executable/evidence are
preserved separately.

**CI candidate preparation.** Immutable new tag `v0.6.11` points only to `7ed10d8`.
Source CI is [42963130063](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42963130063).
The tag-triggered [release run 42963132597](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42963132597)
failed twice before compilation on the pinned runtime MSI GET: curl exit 18,
54,767,616 and 29,601,792 bytes missing. Both logs are retained in I.
A workflow-only follow-up adds `--retry-all-errors` to that same file GET's
existing three-retry/five-second-delay command. File output, version/source guard
and SHA-256 verification remain required. [curl's documented behavior](https://curl.se/docs/manpage.html#--retry-all-errors)
resets partial file output before retry; this does not relax any policy timing
or verification budget. The existing manual rebuild checks out immutable
application tag `7ed10d8` and separately records its workflow identity. Neither
application tag is moved; the candidate remains unpublished.

The first manual rebuild (`42964587182`, workflow `2847eda`) remained blocked in
the SDK step and was cancelled before application compilation or artifact
creation. The two preserved official MSIs were independently rehashed at
`I/preserved-sdk-inputs.json`: runtime 88,322,048 bytes, `31cbc21f…`; development
369,569,792 bytes, `af0a0720…`, equal to the existing full pins. They are retained
as private build-input assets on the unpublished v0.6.11 draft. A manual rebuild
may use these exact files when present, with the same mandatory SHA-256 checks;
otherwise it uses the existing official-origin GET. No local application binary
enters the CI build. Workflow/application identities remain separate.

All 61 new R5 exports matched their Test hashes; index SHA-256
`eff0582836b96cfae6c7b5baaf3b17bb96a557ab612a2053efd5d83b1d514ad7`.
The independent post-R5 snapshot again shows no product process/listener or
managed WFP permit and both owned rules disabled. Matched ordinary attempts in
the two separately identified fault harnesses (`I/fault-before-after.json`):
ensure runner 14.981/14.621 -> 10.453/10.441 s; disable runner 7.472/7.031 ->
5.882/5.793 s; startup retry runner 13.518 -> 10.297 s. Script totals are recorded
separately. These are not controlled A/B attribution, new production-artifact
results or a ten-cycle R2 pass. The F speed table is measured under the runner;
installed repetitions must retain both script and runner time against the limits.

**EOS evidence recovered from the existing full log.**
`I/transport-history.stdout.log` and the 50-second
`I/eos-network-window.stdout.log` contain an earlier line at the same
04:02:02 UTC timestamp: `bound_tcp` reports its Ethernet-bound transport stopped
because the selected Ethernet adapter was unavailable, immediately before SRT's
EOS and bus-thread exit. MAC-verified camera ARP replies were successful at
04:01:56 and again at 04:02:02, with no recorded Ethernet link-down event in the
window. No accepted downstream caller is logged there.

Source review shows the transport checks its existing fence/readiness every
second and aborts its forwarding tasks on refusal; its only fixed timeout is
the five-second initial connect, not an idle streaming deadline. This strongly
supports guarded upstream-transport retirement as the proximate EOS trigger.
It does not establish a camera-origin EOS or physical disconnection. The
generic readiness refusal combines missing/stale selection, native index/status
observation failure or mismatch/down state, and a busy pending-address snapshot
mutex. The historical log does not distinguish these branches. Snapshot
contention is a hypothesis, not a confirmed cause or justification to weaken
identity/readiness checks. No readiness or SRT behavior change is claimed.

Original failed samples remain in `I/original-timing-breakdown.json`. Durations
below are seconds; all recorded runtime admission waits were zero. Runner time
includes process startup/exit and capture around the policy script; it is the
timing-budget measurement. Script imports are separately measured, and the old
ensure `access` stage also includes NetAdapter import.

| Original operation | Samples | Script total | Native runner | Dominant recorded work |
|---|---:|---:|---:|---|
| Startup | 3 | 13.608–14.606 | 14.553–16.025 | Inventory 10.721–11.472, including ownership/disable readbacks; NetSecurity imports 2.486–3.047 |
| SRT unchanged ensure | 3 | 15.512–19.192 | 16.223–20.050 | Prepare 3.592–4.499, shape 2.561–2.799, readback 2.245–2.990; additional ownership, Block and module work |
| RTSP changed ensure | 1 | 24.164 | 24.971 | Prepare 8.940, including rewrite/full verification; shape 2.959, readback 2.808, trusted import 2.850 |
| SRT disable | 3 | 6.042–7.427 | 6.784–8.354 | Ownership 1.581–2.132, disable/readback 1.769–2.152, imports 1.952–2.400 |
| RTSP disable | 1 | 8.790 | 9.747 | Ownership 2.274, disable/readback 2.427, imports 3.058 |

These totals establish expensive repeated provider reads and module/process
costs, not enumeration-only cost or executor contention. Changed-rule work is
retained because it verifies the actual written shape. Historical resource and
observer contributions cannot be subtracted from these failed samples.

All six exact-application-source CI jobs passed in run `42963130063`: Windows
934 tests / 14 ignored, Linux 833 / 2 ignored, frontend, browser, notices and
audit. `I/ci-source-7ed10d8.log` preserves the result. The guarded draft build
uses workflow `03826cfb5d0818547db4101517b550425f9b2496` in
[run 42965430004](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/42965430004),
with application tag still `7ed10d8`. Its SDK setup, source checks and runtime
gates passed before packaging. Draft ID `441266851` remains unpublished.

**Exact installed CI candidate.** `I/candidate-identity.json` records installer
`PocketStream.Desktop_0.6.11_x64-setup.exe`, 48,501,223 bytes, SHA-256
`7279f4275c710c41bc89669f884be6b409f7c7aac827f6d8399343971e084963`;
packaged application 24,710,656 bytes, SHA-256
`382b48e1675caac91b96b1e91c6d5617c9615a66c7f7de31f81fc6de741fdd87`.
Installed G3 is complete/draft-ready, receipt SHA-256
`f8a6b2d9c7f1d9a19e3933f46158360672f84a79dedf29caacbb919d5685b1f8`.
The extracted package has the required administrator/Common Controls manifest,
76 verified runtime DLLs, and differs from the staged CI image only in NSIS's
three-byte `UNK` -> `NSS` marker. Both updater signatures and their trusted
comments verified cryptographically; modified bytes were rejected. The updater
metadata matches version, asset and signature. These checks inspect the private
draft; no public feed was written.

Normal silent upgrade on Test exited 0 in 16.310 s at 05:58:58 UTC, installed
the exact packaged hash, and preserved all three private profile files byte for
byte. Both templates remained compliant/disabled. This upgrade did not require
package-field repair and does not close the separate install-with-repair gate.
The first installed startup runner was 4.960 s (script 4.560, admission 0), with
separate ownership/shape/disable/inventory/module stages.

At 06:01 UTC the host reported AC power, Balanced, 1706 MHz, 11% CPU and about
7 GB free RAM. The 04:45 pre-change checkpoint was on battery; the original
failed samples do not carry per-sample power records. Matched battery
repetition was requested; AC and battery samples must remain separate. The new
installed unchanged-SRT cohort retained its warmup and all ten measured cycles:
ensure runner p50/p95 5.741/5.868 s, disable 2.610/2.975 s, zero admission wait,
all contained/exited and no truncation. Every ensure action was `unchanged`.
This passes the recorded explicit-Wi-Fi/AC case only. Native observers ran
after the cohort, with no rule/WFP enumeration during its policy calls.
Evidence: `I/candidate-events-after-srt-ten.stdout.log` and
`I/candidate-timing-after-srt-ten.json`. A first UI setup attempt failed before
any sample because the controller required a redundant Enable transition; it
is retained separately. The launch controller also initially observed the UI
before its controls loaded; later inspection succeeded without restarting the
application. Neither tooling failure is relabeled as an application pass.

The changed-port RTSP cohort then passed all ten measured cycles, alternating
19554/18554 and ending at saved 18554. Every ensure action was `updated`, so
this includes actual rewrite and full verification. `I/candidate-timing-after-both-sets.json`
pairs each UI case to exactly one successful, contained/tree-exited native
ensure and disable; all admission waits were zero. Nearest-rank percentiles:

| Installed CI case, explicit Wi-Fi, AC | n | Ensure runner p50 / p95 | Disable runner p50 / p95 | Ensure / disable script p95 |
|---|---:|---:|---:|---:|
| Unchanged SRT 18890 | 10 (+ retained warmup) | 5.741 / 5.868 s | 2.610 / 2.975 s | 5.532 / 2.324 s |
| Changed RTSP 19554/18554 | 10 | 8.101 / 8.543 s | 2.769 / 2.967 s | 8.180 / 2.633 s |

Every measured runner sample meets ensure <=15 s and disable <=8 s. Cohort-end
snapshots show both rules disabled, no output socket and no owned permit. A
separate RTSP 18554 start returned OPTIONS 200 and 150 decoded raw video frames
on THINKBOOK-G7 (5.529 s). These are matching-image affected checks, not a full
R2 or R3 pass: battery, All-addresses reference, other port/protocol combinations,
Second and install-with-repair remain pending. AC observations cannot establish
how much of the historical speed difference comes from power versus code.

This is a policy timing pass for those conditions, not uninterrupted-media
qualification of every rapid cycle. Final event review also finds the generic
bound-transport readiness refusal at 06:06:20 and 06:07:33 UTC, immediately after
SRT listener-start events for generations 4 and 11. Each is followed by
`fault=gst_error`, bus join and Recovering -> Stopped as the controller Disables.
No EOS is logged there. UI timestamps place Disable in the same log second;
the records do not resolve its sub-second ordering against the guard refusal.
Both failures are retained in `I/candidate-events-final-capture.stdout.log`;
neither is excluded from the native timing samples or treated as successful
continuous decoding. They strengthen the case for the fixed readiness-reason
capture below, not a speculative camera or retry fix.

The UI observation p50/p95 intervals (Enable/Start through desired-state UI,
and Disable through controls released) are 6.337/6.878 and 3.950/4.458 s for SRT,
8.909/9.425 and 2.925/3.448 s for RTSP. They include UI/persistence/polling and
pipeline work around the native call; they are not isolated teardown times or
remote-media readiness. The separate 150-frame peer results supply decoding
evidence for the two explicitly identified media runs.

**Bounded natural EOS observation on the CI image.** Current replacement CAM
and both physical adapter identities were rechecked. The SRT listener started
at 06:10:22 UTC and remained desired through the no-caller checkpoint at
06:16:44 UTC: 382 seconds at one-second log precision, on AC, with no recorded
EOS or transport refusal in that interval. The new source-pad probe attached.
One native/WFP snapshot was taken at 06:11:12; other observation used saved
redacted logs, not a concurrent native sampling loop. It showed UDP 18890 on
`192.168.141.125`, the SRT rule enabled on Wi-Fi, six permit filters and RTSP
disabled. Ethernet 13 remained up at 100 Mbps and the expected camera MAC was
Reachable.

THINKBOOK-G7 then decoded 150 raw video frames over SRT from 06:16:49 to
06:16:58 UTC (8.237 s). The server logged caller acceptance/removal and no EOS
through the 06:17:34 checkpoint, 38 seconds after caller removal. Normal Disable
retired its listener/rule/managed permits; a bounded eight-second peer attempt
received zero frames afterward. Evidence is `I/candidate-srt-observation.json`,
the corresponding peer JSON/redacted log and installed native snapshots.
This is observed decoding after an uninterrupted no-caller interval, not
decoding after automatic recovery. Natural EOS did not recur in this bounded
experiment; the original exact readiness-refusal branch remains unresolved.

The next smallest EOS experiment is one failing bound-transport guard capture
that distinguishes missing/not-ready/stale selection, index lookup/mismatch,
status lookup/down and pending-snapshot contention with fixed reason codes.
Correlate it with the existing EOS pad/bus sequence and generation/shutdown
fields, link/ARP evidence and an actual decoding peer after recovery. Keep all
readiness/identity fences unchanged. No credential, sensitive URL, native error
payload or element name is needed. A longer blind soak or a speculative retry/
readiness relaxation would not identify which historical guard refused.

**Startup repetition and final shutdown.** At the 13:25 UTC resume Test was
already closed, with a last-boot time of 06:34:41 UTC and no signed-in desktop
user. Native observation found both rules disabled and no owned permits. The
requested interactive Close task had never run (`0x41303`); it was recorded and
retired before another launch. No reboot was initiated by this investigation.
The operator signed in as TSD-0311; console session 1, exact SID/image, physical
adapter identities, disabled profile and native baseline were rechecked.

Two more exact-CI application starts completed the three recorded AC startup
samples. All had admission wait 0, exit 0, contained/tree-exited results and
complete native reconciliation:

| Startup UTC | Policy script | Native runner | Runner excess | Trusted module stage |
|---|---:|---:|---:|---:|
| 06:00:16 | 4.560 s | 4.960 s | 0.400 s | 0.870 s |
| 13:46:22 | 6.451 s | 8.721 s | 2.270 s | 1.949 s |
| 13:54:13 | 5.008 s | 6.377 s | 1.369 s | 1.241 s |

Runner p50/max are 6.377/8.721 s, all below 12 s. This is three observed AC
starts, not a full matched-condition R2 closeout. The second and third full
native reconciliation markers follow the firewall result by 13 and 8 seconds;
that additional address/native recovery work is distinct from F's policy-runner
budget and remains unchanged. A fresh Ethernet-source-bound camera OPTIONS
returned 200 with `40-CD-3A-03-28-E2` Reachable. Post-start power remained AC;
the second resource observation reported 37% CPU, unlike the earlier 2–11%
snapshots. No historical resource contribution is inferred from those points.

The second launch's early cached UI observer again missed controls, while later
inspection passed in the same application process. A qualification-only change
reacquires the current process-owned UI window for lookups; the third launch
then passed. Its first staging attempt had a typed-catch parse error and ran no
UI action; that failed task/hash is retained. The corrected controller is
`bfbaf4f1df58258cc62807b5b501d3d485f1857e431468e52997e9bfb2feee76`.
No application/UI production source was changed by these controller fixes.

Both resumed instances closed by the normal window Close operation. Final
Close was 13:57:36–13:57:37 UTC; the attached-process exit-code property was
unavailable, but WaitForExit and independent process absence were verified.
At **13:59:08 UTC**, `I/candidate-final-clean-retirement.stdout.log` and the
final exported `final-state.json` establish zero product/helper/fault processes,
zero output TCP listeners/UDP endpoints, zero named managed permits and zero
application-bound WFP permits. Both ActiveStore and PersistentStore rules are
disabled, with empty Package/no registry AppPkgId. All this task's qualification
tasks are retired. Saved RTSP/SRT sections (including secrets), key, camera/PTU
roles and selected adapter match the private baseline; Enable is false, output
RTSP 18554, SRT 18890/125 ms. No unresolved native uncertainty remains. Existing
host addresses/bindings and paused A4/B work were not manually changed.

The complete timing analysis is `I/candidate-timing-combined.json`, assembled
from five preserved redacted captures with their SHA-256 identities in
`I/candidate-events-combined.json`. The application log rotated during the
resumed run; no original capture was overwritten or failed sample dropped.
The first 39-file installed export and final 49-file export both verified every
indexed Test hash, with private profiles excluded. Final index SHA-256:
`afa6715bbe195fe8ce9bb44b993563fbacbb091cf89faecb73f1fbb6edc37b24`;
final-state SHA-256:
`b4ed7a5dc1b3ef6def7b22695f138531ab1adaaa1f575cf6eb6ab550efde4daf`.
Transfer receipts and both archives remain in I alongside the separate 61-file
native fault export and all 167 original indexed exports. Both original
v0.6.10 artifact hashes were reverified again at completion.

## Guarded readiness-refusal capture — 11 November 2026 UTC

This bounded follow-up uses a new worktree outside build outputs,
`.worktrees/v0611-readiness-refusal`, branch `diag/v0611-readiness-refusal`,
from clean documentation baseline `8e4c409e2902e6d7239ae035cbc882f62accb212`.
Diagnostic application source is `621defd79515f7214e571299042cc6ba45bab86b`.
No applicable AGENTS.md was found. Root README/DEVELOPMENT/images edits and all
existing worktrees remain preserved. No production behavior fix, new release
tag, push, main merge, publication or updater-feed change was made.

Evidence `G` is this successor worktree's
`src-tauri/target/readiness-20261111T150217Z/`. The matching private Test run is
`%LOCALAPPDATA%\PocketStreamQualification\v0610\readiness-20261111T150217Z`.
Before another experiment, the preserved full-log-derived transport history,
original EOS network window and rapid-cycle capture in I were inspected.
Both current Test log generations and the profile were then copied privately
on Test; full diagnostic logs were also preserved there before and after Close.
Raw logs and profile contents were excluded from the exported evidence.

The pinned SSH host/account/SID, elevated token, interactive TSD-0311 session,
installed CI image, selected Ethernet GUID/MAC/index 13, Wi-Fi GUID/MAC/index 18
and saved replacement CAM were rechecked. Test was initially closed/clean.
Fresh Ethernet-source-bound OPTIONS returned 200 at 15:28:28 UTC, with expected
camera MAC `40-CD-3A-03-28-E2` Reachable. CAM remains `172.31.169.84`, source
`172.31.169.100`; output is Wi-Fi `192.168.141.125`. THINKBOOK-G7 is the read-only
peer, observed source `192.168.141.216`. Recorded power was AC. No Second,
development-PC installation/native mutation, adapter/route/address fault,
PTU motion or paused A4/B work was used.

**Diagnostic identity and verification.** This is a local unsigned diagnostic,
with product version 0.6.11 and updater artifacts disabled, not a CI candidate.
Its evidence cannot qualify the immutable v0.6.11 production artifact.

| Diagnostic artifact | Bytes | SHA-256 |
|---|---:|---|
| Installer | 48,512,861 | `8115917064b0e9f552311ce45f933d1f0496ea581169760a6bff391999022361` |
| Packaged executable | 24,723,456 | `ee0a08996f1221ddbd4d993f8baabc893fe56b3ff3e1b2ea48526401597c1ae8` |
| Staged executable | 24,723,456 | `aa0e7299b7199f107aac244f76cbeb956d1b0242338220c794c222e13d638484` |

The packaged image has the administrator/Common Controls manifest and all 76
pinned runtime DLLs. Only NSIS's three UNK -> NSS marker bytes differ from the
staged image (`G/payload-comparison.json`). Actual generated NSIS compiled-trace
and source contracts passed. Existing shared build-output aliases were copied
and hashed before packaging; both original CI installer/image pairs were
independently rehashed unchanged. Normal diagnostic installation exited 0 in
18.237 s, installed the exact packaged hash and preserved all three private
profile files byte for byte.

Final source checks passed: 288 frontend tests, typecheck, contracts/frontend
build, 938 Rust tests / 14 ignored at default concurrency (36.84 s), formatting,
all-target Clippy with warnings denied and the 76-DLL/third-party closure.
Four added regressions cover exact refusal/read order, busy-snapshot refusal
and pending exclusion, no repeated readiness read, and unchanged Network wire
values. Existing path/identity/fence retirement tests passed. Initial build/
sandbox/tooling failures are retained. The first full Rust run had 12 SRT
fixture startup/recovery failures; the final rerun with GStreamer warnings
captured passed without reducing concurrency. Those failures are retained and
unattributed, not a historical EOS diagnosis or hardware pass.

**What changed.** The actual refusing check carries a fixed reason through the
existing error channel; IPC kind/message remain unchanged. The finite codes
distinguish missing/stale selection, index lookup/mismatch, status lookup/down,
pending snapshot busy, retired transport/relay and changed path. Only the first
refusal per transport is recorded, including the SRT before-send check. Numeric
transport records link to existing generation/instance/data IDs. Retirement,
SRT error-bus/EOS diagnostics, Stop intent and operator Disable/exit have
sub-second timestamps. Ordinary probe refusals are not logged. No new native
read, cross-manager lock, setting, command or generic telemetry owner was added.
Readiness, freshness, pending exclusion, native serialization, synchronous
retirement and retained-result/uncertainty barriers are unchanged; the confirmed
firewall optimization is untouched.

**Exact observed refusals.** All times below are UTC, converted from Test's
Central Standard Time log timestamps. `G/refusal-analysis.json`, the indexed
`events-20261111T155442838Z.json` capture and earlier checkpoint captures preserve
the full ordering; no readiness checks were rerun to assign these reasons.

| Scenario | Refusal / lifecycle evidence | Interpretation |
|---|---|---|
| Three rapid SRT Start/Disable cycles, saved UDP 18890 | Generation 2, instance/data 1, transport 2: `srt_before_send`, `pending_snapshot_busy` at **15:33:02.325758**; runtime GstError .325819, Recovering .325919, shutdown .326002, bus error .326022, transport retirement .345021. Operator Disable reaches the backend only at **15:33:02.753945**. | Unexpected refusal precedes backend Disable by **428.187 ms**, also preceding the UI's Disable timestamp by 383.698 ms. No EOS was observed. Disable interrupts this recovery, so it is not a recovery-acceptance pass. |
| Separate SRT Start, then no further Start | Generation 4, instance/data 1, transport 4: `srt_before_send`, `pending_snapshot_busy` at **15:35:04.032875**; Recovering .032987, shutdown .033090, bus error .033157 (`shutdown_requested=true`), retirement .038770. Automatic zero-delay attempt 1 starts at 15:35:08.723473; instance/data 2, transport 5, listener ready at **15:35:14.853123**. | Unexpected refusal while streaming remains desired; **10.820 s** fault-to-listener-ready. The existing peer was not yet decoding. Media was subsequently decoded from this automatically recovered generation without another operator Start, as detailed below. |
| Single RTSP peer decoding attempt on saved TCP 18554 | Generation 5, transport 6: `serve_interval`, `pending_snapshot_busy` at **15:47:32.622107**; transport retirement .622224 and the original generic unavailable message .622267. The guarded callback marks Failed .621989 before returning that same refusal to Gate; operator Disable is later at **15:50:36.947872**. | Actual bound TCP serve retirement is captured. OPTIONS 200 was followed by **503 and zero decoded frames**. This is a failed affected-media check, not recovered media. |

The other first refusals are normal `relay_retired` during Disable: transports
1, 3 and 5 occur 2.574, 3.651 and 2.265 ms after the backend operator records.
They are distinct from the unexpected `pending_snapshot_busy` cases. All eight
UI controller tasks completed successfully; this does not turn the failed
media cases into passes. The three cycles are not an R2 cohort: the first
ensure rewrote the installed default template; only the next two were unchanged.

The exact pending-snapshot code means selection/fence, native index identity
and native Up-status checks already passed in that invocation, then
`pending_ips.try_lock()` failed. Camera ARP replies bracket all three refusals:
15:32:58.833300 / 15:33:04.081387, 15:35:00.091099 / 15:35:05.343849 and
15:47:29.096318 / 15:47:34.357025. Expected-MAC replies continued and no Ethernet
link-down was logged. One native snapshot at 15:39:20 shows Ethernet Up at
100 Mbps, expected camera neighbor Reachable, the exact UDP listener and six
interface-bound SRT permits. This supports snapshot contention as the direct
cause of these new refusals, not an observed link loss.

Confidence is high for the new captures' exact branch and lifecycle ordering.
The original 04:02:02 EOS and the earlier two CI rapid-cycle faults still lack
branch-level evidence. **EOS did not recur; these captures do not establish
the original EOS branch.** The pending lock holder is also unknown: read-only snapshots and the
durable commit/pending-handover path both use the mutex. A reader-sharing fix,
lock reordering or cached snapshot would remain speculative for the captured
holder. No readiness/recovery behavior fix was made in this bounded slice.

**Actual decoding after automatic application recovery.** A single SRT decoder
process on THINKBOOK-G7 ran from 15:36:00.302608 to 15:42:00.370601 UTC, bounded
to 360 s. First decoded raw frame was 15:36:02.471861; 150 frames were observed
by 15:36:07.326750; final count was **10,626**. The application had recovered
generation 4 without another Start before that first peer connection. The peer
was not connected before the startup fault, so no before-failure decoding or
automatic peer reconnect was demonstrated. This is a partial recovery result,
not the requested complete acceptance sequence or CI-image qualification.

The same decoder continued across a **3.579 s decoder-output observation gap**
at 15:37:11.930358–15:37:15.508946, without manual reconnect. No matching app
fault, refusal, EOS or generation transition was logged. Reader timing alone
does not identify that gap's cause or prove a reconnect. There was no later
refusal/EOS during the six-minute peer window; no longer soak was substituted.
Evidence is `G/srt-continuous.json` and its milestone/progress records. Subsequent
normal SRT Disable passed; the bounded stopped peer received zero frames in
8.116 s. The separate RTSP failed result remains in `G/rtsp-decoded.json`/`.log`.

**Normal closure, restoration and export.** Normal Close was accepted at
15:51:14.572421 UTC. Independent PID/creation-time observation verified all seven
app/WebView processes exited. Diagnostic native cleanup passed at 15:52:34.
The original CI installer `7279f427...` then reinstalled normally, exit 0 in
17.469 s; its exact packaged image `382b48e1...` is restored and was left closed.
No GUI relaunch was used or credited as CI-artifact media qualification.

At **15:56:41 UTC**, independent restored cleanup confirms both owned rules
disabled in ActiveStore and PersistentStore, empty Package/no AppPkgId, zero
product/helper/fault processes, output listeners/endpoints, named managed
permits and application-bound WFP permits. All eight qualification tasks were
retired; no peer decoder fixture remains. Saved RTSP/SRT sections and secrets,
key, selected adapter, camera/PTU configuration and cached roles match the
private baseline; Enable is false and the saved output is RTSP 18554, SRT
18890/125 ms. No unresolved cleanup state or native uncertainty remains.

A final read-only preservation comparison at **16:08:21 UTC** independently
confirms unchanged operator config sections (only runtime `adopted_meta`
metadata excluded), address identities/prefixes, route destinations/interfaces/
next hops/metrics/protocols, DHCP/interface metrics and DNS. It also confirms
zero product processes and zero remaining qualification tasks. Values remain
private; booleans are in `G/baseline-preservation.stdout.log`.

All **68 exported files** verified against their Test hashes, with raw logs and
private profiles excluded (`G/evidence-transfer.json`). Export index SHA-256:
`728e7ebdc9745e4497e5a1f55abbdae66e4467e2ad34eb00ff1a2cf72f5cec81`;
archive: `2a97f36ef0f671ace8c5aace03c174e65eca41e4ebcefe9e1982c2423b88660d`;
restored-state: `3abf508844a64fdc5318c70d23bf4a679d0c207e2aa3c00bdcf1b639bd9f2668`.
Live remote refs still resolve main to `922b414`, v0.6.10 to `f2a6f4f` and
v0.6.11 to `7ed10d8`. Draft 441266851 remains unpublished and public latest is
v0.6.9. Both immutable CI artifact pairs remain unchanged.

## Pending-lock owner capture — 11 November 2026 UTC

This successor worktree is `.worktrees/v0611-pending-lock-owner`, branch
`diag/v0611-pending-lock-owner`, from verified release-derived evidence commit
`81a8c7ee1b78e6f0a2dd75a1d02871c89e5d2a99`. Root edits and prior worktrees are
preserved. Diagnostic source `9d484ec32b4e21e2a11402078a027bb9f50b4faa` tags all
11 production pending-mutex sites as read/write and carries observations from
the actual failed acquisition. A stable nonzero acquisition token identifies
a holder; changed or zero observations remain unattributed. The mutex,
readiness decisions, guard lifetimes, commit/handover barrier and retirement
behavior are unchanged. Only the existing first refusal per transport logs
fixed codes and numeric tokens; no addresses, URLs or secrets are added.

Evidence **H** is this worktree's
`src-tauri/target/pending-owner-20261111T170000Z/`, with a matching private Test
run under `%LOCALAPPDATA%\PocketStreamQualification\v0610\`. This remains an
unsigned local diagnostic, version 0.6.11, with updater artifacts disabled;
it is not a new CI candidate or immutable-artifact qualification.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Diagnostic installer | 48,496,464 | `70873528d8d62e5f909c14f971796880e9fbea3602215987c7c9943f9475b0d7` |
| Packaged executable | 24,699,392 | `1804a07994734e1681d509fc6cb31561c4fa14622cf3231b5e48437f02eead5d` |
| Staged executable | 24,699,392 | `4193f12b992dfae63f6f38e2260c93e133fd89b59242464a31dcb90517885522` |

The packaged administrator/Common Controls manifest, 76 DLL hashes, generated
NSIS contract and the three expected UNK -> NSS byte differences passed.
Generated Rust notices match the preserved identical dependency lock and are
verified at the required packaged path. Rejected intermediate packages and
build-order/prerequisite failures remain in H. No incomplete package was
installed. Source checks passed: 942 Rust / 14 ignored (37.15 s, default
parallelism), 288 frontend, typecheck, build/contracts, formatting, all-target
Clippy and third-party closure. Four additional regressions cover attribution,
ambiguous handoffs, cancellation and commit/handover exclusion.

Test identity/account/session, original CI image and closed native baseline
were rechecked. The full private baseline export completed at 17:13:06, before
application launch; no inventory observer overlapped the reproduction. Bound
camera OPTIONS returned 200 at 17:14:37 with the same replacement camera MAC,
Ethernet GUID/source and Wi-Fi output as G. Recorded power was AC. Installation
exited 0 in 15.336 s with private profile files byte-identical. The first Launch
controller missed a delayed informational `listening-notice-dialog`; its failed
receipt and value-free accessibility inspection are retained. The established
close-only acknowledgement through Inspect succeeded without relaunch or a
product change.

| Observation | Established result |
|---|---|
| Three SRT Start/Disable cycles | Generation 3 / transport 3 refused at 17:23:07.673346, upstream `rtsp_before_send`, `pending_snapshot_busy`. Backend Disable follows at 17:23:07.810109: **136.763 ms later**. No runtime fault is claimed for this interrupted case. The transport context identifies SRT despite the shared upstream stage label. |
| Separate SRT Start | Generation 4 / transport 4 refused at 17:24:50.187349, `accept`, `pending_snapshot_busy`; a GStreamer error followed at .197189 and automatic recovery rebuilt instance/data 2, transport 5. Listener readiness at 17:25:01.328293 is **11.141 s from refusal**, with the recovery record reporting 11.130 s from its own start. |
| Owner attribution | Both refusals have `pending_owner_state=unattributed`, `pending_before=0`, `pending_after=0`. Neither establishes a reader/writer holder. Publication/release gaps, a queued/reserved permit and a complete short acquisition between observations remain distinguishable possibilities. |
| Single SRT peer, 180 s | The decoder logged automatic reconnect attempts and subsequently decoded **5,021 raw frames** without manual reconnect, first frame 17:25:03.112432 in the peer clock. No pre-failure decoded frame was observed; full recovery acceptance remains pending. No >2 s frame-output observation gap was recorded after decoding began. |
| RTSP peer | OPTIONS 200 and **150 decoded raw frames**, exit 0 in 7.662 s. This isolated diagnostic result does not erase G's preserved 503/zero-frame failure. |

No EOS recurred; the historical 04:02:02 EOS branch remains unproven. A read-only
clock comparison bounds Test-minus-peer between -1.484 and +0.940 s at the
sample, so fine cross-host event ordering is not asserted. The three cycles
are not an R2 cohort, and their first Ensure can rewrite the installer template.
No production behavior fix is justified by H's unknown holder alone.

Normal Disable and Close completed; Close ran 17:34:06.595–17:34:07.533. At
17:34:12, all seven recorded app/WebView processes had exited. Diagnostic
cleanup passed at 17:34:26. The original CI installer reinstalled normally,
exit 0 in 17.138 s, restoring packaged hash `382b48e1...` and leaving it closed.
Independent restored cleanup at **17:37:50 UTC** confirms two disabled owned
rules, zero product/helper/fixture processes, output listeners and application
WFP permits, with settings/secrets/roles preserved and all owned tasks retired.
The subsequent baseline comparison also confirms unchanged addresses, routes,
DHCP/interface metrics, DNS and operator config sections (only runtime
`adopted_meta` excluded). No cleanup uncertainty remains.

All **81 exported files** verified against Test hashes. Index SHA-256 is
`0fbdaf07cfc81e3c66fece11d10583295b260559516f329c9707c80c2e1944e0`;
archive SHA-256 is
`a64896ea83231e42be90ef82f709b24f7636c39b5ec508649f5cf33346960ab2`.
H contains 675 deduplicated redacted events merged from the indexed captures;
the initial derived-array parsing failure is retained. Raw logs and profiles
remain private on Test. The next diagnostic refinement must cover acquisition
attempts through actual unlock, including queued access, without guessing a
holder from a later read or changing the readiness decision.

## Pending-lock holder established — 11 November 2026 UTC

The second owner capture, **H2**, is
`.worktrees/v0611-pending-lock-owner/src-tauri/target/pending-handoff-20261111T173700Z/`.
Diagnostic source `80e978ddc18ea1855a538f8a1878e150c2786bdb` retains the same
exclusive mutex and readiness behavior. It additionally tracks fixed-site
acquisition attempts through actual unlock, covering queued/reserved permits
and complete short acquisitions. Ambiguous or mixed candidates remain
unattributed. Only the existing first-refusal record is extended; no sensitive
URLs, camera credentials or SRT secrets are logged.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Diagnostic installer | 48,497,112 | `edfcd2b52ad801487a8607ec9a871110a46b9c75ba95b95b594d093c32e10fdc` |
| Packaged executable | 24,741,376 | `3477b08619d2e7b9b78122ca26dd9b053fdc145cc6113bca615c66e46f116ed4` |
| Staged executable | 24,741,376 | `e4562f4df9d0b736543ef5ce93572313814dc9839c78c2b7243d24eeeb622c36` |

This is another unsigned local diagnostic, not a CI candidate. Administrator/
Common Controls manifests, 76 DLL hashes, generated NSIS contract, required
Rust notices and the three expected UNK -> NSS differences passed. Final source
checks: **945 Rust passed / 14 ignored**, default parallelism, 36.59 s; formatting,
all-target Clippy and build/contracts passed. Frontend code is unchanged from
H's 288-test/typecheck result. The immediately preceding full Rust run had one
SRT fake-policy fixture fail its PLAYING transition (944 passed, one failed,
14 ignored); that failed log is preserved without an assigned cause. The
unchanged rerun passed. Added diagnostic regressions include an actual queued
Tokio permit before guard publication, cancellation and ambiguous candidates.

Fresh Test identity/account/session, original CI image, native closed baseline,
AC power and operator configuration were checked. H's full private firewall
inventory is referenced explicitly; a new bulk observer was not run during
reproduction. The bound camera returned OPTIONS 200 at 17:53:32 with the same
replacement MAC `40-CD-3A-03-28-E2`, Ethernet GUID/source and Wi-Fi output.
Installation exited 0 in 15.184 s; private profile files were byte-identical.
The UI controller acknowledged the delayed informational listening notice
through its normal close-only action. No product UI behavior changed.

**Confirmed production defect:** at **17:57:20.576281 UTC**, SRT generation 2,
instance/data 1, transport 2 refused `srt_before_send` with
`reason=pending_snapshot_busy pending_owner_state=stable pending_owner=scope_filter
pending_phase=read pending_acquisition=1293 pending_before=20689 pending_after=20689
pending_candidates=1`. The same nonzero acquisition surrounds the actual failed
try-lock. Another read-only `adapter_selector::probe_scope_with` pending filter
therefore held the mutex. The exact outer caller/thread is not distinguished;
the held critical section and read phase are established.

The runtime fault follows at .576461, Starting -> Recovering at .576699, bus
error at .576868 (`shutdown_requested=false`), shutdown at .576886 and retirement
at .581302. Backend Disable arrives at **17:57:20.795466**, **219.185 ms later**;
the UI Disable timestamp is also 171.017 ms later. This is a read/read collision
that falsely rejects an otherwise valid readiness snapshot, not a refusal
caused by that Disable. Native selection/index/Up checks passed first. Disable
interrupts this recovery, so this three-cycle capture claims no recovery or R2
acceptance. No EOS occurred; H2 does not establish the historical EOS branch or
retroactively identify the holder in G/H's other failures.

The smallest justified behavior change is shared pending readers with exclusive
mutations and durable commit/handover. Fresh native observations, pending-IP
exclusion and held/queued writer barriers must remain intact. Implementation
is isolated in `fix/v0611-pending-readers` from verified release-derived commit
`81a8c7e`; experimental owner instrumentation is excluded. Its regressions,
unused version/tag, CI build and exact-artifact Test qualification remain work
to complete, with no timing budget relaxation.

The diagnostic was stopped normally after three cycles; saved RTSP/disabled
output was restored. All seven recorded app/WebView processes exited by
18:00:26.850517; diagnostic native cleanup passed at 18:00:39.868949. Original
v0.6.11 CI installer restoration exited 0 in 15.657 s, restoring packaged hash
`382b48e1...`. At **18:03:54.130888 UTC**, independent checks found two disabled
owned rules and zero product/helper/fixture processes, output listeners or
application WFP permits. Settings, secrets, selected roles and native baseline
were preserved; four owned tasks were retired. No cleanup uncertainty remains.

All **47 exported files** verified against Test hashes at 18:04:42.
`H2/evidence-transfer.json` identifies the export. Index SHA-256:
`49eadc5a2df3342e1b80f9904fbbac78d49b38d3fa17233b3aeba2798c8dd2e7`;
archive SHA-256:
`8a03ba8b92aaef0376dea9d855972a52e1caa8cbe8e8bbb506e519568c9600a4`.
Private profiles and raw logs remain on Test. Main and both existing tags and
CI candidates are unchanged; v0.6.12 was verified unused before preparation.

## Pending-reader fix candidate preparation — 11 November 2026 UTC

Branch `fix/v0611-pending-readers` in `.worktrees/v0611-pending-readers` is based
on verified release-derived `81a8c7e`, with H/H2 documentation carried forward.
The production change replaces the pending-address mutex with Tokio's reader/
writer lock. Five read-only sites share readers; six mutation/commit sites
remain exclusive. The readiness check uses `try_read` after the same fresh
native selection/index/Up observations and excludes the same pending addresses.
Active and queued writers still refuse readiness without waiting. Durable
commit and exact breadcrumb removal remain under one exclusive guard, with no
await between them. Experimental owner instrumentation is not included.

Three regression tests cover a held reader with fresh native addresses and
pending exclusion, a queued writer and its cancellation, and exclusive durable
commit/handover with failed-commit breadcrumb retention. Existing active-writer,
selection, cancellation, retirement, native accounting and recovery tests remain
in place. The prior first-refusal and EOS diagnostics are retained.

Version **0.6.12** was verified unused remotely before updating all five source/
lockfile root versions. `bump-version.ps1` failed to parse under this host's
Windows PowerShell 5.1 before execution; PowerShell Core is absent. Counted
exact replacements performed the same version update without changing the
release script. Evidence **J** is this worktree's
`src-tauri/target/pending-readers-20261111T181000Z/`. The first frontend build's
sandbox directory denial is preserved; the unchanged build with dependency
access passed. Frontend **288/288**, typecheck, build/contracts, formatting and
all-target Clippy passed. The first full Rust run had **940 passed / one failed /
14 ignored**, 37.31 s: the existing SRT fake-policy fixture failed to enter
PLAYING, as also seen before this fix in H2. Its log is preserved. The unchanged
full rerun passed **941 / 14 ignored in 37.03 s**, at default parallelism,
including all three new regressions. No native mutation fixture runs
on the development PC. CI and installed-candidate results are recorded below
when available; local results do not qualify an artifact.

## v0.6.12 exact CI candidate follow-through — 11 November 2026 UTC

The confirmed pending-reader fix is source **`e98717193164f2682ad1f9effe8e9a188cd14483`**
on `fix/v0611-pending-readers`, with new immutable application tag **v0.6.12**.
Application and workflow commits are identical. Source
[CI 43076399083](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/43076399083)
passed all six jobs: Windows **941 / 14 ignored** (36.24 s), Linux **840 / 2
ignored** (27.20 s), frontend **288**, browser checks at both sizes, notices and
audit. The
[release run 43076399335](https://github.com/RustRunner/PocketStream-Desktop/actions/runs/43076399335)
passed its own 941-test Windows rerun (44.28 s), typecheck, contracts, formatting,
Clippy, notices/audit, staged closure, generated installer and installed G3.
No workflow retry or existing-tag change was needed.

| Candidate artifact | Bytes | SHA-256 |
|---|---:|---|
| CI installer | 48,512,019 | `79377f5b25f74fb13cf265728959ea04a748b6731b67afbd16f0c1d5bc5fcefa` |
| Packaged executable | 24,756,224 | `18142f366afb924709505c07e99ff19e51d7fccdb5285f989c10afce3f536c18` |
| Staged executable | 24,756,224 | `d3d442af810802b9994eee19544a3f9b0991017549f8bcea3cd57bdba21e45c5` |

J's `candidate-identity.json`, `payload-comparison.json`, `updater-verification.json`
and downloaded CI receipts tie these identities together. Installed G3 receipt:
`a7072b182cfeee3ee86b154076266d65ad702a7cccf2839e0cf425ccc2de103d`.
The download matches GitHub's asset digest and CI's installed bytes. Updater
and trusted-comment signatures verify; altered installer bytes are rejected.
The packaged administrator/Common Controls manifest, all **76 DLLs**, generated
NSIS compile contract and only three UNK -> NSS byte changes pass. Required
`resources/licenses/generated/THIRD-PARTY-RUST.md` is present, SHA-256
`3a869762d4fc019f9ad047cc5954dad7e61cc6b9ef3496a0ec57ac3ff37f58f1`.
The candidate remains an unpublished draft; no public feed or main merge occurs.

Test identity, elevated account, signed-in/unlocked TSD-0311 desktop, original
CI image, saved replacement camera and clean native baseline were rechecked.
Bound camera OPTIONS returned 200 at 18:50:27 with the same MAC/GUID/source.
Normal installation exited **0 in 15.242 s** at 18:51:09, producing the exact
packaged hash above with profile files byte-identical and both owned templates
disabled. Qualification uses this CI image; local H/H2 results do not transfer.

The first startup policy native/script durations are **6.359 / 5.090 s**, with
zero admission wait; full address/native reconciliation completed separately
at 18:52:01.848090. The following cohorts each retain one warmup and **ten
measured cases**, at the saved explicit Wi-Fi scope on AC/Balanced power:

| Cohort | Ensure native p50 / p95 | Disable native p50 / p95 | Result for recorded conditions |
|---|---:|---:|---|
| Unchanged SRT, UDP 18890 | 6.838 / **7.931 s** | 3.574 / **3.817 s** | 10/10 within unchanged 15/8 s limits |
| Changed RTSP, TCP 19554 / 18554 | 9.227 / **9.326 s** | 3.627 / **3.687 s** | 10/10 within unchanged 15/8 s limits |

Ensure script p50/p95 is 5.818/6.620 s for unchanged SRT and 7.658/7.710 s for
changed RTSP. Disable script p50/p95 is 2.572/2.837 and 2.607/2.670 s respectively.
Runner minus script duration is 0.957–1.643 s across these measured calls; this
includes process startup and other runner costs, not a separately isolated
process-start measurement. Admission is 0 ms except one SRT disable at 5 ms.
The source records module loading and individual policy stages separately in
`J/timing-stage-summary.json`. SRT reports unchanged templates; all ten changed
RTSP cases report updated templates. The SRT warmup's initial repair is retained
separately (8.804 s native ensure), not counted as an unchanged measured sample.

Resource snapshots are outside the cohorts: AC, Balanced, 1.706 GHz reported
current clock, 16% then 5% CPU load and approximately 8.9–9.0 GiB free physical
memory. No bulk native snapshot/polling observer runs during their timed calls;
the established UI/socket checks remain part of the procedure. Native/WFP
snapshots occur after each cohort. These observations do not establish matched
historical power/resource conditions or quantify every observer's contribution.
This is a passing affected subset, **not full R2**.

No pending-snapshot refusal or EOS was observed in the two cohorts. All 11 SRT
refusals are `relay_retired`, **0.986–4.263 ms after** their corresponding backend
Disable (`J/srt-cohort-refusal-order.json`). This differs from H2's confirmed
reader refusal 219.185 ms before Disable. Normal synchronous Disable retired
each listener, and post-cohort snapshots found disabled rules and zero owned
WFP permits.

The saved RTSP output returned OPTIONS 200 and decoded **150 raw frames** on
THINKBOOK-G7 in 5.672 s, exit 0; after normal Disable, the peer could not connect.
Active SRT and RTSP snapshots independently verify six permits each, including
the exact application, local port, protocol and Wi-Fi LUID `19985273102270464`
with equality conditions and required layers.

The single SRT decoder ran **360.035 s**, 19:04:19.825526–19:10:19.844233 in the
peer clock, and decoded **10,774 raw frames**, with zero recorded frame-output
gaps over two seconds and no reconnect/EOS events. The observer stopped its
own decoder at the bound (exit -1, not a natural pipeline exit); Test logged
normal caller removal at 19:10:23.731672. No application EOS or recovery occurred.
This is sustained remote-media evidence, not recovery acceptance. Peer and Test
timestamps are not used to claim subsecond cross-host ordering.

The live SRT -> RTSP selection preserved desired streaming. SRT retirement
completed at 19:11:03.147231 before RTSP Ensure admission at .195395; RTSP
listened at 19:11:10.479809. A fresh native observation found SRT disabled,
RTSP enabled and only six RTSP permits. An unnecessary subsequent Start
controller refused its precondition, `Expected stopped listener before Start`,
before issuing an application command. Its failed receipt is retained; the
already running listener is used for the extended RTSP observation. This is a
qualification-controller sequencing error, not a new production defect.

The extended RTSP serve-guard check decoded **5,400 raw frames in 180.688 s**,
OPTIONS 200 and exit 0, from 19:13:21.177766 to 19:16:21.866107 in the peer clock.
Its one 240-second observation bound scales the established 150-frame peer
procedure to 5,400 frames; it changes no application timing budget. Captures
through that run contain zero pending-snapshot refusals, EOS events or non-none
relay faults. Both peer decoders exited. Normal output Disable restored the
saved stopped RTSP selection before Close.

All three startup observations use the same installed CI image. These are
policy durations, not total application startup or media readiness:

| Policy completion UTC | Native runner | Policy script | Admission | Full native reconciliation complete UTC |
|---|---:|---:|---:|---|
| 18:51:54.058699 | 6.359 s | 5.090 s | 0 ms | 18:52:01.848090 |
| 19:19:38.237507 | 6.296 s | 4.956 s | 0 ms | 19:19:45.983128 |
| 19:21:21.624978 | 6.494 s | 5.079 s | 0 ms | 19:21:29.398814 |

Each is within the unchanged 12-second policy target. Full native/address
reconciliation completes another 7.746–7.789 s later; the conflicting-write
barrier remains until that completion. Three startup observations do not close
the full repetition/condition matrix. Each normal Close was followed by a
PID-and-creation-time check confirming all seven recorded application/WebView
processes exited. Final exit verification is **19:23:46.501607 UTC**.

For comparison with the preserved failures, these are like-for-like policy
script durations; the repeated candidate cases report nearest-rank p95, not
an inferred historical percentile:

| Operation | Original failed script samples | v0.6.12 script observation | v0.6.12 native observation |
|---|---:|---:|---:|
| Startup | 13.608 / 14.606 / 14.002 s | 5.090 / 4.956 / 5.079 s | 6.359 / 6.296 / 6.494 s |
| Unchanged SRT Ensure | 17.203 / 15.512 / 19.192 s | p95 6.620 s, n=10 | p95 7.931 s |
| Changed RTSP Ensure | 24.164 s | p95 7.710 s, n=10 | p95 9.326 s |
| RTSP Disable | 8.790 s | p95 2.670 s, n=10 | p95 3.687 s |

These comparisons support the affected improvement, with the historical
resource/observer uncertainty stated above. Repeated firewall-provider reads
and module startup explain the established native cost; admission did not
explain the original failures. The retained v0.6.11 policy optimization removes
redundant reads without dropping ownership, Block, identity or post-write
checks. The v0.6.12 change separately fixes the confirmed read/read readiness
refusal. It does not claim to explain the historical EOS.

Final independent native verification at **19:23:54.653573 UTC** found the exact
CI image `18142f…536c18` installed and closed, both ActiveStore/PersistentStore
owned rules disabled, no AppPkgId on either template, zero product/fixture
processes, zero output listeners/endpoints and zero application-bound WFP
permits. All owned qualification tasks were retired. At **19:23:58.676006 UTC**,
address/prefix identity, routes/next hops/metrics, DHCP/interface metrics, DNS
and operator configuration sections matched baseline. Key, saved secrets,
camera/PTU roles and output settings were preserved; runtime liveness metadata
and device-cache observations are not asserted byte-identical. No cleanup
uncertainty remains. No Second host, PTU movement or development-PC native
mutation was used.

`J/candidate-final-assembled.json` deduplicates the already redacted captures
without changing originals; `J/candidate-final-timings.json` pairs all measured
calls and retains the warmups. The unchanged full Rust rerun and both CI Windows
runs passed; the earlier local fixture failure remains in
`J/rust-test-policy-fixture-failure.log`. Its adjacent SRT bind conflict on
59011 does not identify the competing owner in interleaved test output; no
production change is attributed to that fixture failure.

The final Test export was downloaded and **all 110 indexed files** verified
against their recorded byte lengths and SHA-256 values. Receipt:
`J/evidence-transfer.json`; index SHA-256
`818ba93b29c60a4287118e5198585c61755ddd401beabaa4f3452afb01a9daf3`;
archive SHA-256
`f1051fc6b1bb2b58be6ccfa2387b427a647c7c366f48a62d8515ffcf8d1c98da`.
Private profiles and raw logs remain on Test; only redacted evidence and private
file hash/index receipts were exported. Original failed samples and all earlier
candidate artifacts remain preserved.

## Controlled SRT recovery qualification — 11 November 2026 UTC

Evidence **K** is this worktree's `src-tauri/target/srt-recovery-20261111T214000Z/`.
One operator-authorized, precisely targeted upstream TCP abort tested whether an
already-decoding remote SRT viewer resumes without intervention on the exact
v0.6.12 CI image `18142f…536c18`. It qualifies recovery behavior only. It does not
identify the historical v0.6.10 refusal branch or that connection's close semantics.

Test identity, elevated account, unlocked TSD-0311 desktop, the closed exact image,
the staged controller/observer hashes and the absence of leftover tasks were
rechecked. The fresh private baseline at 21:50:57.251 recorded RTSP selected with
the output stopped, SRT 18890 without passphrase or stream ID, the explicit Wi-Fi
scope, Ethernet source 172.31.169.100 and camera RTSP port 554, with clean owned
rules/WFP, on AC/Balanced (3% load, 9.3 GiB free). Bound OPTIONS from
172.31.169.100 to 172.31.169.84:554 returned 200 at 21:51:13 with neighbor MAC
`40-CD-3A-03-28-E2`.

The qualification-only fixture `K/TcpAbort-Fixture.ps1`, SHA-256
`4415032639d35fb5652e5cbcd63bbcc905a8a81f389241e1ff989696bc18219e`, follows the
Microsoft Learn contract: `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)`
rows with in_addr addresses and network-order ports in the low 16 bits at
padding-aware offsets, and one elevated `SetTcpEntry` with
`MIB_TCP_STATE_DELETE_TCB` (12). It parsed under Windows PowerShell 5.1, and its
reader matched all 44 non-listening IPv4 connections that `Get-NetTCPConnection`
reported on THINKBOOK-G7, without entering the abort path. It refuses unless exactly one
Established row matches the installed image's PID and creation time, the verified
source, camera address and saved camera port. It re-validates immediately before
acting, refuses after any refusal, EOS, bus error, runtime fault or recovery since
Start or without an accepted caller, and writes a one-shot marker before its single
call. The documentation does not say whether the remote end receives a reset; only
local effects are recorded.

SSH line-echo clock comparison gives Test − THINKBOOK-G7 = **−1184.525 ms ±10.979
ms** before (best round trip 21.958 ms, 20 samples) and −1188.656 ±9.837 ms after,
a −4.1 ms drift. Cross-host values below carry ±42 ms (clock, ≤16 ms Test fixture
timestamp resolution, ≤15 ms peer line-read latency) and are not otherwise ordered.

The established controller launched PID 16316, created 21:51:31.5693990Z. Startup
policy native/script was 6.529/5.110 s with 0 ms admission; full reconciliation
completed at 21:51:50.444. The controller selected SRT and started the saved output
at 21:53:03.880: Ensure admission 0 ms, native/script 7.234/6.042 s, listener at
21:53:12.858, generation 1 / instance 1 / data 1 on bound transport 1. The running
snapshot at 21:53:51–56 verified the enabled SRT rule, the PID-owned UDP
192.168.141.125:18890 listener and exactly six permits with the exact application,
port 18890, protocol 17 and Wi-Fi LUID `19985273102270464` equality conditions on
the required layers.

One decoder, PID 2524, used the established pinned peer launcher and pipeline. Its
first frame was 21:54:13.720 in the peer clock; Test accepted the caller at
21:54:12.029. The read-only selection at 21:54:33.955 found exactly one matching
Established connection, `172.31.169.100:59941 → 172.31.169.84:554`, which was also
the only camera connection from any process. The application's other rows were the
loopback proxy listener and its rtspsrc pair. The abort followed 1,365 decoded
frames and 45.479 s of gap-free decoding, more than 30 s after the last bulk
observer, with no refusal, EOS, fault or recovery logged since Start.

| Test UTC (21:55:) | After fault | Observation |
|---|---:|---|
| 03.5589 | 0 | `SetTcpEntry` returned `NO_ERROR` (8.3 ms call); tuple absent 11 ms later |
| 03.5653 | 6.3 ms | Proxy forwarding ended with os error 10054; no transport refusal |
| 03.5655–.5659 | 6.5–6.9 ms | `srt_eos` rtsp_source → output → bus, all `Seqnum(22)`, generation 1 / instance 1 / data 1, `shutdown_requested=false`; message source pipeline |
| 03.5660 | 7.1 ms | `Streaming -> Recovering fault=eos` |
| 03.5757 | 16.8 ms | Transport 1 retired (`owner_shutdown`); bus thread joined |
| 04.6444 | 1.085 s | Disable admitted, 0 ms wait |
| 08.1340 | 4.575 s | Retirement complete: native 3.488 s, script 2.461 s, `inactive`, 0 blocks, not uncertain; backoff attempt 1, 0 ms |
| 08.1464 | 4.587 s | Ensure admitted, 0 ms wait |
| 14.0954 | 10.536 s | Ensure applied and verified: native 5.948 s, script 5.071 s, unchanged template |
| 14.1182–.1191 | 10.559–10.560 s | Transport 2 context generation 1 / instance 2 / data 2; listener started; `listener_ready` 10.552 s after recovery start |
| 14.1617 | 10.603 s | Caller re-accepted, 1/10 (the only peer) |
| 14.2483 | 10.689 s | `Starting -> Streaming` |
| ≈14.514 | 10.955 s ±42 ms | First resumed decoded frame (peer clock 21:55:15.698) |
| 45.1851 | 41.626 s | Healthy for 30 s; recovery backoff reset |

Disable stages: trusted modules 967, ownership 891, disable 281, shape 198, input
99, inventory 17 and access 8 ms. Ensure stages: shape 1,055, trusted modules 924,
ownership 785, bind modules 598, blocks 585, readback 492, interface 206, prepare
204, enable 124, input 83, access 7 and inventory 7 ms. Runner minus script is
1.027 s for Disable and 0.877 s for Ensure. The 1.069 s from bus-thread join to
Disable admission precedes native accounting. Both calls are within the unchanged
8/15-second limits.

The same decoder ran its full 300.028 s bound and decoded **8,642 raw frames**:
1,532 before the interruption, then one 10.947 s gap (last pre-fault frame
21:55:04.751, first resumed frame 21:55:15.698, peer clock), then **7,110** after
resuming. There was no other gap over two seconds. At least 150 resumed frames
were decoded by 21:55:24.565 (peer), within 19.82 s of the fault. The last
pre-fault frame (≈21:55:03.566 Test) cannot be ordered against the fault within
±42 ms. Listener readiness to the first resumed frame was 0.395 s ±42 ms. There was
no manual reconnect, restart or Start. The observer stopped its own decoder at the
bound (exit −1), and Test logged the caller's removal at 21:59:16.880. The
post-recovery snapshot at 21:56:32–37, more than 30 s after media resumed, again
verified the rule, the PID-owned listener and exactly six permits with the exact
conditions (new filter IDs 88699–88704).

Normal Disable at 21:59:44.295 stopped data 2 with the expected shutdown-order
`relay_retired` before-send refusal for transport 2, 0.945 ms after `srt_shutdown`.
Disable admission was 0 ms, native/script 3.882/2.804 s, with retirement
`inactive`. A fresh peer then decoded 0 frames within 8 s. The saved stopped RTSP
selection was restored at 22:00:34 without a firewall operation. After normal Close
at 22:01:26, a PID-and-creation-time check found all seven application/WebView
processes exited (22:01:46.154).

At 22:02:09.779 the exact image was installed and closed: both owned rules
disabled in both stores, no AppPkgId, no product or fixture process, no output
listener or endpoint and zero application-bound WFP permits. All six owned tasks
were retired. The key, camera/PTU roles, cached roles, selected adapter and output
sections matched baseline. At 22:02:23.360 addresses, routes, next hops, metrics,
DHCP/interface metrics, DNS and operator configuration sections matched baseline.
The fixture marker and exactly one abort record remain. The redacted export of 55
files was verified by length and SHA-256 (index `d999e786…357b`, archive
`c0c8362b…3cdc`); private profiles and raw logs remain on Test. No Second host,
PTU movement, camera reboot, adapter change, unrelated network change or
development-PC native mutation was used.

**Result: pass**, scoped to automatic EOS-path recovery of one already-decoding
remote SRT caller under these conditions: saved SRT 18890 on explicit Wi-Fi,
AC/Balanced, and one THINKBOOK-G7 caller using the established GStreamer `srtsrc`
pipeline without passphrase or stream ID, after one controlled upstream camera
abort. The application process stayed the same throughout. Recovery kept generation
1 and advanced instance and data from 1 to 2. Retirement and Ensure were verified and
contained within the unchanged limits. The same decoder produced 7,110 frames after
the interruption, and a later snapshot verified the six exact permits.

This fault entered through the proxy's forwarding error, not a readiness refusal;
the transport stayed active until owner shutdown. It shares the downstream path
with the historical event: loopback close, rtspsrc EOS, bus EOS, then `fault=eos`
recovery. It does not identify that event's refusal branch or close semantics.

The run does not qualify:

- the gst_error path or a refusal-triggered retirement;
- RTSP output;
- callers with a passphrase or stream ID, or other client implementations;
- battery conditions;
- repetition; this is one sample.

The bounded peer message buffer filled with per-frame property notifications, so
`srtsrc` messages around the interruption were not retained. Frame counting and gap
timing use the established line pattern and are unaffected. The historical 24.173 s
v0.6.10 recovery is not compared beyond recording: images, timings and conditions
differ.

## Battery preflight observation — 11 November 2026 UTC

Evidence **L** is `src-tauri/target/r2-matched-power-20261111T223749Z/` in this
worktree. The operator requested the matched-power cohorts, then questioned their
value and whether further production/test changes were justified. Both cohorts
were held before execution while that scope decision was pending. No Ensure/
Disable cycle or stream was started, and no battery-cohort pass is claimed.

Test was initially AC/Balanced at 100% charge, closed on the exact v0.6.12 CI
image. The operator disconnected only the charger. Fresh baseline at
22:40:43.200684 verified Offline/Balanced, 100% charge, the same host/account,
unlocked desktop, camera/adapter identities, stopped saved RTSP output and clean
owned native state. Reported clock was 1505 MHz, load 3%, free memory about 9 GiB.
The bound replacement-camera OPTIONS probe returned 200 with the expected MAC.

The one normal launch (PID 17872) produced a startup policy observation:
**11.545 s native / 9.688 s script**, admission **0 ms**, contained and exited,
policy completion 22:42:07.409111. Script stages in milliseconds: ownership 3763,
trusted modules 2331, inventory 1885, shape 936, disable 540, input 213, access 20.
Full native/address reconciliation completed separately at 22:42:21.098346.
This single observation is within the unchanged 12-second policy limit; it is
not a startup percentile or matched historical comparison.

The app was normally closed at 22:44:32–34. All seven recorded application/
WebView processes had exited by 22:45:02.281666. Native verification at
22:45:17.237891 found both owned rules disabled in both stores, no AppPkgId,
no product/fixture processes, output listeners/endpoints or application WFP
permits. Both owned tasks were retired. No production code or regression tests
were changed, and no new artifact was built or installed.

**Baseline exception retained:** the final network comparison failed only its
DHCP/interface-metric group. A numeric CIM comparison narrowed the actual
difference to Wi-Fi index 18, both IPv4 and IPv6 interface metrics **35 -> 45**;
DHCP and AutomaticMetric stayed enabled. All other interface settings, addresses,
routes/next hops/route metrics, DNS and operator configuration sections matched.
Wi-Fi remained Up (234 Mbps at the follow-up). The cause of this automatic-metric
value change is not attributed; no metric was forced back and full network-value
preservation is not claimed. Owned application retirement is verified. An initial
diagnostic rendered deserialized enum numbers versus live enum names; that
comparison is preserved, and the numeric comparison supersedes its broad matches.

The first export verified 31 files. The addendum, including both interface
comparisons, verified **33 files**; `L/evidence-transfer-addendum.json` records
index SHA-256 `70193dbf8f9fe0f836be156ca65ddd8af9cc89e535468d4b65a887ab09802085`
and archive SHA-256 `ae07900d3ecab78e50c90ad7895514133b2d3f3d23f7bebf97fac2838552dfa5`.
Private profiles and raw logs remain on Test. Both exports and the failed baseline
comparison are preserved.

Battery repetition was a diagnostic follow-up to power uncertainty. F hardware
item 3 and consolidated R2 require timing repetitions and the stated limits;
they do not explicitly add a battery matrix. The two already completed AC cohorts
remain valid for their recorded conditions. Battery follow-up is not promoted to
an additional mandatory release gate, and no new production fix is justified by
this single startup observation or the interface-metric difference.

## Operator-requested card cleanup (2026-11-11; source validation only)

The operator requested removal of the re-stream card's **Bound** and **Windows
rule** rows and the duplicate scrollbar in Nodes. This explicitly authorizes
this presentation change in addition to the earlier bounded reliability work.
Implementation is isolated on `fix/v0612-card-cleanup`, based on the verified
release-derived `9752c6fa05fb0531479a2f4e3abbe2626fa40f2c`, with source commit
`a876b4e863523c82efd4025a2c62de8002184a91`.

Both detail rows and their renderer accesses are removed. Policy warnings,
retry countdowns and retained retirement failures use the existing Reason row;
healthy listening has no extra policy detail row. Relay and policy failures can
appear together, with full repair guidance available in the tooltip. The Bind
selector and backend policy/lifecycle behavior are preserved.

The Nodes scrollbar cause was reproduced in an isolated browser with 24 nodes:
both `.card-body` and `.device-list` scrolled vertically. Removing the nested
list's height/overflow restriction leaves the card body as the single scroll
area. The same regression passed afterward at 1280x800 and 960x600, with and
without a capture-scope notice. The last node remained visible and keyboard
accessible; the header and footer stayed visible. Browser checks also confirmed
long Reason text wraps, stopped failures persist, and healthy state clears it.

Validation: **289 frontend tests passed**, TypeScript passed, all build contracts
passed, and the Vite production frontend build passed. The existing Windows
browser check passed at both sizes. Browser rendering and esbuild required the
normal environment outside the restricted filesystem sandbox; no installed app
or native fixture was launched on the development PC. Local evidence is in
this worktree's `src-tauri/target/ui-layout/`: `result.json` SHA-256
`fef673217473f8f550ba7f330a5100b8fa4d7748dbb5b2696acf0923dd9c4ddf`;
preserved pre-fix `nodes-before-1280.json` SHA-256
`c667cdc920ce878cc4a911e18141dc8f811d95950842853aa330b6e84b519865`.
The before capture uses the base production source plus the new layout probe;
the passing capture uses the source commit above.

This is a source-only UI change. No new release version/tag, CI-built installer
or installed-candidate qualification was prepared for it. Test was not contacted
or mutated for this change; its last verified state remains the preceding entry.
The v0.6.12 artifact and its qualification remain tied to their existing hashes.
Including this cleanup in a release requires a new unused version/tag and an
exact CI-built artifact with affected installed UI checks. Existing release gates
remain open; this UI validation does not close timing or recovery gates.

## Remaining gates and release state

The v0.6.10 and v0.6.11 results above remain attached to their original images.
The new unpublished v0.6.12 CI candidate has passing source/packaging checks,
normal Test upgrade, two ten-case AC policy cohorts, three startup observations,
custom-port RTSP/SRT decoded media, live protocol handover, exact WFP conditions,
one controlled EOS-path SRT viewer recovery and normal shutdown/retirement. It
fixes the confirmed read-only pending-holder refusal with reader/writer exclusion
preserved. The standalone native fault
harness still qualifies only its separately identified policy/executor source;
it does not close production application/SRT lease, fault-UI or ownership cases.

Ready for public release: **no**. Reconcile the completed AC timing cases against
the remaining R2 protocol/template, startup/install-repair and Second requirements. Historical
resource/power comparability remains a diagnostic limitation, not an extra battery
gate. All-addresses reference and remaining port/protocol/binding combinations
also remain in the qualification matrix. Historical EOS origin remains
unproven and cannot be attributed from the preserved evidence. The reader-holder
capture establishes a different recorded refusal, and the controlled abort
qualifies recovery behavior only. Automatic recovery of an already-decoding SRT
caller, with at least 150 decoded frames after recovery and no manual peer action,
is now qualified for the recorded EOS-path scope above. Still unqualified: the
gst_error and refusal-triggered paths, RTSP-output viewer recovery, other clients
and repetition. The remaining R3–R10 subcases, separately authorized Second,
disposable VM and operator hardware gates retain their stated pending status. No
Second host is authorized. Paused A4/B,
discovery/Clear, privilege integration and PTU movement remain outside this task.

Next bounded action: reconcile existing R2 evidence and execute only the missing
authorized cases on this exact image. The battery cohorts above remain unrun
pending the operator's scope decision; do not repeat the completed AC cohorts
without an identified coverage gap. Second-host repetitions still need separate authorization.
RTSP-output recovery needs its acceptance stated before it runs, for example a
fresh session decoding without operator action. The established RTSP peer
pipeline (`rtspsrc` under gst-launch) has no reconnect behavior and exits at end
of stream. No further timing or EOS production fix is justified by current evidence. Native policy-failure UI still needs the
prescribed separately identified fixture. Any further production change needs its
own unused version/tag and exact CI artifact qualification.

Test remains installed on **v0.6.12**, normally closed with owned native retirement
verified at **22:45:17 UTC**. The Wi-Fi automatic-metric baseline exception above
is retained; full network-value preservation is not claimed for L. The prior
release completion checks identify v0.6.12 draft **442083374**, v0.6.11 draft
441266851 and v0.6.10 draft 440937913, all unpublished. Main remains
`922b41434bd16a76eedddace9cdf6bbb101e0901`; all three immutable tags resolve to
their recorded application sources. Public latest is still v0.6.9, release
427201837, with updater asset 686372120 SHA-256
`e2002dce38f57c36cb4f607a9192f4d318c75d4c1d082d54085c34a91c8ab66a`.
Root edits and existing worktrees are preserved. No main merge, public feed
update or publication was performed.

Known product limitations are retained in [release notes](../../RELEASE-NOTES.md)
and [user instructions](../../README.md): current discovery contention/history,
non-atomic Clear, persistent host bindings, separate shared-subnet protection and
unchanged administrator privilege model. S1-S5/D/B are not included in this train.
