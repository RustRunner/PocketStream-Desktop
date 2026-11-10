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

The fixed existing post-enable timeout harness was compiled and listed, not run.
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

Host assignments: Test = authorized `DESKTOP-PI5BMJR` at `192.168.1.73`; VM =
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
| R2 | F hardware 3; N: ten ensure/disable cycles with unchanged/custom ports; p50/p95/stages; Test ensure <=15s (goal 10), disable <=8s, startup <=12s, install <=35s; Second ensure <=5s/startup <=4s with capability comparison | Test + Second | Final CI artifact | Partial: individual startup, ensure, disable and install samples within Test budgets (above). Ten cycles, percentiles and Second targets pending |
| R3 | F 4-6; T/N/R: RTSP and SRT, default/custom ports, wildcard/explicit Wi-Fi, WFP permits/interface filters, OPTIONS 200 + >=150 H.264 buffers, SRT handshake/media; Stop removes filters/disables rules and prevents access | Test + Second + Peer | Final CI artifact | Default wildcard and custom Wi-Fi media passed for both on Test/Peer; SRT default needed recovery. Default Disable, custom RTSP Stop and peer negative probes passed. Second and remaining binding permutations pending |
| R4 | F 7; R 3: authorized overriding Block survives install/ensure/Stop/uninstall; disabled/other-protocol observations remain cautious; remove fixture Block and Stop/Start restores media | Test + Second + Peer | Final CI artifact | Partial: Sandbox installer preservation passed. Physical overriding Block, cautious UI and removal/recovery pending |
| R5 | F 8-9; N; R 2/4: fixed post-enable timeout proves actual write and contained/exited writer; successful settle, retained accounting/retry; double failure and failed recovery retain barrier; later qualified Stop retires exactly | Test + Second | Hash-pinned fault fixture and final CI artifact | Pending; fixed harness and guarded controller staged on Test. Execute the firewall revision 3 procedure with its independent baseline and record actual mutations and outcomes |
| R6 | F 10; N exit; Q startup: fixed one-shot failure settles/retries within original workflow; queued/admitted Stop/exit prevent obsolete Ensure; unresolved lease survives and reconciles next start | Test + Second | Fixed fault candidate / CI artifact | Pending |
| R7 | T hardware; R 4: 20 wildcard Start/Stop cycles per host, both protocols, unrelated churn, explicit bind camera churn, settled usable address change without duplicate rebuild; Stop/newer Start wins | Test + Second + Peer | CI f2a6f4f (identity above) | Pending; retain listener/scope/rule/lease generations and churn records |
| R8 | N hardware; R 1: Start/Stop/retry under current real or qualified scratch contention; separate admission/native timing; User admission <=15s, saturation expires without delayed writes; early/late scratch cleanup and retained uncertainty | Test + Second | Final CI artifact / qualified controlled fixture | Partial: ordinary Start/Disable passed with discovery active; recorded admission wait 0 on RTSP. Actual saturation, scratch cleanup and uncertainty pending |
| R9 | E hardware: false config -> Enable -> Start without Save, both outputs; Disable while running waits/reports errors; preserve all drafts/secret intents; accepted flag persists after restart | Test + Peer | Final CI artifact | Partial: Enable/Start without Save and Disable/retirement passed for both; saved SRT port and secret were unaffected by drafts and the port draft stayed visible. Enable true on disk after Close. Visual secret-draft, native failure UI and persistence across restart pending |
| R10.1 | Q fresh/reinstall/upgrade/uninstall in interactive/passive/silent/updater modes; install without /R, correct disabled template shapes, maintenance before deletion, diagnostics on failure | Fresh VM + Test where required | Final CI artifact + hashed legacy installers | Partial: exact final fresh CI /S, Sandbox supported silent/passive/updater/reinstall/uninstall, real Test upgrades passed. Interactive completion and remaining failure/relaunch modes pending |
| R10.2 | Q legacy 0.6.7 migration/custom/duplicate/disabled/program-scoped rules; indistinguishable manual clone convention; foreign/unrecognized/colliding rules; repeated/partial recovery; exact preservation | Fresh VM | Final CI artifact / separately identified partial-provider fault build | Partial: supported seeded migration, preservation, conflict/retry/collision passed in Sandbox. Actual v0.6.7 installer and partial-provider injection pending |
| R10.3 | Q strict malformed/unknown/unelevated/unprotected entry refusal, no GUI/profile/native writes; install gate/HostOwner Busy, cancel, file replacement/maintenance failure, every exit path and launch after release | Fresh VM | Final CI artifact | Partial: Sandbox strict entry, welcome Cancel, supported ownership gates and maintenance conflict/retry passed. Full failure/exit/relaunch matrix pending |
| R10.4 | Q continuous ownership, legacy process/image-in-use refusal, no process kill/previous-uninstaller child, bootstrap-parent propagation, launch/finish timing and independent accounts/logon sessions | Full disposable Windows VM/Second | Final CI artifact | Partial: supported image-in-use refusal passed in Sandbox. Continuous ownership and unsupported cross-account, session and bootstrap paths pending |
| R10.5 | Q binding/settings: Wi-Fi/VPN/non-VPN virtual churn, IPv4 inventory vs native/listeners, failure -> Unknown -> recovery, stable GUID/alias/index/restart, reused/ambiguous legacy alias, failed-save migration, stale async races, QR exclusions | Test + Second + Peer | Final CI artifact | Partial: custom explicit Wi-Fi listener/scope and real settings save/readback passed. Other adapters, churn, errors, migration and restart pending |
| R10.6 | Q hardware: settings save/readback, both confirmation Cancels, selected-adapter proof and positive candidate ICMP, visible playback/recovery, PTU role/position/limits/presets/cold start and individually operator-confirmed directions/Home/stop, normal Close/restoration | Test + physical camera/PTU + operator | Final CI artifact | Partial: visible playback, normal Close and re-stream rule retirement confirmed. PTU web link blocked by current shared-subnet route; physical confirmations, positive ICMP, PTU motion and other hardware cases pending |
| R10.7 | Q existing resource gates: 20 cable cycles, 5 camera reboots, >=60 minutes representative playback/recording/relay, process-tree resources and notices; recovery/address/native postconditions applicable to this unchanged production path | Test + physical hardware/operator | CI f2a6f4f (identity above) | Pending; discovery redesign/S-R2/B gates remain separate |
| R10.8 | Packaged runtime closure/import/plugin/source/G3 installed gate, generated installer trace, requireAdministrator/Common Controls manifests, staged-vs-packaged image identity, updater signature/public key and feed/version checks | CI + read-only development inspection; isolated installed update fixture | Final CI artifact | Partial: final G3, exact runtime/source closure, generated NSIS, PE manifests, staged/packaged comparison and Tauri signature verified. Authenticode absent; true signed updater transport pending |

## Remaining gates and release state

R0 audit repair and source validation passed. Installer built: yes, and the
downloaded hashes match the exact final CI installed candidate. Working on the
tested configuration: yes, including both real upgrades, live preview, default
and custom remote RTSP/SRT, and firewall retirement on Stop/Disable. Ready for
public release: no. The remaining gates above require more isolated Test time,
a separately authorized Second and full disposable Windows VM, and operator-led
hardware testing. The release is still a draft. No tag was moved, no public feed
changed, and no main merge was performed.

Resume with the guarded R5 fault run on Test after rechecking the installed hash,
closed app and disabled-rule baseline, then a normal relaunch without Start for
R9. No further native operations were started after the operator's Stop/Close.

Known product limitations are retained in [release notes](../../RELEASE-NOTES.md)
and [user instructions](../../README.md): current discovery contention/history,
non-atomic Clear, persistent host bindings, separate shared-subnet protection and
unchanged administrator privilege model. S1-S5/D/B are not included in this train.
