# Re-stream Enable persistence: revision 2 local verification

Date: 3 November 2026. Local implementation checkpoint. Hardware qualification,
privilege-branch integration, installation, publishing and release remain separate.

## Verified base and preservation

Read the complete revision 2 specification at
`C:\Users\joshu\Documents\Untracked\02NOV26-restream-enable-toggle-persistence-spec.md`
before editing. Also read these four notes in the selected base in full:

- `firewall-revision3-local-verification.md`
- `restream-topology-revision2-local-verification.md`
- `native-executor-admission-revision2-local-verification.md`
- `restream-firewall-status-and-retry-revision2-local-verification.md`

No applicable `AGENTS.md` was found in the repository, selected/task worktrees,
their source subdirectories, or their ancestors. The inspected implementation
worktree was clean on `feature/restream-firewall-status-r2`, at exactly
`e1661dcc5ab06a6d9954cb8cc181ed43d3e5a4ad`. Rechecked prerequisite ancestry:
`d7f8644`, `0728129`, `6dd6707`, `15d7dd4`, `be3a1ee`, and `e1661dc` are all
ancestors in that order.

Created the isolated branch `feature/restream-enable-r2` from that exact HEAD in:

`C:\Users\joshu\PocketStream-Desktop\src-tauri\target\restream-enable-r2-worktree`

Historical `main` was not used as the implementation base. The prerequisite
worktree remains clean. The original checkout remains `work/privilege-v2-b-r5`
at `fd65b1dd4a1c220eb30b039eb642868373099725`, with its unrelated modified
README, untracked DEVELOPMENT document and images preserved. Existing worktrees
were retained. At the 3 November checkpoint the implementation was an uncommitted
local diff in the task worktree; see the later commit checkpoint below.

## Acceptance review

| Revision 2 requirement | Implementation and evidence |
|---|---|
| Enable persists before Start | The change handler takes the existing Settings Save latch, builds `buildRestreamEnableUpdate` from accepted config, and sends one existing `apply_restream_settings` transaction. It publishes the flag only after acknowledgement. The VM enable-then-Start case proceeds without Save; backend Enable validation is unchanged. |
| Off stops; on never implicitly starts | Off uses the same settings transaction, with no separate Stop. Frontend cases cover RTSP and SRT in Listening, Streaming, Recovering and Failed desired states, plus already-stopped off/on. The existing RTSP backend proof is retained; the new SRT-selected regression verifies synchronous stop, false/true commits, absent listener/desired state, UDP port release, preserved protocol selection and equality of both canonical sections apart from enabled. The SRT fixture includes a nondefault latency/stream ID and an available protected passphrase. |
| Accepted state and full busy lifetime | Start derives from accepted `config.rtsp_server.enabled` or desired state, subject to existing busy guards. Enable is disabled before config loads and during Start/Stop, protocol, bind and Save work. During Enable/protocol writes all specified controls and the spinner remain busy through command completion and error reconciliation, even after stopped/matching status. No timeout was added. |
| Canonical sections and draft preservation | The builder resubmits canonical ports, token, latency, stream ID and both aliases/GUIDs, with passphrase `keep`. Contracts exercise both flag values and input immutability. Enable success does not reload config or broadly repaint settings. Failure refreshes config while repainting only Enable. VM cases preserve all edited protocol fields, other sidebar drafts, passphrase replacement, unconfirmed deletion and confirmed passwordless intent. |
| Acknowledgement and reconciliation | Success explicitly paints the acknowledged checkbox before applying the operation result. A forced second event may restore the prior checkbox while pending; completion repairs it and a subsequent Save payload reads the acknowledged true flag. Failed writes accept either returned canonical flag, rather than assuming rollback. A failed read preserves the previous snapshot, logs its own error, and appends the specified last-confirmed-value disclosure to the original error toast. No retry or follow-on Stop is sent. |
| Protocol latch ownership | Only the owning handler's `finally` releases `restreamProtocolBusy`, after response processing or canonical error reload. Existing request-generation guards remain. Removed `restreamProtocolPending`, `restreamProtocolExpectedDesired`, `restreamProtocolNotificationsPending`, `restreamSwitchStatusIsFinal`, its import/assertions and the expected-protocol finish argument. Deferred cases cover stopped/live switches, success, rejected commands with deferred successful/failed reloads, refused forced Enable, and a later accepted Off without an older completion overwriting it. |
| Policy notifications and stopped failures | Notification suppression uses the corrected busy latch. The existing protocol notification regression retains its toast assertions and now checks disabled controls. The shared stopped-render path resets the warning baseline even when a command result precedes stopped status. The latest status cache remains intact, so failed retirement stays visible beside Offline. Existing Start preference for newer live observations and CAM-role regressions remain covered. |
| Scope | No new IPC, wire type, dependency, queue, backend production change, lifecycle/retirement change, validation wording change, A04 refactor, installer/version change or privilege integration. The only Rust source addition is the SRT regression in the existing test module, using existing helpers. |

No material specification deviations are known. The existing broad error reload
for protocol/bind/Save remains unchanged; its draft repaint is outside this task.
No guarantee of frontend/backend agreement is made after both write and reload
fail. A completed disable describes the saved flag and listener transaction;
it does not assert verified firewall retirement or an end-to-end latency bound.

## Local checks and build inputs

Commands ran in the isolated task worktree using the existing ancestor
`node_modules`, installed GStreamer MSVC SDK, inherited pkg-config configuration
and ignored Cargo cache. No dependency installation was needed. Rust commands used:

```powershell
$env:CARGO_TARGET_DIR = 'C:/Users/joshu/PocketStream-Desktop/src-tauri/target'
$env:PATH = 'C:/Program Files/gstreamer/1.0/msvc_x86_64/bin;' + $env:PATH
```

The inherited `.cargo/config.toml` points `PKG_CONFIG` and `PKG_CONFIG_PATH` at
that SDK. Copied the prerequisite worktree's two ignored local GStreamer resource
placeholders for normal Tauri compilation inputs. The frontend build generated
this worktree's actual dist output. These inputs are not packaged runtime or
installer qualification artifacts.

| Check | Result |
|---|---|
| `node --test tests/restream-enable.test.cjs tests/restream-firewall-status.test.cjs tests/notification-behavior.test.cjs` | **97 passed**, zero failures; includes **46 new Enable cases** using the shared VM fixture. |
| `npm.cmd test` | **287 passed**, zero failures on final frontend fixtures. |
| `npm.cmd run typecheck` | Passed. |
| `npm.cmd run check:contracts` | Passed; canonical builder/secret/bind, unchanged DOM/card, 46-command IPC/ACL, installer source and Rust dependency boundaries. |
| `npm.cmd run build` | Passed outside sandbox; real Vite dist generated. |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked srt_selected_enable_only_apply_stops_and_preserves_protocol_settings -- --nocapture` | **1 passed**, zero failures. |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed. |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` | **931 passed, 14 ignored**, zero failures outside sandbox, at default parallelism (`RUST_TEST_THREADS` unset). Both the retained RTSP Enable proof and new SRT case passed. |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed. |
| `npm.cmd run check:ui` | Passed outside sandbox at **1280x800 and 960x600**, including the existing card/policy layout, sidebar/accessibility, toast and repeated-click checks. Native calls are stubbed by that harness. |
| Final diff/ancestry/preservation review | Passed; all six prerequisites remain ancestors in order, original checkout/prerequisite worktree preserved, nine intended changed/new files, no whitespace errors or ACL/IPC/dependency/version changes. |

### Environmental and unsuccessful runs

- Creating the requested worktree initially failed because the sandbox could not
  write its Git ref lock. The approved unrestricted command created the isolated
  branch/worktree successfully; no existing branch or worktree was reset.
- The sandboxed build passed contracts but esbuild was denied ancestor directory
  reads while loading `vite.config.js`. The unrestricted build passed.
- The sandboxed browser check timed out at DevTools `Runtime.enable`. The
  unrestricted browser run passed both sizes. These two limitations match the
  predecessor notes.
- The sandboxed normal Rust suite passed **928 tests**, failed only the existing
  three real host enumeration tests (`list_all_returns_ok`,
  `list_physical_returns_ok`, `list_all_adapters_returns_ok`), and left **14 ignored**.
  Each failure reported `Network("Native operation failed; inspect network state
  before retrying")`, matching the predecessor sandbox limitation. The new SRT
  regression passed in that run. The unrestricted normal-parallel run then
  passed all 931 active tests. The predecessor's intermittent UDP port-reuse
  fixture failure did not occur in either full run here.
- Existing linker delay-load warnings and sandbox Cargo path-canonicalization
  diagnostics appeared. No assertion was weakened, no native qualification test
  was selected, and no production teardown or timeout was adjusted.
- Tauri's build regenerated permissions with LF endings. Verified every generated
  permission against the clean base with line endings normalized, then restored
  the task checkout's CRLF endings. There is no permission content or final
  permission-file diff.

There are no remaining local validation blockers. Final frontend rechecks followed
the review correction of test fixture scope/config fields to match current wire
types; no production behavior or existing assertion was relaxed. Broad suites
were not repeated after their final clean pass without a relevant change/failure.

Routine command logs are ignored `enable-*.log` files in the task worktree.
Final frontend results are in `enable-frontend-focused-final.log`,
`enable-npm-test-final.log` and `enable-contracts-final.log`. Build/browser
results are in `enable-build-final.log` and `enable-ui-unrestricted.log`. Rust
results are in `enable-rust-focused.log`, `enable-rust-full-sandbox.log`,
`enable-rust-full-unrestricted.log`, `enable-fmt.log` and `enable-clippy.log`.
Browser artifacts are under ignored `src-tauri/target/ui-layout/`.

## Remaining qualification

Hardware qualification was not performed. On an authorized installed test
candidate on DESKTOP-PI5BMJR, still verify fresh false-config Enable-then-Start
without Save, disable while listening with actual synchronous completion latency,
draft/secret intent followed by Save, persistence across restart, and the same
workflow with SRT selected. Preserve any reported rule-retirement failure.

The predecessors' WFP/enabled-rule observations, remote RTSP/SRT media,
contention/timeout/settlement timing, installed maintenance/upgrade and installer
qualification remain separate. Privilege-branch integration must retain its
`qualification-b2` gates and receive fresh diff/maintenance checks. No install,
publication, version bump or release was performed or qualified by local tests.

## Commit checkpoint: 10 November 2026

Reviewed and committed the nine implementation, regression and evidence files on
`feature/restream-enable-r2`, retaining `e1661dc` and all six prerequisite commits
as ancestors. No production code was changed during this checkpoint review.

Fresh checks passed: `npm.cmd test` (287 tests), `npm.cmd run typecheck`,
`npm.cmd run check:contracts`, `cargo fmt --manifest-path src-tauri/Cargo.toml
--all -- --check`, and the focused
`srt_selected_enable_only_apply_stops_and_preserves_protocol_settings` Rust test
(one passed). The full Rust suite, Clippy, frontend build and browser checks above
remain the 3 November results; they were not rerun at this checkpoint. Fresh test
logs are `enable-checkpoint-npm-test.log` and `enable-checkpoint-rust-focused.log`.
The Rust build regenerated permission-file line endings; their normalized content
was checked against HEAD before restoring the existing CRLF format.

The redundant topology worktree's two modified source files and untracked evidence
file were verified against the blobs already committed in `15d7dd4`; no separate
topology commit is needed. That worktree and the unrelated documentation edits in
the workspace root were preserved.

Local `main` is still `f81ca5d`. The cached `origin/main` is `f042eb1`, six
documentation-only commits ahead; no remote fetch was performed. Neither the
re-stream chain nor the new Enable commit is integrated into main or the privilege
branch. Discovery revision 5 and Clear nodes revision 1.5 remain unimplemented;
their shared release unit, persistent-metric S-R2 qualification, and the hardware,
installer/upgrade and privilege-integration work above remain pending.
