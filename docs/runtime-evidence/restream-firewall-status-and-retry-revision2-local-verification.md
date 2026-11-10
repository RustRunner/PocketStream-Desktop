# Re-stream Windows rule status and retry: revision 2 local verification

Date: 3 November 2026. Local implementation checkpoint. Hardware, installed maintenance/upgrade and release qualification remain **pending**.

## Actual base and preservation

Read the complete revision 2 specification at `C:\Users\joshu\Documents\Untracked\02NOV26-restream-firewall-status-and-retry-spec.md`, the firewall revision 3, topology revision 2 and native admission revision 2 prerequisite specifications, their three local verification notes, and the release qualification matrix. No applicable `AGENTS.md` was found in the repository, task/prerequisite worktree or their ancestors.

Rechecked refs, worktrees and working files before editing. The clean prerequisite branch `hotfix/native-admission-r2` pointed to **`be3a1ee3180b7e5cbe736f65fbd24a304e66a583`**. Created `feature/restream-firewall-status-r2` from that exact commit in:

`C:\Users\joshu\PocketStream-Desktop\src-tauri\target\restream-firewall-status-r2-worktree`

All prerequisite commits remain ancestors, in order: `d7f8644`, `0728129`, `6dd6707`, `15d7dd4`, `be3a1ee`. Historical `main` at `f81ca5d` was not used as the base. The prerequisite worktree remains clean. Other worktrees were preserved, including the topology worktree's existing changes. The root checkout remains `work/privilege-v2-b-r5` at `fd65b1dd4a1c220eb30b039eb642868373099725`, with its unrelated README, DEVELOPMENT and image changes preserved.

This task does not merge into the privilege branch, publish, install, bump the release version or release the application. Ordinary tests did not mutate real firewall rules or select ignored native qualification tests.

## Implementation decisions and review

- One private `PolicyRetry` record belongs to each desired listener generation. It holds the consecutive admission counter, capped admitted-failure counter and optional Tokio due instant. It is initialized with a new generation and removed with Stop intent; rebuild, successful policy and identical Start retain the failure budget. It never substitutes for `firewall_generation`.
- Classification consumes the existing `PolicyResult` admission flag. Unadmitted Unavailable uses the existing recovery delays without the zero step. Current policy stages and certain settled native failures retry after 60 seconds, with at most five supervisor retries ending in an admitted retryable failure. Uncertainty and unlisted/terminal stages stop automatic retries. An unexpected Ensure Inactive requires explicit refresh. Admission refusals do not consume the failure budget; an explicit same-generation refresh can request another individual attempt after exhaustion.
- The existing apply/retire helpers and instance `RelayPolicy` remain the only policy path. Matching-generation retries Ensure directly. An older lease remains authoritative until admitted Inactive retirement; its actual result classifies the pending apply for the desired generation. No fictitious Ensure/admission result is logged for failed prior retirement. No-call retirement remains idempotent.
- The existing supervisor services policy retries inline on its one-second tick. Faults and recovery have priority. Dispatch rechecks epoch, desired generation, installed listener generation, listener/health liveness and stable health under lifecycle serialization. It uses the installed specification's role, port and native identity, including when an older lease still blocks application. Unsafe explicit identity omissions remain ineligible. No new worker, retry timer service, detached retirement or policy-task registry was added.
- Admission-only supersession cancellation and existing acknowledgement, settlement, retained-ID recovery and outer-cancellation barriers remain intact. Epoch-only supersession does not retire a still-desired same-generation lease. An admitted result can satisfy a coalesced manual request; an unadmitted Inactive sentinel preserves the existing outcome/request and cannot clear a pre-existing lease. Stale handlers cannot clear another generation's schedule. Stop still tears down and retires synchronously, including a captured older lease, and retains unsuccessful retirement evidence.
- `firewall_next_retry_secs: Option<u64>` / `number | null` is the only added serialized field. It uses ceiling seconds for an eligible live generation, stays zero while due/queued/admitted, and is null when unscheduled or ineligible. `FirewallOutcome`, `RestreamServerInfo`, IPC commands, dependencies and policy/executor code are unchanged.
- Each actual relay policy result produces one bounded `event=relay_firewall` line with phase, real lease/attempt generation, role, admission, outcome, verification, Block count, stage, uncertainty and scheduling decision. Reasons reuse JSON escaping and relay credential/token redaction. Full Block names stay in the UI detail rather than the new log line. Existing admission/native/settlement logging is reused.
- The card shows Bound and Windows rule rows after URL. Local Listening/Starting/Reconnecting/Failed text remains separate from the last policy observation. Applied with observed Block names is a possible conflict; missing verification/outcomes and inactive while desired are warnings. Non-inactive outcomes, including failed retirement/startup reconciliation, remain visible while stopped. Long values wrap within the existing scrollable card and retain full text/guidance in titles through text/title assignments.
- The existing Start/Stop controls remain. Start owns its one completion notification, preferring a relevant live observation over a stale reply; absent Start-reply timing never implies a retry schedule. A policy-warning baseline deduplicates stable transitions, suppresses hydration/countdown/warning-to-warning notifications, survives temporary recovery observations and resets while stopped. Bind/protocol/settings operations suppress intermediate transitions, including the interval after protocol status releases controls but before its command reply. Late replies preserve newer listener/stopped observations.

Final diff review checked lifecycle ownership, same-generation epoch changes, older retained leases, supersession, budget retention, status/reply ordering and stopped failures. Existing regression assertions remain, with mechanical private-helper result adaptations, the one-field payload-count update and obsolete policy wording updated to revision 2. Focused Rust cases use the existing instance fixtures in a separate included test file; frontend VM cases share the existing DOM/IPC fixture. The logging test restores its previous global log filter. No material implementation deviation from revision 2 is known.

## Build inputs and local checks

Commands ran from the task worktree using the installed GStreamer MSVC SDK, inherited local pkg-config configuration and existing ignored Cargo cache:

```powershell
$env:CARGO_TARGET_DIR = 'C:\Users\joshu\PocketStream-Desktop\src-tauri\target'
$env:PATH = 'C:\Program Files\gstreamer\1.0\msvc_x86_64\bin;' + $env:PATH
```

Copied the prerequisite worktree's ignored local GStreamer resource placeholders and generated frontend dist as normal Tauri compilation inputs. They are not installer/runtime qualification artifacts. JavaScript commands use `npm.cmd` and the existing ancestor `node_modules`; no dependencies were installed or changed.

| Check | Final result |
|---|---|
| Focused existing relay suite during implementation | 62 passed; original topology, admission, cancellation, Stop and lease tests preserved |
| Focused policy retry suite | 15 passed; also all passed in the final full suite |
| Focused formatter/card/notification VM tests | Passed, including actual Start replies without desired/state/countdown and the three event/reply orderings |
| `npm.cmd test` | **241 passed**, zero failures |
| `npm.cmd run typecheck` | Passed |
| `npm.cmd run check:contracts` | Passed; DOM/restream, 46-command IPC/ACL, installer source and Rust boundaries |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed; the included Rust test file was also checked directly with `rustfmt --check --edition 2021` |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` | **930 passed, 14 ignored**, zero failures, outside sandbox at default parallelism on final source |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed on final source |
| Separate `npm.cmd run check:ui` | Passed outside sandbox at **1280×800 and 960×600**; actual renderer, long scope/reasons/Block names, in-card wrapping, scroll access, full titles, desired/stopped/inactive row visibility, existing sidebar/toast/repeated-click assertions |
| Diff/ancestry/preservation review | Passed; no policy script/executor, dependency, configuration, IPC-command or ACL content changes |

The focused Rust cases cover current/settled stages versus true uncertainty; admission saturation and failure-budget accounting; both protocol role/port/interface inputs; matching-lease Ensure; older-lease retry and further replacement; scheduled/queued/admitted Stop; identical Start during queued/admitted retries; stale dispatch/publication; explicit refresh after exhaustion and for repaired terminal/conflict observations; fault priority and rebuild classification; ceiling/zero/null timing; and exactly one redacted outcome log per actual call.

### Environmental and unsuccessful runs

- The sandboxed full Rust run passed 926 tests and failed the three existing real adapter enumeration checks plus the old 27-field status payload assertion. That assertion was updated to 28 with an explicit nullable-field assertion. The three enumeration checks passed on unrestricted full runs, as in the prerequisite notes.
- Two early unrestricted default-parallel runs passed 929 tests but hit `persistence_and_restoration_failures_are_reported_together`: the unchanged SRT fixture could not reclaim its old UDP port within its existing retry window (OS error 10048). This same intermittent scenario is recorded in the admission predecessor's verification note. It passed in isolation. An eight-thread diagnostic full run passed all 930 active tests. After the final logging-fixture filter restoration, the full suite passed at default parallelism, with `RUST_TEST_THREADS` unset. No SRT teardown, port-release assertion, retry window or production timeout was relaxed. These failures remain recorded; a passing rerun does not establish absence of the intermittent fixture issue.
- The sandboxed browser layout run timed out at DevTools `Runtime.enable`; unrestricted runs passed. Native UI actions are stubbed by the harness. This matches the predecessor's sandbox limitation.
- Existing linker delay-load warnings, sandbox path-canonicalization diagnostics and a GLib Windows application-manifest warning appeared. They did not prevent the final successful checks and are not hardware qualification evidence.

Routine command logs are ignored `status-retry-*.log` files in this worktree. In particular, `status-retry-full-lib-reviewed.log`, `status-retry-clippy-final.log`, `status-retry-npm-test-final.log` and `status-retry-layout-final.log` record the final checks; earlier attempts and the eight-thread diagnostic remain separate. Browser screenshots and geometry results are under ignored `src-tauri/target/ui-layout/`. Build-generated permission line-ending churn was excluded; there is no ACL content change. There are no outstanding local gate blockers after the final successful runs; the observed intermittent UDP fixture behavior remains a limitation to retain when interpreting repeatability.

## Remaining qualification

Hardware qualification was not performed. Use an authorized installed candidate containing every prerequisite and this feature on DESKTOP-PI5BMJR first, then the development PC. Retain actual admission/policy/settlement/listener timings for RTSP/TCP 8554 and SRT/UDP 8890 under contention; qualified settled-timeout versus unresolved-uncertainty cases; approved enabled/disabled/other-protocol Block-rule observations; and Stop/replacement during queued and admitted retries. Verify final listener, rule and lease outcomes, including failures, rather than treating Stop return as proof of disabled policy.

Independent remote RTSP/media and SRT/media, WFP enforcement, installed maintenance/upgrade and installer timing, privilege-branch integration and its `qualification-b2` gates, and release/signing/update qualification remain separate pending work. Re-verify installer maintenance when porting to the privilege branch. Local socket state, last-applied policy, card text, unit tests and this checkpoint establish no measured remote connectivity or release readiness.
