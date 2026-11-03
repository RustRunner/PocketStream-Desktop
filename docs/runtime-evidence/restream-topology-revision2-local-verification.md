# Re-stream bind topology: revision 2 local verification

Date: 3 November 2026. Local implementation checkpoint; hardware qualification and release readiness remain **pending**.

## Baseline and scope

Read the complete revision 2 specification at `C:\Users\joshu\Documents\Untracked\02NOV26-restream-start-topology-race-fix-spec.md` and the predecessor's `firewall-revision3-local-verification.md`. No applicable `AGENTS.md` was found in the repository, implementation worktree, or their ancestors.

Verified the clean `hotfix/firewall-r3` worktree at `6dd6707577974c7a3079a0cdb01ddb5da3666e42` before editing. Created `hotfix/restream-topology-r2` at that HEAD in `C:\Users\joshu\PocketStream-Desktop\src-tauri\target\topology-r2-worktree`. All three predecessor commits (`d7f8644`, `0728129`, `6dd6707`) remain ancestors. The hotfix HEAD had not advanced at final review.

The original checkout remains `work/privilege-v2-b-r5` at `fd65b1dd4a1c220eb30b039eb642868373099725`, with its unrelated README, DEVELOPMENT and image changes preserved. No merge, push, publication, release version change, installer operation or privilege-branch integration was performed.

## Acceptance review

| Requirement | Implementation and local evidence |
|---|---|
| Pure row resolution | `bindings::resolve_rows` contains the existing selection body. The async wrapper still samples revision before its bounded native read. Tests cover GUID/alias/rename, missing/ambiguous/down/empty identity, unusable addresses, filtering, sorted/deduplicated wildcard exposure and supplied stamps. |
| All six checkpoints | Start and recovery use shared `bind_validity` classification at preflight, policy and install. Global revision equality is only a dirty-observation fast path, never a listener installation/abort condition. Known wildcard observations refresh exposure or become Unknown; explicit binds reject relevant mismatch or failed resolution. |
| Ownership and cleanup | Full epoch, stored intent, desired state and generation guards surround validation reads and installation. Failure/retry attribution rechecks ownership after candidate shutdown and generation-owned lease retirement. Superseded reads and cleanup cannot publish topology failure for a newer intent, including one retaining the old generation. Existing genuine-supersession error text is preserved. |
| Atomic scope publication | Intermediate refreshes stay local. Successful installation publishes the final spec and listener under the state lock; Start returns that same scope. No returned observation is relabelled with a later revision. |
| Watcher handoff | After lifecycle acquisition, the watcher compares against the current published spec under the state lock, retaining revision, generation, instance and intent guards. The regression reserves N while A is published, blocks recovery's final observation, lets the watcher capture A/N and resolve B, then installs B/N before releasing the watcher. N never changes during that handoff. |
| Freshness and retries | Tests move revision during final Start/recovery reads, verify the older returned stamp installs, and reconcile a later watcher observation. Unknown repairs at the same revision. Unrelated churn reaches listener readiness on the current recovery attempt; actual invalidation follows normal retry/backoff accounting. |
| Narrow instance providers | Private binding and policy providers are shared by the service and supervisor. Initial resolution, validation, watcher/recovery resolution and all relay retirement paths use them. Tests script per-instance observations and policy outcomes with notification barriers; no production topology mutation, host adapter reconfiguration or global mutable hook was added. Fixtures remain local to the relay tests because no other module needs them. |
| Firewall/lifecycle preservation | Production policy providers await the existing ensure/disable wrappers inline. Firewall settlement, retained barriers, cancellation, lease ownership, Stop ordering and synchronous teardown contracts are unchanged. Existing settlement, caller-abort and old-Stop regressions pass. |

Only `src-tauri/src/network/bindings.rs`, `src-tauri/src/streaming/relay_service.rs` and this evidence file are part of the task diff. No URL-refresh, admission, status/discovery, IPC, frontend, policy implementation or configuration change is included. No material specification deviations are known.

## Local checks

Checks ran from the task worktree using the installed GStreamer SDK and the existing ignored Cargo target cache. Ignored resource placeholders and the predecessor's generated frontend dist provided compile inputs; they are not packaged runtime or qualification artifacts.

| Check | Final result |
|---|---|
| Focused relay suite (`streaming::relay_service::tests`) | **57 passed**, zero failures, normal parallel execution |
| Focused binding suite (`network::bindings::tests`) | **8 passed**, zero failures |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` | **889 passed, 14 ignored**, zero failures, outside sandbox |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --check` | Passed |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed |
| `npm run check:contracts` (Windows `npm.cmd`) | Passed: DOM, RTSP/SRT, IPC, installer source and Rust boundaries |
| Final diff/ancestry review | Passed; predecessor commits retained, no unrelated source changes or whitespace errors |

The sandboxed full Rust run passed 886 tests and failed only the existing `list_all_returns_ok`, `list_physical_returns_ok` and `list_all_adapters_returns_ok` host enumeration tests, each reporting `Network("Native operation failed; inspect network state before retrying")`. The unrestricted full rerun passed all 889. Native qualification tests remained ignored. PowerShell execution policy blocked `npm.ps1`; invoking `npm.cmd` ran the same contracts script successfully. There are no remaining local verification blockers.

During development, health assertions were corrected to accept both Listening and Streaming (SRT may already be Streaming). A recovery test uses the actual backoff clock because pausing Tokio also advances the existing native-thread shutdown timeout. Race ordering uses explicit notifications or a polled pending future, not sleeps. The newer-Start supersession fixture uses a separate replacement endpoint to avoid incidental immediate RTSP port reuse; recovery invalidation tests still rebuild the same endpoint and verify expected lease retirement and attempt counts. Clippy's fixture lock warning was fixed by ending the guard's lexical scope before awaiting Stop. No production teardown or timeout was changed to accommodate these tests.

Routine logs are retained as ignored `topology-*.log` files in the implementation worktree. Earlier failed development runs are diagnostic only; the final results above describe the final source diff.

## Remaining qualification

Hardware qualification was not performed. On DESKTOP-PI5BMJR, then the development PC, run the specification's 20 wildcard Start/Stop churn cycles with both protocols; explicit Wi-Fi/unrelated Ethernet churn; settled address-change recovery; and concurrent Stop/newer Start cases. Retain final listener, scope, rule and redacted validity-event evidence. A real unusable/down interval may legitimately consume recovery attempts.

Admission/churn overlap qualification requires a candidate with all three firewall revision 3 commits, this change and the separately deferred admission-wait implementation. Enabled-rule/WFP verification, remote RTSP OPTIONS 200 and H.264 buffers, SRT handshake/media, installer upgrade and policy timing/timeout qualification remain subject to the predecessor's release gates. Scope convergence and loopback unit tests do not establish remote reachability or firewall enforcement. Privilege-branch integration and its installer maintenance checks remain separate work.
