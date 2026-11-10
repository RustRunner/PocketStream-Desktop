# Native executor admission: revision 2 local checkpoint

Date: 3 November 2026. Local implementation and verification checkpoint. **Hardware qualification, installed maintenance/upgrade qualification and release readiness remain pending.**

## Source and prerequisite preservation

Read the full revision 2 specification at `C:\Users\joshu\Documents\Untracked\02NOV26-native-executor-admission-wait-spec.md`, plus both predecessor notes: `firewall-revision3-local-verification.md` and `restream-topology-revision2-local-verification.md`. No applicable `AGENTS.md` was found in the original checkout, either prerequisite worktree, or their ancestors.

Rechecked the actual branches, worktrees and dirty files before editing. Both hotfix refs still pointed to `6dd6707577974c7a3079a0cdb01ddb5da3666e42`. The firewall worktree was clean. The topology worktree still contained its uncommitted `network/bindings.rs`, `streaming/relay_service.rs` and verification note.

Created branch `hotfix/native-admission-r2` in `C:\Users\joshu\PocketStream-Desktop\src-tauri\target\native-admission-r2-worktree` at `6dd6707`. Copied those three topology files byte-for-byte, verified their hashes, and recorded only that prerequisite as local commit `15d7dd44d2b8322b35df65610d4699f6aa227528`. The admission diff is separate from that base commit. Verified all three required firewall commits (`d7f8644`, `0728129`, `6dd6707`) are ancestors.

The original topology worktree and its dirty files were preserved. The original checkout remains `work/privilege-v2-b-r5` at `fd65b1dd4a1c220eb30b039eb642868373099725`, with the unrelated README, DEVELOPMENT and image changes preserved. No reset, privilege-branch merge, push, publication, installation, version change or release was performed.

## Implementation decisions

- One `VecDeque` in the existing executor state stores original sequence, class, enqueue instant and absolute deadline. Selection computes Policy > User > Cleanup with complete ten-second promotions capped at Policy, then original sequence. Queue selection/removal and Idle-to-Running happen under the same mutex. There is no permit, reservation, additional execution phase, helper queue or scheduler framework.
- A future-owned synchronous drop guard removes queued admission, including cancellation after wake but before another poll. Biased abort/deadline checks run before every attempt, including initially Idle, and the deadline and shutdown are checked under the mutex before Running. After Running, returning Pending has no further asynchronous suspension. Cancellation racing after the last abort poll can lose to that transition and then follows the existing admitted cancellation contract.
- Idle waiting futures also recheck at the earliest existing admission deadline. This prevents an expired, unpolled owner from stranding another live waiter. These are the stored admission deadlines inside the waiting futures; no reservation watchdog, detached timer task or priority-promotion timer exists.
- Fail-fast submission and availability use the same live queue and retained-state rules. Background writers never await admission. Initial recovery is waitable; abandoned or Uncertain retained results refuse ordinary admission. Explicit recovery retains its existing exception to queue precedence and its checked retained ID.
- Matching Running/Retained IDs carry explicit requester presence. `Pending::wait(&mut self)` keeps production tickets alive through completion, reply and acknowledgement. Drop marks only its matching ID absent and requests cancellation. Live non-Uncertain acknowledgement remains Busy without a grace timer; abandonment and Uncertain remain barriers. A stale Drop cannot affect a newer ID.
- Managed User requests wait 15 seconds; Cleanup waits 30 seconds with its close signal as the admission-only abort. Their existing wrapper establishes `NATIVE_SCOPE`, retains scope failure/mutation classification, and acknowledges ordinary non-Uncertain results. User expiry keeps the existing Busy text. Existing native execution, settlement and ten-second manager-lock budgets remain separate.
- Runtime policy waits 45 seconds and returns internal `PolicyResult { outcome, admitted }`. Superseded admission returns unadmitted Inactive solely as a cancellation sentinel; timeout returns the specification's unavailable text. Scope refusals are unadmitted; accepted scope/recovery/native failures remain admitted. Test/non-Windows wrapper guards retain their existing native-free outcomes and mark them admitted. No IPC/serialized outcome changed.
- Ensure's admission abort uses the existing atomic epoch, stored intent, desired state and generation predicate, with notification registered before checking and an atomic epoch check before awaiting relay state. Unrelated topology revisions do not abort it. Retirement Disable always supplies a never-resolving supersession abort. Supersession stops affecting a request once Pending exists. Stop remains synchronous under its existing lifecycle serialization; outer cancellation and the existing five-second exit timeout retain their conservative barriers.
- Existing leases clear only after admitted Inactive retirement. Same-generation re-ensure preserves its existing lease. Only the exact provisional lease installed by a never-admitted, now-obsolete Ensure can be discarded; refusals for current intent retain the conservative lease and unavailable state. The topology policy provider and existing policy seams carry the new result and abort input; production still reaches `execute_settling` and retained recovery bookkeeping.
- One lazily started `temporary_cleanup` task belongs to each manager. It retains one handle, a close flag and a coalesced request bit; the durable pending rows are its only work list. It quiesces on a registered notification when empty, so scheduling at either side of the empty check re-arms the same task. It has no periodic scan and continues cleanup of existing rows across mode changes.
- `PendingAdoptOps::remove` and temporary reconciliation schedule remaining durable rows on early refusal, late submission refusal, failure or cancellation. The hook is non-blocking under manager locks; generic adoption fakes need no manager. All production adoption/probe constructors carry the same hook, and startup completion schedules remaining work.
- Cleanup admits before acquiring manager locks, enters the shared `NATIVE_SCOPE`, tries discovery serialization, takes the pause fence, and bounds address-lock acquisition at ten seconds. It re-reads rows and reuses `reconcile_temporary_locked`, preserving adapter/owner/prefix, committed/manual claim and fresh absence/readback checks. Contention finishes and acknowledges a no-mutation attempt before backoff. Remaining work retries after 1, 2, 5, then at most 10 seconds; uncertainty remains fenced.
- Temporary reconciliation now returns its observed errors as well as logging them. The cleanup transaction therefore sees persistence failure after a successful mutation and retains Uncertain instead of treating a swallowed error as success. Existing immediate callers retain their best-effort behavior. A narrow persistence seam and the existing native execution body with injected fake work support ordinary tests without disk or native mutations.
- Exit closes the cleanup task before streaming/address cleanup acquires locks. Queued admission/backoff observes close, while an admitted cleanup requester continues through its response/acknowledgement path. Executor shutdown joins native work before cleanup's handle is joined, outside manager/relay locks. Drain still inspects Running only and skips managed lock acquisition.

Admission decision logs sample `queue_depth` as the number of **other live waiters after removing the deciding entry and pruning expired entries**. Shutdown has already cleared its queue. A dropped admission logs Superseded. Runtime policy logs role, mode, acceptance/refusal reason and admission wait separately from native policy timing. Cleanup scheduling is coalesced, and blocked/rescheduling decisions include remaining row count and bounded backoff.

No policy script, settlement algorithm, runner budget, topology validity algorithm, helper transport, dependency, frontend, configuration format or public IPC shape changed. The small cleanup owner lives in a dedicated network module rather than enlarging the manager facade. No material revision 2 design deviations are known.

## Local verification

Used the installed GStreamer MSVC SDK, inherited local pkg-config configuration and existing ignored Cargo cache. Commands ran from the isolated task worktree with:

```powershell
$env:CARGO_TARGET_DIR = 'C:\Users\joshu\PocketStream-Desktop\src-tauri\target'
$env:PATH = "$env:GSTREAMER_1_0_ROOT_MSVC_X86_64\bin;$env:PATH"
```

Copied the predecessor worktree's ignored local resource placeholders and generated frontend dist for normal Tauri compile inputs. These are local build inputs, not packaged runtime or qualification artifacts. JavaScript commands use Windows `npm.cmd`.

| Check | Final result |
|---|---|
| Focused executor suite | 11 passed, including unpolled-owner expiry, FIFO/aging, simultaneous-ready abort/expiry, no barging, drop, acknowledgement, startup barriers, checked IDs, drain and shutdown |
| Focused native_operations suite | 19 passed, 1 ignored; includes policy/User contention, User expiry behind policy, managed lock cycle, inline native scope, admission-only cancellation, caller-abort persistence/barrier and recovery provenance/role assertions |
| Focused cleanup suite | 7 passed; early/late refusal, scope, coalescing/re-arm, lock contention/timeout, mode change, ownership conflicts, native/persistence failure and queued/admitted shutdown |
| Focused relay suite | 62 passed in normal parallel execution; includes all topology predecessor tests, queued/obsolete Ensure cancellation, retirement across supersession, unadmitted lease handling, admitted cancellation, synchronous Stop and old-Stop/new-listener ownership |
| Focused firewall / native runner | 14 firewall tests passed; 3 runner tests passed, 2 ignored |
| Focused bindings / adoption / BindingStore | 8 / 58 / 7 passed |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` | **915 passed, 14 ignored**, zero failures, outside sandbox, normal parallel execution |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed after final executor change |
| `npm.cmd test` | 231 passed, zero failures, including the pure firewall provider fixtures |
| `npm.cmd run typecheck` | Passed |
| `npm.cmd run check:contracts` | Passed: DOM, RTSP/SRT, IPC, installer source and Rust boundaries |
| Diff/ancestry/source preservation review | Passed; only admission source, focused fixture adaptations and this note belong to the task diff |

The preliminary sandboxed full run passed 911 tests and failed only the existing three real adapter enumeration checks (`list_all_returns_ok`, `list_physical_returns_ok`, `list_all_adapters_returns_ok`), each with the predecessor's native enumeration failure. The unrestricted rerun before the final extra expiry regression passed 914 tests with 14 ignored. The final unrestricted rerun includes that regression and passed all 915 active tests. Ordinary tests did not select ignored native firewall or address qualification. Existing linker delay-load warnings and sandbox path-canonicalization diagnostics are build-environment messages, not qualification results.

One intervening full run passed 914 tests but hit an intermittent UDP port-release failure in the unchanged `persistence_and_restoration_failures_are_reported_together` scenario. The exact scenario passed in isolation, then the full normal-parallel run passed on the same final source. No teardown assertion, socket retry budget or production lifecycle was changed to accommodate it. Its diagnostic log is retained separately from `admission-full-lib-final.log`. There are no remaining local verification blockers.

During development, the new post-admission abort test initially expected an abort-channel receiver to survive successful admission. Its producer correctly found that admission had already dropped that receiver; the test now ignores that send result and still asserts that admitted work is neither dropped nor cancelled by supersession. A zero-test runner filter was corrected to `network::native_runner`, which ran the actual three ordinary tests. The production-only dead-code expectation on the preserved fail-fast `submit_managed` entry documents that managed waiting callers now use `admit`; test/qualification callers still verify that entry's no-barging behavior. No retained-barrier, recovery, topology or lease assertion was weakened.

Routine diagnostic logs are ignored `admission-*.log` files in the task worktree. Earlier compile/test attempts are diagnostic only; the final results above apply to the implementation.

## Remaining qualification and integration

Hardware qualification was not performed. Use a candidate containing all three firewall slices, the topology prerequisite and admission work. On DESKTOP-PI5BMJR first, then the development PC, retain RTSP/SRT contention, policy/settlement/listener timing, saturated User expiry, early/late scratch refusal and eventual exact cleanup, queued/admitted Stop and exit, conservative lease retention, and next-start reconciliation evidence.

Enabled-rule/WFP enforcement, remote RTSP OPTIONS 200 and H.264 buffers, SRT handshake/media, installed upgrade/maintenance behavior, installer timing and the predecessor's explicit post-enable timeout/settlement qualification remain pending. Admission and fake native IO tests prove none of those hardware/release conditions. No unconditional cleanup or end-to-end Stop latency guarantee is claimed.

Privilege integration remains separate. Preserve `qualification-b2` mutation gates before executor creation/waiting/helper work, retain the installer maintenance journal/owner lifecycle and re-verify maintenance after that future port. This task does not merge into the privilege branch or authorize publication, installation or release.
