# A03 Revision 3 implementation record

Implementation started on 2026-10-25 at `b849dfc0e073a1503c439585386d5665b7d07230`
on `main`, with a clean worktree. This exactly matches the reviewed baseline;
there were no user changes to reconcile. No applicable AGENTS.md was found in
the repository or its ancestor directories. Specification: Revision 3 of
`C:\Users\joshu\Documents\Untracked\23OCT26-A03-orchestration-ownership.md`,
read in full before editing. Only early-start slices 1–6 are in scope.

A4 release qualification remains incomplete/deferred. B and streaming slices
7–10 remain deferred. These source gates confer no installed-package, physical
timing, hardware, firewall, recovery, security or signed-update qualification.
Frozen v2-A evidence is unchanged. No push, publication, installation, reboot
or host network/firewall mutation is part of validation.

Environment: Windows x86_64 MSVC; Rust 1.97.1 (`8bab26f4f`), Cargo 1.97.1,
LLVM 22.1.6, Node v24.14.0, npm 11.18.0. Existing `.cargo/config.toml`
selects `C:\Program Files\gstreamer\1.0\msvc_x86_64\bin\pkg-config.exe`
and its SDK pkgconfig directory. Cargo.lock retains Tauri 2.10.3/Tokio 1.50.0.
Existing build-script test manifest and native delay-load settings are retained.

Baseline rerun (not historical credit): `cargo test --lib --locked` **789
passed, 0 failed, 10 ignored**; fmt and all-target Clippy with `-D warnings`
passed. Frontend **204 passed**, typecheck/contracts/build passed. The
[test inventory](a03-revision3/baseline-rust-inventory.txt) records all 799
Rust scenarios; [ignored tests](a03-revision3/ignored-tests.json) retain all
10 opt-in reasons. Ordinary enumeration failed in the restricted sandbox
(786 pass / 3 enumeration failures / 10 ignored), then passed outside it;
esbuild also needed parent-directory access outside the sandbox. The passing
baseline logs are in [a03-revision3](a03-revision3). No ignored test was enabled.

Each slice is retained as a separate local review commit. Gate results and
scenario movements are recorded below as implementation progresses.

1. Composition: shared managed `Arc<AppConfig>`, `Arc<NetworkManager>` and
   `Arc<StreamManager>`; matching extractors including ACL fixture; object-safe
   bind-once bridge; eagerly constructed registry emitter with unchanged 150 ms
   coalescing; staged dependency guard in contracts; corrected reaper comment.
   Constructors start no tasks. Setup binds before status/watchers/hydration.
   Native request wrappers remain whole workflows. Added bridge bind/unbound
   tests, emitter coalescing/rearm regression and inferred-lookup guard checks.

   Slice 1 gates: 792 Rust passed / 10 ignored (3 new bridge/emitter tests);
   205 frontend passed (1 new boundary test). Fmt, Clippy, typecheck, contracts
   and frontend build passed. No existing scenario was removed or ignored.


2. AdapterSelector owns selection, presence control/task handle and shared local
   MAC callback view. It proposes without committing; facade retirement precedes
   commit. Playback consumes the selection watch in its existing supervisor wait;
   repeated/latest/closed-channel behavior is covered. Frontend event points
   remain. Verified write-only manager name/index fields were removed. Existing
   selection policy tests moved by name; presence task dependency closure follows
   in slice 5. Gates: 795 Rust passed / 10 ignored; 205 frontend passed; fmt,
   Clippy, typecheck, contracts and build passed. Three focused tests added.


3. BindingStore owns AddressIo, address serialization/pause generations, live
   routes, durable temporary adapters, metadata/liveness and manual helpers.
   Facade retains timed lifecycle admission and mode/refresh sequencing; helpers
   run inline within NATIVE_SCOPE. Address/refresh retained adapters now capture
   owned config/facade/bridge references. Cleanup uses the shared config at the
   existing capture-initialization guard. Six existing binding scenarios moved;
   pause-cancellation regression added. Gates: 796 Rust passed / 10 ignored;
   205 frontend passed; fmt, Clippy, typecheck, contracts and build passed.
   Existing caller-abort persistence, uncertain barrier, single-budget admission,
   temporary recovery and managed-drain deadlock regressions remain passing.


4. CaptureSession owns listener/incarnation/candidates/signal/solicitation and
   prior joins; keep/replace/restart decisions and eight existing scenarios moved.
   Capture callbacks receive bridge/config plus documented fence/map adapters.
   Verified unpopulated manager/listener exclusion storage removed; pure legacy
   classifier scenarios remain. A new stop test proves retirement, stale callback
   rejection and parking an unfinished join before the existing drain. No new
   wait/deadline was added. Explicit sweep/watchdog dependencies replace listener
   AppHandle use. Gates: 797 Rust passed / 10 ignored; 205 frontend passed;
   fmt, Clippy, typecheck, contracts and build passed.


5. DiscoverySession owns generation/clock, legacy ARP map and adopt/watchdog
   handles; adoption loop/probes moved into adopt_loop.rs with concrete owner
   dependencies. Presence owns verification execution without service lookups.
   The verified liveness no-op and both callers were removed; live liveness
   stamping remains. Existing watchdog/fence/evidence tests moved by name.
   Added cooperative stop-order/clock retirement and aborted-caller paired-event
   regressions. The sweep still starts after 500 ms and uses its existing fence;
   no sweep join/abort was added. Native drain and best-effort temporary cleanup
   remain at the facade. Gates: 799 Rust passed / 10 ignored; 205 frontend
   passed; fmt, Clippy, typecheck, contracts and build passed.

6. Network closure: readiness supplies playback/relay reads, selection watch,
   verified wake and diagnostic probe; scan and pinger own their workflows and
   handles. The former pinger APP global is gone, retaining its initialization
   gate as an owner field. Snapshot reads remain nonblocking. Automatic route
   publication/IDs and local-MAC refresh enter their owners. The binding snapshot
   retains its original binding/liveness/session-clock read order. All retained
   request/recovery adapters capture explicit owned dependencies and await the
   same whole workflows. Topology returns an observation to the existing watcher
   adapter, including its independent successful retry and failed-observation
   suppression. No temporary network boundary exception remains; the staged
   streaming path has zero permitted lookups. Added five focused regressions for
   topology observation/routing, pinger join lifetime and readiness admission.
   The [architecture record](../architecture/ownership.md) describes actual
   ownership, callback/fence views, native routes and startup/exit order.

   Final gates: **804 Rust passed, 0 failed, 10 ignored; 205 frontend passed**.
   Fmt, all-target Clippy with warnings denied, typecheck, contracts and frontend
   build passed. A Clippy test-module-placement issue was corrected before the
   passing rerun. The additional `cargo build --locked` desktop development build
   passed; it retains the existing LNK4199 unused delay-load-import warnings.
   The built application was not launched for qualification.

| Review slice | Local review commit | Rust pass / ignored | Frontend pass |
| --- | --- | --- | --- |
| 1 | `47d965e` | 792 / 10 | 205 |
| 2 | `a46a222` | 795 / 10 | 205 |
| 3 | `5b5ded8` | 796 / 10 | 205 |
| 4 | `adc16b2` | 797 / 10 | 205 |
| 5 | `73d82b9` | 799 / 10 | 205 |
| 6 | Commit containing this completed record, titled “A03 slice 6: close network dependencies and record ownership” | 804 / 10 | 205 |

Every slice passed all seven required gates. Machine-readable per-slice gate
records, final gate output and the desktop build output are in
[a03-revision3](a03-revision3). Captured PowerShell output was normalized to UTF-8
and trailing log whitespace removed for review; no results were changed.

The [scenario accounting](a03-revision3/scenario-accounting.json) reconciles the
799 baseline declarations with 814 final declarations: 775 keep their exact
test path, 24 move by preserved scenario name and 15 are new. No scenario is
missing; all 10 ignored names/reasons are unchanged. This accounts for the
789-to-804 passing count without claiming platform or hardware credit. Final
inventory is [recorded separately](a03-revision3/final-rust-inventory.txt).

The [contract comparison](a03-revision3/contracts-preserved.json) records the same
16 emitted event names, the byte-equivalent normalized 27-field `StreamStatus`
declaration, unchanged frontend mirrors/configuration and unchanged native
executor/runner/host-owner/provider/maintenance inputs. The ordinary contract
gate reports 46 commands, 46 referenced wrappers plus the event helper and 9
plugin permissions. Payload construction and event points were reviewed with
the moved code; aggregate name counts alone are not behavior evidence.

Only `x86_64-pc-windows-msvc` is installed in this environment. The available
Windows SDK include version is `10.0.26100.0`. No non-Windows target build was
executed. Opt-in fixture operations were not enabled. The Windows source/unit
checks do not establish the following outstanding A4 gates:

- Full machine/installer predecessor, terminal, cross-account/session and
  integrity-level ownership matrix.
- Physical DHCP/static/DNS/routes/renew/restart, actual cancellation/uncertainty,
  partial-provider mutation, crash recovery and unmodified-candidate repair.
- Wider GUID/Any/firewall/listener races, unrelated-adapter physical topology,
  migration/observation/persistence failures and GUID/alias reuse transitions.
- Cable/reboot recovery, measured stop/notification timing, remaining PTU/operator
  and relay cases, and longer or other-load endurance.
- Installed-package hardware, signed-update success/failure/rollback, complete
  G1-R/G2/G3 native/source closure and fresh security review.

The existing [A4 remaining checklist](privilege-v2-a4-remaining.md) and frozen
v2-A development evidence remain unchanged. New A03 source/builds inherit no
artifact-specific binary qualification. **A4 remains incomplete/deferred; B
and streaming slices 7–10 remain deferred.** No installation, publication,
push, reboot or host network/firewall mutation was performed.

