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

