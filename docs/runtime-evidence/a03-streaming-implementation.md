# A03 streaming implementation (slices 7–10)

Started on 2026-10-25 at reviewed HEAD
`6f8a727c33de7e722040aeb97ab7aff6538ba277`, on `main`, clean worktree.
No applicable AGENTS.md was found in the repository or ancestor directories.
The external A03 specification, ownership record, historical slices 1–6 record,
v2-A checkpoint and A4 remaining checklist were read before implementation.

The user explicitly rescheduled slices 7–10 before A4 qualification, superseding
Revision 3's sequencing restriction for these implementation slices. Revision 4
records that authorization while preserving its historical baseline/history.
A4 remains incomplete/deferred; B remains deferred. No release qualification
is inferred from source/unit/build checks. Frozen v2-A and slices 1–6 evidence
remain unchanged. No host network/firewall mutation, installation, launch of
qualification artifacts, reboot, push or publication is part of this work.

Environment retains the documented Windows x86_64 MSVC/GStreamer SDK configuration,
Rust/Cargo 1.97.1, Node 24.14.0, npm 11.18.0, Tauri 2.10.3/Tokio 1.50.0 lockfile.
`rustc -vV` reports LLVM backend 22.1.6; Windows SDK includes are 10.0.26100.0.
Baseline inventory and ordinary test output are in [a03-streaming](a03-streaming).
The restricted baseline reproduced the three read-only adapter enumeration
failures documented in the earlier track; the unrestricted rerun is recorded
separately. Ignored fixture operations remain opt-in.

Implementation and per-slice validation are recorded below as completed.

Baseline rerun: **804 Rust passed / 10 ignored; 205 frontend passed**.
The original HEAD and counts match the reviewed baseline. No reset or unrelated
change was needed. `baseline-rust-inventory.txt` enumerates all 814 scenarios.

7. Streaming preparation: `VideoSurface` owns HWND incarnations and all
   main-thread create/replace/position/visibility/conditional-release/destruction
   dispatch via the existing AppBridge. Status composition and the deduplicated
   broadcaster moved to `status.rs`; the unchanged watch and both 1 Hz/Skip
   supervisors retain existing refresh points. Constructors spawn no work;
   setup continues to enter Tauri's runtime when starting tasks.

   UDP admission moved to focused guards at the existing state-lock sites.
   The common lock remains: actual desired/live relay and playback-source state
   are the occupancy authority, with no redundant claim or changed release
   point. The later owners will receive restricted projections of that same
   lock, preserving atomic admission and coherent status without independent buses.

   Five existing surface/status scenarios moved by preserved name. Five new
   regressions cover concurrent UDP starts; failed desired relay occupancy and
   stale Stop; whole-transition status coherence; recycled HWND stale queued
   work; and failed surface replacement. Gates: **809 Rust passed / 10 ignored,
   205 frontend passed**, fmt, all-target Clippy (`-D warnings`), typecheck,
   contracts and frontend build passed. Initial new-test compile/Clippy issues
   were corrected before the passing rerun; initial logs remain separate.
   See `slice-7-gates.json` and `slice-7-scenario-accounting.json`.

   Local review commit: commit containing this record, titled
   “A03 slice 7: own video surface and prepare coherent streaming boundaries”.

8. Playback ownership: `PlaybackService` encloses playback/recording fields,
   lifecycle/epoch/wake controls, diagnostic task and supervisor. Existing Option
   representations and transitions moved without an enum redesign. The owner
   receives a `PlaybackSlot`, surface and the single `StatusPublisher`; the slot
   exposes only playback mutation and checks UDP occupancy under the original
   shared lock before returning that projection. Readiness/selection/verified
   wake and source-bound transport validation retain their existing behavior.
   Shared URL/readiness policy is in `source.rs`; the RTSP client's redaction
   call now uses that helper rather than the streaming facade.

   Eleven existing playback scenarios moved by name. Three new tests cover
   construction outside a runtime, failed recording-finalize path retention,
   and an old lifecycle-gated retirement preserving newer intent while reporting
   only the old recording. Gates: **812 Rust passed / 10 ignored; 205 frontend
   passed**, fmt, all-target Clippy, typecheck, contracts and frontend build
   passed. The focused playback run passed all 14 scenarios. Test-import/parse
   errors during extraction were corrected before the passing full gates.

   Local review commit: commit containing this record, titled
   “A03 slice 8: extract playback and recording ownership”. Slice 7 is `7441870`.

9. Relay ownership: `RelayService` encloses listener state, complete settings/
   protocol transactions, lifecycle gates, intent/generation, supervisor, topology
   handling and both firewall outcome and lease generation. `RelaySlot` exposes
   only relay mutation; its UDP check reads playback occupancy at the original
   admission point under the joint mutex. The facade delegates. No relay-native
   executor, barrier or task was added. Automatic recovery retains its backoff,
   three-bind-failure re-resolution and generation/instance/topology checks.

   Policy-result closures allow deterministic lease tests while production
   continues to await `firewall::ensure/disable` inline through the existing shared
   retained executor. They test lease installation before dispatch, canceled
   caller retention, failed/uncertain/unavailable retirement, retirement before
   replacement and stale completion fencing. Only Inactive clears a matching
   lease. Existing separate listener/outstanding-firewall Stop generations and
   unavailable-automation listener startup remain unchanged. These fakes prove
   lease logic, not native cancellation or physical firewall qualification; the
   unchanged executor/runner scenarios remain the native lifetime regression net.

   Thirty-three existing relay scenarios moved by preserved name; five tests
   were added. Final gates: **817 Rust passed / 10 ignored; 205 frontend passed**,
   fmt, all-target Clippy, typecheck, contracts and frontend build passed. Initial
   extraction/test closure errors and Clippy visibility issues were corrected
   before the passing rerun. Local review commit: commit containing this record,
   titled “A03 slice 9: extract relay transactions topology and firewall ownership”.
   Slice 8 is `60db6fe`.

10. Streaming closure: the facade now contains construction, delegation and
    startup composition. Production receives bridge and CameraReadiness explicitly
    at construction; no late readiness slot remains. Services have private state
    handles and lifecycle/epoch controls. Their concrete projections preserve the
    original shared serialization and UDP release points; the status sender is
    private to StatusPublisher. Shared source policy and its tests live in
    `source.rs`; DTOs remain exported at their original public module paths.
    The temporary `streaming/mod.rs` boundary exception and temporary-allowlist
    machinery are removed. Permanent composition/OS adapters remain documented.

    Six new regressions cover exact UDP errors in both start orders, an actual
    failed RTSP listener construction retaining desired occupancy until Stop,
    stale Stop preserving replacement playback source, stale Stop preserving a
    replacement listener/UDP/firewall lease, single-watch broadcast payload and
    deduplication, and immediate conditional surface release with stale queued
    destruction. The earlier stale position/visibility/replacement scenarios
    remain intact. Twenty-two existing source/status scenarios moved by name.

    The new occupied-port fixture initially reserved a specific loopback address,
    which did not conflict with GIO's wildcard listener on Windows, even with
    exclusive ownership. The corrected fixture reserves the same wildcard
    endpoint exclusively, independently asserts that a second wildcard bind
    fails, and requires the actual `RTSP server socket failed:` error. The
    [focused native socket log](a03-streaming/slice-10-occupied-fixture.txt)
    records GStreamer failing to bind `0.0.0.0`, plus the passing occupancy/release
    assertions. Earlier failed attempts remain separate; no production behavior
    or test expectation was weakened to make the fixture pass.

    Final gates: **823 Rust passed, 0 failed, 10 ignored; 205 frontend passed**.
    Fmt, all-target Clippy with warnings denied, typecheck, contracts, frontend
    build and the additional `cargo build --locked` desktop development build
    all passed. The existing LNK4199 unused delay-load-import warnings remain.
    No built application or qualification artifact was launched.

| Slice | Local review commit | Rust pass / ignored | Frontend pass | Required gates |
| --- | --- | --- | --- | --- |
| 7 | `7441870e52dfe4ef4946212a7c8be1691bc57869` | 809 / 10 | 205 | All seven passed |
| 8 | `60db6fe77f5127728d16ac9d9b927253bcd5c934` | 812 / 10 | 205 | All seven passed |
| 9 | `a8fd77c9763b30b778bce568bd9773ca8fefe4a1` | 817 / 10 | 205 | All seven passed |
| 10 | Commit containing this completed record, titled “A03 slice 10: close streaming ownership and record implementation acceptance” | 823 / 10 | 205 | All seven plus desktop development build passed |

Per-slice commands, exit codes and full logs are retained in
[a03-streaming](a03-streaming). Each slice ran `cargo test --lib --locked`,
`cargo fmt --check`, `cargo clippy --all-targets --no-deps --locked -- -D warnings`
from `src-tauri`, then `npm.cmd test`, `npm.cmd run typecheck`,
`npm.cmd run check:contracts` and `npm.cmd run build` from the repository root.
The final slice additionally ran `cargo build --locked` from `src-tauri`.
Read-only adapter enumeration and esbuild parent-directory access used the
documented unrestricted validation context. Fixture operations stayed ignored.
Captured logs are normalized to UTF-8 with trailing whitespace removed.

The [final scenario accounting](a03-streaming/slice-10-scenario-accounting.json)
reconciles **814 starting declarations with 833 final declarations**: 743 keep
their exact path, 71 move by preserved scenario name, and 19 are new. There are
no missing or renamed scenarios, no new ignores, and all ten ignored names,
paths and reasons are unchanged. Every moved pair and every added test name is
listed, with per-slice accounting alongside the gate results. The 804-to-823
passing change comes entirely from added ordinary regressions. Frontend scenario
count remains 205. Totals alone are not used as preservation evidence.

The [contract comparison](a03-streaming/contracts-preserved.json) checks the actual
`6f8a727` baseline: all **46 command signatures**, **16 emitted event names**,
the unchanged **27-field StreamStatus** and both relay-result DTO declarations,
and all **25 state-field names/types** across the two owners. The ordinary
contract gate also preserves **46 referenced wrappers plus the event helper and
9 plugin permissions**. No baseline error literal is missing. Frontend mirrors,
persistence/configuration, build inputs, frozen v2-A evidence and the historical
slices 1–6 record are unchanged. Every network source is unchanged. Media server,
audio and recorder production code is unchanged; playback-pipeline production
code changes only its redaction dependency to the moved identical helper.
The Windows exit tail, including retained-native shutdown and the second cleanup
pass, is unchanged. Payload construction/refresh points were also reviewed with
the moved code, and the new broadcaster regression checks the actual 27-field
payload; name counts alone do not establish those properties.

All A03 **implementation** acceptance criteria are now met: concrete ownership
and private mutation handles, explicit dependencies, original state/lifecycle/
transaction behavior, UDP/status/HWND and policy fencing, no temporary boundary
exceptions, preserved contracts/scenarios, passing per-slice gates and four
separate buildable local review units. Retaining common streaming serialization
is deliberate preservation, not unfinished ownership extraction. There are no
known remaining implementation gaps in slices 7–10.

Only `x86_64-pc-windows-msvc` was built; no non-Windows target is installed here.
The documented SDK configuration remains local/ignored; its current hash is in
the comparison record. Ordinary tests use synthetic media and temporary listener
sockets/files; they do not qualify physical camera, cable, stop timing or native
policy/provider behavior. Firewall-result fakes establish lease logic only.

**A4 remains incomplete/deferred; B remains deferred. No release qualification
is inferred from these source/unit/development-build checks.** The unchanged
[A4 remaining checklist](privilege-v2-a4-remaining.md) still governs machine and
cross-account/session/integrity ownership, physical DHCP/static/DNS/routes/restart,
cancellation/uncertainty/crash recovery and partial-provider faults, broader
GUID/Any/firewall/topology transitions, operator/PTU/timing/endurance, installed
hardware, signed updates, G1-R/G2/G3 closure and fresh security review. Historical
artifact-specific v2-A credit is not transferred to new A03 binaries. No host
network/firewall configuration mutation, installation, qualification-artifact
launch, reboot, push or publication was performed.
