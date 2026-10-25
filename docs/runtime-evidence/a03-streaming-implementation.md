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
