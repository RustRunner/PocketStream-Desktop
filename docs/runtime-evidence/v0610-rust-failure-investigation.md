# v0.6.10 Rust failure investigation

Date: 10 November 2026. Based on integration commit `fa332fc` on
`integration/v0.6.10`. This follows the failing default-parallel runs in
[the integration checkpoint](v0610-integration-local-verification.md).

## Settings rollback fixture

`persistence_and_restoration_failures_are_reported_together` failed again in
the full suite and the streaming subset. It stopped a real SRT listener, then
tried to take its UDP port with a standard socket within two seconds, solely
to force restoration to fail. Instrumented allocations in the full failing
run contained 322 UDP port samples with no duplicates.

A temporary measurement kept another `srtsink` element alive, stopped and
dropped a listener, and probed the released port. Application shutdown finished
in 128 ms; the raw UDP port became available at 1,037 ms in isolation and
1,865 ms alongside streaming tests. The original two-second takeover still
failed in the combined runs. Native cleanup timing is not the transaction
contract this fixture needs to assert.

These checks loaded the local GStreamer 1.28.1 SDK and SRT 1.5.4
(`srt_getversion() == 0x010504`). SRT closes a listening socket before its
garbage collector disposes of the underlying socket/multiplexer; see
[SRT 1.5.4 socket lifecycle](https://github.com/Haivision/srt/blob/v1.5.4/srtcore/api.cpp).
This is separate from the pinned release runtime (GStreamer 1.26.11 with
patched SRT 1.5.7). No SDK or release dependency was changed.

The fixture now uses RTSP and occupies its TCP port after shutdown. It still
executes a real settings transaction, injects a persistence error, forces an
actual listener bind failure during restoration, and checks both errors,
unchanged saved settings, desired/failed status and absence of a running server.
It additionally checks that the restoration error came from the RTSP socket.
The unused UDP takeover/retry helper was removed. Existing SRT lifecycle,
admission and settings tests remain in place.

## RTSP readiness race behind the topology symptom

The topology fixture passed ten complete iterations (120 scenarios) while a
separate SRT element kept the native runtime alive. SRT teardown alone did not
reproduce its binding-read panic.

Inspection found that RTSP sent its readiness signal immediately before
entering `MainLoop::run`. A Stop in that interval could call `quit` before the
loop was running. The thread could subsequently enter the loop, miss the Stop,
and retain the TCP listener after the bounded teardown gave up.

A temporary four-second scheduling delay between the old readiness signal
and `run` reproduced the exact topology failure at RTSP checkpoint 2. Diagnostics
showed recovery attempt 1 failing to bind `127.0.0.1:57000` (address in use),
followed by another recovery attempt exhausting the fixture's binding reads.
Thus `unexpected binding read` masked the listener lifecycle failure. The
original uninstrumented failure log cannot identify its protocol, but this
controlled reproduction establishes a concrete production race with the same
failure path. The diagnostic delay was removed.

Readiness is now sent by a one-shot source dispatched inside the dedicated
GLib loop. An immediate Stop therefore sees a running loop. If startup already
timed out, that source observes the shutdown flag and quits when dispatched.
The existing one-second startup and three-second teardown deadlines remain.
No recovery attempts, binding expectations or suite concurrency were relaxed.

A regression test starts real RTSP listeners on OS-assigned loopback TCP ports,
asserts the loop is running before Start returns, immediately stops each
listener, and verifies port reclamation and absence of spurious fault events.
It exercises sixteen start/stop cycles. It failed against the delayed old
readiness implementation at `ready must mean the loop is running`.

## Verification

Used the same SDK, shared Cargo target and unrestricted native-read test
environment as the integration checkpoint. `POCKETSTREAM_RELEASE` and
`RUST_TEST_THREADS` were unset for both final full runs.

| Check | Result |
| --- | --- |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked`, default parallelism, run 1 | 932 passed, zero failed, 14 ignored (27.55 s) |
| Same full command, run 2 | 932 passed, zero failed, 14 ignored (27.57 s) |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed |
| `npm.cmd run check:rust-boundaries` | Passed |

Both formerly failing tests and the new sixteen-cycle RTSP regression passed
in both full runs. Final logs are `rust-failures-fixed-full-1.log`,
`rust-failures-fixed-full-2.log`, `rust-failures-fixed-fmt.log` and
`rust-failures-fixed-clippy.log`. The extra test accounts for the increase from
931 to 932 passing tests. The fourteen ignored tests were not enabled or
reported as passes. Frontend files are unchanged, so the earlier frontend/UI
checks were not repeated. Generated permission content was checked against
HEAD before restoring its original line endings.

Diagnostic logs are ignored `rust-*.log` files in the integration worktree,
including `rust-failures-diagnostic.log`, `rust-streaming-diagnostic.log`,
`rust-topology-stress-diagnostic.log`, `rust-topology-lost-quit-diagnostic.log`
and `rust-rtsp-readiness-regression-red.log`. Temporary port logging, recovery
logging, runtime inspection, stress-loop changes and scheduling delays were
removed. Production changes are confined to RTSP readiness; the topology test
is unchanged.

This remains local verification. Hardware, remote media, installed upgrade,
the pinned release runtime and release qualification remain pending. Main,
the privilege branch, package versions and the unrelated root checkout edits
remain unchanged.
