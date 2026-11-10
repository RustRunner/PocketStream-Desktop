# v0.6.10 integration branch local verification

Date: 10 November 2026. Local source integration checkpoint; hardware,
installed-upgrade and release qualification remain pending.

Follow-up: [Rust failure investigation and fixes](v0610-rust-failure-investigation.md)
records the SRT fixture correction, RTSP readiness race reproduction and fix,
and two passing default-parallel full runs (932 passed, 14 ignored). The
original merge-checkpoint results below are retained as historical evidence.

## Integrated source

Fetched `origin/main` from GitHub and verified it at
`f042eb11b01818a83e60f141f8a830404c483402`. Created the isolated branch
`integration/v0.6.10` from that commit in
`C:\Users\joshu\PocketStream-Desktop\src-tauri\target\integration-v0610-worktree`.
No applicable `AGENTS.md` was found in the repository, worktree or checked
source/ancestor paths.

Merged `feature/restream-enable-r2` at
`001150af753ec39fe4956546d3404e7fa8d14557`, containing the complete ordered chain:
`d7f8644`, `0728129`, `6dd6707`, `15d7dd4`, `be3a1ee`, `e1661dc`, `001150a`.
The merge had no conflicts and required no application changes. The application,
tests, scripts and dependency inputs match the feature tip; the README,
DEVELOPMENT guide and workflow images match fetched main. This evidence note is
the only additional tracked content introduced during integration.

Local `main` remains `f81ca5d`. The root checkout remains
`work/privilege-v2-b-r5` at `fd65b1d`, with its unrelated README, DEVELOPMENT and
image edits preserved. All predecessor branches and worktrees remain intact.
The integration was not pushed, merged to main or ported into the privilege
branch. Application/package versions remain 0.6.9; the branch name identifies
planned work, not a released version.

## Build inputs and checks

Used the existing ancestor `node_modules`, installed GStreamer MSVC SDK,
inherited `.cargo/config.toml` pkg-config paths and shared ignored Cargo cache:

```powershell
$env:CARGO_TARGET_DIR = 'C:/Users/joshu/PocketStream-Desktop/src-tauri/target'
$env:PATH = 'C:/Program Files/gstreamer/1.0/msvc_x86_64/bin;' + $env:PATH
```

`POCKETSTREAM_RELEASE` was unset. The first two full Rust runs used default
parallelism (`RUST_TEST_THREADS` unset); the diagnostic run used eight threads. The
frontend build generated this worktree's dist. Copied the two ignored local
GStreamer resource placeholders from the predecessor for normal Tauri test
compilation; they are not a packaged runtime. No dependencies were installed or
changed. Build/browser and full Rust checks used unrestricted execution because
the predecessor checks established sandbox directory/DevTools/native-enumeration
limitations.

| Check | Result |
| --- | --- |
| `npm.cmd test` | 287 passed, zero failures |
| `npm.cmd run typecheck` | Passed |
| `npm.cmd run build` | Passed, including DOM/re-stream/IPC/installer/Rust-boundary contracts |
| `npm.cmd run check:ui` | Passed at 1280x800 and 960x600; native calls stubbed by the harness |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check` | Passed |
| Full Rust suite, default parallelism, first run | 930 passed, one failed, 14 ignored: known SRT port-reclaim fixture |
| Full Rust suite, default parallelism, second run | 930 passed, one failed, 14 ignored: topology fixture binding-read assertion |
| Focused `persistence_and_restoration_failures_are_reported_together` | One passed |
| Focused `start_invalidates_real_change_or_read_failure_at_each_checkpoint_then_recovers` | One passed |
| Full Rust suite, diagnostic `RUST_TEST_THREADS=8` | 931 passed, zero failures, 14 ignored |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed |

The first default-parallel Rust run passed 930 tests, failed one and left 14
ignored. The failure was the pre-existing
`persistence_and_restoration_failures_are_reported_together` fixture at
`streaming/test_support.rs:225`: the old SRT listener's UDP port could not be
reclaimed within its existing retry window (OS error 10048). The admission and
status/retry predecessor notes record the same intermittent scenario. No source,
assertion, test retry window, production teardown or timeout was changed.

The second default-parallel full run passed the SRT fixture but failed
`start_invalidates_real_change_or_read_failure_at_each_checkpoint_then_recovers`
at `streaming/relay_service.rs:3352` with `unexpected binding read`. That topology
fixture supplies a finite sequence of binding observations and observed an extra
read in the combined run. It passed in isolation with a backtrace enabled. Its
cause remains unconfirmed; it is not established to be the same UDP-port issue.
The application/test tree is identical to the feature tip, so neither failure
was introduced by a merge conflict resolution.

Routine logs are ignored `integration-*.log` files in this worktree. Browser
artifacts are under `src-tauri/target/ui-layout/`. Preserve the first failing
Rust log alongside the focused and full rerun results; a passing recheck does
not establish that the intermittent port-release or topology issue is absent.
Default-parallel validation is not green at this checkpoint. Investigate these
failures before claiming a clean main/release candidate; do not permanently
reduce test concurrency or weaken assertions to conceal them.

The Rust build regenerated permissions with LF endings. Normalized hashes were
compared against the staged merge before restoring the original CRLF format;
there is no permission-content change. Existing delay-load linker warnings and
sandbox Cargo path-canonicalization warnings appeared without failing the
formatting/Clippy checks. No assertions or test scheduling defaults were changed.

## Next work and remaining limits

Use this integration branch or a verified successor as the base for discovery
and Clear All. Follow the untracked
`Documents/Untracked/10NOV26-v0610-consolidated-delivery-spec.md`, beginning with
S0 specification reconciliation and S1 discovery simplification/bounded proof.
Neither discovery implementation has started in this checkpoint.

All five feature notes' hardware, WFP, remote RTSP/SRT media, contention/settlement,
installed maintenance/upgrade and release gates remain pending. Discovery S-R2
and privilege integration/production gates remain separate work. No native
qualification fixture, installed app, adapter/firewall mutation, version bump,
publication or release was performed by this integration task.
