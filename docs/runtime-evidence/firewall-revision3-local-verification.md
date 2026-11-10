# Firewall enforcement, speed and recovery: revision 3 local checkpoint

Date: 3 November 2026. Implementation checkpoint only; hardware qualification and release readiness are **pending**.

## Source and review boundaries

The full revision 3 specification was read from `C:\Users\joshu\Documents\Untracked\02NOV26-firewall-rule-enforcement-and-policy-speed-spec.md`. No applicable `AGENTS.md` was found in the repository or its ancestors.

Verified starting state: `main` at `f81ca5d848f4db6600cb24bf505ddeec1850a720`; the original checkout remained `work/privilege-v2-b-r5` at `fd65b1dd4a1c220eb30b039eb642868373099725`, with unrelated README, DEVELOPMENT and image changes excluded from this work.

Implementation is on `hotfix/firewall-r3`, in `C:\Users\joshu\PocketStream-Desktop\src-tauri\target\firewall-r3-worktree`. The three slices are separate local commits, in order:

1. Enforcement/repair, light ownership reads and runner budgets (`d7f8644`).
2. Policy speed, query/read expectations, bounded report timings and probe anchors (`0728129`).
3. Timeout settlement, conditional recovery admission, startup retry, regression tests and qualification procedure.

All three are required together. No push, publication, version bump, installer upgrade or integration into the original checkout was performed.

## Implementation and scope review

New/Set provider calls never bind Package. Empty-package template verification is distinct from historical legacy recognition. Owned defective templates are disabled, removed, checked absent and recreated; startup detects and disables them. The fixture covers both roles, wildcard/SID packages, failed repair and concurrent package changes.

Ensure has no full-store query, reuses its full shape, skips unchanged rewrites, observes filtered blocks before enable and reads only the enabled application/port/interface scope. Mutation bookkeeping precedes every enable, including an enable that mutates then throws. Startup uses two application-filter reads with its one legacy inventory. Timing reports parse with a default for old reports and retain strict unknown-field rejection. The script is 19,359 bytes, 3,701 bytes larger than the baseline and below the specification's growth/command-line budget.

Settlement and startup retry remain inside the admitted execution. Eligibility requires actual containment and tree-exit facts. Runtime recovery requires the original runtime role, firewall origin and inspected retained ID; that ID and Uncertain state are checked under the executor lock. Failed recovery preserves the unresolved cause and replaces only its latest attempt, accumulating retirement evidence conservatively. Only verified Inactive resolves it. Runtime recovery does not write the maintenance journal slot. An abandoned ordinary requester still leaves its completion retained, even after successful safety settlement.

Final diff review found no queue, generic retry service, worker process, runtime WFP inspection, IPC/UI/configuration change, asynchronous Stop or relay lifecycle change. Management/CimCmdlets imports are deliberately retained because removal lacks runner-based 5.1 measurements, as revision 3 permits. NetAdapter imports require an explicit interface identity. No material revision 3 implementation deviations are known.

## Local verification

Commands ran in the isolated worktree. Cargo used the existing ignored target cache and installed GStreamer SDK; ignored resource placeholders enabled the normal Tauri build checks. The frontend build generated its real dist output. These build inputs are not installer qualification artifacts.

| Check | Result |
|---|---|
| `node --test tests/firewall-policy.test.cjs` | Passed: 26 fake-provider cases, zero native policy mutations; bound-parameter Package assertions across every mode |
| Focused firewall, runner, executor and native_operations Rust tests | Passed, including the existing caller-abort persistence/barrier regression; native qualification cases remained ignored |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` | Passed outside sandbox: **869 passed, 14 ignored**, zero failures |
| `npm test` | **231 passed**, zero failures |
| `npm run typecheck` | Passed |
| `npm run build` | Passed, including DOM/restream/IPC/installer/Rust-boundary source contracts |
| `npm run check:ui` | Passed outside sandbox: isolated browser layout and repeated-click checks |
| `cargo fmt --manifest-path src-tauri/Cargo.toml --check` | Passed |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --no-deps --locked -- -D warnings` | Passed |
| Read-only Windows PowerShell 5.1 filtered provider query | ActiveStore + Action Block + Direction Inbound succeeded (4 rows). The same parameter set with Action NotConfigured produced exact `CmdletizationQuery_NotFound,Get-NetFirewallRule` / ObjectNotFound for zero matches. No rule mutations |

The initial sandboxed Rust run passed 866 tests and failed three real adapter enumeration tests; the unrestricted rerun passed all 869. The sandbox also denied esbuild directory reads and timed out the headless browser DevTools connection; both checks passed on unrestricted reruns. A preliminary DisplayName + Action/Direction query was rejected as AmbiguousParameterSet; production uses only the verified Action/Direction set. None of these attempts is hardware timing evidence. Routine logs remain in the worktree's ignored `revision3-*.log` files.

## Qualification-only timeout procedure (not executed here)

`FirewallQualification` is compiled only into the Rust test executable. Its host-owned one-shot atomics are consumed for the intended attempt before spawning PowerShell. The fixed ensure injection delays 45s **after the enable write**, before readback, against the unchanged 30s budget. It emits `qualification_after_enable`; the harness requires that marker, TimedOut termination, verified containment and tree exit. The settle is excluded from that fault. Separate one-shot faults cover a settle timeout, a pre-write recovery failure and the first startup attempt's 1s budget. A subsequent ensure and startup attempt use normal budgets. Ordinary tests verify one-shot consumption and command-line size without dispatching native writes.

On an isolated elevated qualification host with the candidate installed at the fixed Program Files path, no product host running, and rule state backed up, the ignored test can be explicitly selected:

```powershell
$env:POCKETSTREAM_FIREWALL_TIMEOUT_PROBE='approved-isolated-installed-rules'
cargo test --manifest-path src-tauri/Cargo.toml --lib --locked network::native_operations::tests::qualify_firewall_post_enable_timeout_and_explicit_recovery -- --ignored --exact --nocapture
```

Retain the test executable/source hashes and its `FIREWALL_READ_PROBE` records. This test mutates the two managed installed-image rules through fixed policy (runtime timeout scenarios target RTSP; startup disables both roles). It exercises single/double timeout, pre-write failed recovery, explicit successful retry, subsequent normal ensure/disable and startup retry inside one scope. Require event 2099 Active: Yes and the post-enable marker before timeout, Active: No after settlement, and independent disabled-rule readback. Verify executor admission and subsequent auto-adopt/native writes in the installed session. Repeat the listener lifecycle and timeout qualification with SRT as required by the hardware matrix. Do not replace this with a short whole-process ensure budget.

## Privilege branch inspection and later integration

Read-only comparison with `work/privilege-v2-b-r5` at `fd65b1d` confirmed the shared policy, executor, relay and fixture baseline. The branch's maintenance path was traced through installer `PS_MAINTENANCE`, early entry, `maintenance::protected_root`, `firewall::maintenance`, firewall_request and the same fixed policy/runner.

On that branch, protected_root still verifies an elevated token, rejects reparse ancestors, and checks the executable and immediate install directory's ownership/write ACL. It delegates those path checks to protected_path_root/named_descriptor; added retained-handle/ancestor checks serve the helper preflight rather than replacing installer maintenance. Early entry still reserves and persists a protected maintenance journal and acquires HostOwner without reacquiring the installer's InstallGate.

Before merging, preserve the branch's `qualification-b2` entry rejection and the early firewall_request mutation gate **ahead of** the new recovery/helper paths. Re-anchor both execute_settling call sites and conditional recovery admission in native_operations.rs. Keep the branch's FirewallRule Deserialize derive and additional qualification runner operations. Integration, branch-specific build/tests and installed maintenance verification after integration remain pending; the dirty original checkout was not merged or modified.

## Remaining release gates

- Test PC DESKTOP-PI5BMJR first, then dev PC: real v0.6.8/v0.6.9 installer upgrades, absent AppPkgId, two repair journal records, installer completion inside 65s including setup/teardown/journal work.
- WFP permit filters at the named ALE layers while each role is enabled, absent after disable; preserve exact UDP layer evidence and Query User drop attribution.
- Remote RTSP OPTIONS 200 and at least 150 H.264 buffers, remote SRT handshake/media; default/custom ports, explicit interface, preserved overriding Block rules and disable behavior.
- Ten runner-measured ensure/disable cycles on each host; p50/p95 and startup/install-with-repair timing targets. No timing target is claimed from fake-provider or unit-test duration.
- Native post-enable timeout/settle, double failure, pre-write failed recovery, subsequent successful Stop/native admission, requester cancellation and startup retry evidence on the qualification build.
- Integration into the privilege branch and its maintenance/build/gating verification.

The [release matrix](privilege-v2-release-qualification.md) keeps WFP, remote-connect, timing and package-upgrade evidence explicitly pending. This checkpoint does not establish release readiness.
