# Rev 2-A.1 native ownership prerequisites

The explicit A-S2 and A-S4 **ownership** fixtures pass. [Machine-readable evidence](privilege-v2-native-prerequisites.json) ties the results to the test executable, fixed-script hash, source inputs, command, environment and logs. These are prerequisite proofs, not A2 production integration or A3 bind qualification.

The Windows-only primitives are currently compiled under `cfg(test)`. The opt-in process fixture lives under `src-tauri/tests/fixtures` and is loaded inside the network test module to reuse private seams. Ordinary tests do not run these process experiments. No new test constructs `NetworkManager`. Address effects use the existing `FakeAddressIo`, `AddressOps`, `PendingAdoptOps`, retained-binding policy and `AppConfig` serialization; the fixture never changes native addresses, routes, DHCP or firewall policy.

A-S2 observations:

- Five ASCII/smart quote, Unicode, newline and wildcard/command-shaped inputs round-tripped through bounded UTF-8 JSON stdin. Windows PowerShell 5.1 returned the identical fixed script AST text for every input.
- Required cmdlet failure returned a failed structured step and process exit 71. The fixed invalid `ipconfig` option returned native exit 1, checked explicitly, and a failed structured step/process exit 71.
- The executable/system working directory come from Windows system-directory APIs. The explicit environment excludes user overrides; `PATHEXT=.EXE` is required for PowerShell 5.1 to wait for native executables. Utility, Management and CIM modules import from absolute protected paths with autoload disabled. No privileged temporary file is needed.
- The process is created suspended with an atomic job-list attribute, containment is queried before resume, and the job has kill-on-close. A four-second timeout retired the observed process tree; retained process handles were signaled. Both output streams drained independently to 32 KiB, marked truncation and rejected an oversized structured result despite exit zero.
- The actual requesting Tokio task was aborted after native dispatch, before the independent 15-second runner deadline. The executor retained `Completed` when the prior fake provider effect could be observed and `Uncertain` when it could not. Conflicting writes were refused; failed observation retained the pending row and barrier. Existing pending-address reconciliation accounted for the effects before admission resumed. Retained completion and admission remain bounded at one and zero queued requests, respectively.

A-S4 ownership observations:

- A second process received Busy before initialization and left the shared fixture state unchanged.
- The sole fixture owner was terminated after the contender exited, with no parent mutex handle. Its replacement created a fresh mutex and received no abandonment indication, yet began with writes blocked. Failed observation and identity replacement made no guessed writes. Existing reconciliation removed the pending temporary address, preserved the retained binding, then admitted conflicting work. Executor shutdown preceded owner release.
- A dedicated thread owns/releases the mutex. Readback verifies the protected DACL, explicit Interactive synchronize/modify/read-control grant and Medium no-write-up label. Only Windows' SACL auto-inherited bookkeeping flag is normalized. A colliding event and foreign Everyone-grant DACL were refused.

Reproduce in the required Windows/GStreamer build environment, from `src-tauri`:

```powershell
cargo test --lib --locked --offline network::native_qualification::qualify_ -- --ignored --test-threads=1 --nocapture
```

Earlier fixture failures remain recorded: disabled autoload initially preceded a cmdlet-based encoding constructor; mutex readback mapped generic rights and added SACL bookkeeping; an empty `PATHEXT` did not yield a native exit status. The final fixture uses .NET encoding construction, native access masks with strict semantic readback, and fixed `PATHEXT`. Cargo's automatic integration-test discovery was also corrected by placing the private-seam fixture under `tests/fixtures`.

Cross-account/cross-logon and cross-integrity execution were not exercised by this same-account, medium-integrity fixture. Production startup/writer integration, all-interface bind refresh, firewall/install qualification and installed-package evidence remain pending. The JSON's pending PTU gate reflects this earlier checkpoint; the [A1 continuation](privilege-v2-a1-continuation.md) records later successful camera and corrected PTU smoke. The release manifest remains `requireAdministrator`, the application contract remains 46 commands, and B implementation stays deferred.
