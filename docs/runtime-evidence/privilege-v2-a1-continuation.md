# A1 production smoke continuation

The A1 worktree was **uncommitted during qualification**. Its 76 recorded input files and tested development executable were verified byte-for-byte against the earlier evidence before this continuation. No A2 application integration or B implementation was performed. The later [commit checkpoint](privilege-v2-commit-checkpoint.md) records the committed source groups; statements below about pending gates and uncommitted state retain their historical context.

[Actual production workflow evidence](privilege-v2-a1-production-smoke.json) records the unchanged executable SHA256, native prompts, backend readbacks, before/after network state, cleanup and failed fixture attempts. The isolated dialog example is separate evidence and does not replace these workflows.

On the real production page and handlers, artifact `be1be2c86338167fe4540124b72f005d94ad948f2ce23327323c52ea590dffc1` passed:

- Save Settings: RTSP input port `554 → 13554 → 554`, verified through real backend readbacks.
- Configure → Remove primary: the native prompt identified `192.168.1.100` on Ethernet; Cancel retained the address and open dialog.
- Configure → DHCP → Close: the backend warning reached the native confirmation; Cancel retained `static_manual` and re-enabled the controls.
- The production Close action completed normally. The original profile, cache, key and logs were restored and verified by hash. Addresses, DHCP, DNS and routes on the selected adapter were unchanged.

This was the existing development executable at medium integrity, with a temporary valid profile and disabled output. CDP drove actual DOM handlers and UI Automation inspected only that process's native dialogs. No production assets, functions, modules or IPC handlers were replaced.

Two earlier fixture attempts do not qualify: one supplied an invalid RTSP token and triggered configuration recovery; the other could not read DirectUI dialog text through GetWindowText. Their failure and cleanup details are retained. The successful fixture validates the loaded profile before any action and reads native dialog text through UI Automation.

The user connected a replacement camera, confirmed at `172.31.169.84`, MAC `40:cd:3a:03:28:e2`, through Ethernet index 15, MAC `40:c2:ba:cf:d5:75`. The user-started installed copy has a different hash and cannot qualify the A1 source. It established the `172.31.169.102/24` host binding; continuation must preserve that current user state. The PTU endpoint is still under investigation: `192.168.1.74` was observed with `08:df:ec:22:01:77`, but subsequent fresh identity checks are intermittent or fail. The encoder at `.84` returns HTTP 405 to a read-only `PP&TP` POST at `/API/PTCmd`.

The optimized A1 release executable, SHA256 `c483047a2d962b153cc41069daa9041d6168a25c952672f295e71a80ab292d8f`, was built with `POCKETSTREAM_RELEASE=1`, its embedded `requireAdministrator`/Common Controls manifest extracted, and that exact staged image launched elevated. The installed copy exited cooperatively first. The A1 image used bundled GStreamer 1.26.11 and the current user profile with output disabled.

- Production discovery passed: selected Ethernet index 15, PacketMonitor source 115, selected-interface capture, and fresh verification of camera `172.31.169.84` / `40:cd:3a:03:28:e2`.
- Initial playback passed through the real CAM/Start Stream workflow: the pipeline reached Playing, the backend reported `playing`, and the user confirmed **“Live video is visible.”** Two later frame-stall recovery cycles returned to `playing`; this evidence does not establish uninterrupted soak performance.
- PTU remains unqualified. The user reports that the A1 app cannot connect or pan/tilt and cannot open the candidate's web page. Its initial control query reached the backend but failed the existing route/identity safety gate. Fresh resolution repeatedly failed with error 67; source-bound TCP port 80 timed out while the camera's HTTP positive control connected. Candidate `192.168.1.74` / `08:df:ec:22:01:77` is not assumed to be a stable, verified PTU. No successful PTU query or controlled motion result is claimed.
- The A1 process exited through its production Close action. The original output-enable flag was restored after exit, preserving the current camera, credentials and pending/retained binding records. The three existing native addresses, including user-adopted `172.31.169.102/24`, were preserved. No firewall/install operation was run.

The machine-readable record includes the release hash, launch record, selected log evidence, source-bound observations, actual cleanup and recorder limitations. All 76 original A1 input hashes were rechecked before starting ownership-proof work. Since then, only Cargo Windows dev features and `cfg(test)` module wiring changed among those original inputs; the new primitives remain test-only.

[A-S2 and same-account A-S4 ownership prerequisites now pass](privilege-v2-native-prerequisites.md): fixed-script/data separation, native failure reporting, complete child-tree timeout, actual caller-task abort with retained completion/barrier, two-process exclusion and recovery after a sole-owner crash without abandonment. The final exact test executable and source hashes are recorded separately from the production A1 artifact. Cross-account/logon/integrity execution and the A-S4 bind matrix are not claimed.

The final full repository check passed: 764 Rust tests, 7 deliberately ignored tests, typecheck, contracts, production frontend build, formatting and all-targets clippy. All 174 frontend tests passed; the four opt-in prerequisite fixtures passed separately. Only the existing linker delay-load warnings remain. No commit, reset or stash was performed during that qualification run.

At that checkpoint, A2 production integration was deferred while A1's PTU workflow was unresolved. The follow-up below records its later successful production smoke. Firewall/install qualification still requires an isolated Windows fixture; A2–A4 remain incomplete and B implementation stays deferred. The 46-command phase contract and `requireAdministrator` release manifest are preserved.

## Corrected PTU endpoint — diagnostic follow-up

The user identified the PTU as `192.168.1.202` on another PC running PocketStream 0.6.7 in Static-Auto. That PC initially used primary `192.168.0.100` and had automatically adopted `172.31.169.98` for the camera. The PTU appeared only after the user manually configured the matching subnet. The other PC's executable hash and discovery/adoption logs have not been supplied; the cause of the missed PTU adoption remains unresolved.

At 2026-10-24 04:20 UTC, read-only diagnostics from this PC, bound to Ethernet source `192.168.1.100` on index 15, confirmed HTTP 200 from `.202`, the FLIR web-page title, neighbor MAC `fc:68:3e:22:05:28`, and HTTP 200 from `POST /API/PTCmd` with query `PP&TP`, returning `PP=0`, `TP=0`, `status=*`. No movement command, adapter/configuration change or application launch was performed. The earlier `.74` observations remain historical evidence of the incorrect candidate.

These direct HTTP checks establish the corrected endpoint's reachability and query response, not an A1 production-handler or motion qualification. Production PTU smoke must use `.202` with its verified identity on the recorded A1 artifact. The other PC's startup-through-manual-change log is needed to distinguish no initial ARP observation from a capture, verification or adoption failure. Machine-readable observations are in `ptu_endpoint_followup` in the production smoke JSON.

The user subsequently confirmed that the other PC's log is unavailable. Initial inspection found only the current PC's 22:25–22:47 sessions on October 23, with `192.168.1.100`, `192.168.0.100` and `172.31.169.102` already present at discovery startup. Those sessions contain no corrected PTU IP/MAC entry or other-PC `172.31.169.98` binding.

During review, the user launched another local session at 23:28:07. Its actual image is the installed copy, SHA256 `38e723e21eb0ffe9ee7315b862faefe06a7930e90fe92981b6f3706f3425b69f`, rather than the A1 release. At 23:28:23 it logged successful bound ARP/identity probes for `.202`, the correct MAC becoming live by `fresh_verification`, and `ARP: 192.168.1.202 (fc:68:3e:22:05:28)`. This establishes observation and verification in this new local run with the matching subnet already configured. It does not establish off-subnet auto-adoption on the other PC or qualify A1 PTU control. Stable snapshots, image identity, coverage, hashes and a focused excerpt are recorded in the JSON's `ptu_endpoint_followup.log_review`.

The historical cause therefore remains **undetermined**. Absence of an IP/MAC line alone cannot establish absence of captured ARP: unscoped candidate insertion has no per-peer log, and rejection logging is rate limited. Cache hydration is not fresh observation evidence, and a directed verification attempt may originate from cache. A fresh controlled run must preserve logging from before startup through the manual subnet change, including the rotated log if applicable; ambiguous application logs require a paired selected-Ethernet capture. No app launch, network/configuration change or motion command was performed for this log review. Production PTU smoke remains pending.

## PTU role-handoff correction

The user then confirmed `.202` worked in the installed copy and reported a red halt-failed toast when assigning its PTU role. The log identifies the failed halt target as the stale outgoing `.74` selection. [The correction and evidence](privilege-v2-ptu-handoff.md) preserve precautionary stop/retry while tying the motion alarm to movement actually dispatched in the session. All 184 frontend tests, including 29 PTU workflow tests, passed. The 46-command contract and release manifest remain intact.

New A1 candidate SHA256 `4337b1dca9a158a9e71c24d2c8b34079cdf2ac4e8b167d0f7e736ab0413e059e` passed the real `.202` role/query check with output disabled: the user confirmed reconnection without a red toast and the backend returned actual PTU limits. The user also observed movement then stopping; the log identifies the input as Home, despite the user's D-pad description. The corrected build's Close button and process exit passed, the original profile was restored by SHA256, and native bindings were unchanged. The installed executable was not replaced.

The old installed copy required separately recorded quiescent-process recovery after normal close stalled; that was not graceful-exit qualification. Earlier artifact hashes and qualification results remain historical evidence. A-S2 and same-account A-S4 ownership prerequisites have passed, while A2 production integration, the bind matrix, isolated firewall/install gates and A4 remain incomplete. B implementation stays deferred.
