# Isolated installer and elevated hardware qualification — 25 October 2026

**28 Windows Sandbox scenarios passed against the rebuilt package.** The corresponding elevated staged image passed the available camera/PTU smoke while preserving host native configuration, including automatic cached-role retry and individually confirmed motion/stop controls. This is partial qualification: positive candidate ICMP, DHCP confirmation Cancel, independently observed position replies and the remaining matrices below are pending. A4 and overall qualification remain incomplete. B remains deferred.

The [machine-readable record](privilege-v2-final-qualification.json) contains the 230 source hashes, artifact references, scenario results, failures, cleanup and limitations. Earlier integration, hardware and [pre-restart checkpoint](privilege-v2-sandbox-checkpoint.md) records remain historical. Their preparation-time statements do not describe the later runs recorded here. The operator's earlier isolated-prerequisite sequencing exception remains recorded; it never credited an unavailable test as passed.

## Exact candidate

| Artifact | SHA-256 |
|---|---|
| Optimized staged host, used on connected hardware | `aed0e7bf884402ac7dbdb7397f9156108f5edb0b95bdfa7ba3308aa233f8a566` |
| NSIS package, executed only inside Sandbox | `0d408f871d1d34dfc232e7887a529f5c77fb26329143f9e5445d43861cca55f1` |
| Embedded/installed host, used by native Sandbox cases | `fe1be61bedf2852404877a1cf7255b1ed5e1f4d75a73016ff098cd3ec6b62b6d` |
| Combined 230-source input digest | `ec3d6371dc31e04ff835c5ba055ecc3228d3d141ab374734f4dbeaabe72970c6` |

All source and artifact references were reverified. Raw source files are sorted by ordinal relative path and hashed as `SHA256 + two spaces + path + LF`. New qualification fixtures have separate hashes. Package extraction established that staged and embedded images differ only at the three-byte `UNK`/`NSS` bundle marker. Windows SDK manifest extraction verified **requireAdministrator** and Common Controls v6 in both hosts and the installer. The command contract remains **46**, including `list_bind_interfaces`.

The optimized build completed successfully with signing and updater artifacts disabled. Existing unused delay-load import linker warnings remain in its log. This unsigned inspection package does not qualify signed update or installed-hardware/G3 release closure. Hash-named images, package, manifests, generated NSIS, compiler trace and metadata are retained under `src-tauri/target/privilege-final/rebuilt-ptu-retry/`; build outputs and private records are excluded from Git.

## Demonstrated fixes and software checks

Fresh installation initially failed because NSIS `GetFullPathName` returned an empty result for a destination whose final component did not exist. The installer now uses Windows lexical path resolution, retaining Program Files bounds, traversal refusal and existing-component reparse checks. The next attempt exposed maintenance rejecting the normal inherited TrustedInstaller grant. That fixed service SID is now accepted as a privileged writer; only Administrators/SYSTEM remain permitted owners, and ordinary user/unknown-service writes remain rejected. A separate negative regression corrected a missing `FILE_DELETE_CHILD` bit in the ACL write mask.

On hardware, the previous image initialized a cached PTU before Ethernet readiness and never retried when the same MAC/IP became verified. The frontend now retries an uninitialized live target through the existing device-list subscription and shares one pending initialization per identity/generation. It reuses the serialized PTU queue and existing stale-operation fences.

Validation passed: **789 ordinary Rust tests, 10 ignored opt-in native/hardware tests; 200 frontend tests; all 31 PTU workflow tests; typecheck; formatting; all-target Clippy with warnings denied; frontend build; source/generated/compiled-trace installer contracts; 46 IPC commands/wrappers and nine plugin permissions.** The two PTU regressions failed before the fix and passed afterward. Native mutation opt-ins were removed from the ordinary test environment. No ignored test receives qualification credit.

## Sandbox results

Windows Sandbox was enabled without forcing a restart. Windows returned `RestartNeeded=true`; resume instructions were committed, the operator explicitly confirmed the restart, and the resumed guest subsequently booted. Host observations identify Windows 11 Professional 25H2, build 26200.9711. The guest reported Windows 10.0.26100.0 APIs, PowerShell 5.1.26100.9711, x64, elevated WDAGUtilityAccount/session 1, running BFE/MpsSvc/Winmgmt, trusted system modules, a working firewall provider and WebView2 155.0.4283.62. No fake provider or weakened physical-adapter eligibility was used.

The tested `.wsb` mapped seven installer/script inputs read-only and a dedicated results directory writable. The supplemental failure script was separately hash-verified and mapped read-only. The updated reusable generator includes that script directly as an eighth input. Clipboard, audio/video, printer and vGPU redirection were disabled; Sandbox networking supplied its own virtual switch. Nothing installed, uninstalled or mutated firewall policy on the working PC.

| Executed subset | Result |
|---|---|
| Protected destination and traversal refusal; interactive welcome Cancel | Passed; rejected destinations left no installation; Cancel exited 1 without image, registration, rules or profile initialization |
| Fresh silent, passive and updater installs; silent/passive/updater reinstalls | Passed; exact embedded image and all 93 payload files checked on initial fresh install; disabled templates and all intended filters verified |
| Strict entry, unprotected maintenance, image-in-use and HostOwner Busy | Passed; expected refusals, unchanged image, repair after owner release |
| InstallationGate admission | Passed; maintenance admitted, ordinary host reported Busy before profile/log initialization, message dismissed and process exited |
| Legacy/custom/duplicate/disabled/program-scoped migration and repetition | Passed; intended Allow shapes retired, both v2 templates verified |
| Private-profile migration conflict and exact-name foreign collision | Passed; nonzero failure preserved conflict/collision, successful retry after fixture repair |
| Block/foreign/unrelated rule preservation | Passed across migration, failures, upgrade and uninstall, including all seven filter classes |
| Standalone silent/passive uninstall, installation afterward and final cleanup | Passed; bounded wait verifies image, registration and owned-rule removal after the copied child completes |
| Actual predecessor installer upgrade and upgraded uninstall | Passed with predecessor package `35e2d0a4eff03cd4f5bac95e15315b088873298318ffcf3ae6ab63b2f99e90af`; legacy shapes were explicitly seeded, not emitted by a running old application |
| Locked `avcodec-61.dll` extraction, actual Ignore and fatal OK | Passed; installer returned 71 and retained incomplete/no-rollback diagnostic; repair verified the full payload |
| Locked payload deletion in a verified copied uninstaller child | Passed; direct child returned 71, retained maintenance image/registration and incomplete diagnostic; repair and final standalone uninstall passed |

The primary run completed **22 scenarios** and the supplemental run completed **six**, including setup/repair/final cleanup. Expected refusal/failure paths are passing tests of that behavior, not successful installations. The supplement clears only the payload extraction/deletion entries in the primary report's pending list. These results do not establish standalone bootstrap-parent error propagation or continuous ownership timing.

**1,677 exported files** were hashed before Sandbox closed: results, transcripts, process records, complete native rule/filter/adapter/address/DHCP/DNS/route snapshots and protected journals. All read-only input hashes matched. Final guest inspection found no product processes, installed image, uninstall registration, application profile or owned v2 rules. Seeded preserved policy and diagnostic files remained only inside the disposable guest until closure. The export index is `target/privilege-final/rebuilt-ptu-retry/sandbox-export.json` relative to `src-tauri`.

Earlier unsuccessful runs remain exported: original destination failure; maintenance exit 77 after the path-only fix; preservation-name fixture precedence error; a managed-mutex SACL privilege error; and an uninstall assertion made before its child finished. The mutex helper now uses the same native `CreateMutexExW` descriptor/rights as production, and the uninstall fixture waits for all three postconditions. Complete filter classes are queried in batches; coverage is retained. Earlier diagnostic packages receive no final-candidate qualification credit. The long tool stall is not endurance evidence.

## Connected hardware results and restoration

Fresh production observations selected Ethernet index **15**, GUID `{812AD22F-3345-4817-B6D7-708D769E69AC}`, MAC `40:c2:ba:cf:d5:75`, Up. Existing `/24` bindings were `172.31.169.102`, `192.168.0.100`, `192.168.1.100`; DHCP was disabled and DNS empty. Native fresh resolution confirmed camera **172.31.169.84 / 40:cd:3a:03:28:e2** and PTU **192.168.1.202 / fc:68:3e:22:05:28**, using the corresponding existing sources and selected index. Historical `.74` was not treated as the PTU.

Preflight found no pending scratch rows, existing desired-present bindings, no exact v2 rules and two enabled broad historical Allow rules. A hash-checked copy of the production policy renamed every native writer to a throwing fixture function and predicted an inventory refusal before writes. Actual startup reproduced that refusal and retained the recovery barrier. Successful reconciliation would require host firewall migration, which was prohibited. This specific barrier, existing bindings and disabled output established the safe read-only run; output disabled alone was not the proof. No host maintenance or migration was used to bypass recovery.

The final staged image ran with an elevated token as PID **11036**. Its run is retained under `target/privilege-final/hardware-ptu-retry/` relative to `src-tauri`.

| Production workflow | Observation |
|---|---|
| Settings save/readback | Final repeat passed `554 → 13554 → 554`, with both saved log entries and persisted values |
| Remove primary address, native Cancel | Passed; real confirmation observed/cancelled and original address retained |
| DHCP native Cancel | **Pending:** recovery guard refused the unconfirmed mode request before the confirmation could appear; original mode restored in UI and persisted mode unchanged |
| Discovery/visible playback | Both current devices appeared in Nodes; operator confirmed updating live video |
| Cached PTU cold-start retry | Early adapter-unavailable at 11:22:13 local; automatic limits read at 11:22:20 after fresh discovery, before manual role changes |
| PTU limits and role assignment | Candidate logged `big=1001 small=100`; operator confirmed Clear → PTU reconnect without error |
| Left, Right, Up, Down | Operator tested and separately confirmed each moved and stopped after release |
| Home | Operator confirmed return and stop, plus live video updating; frontend logged homing and return to speed mode |
| Position replies | Home exercises the `PP&TP` polling path, but raw response values were not captured; return-to-speed-mode also follows a caught query failure. Independent successful reply evidence remains **pending** |
| Positive ICMP inside candidate | **Pending:** 75-second passive observation captured no replies; no inference that ICMP itself failed. No external ping is substituted for this gate |
| Normal Close | Operator confirmed window closed; complete process exit code 0 verified |

All motion controls were operated by the user. No automation commanded motion. Presets, boundaries and measured stop latency were not exercised.

One frame stall was logged at **11:28:32**, with playing again at **11:28:33**, reported recovery **706 ms**. This is the recovery phase after the “no usable frames for 3 seconds” detector fired; exact total interruption was not measured. A later playing status at 11:29:03 and the operator's video confirmation were retained. The initial transient PTU error, recovered stall and all unsuccessful UI attempts remain in the log.

The UI fixture initially missed the optional notice/accessibility readiness, then encountered a live-log sharing exception; one concurrent settings save reported Access denied. Its readers now share read/write/delete, and the final repeat passed. No product save behavior was changed. A separate workspace-only atomic-replacement probe also returned Access denied and did not isolate the save error's cause; it is retained without passing credit. The environment-based WebView diagnostic endpoint was unavailable. [Microsoft's WebView2 explanation](https://github.com/MicrosoftEdge/WebView2Feedback/issues/5645) describes elevated-host override restrictions; no machine debug policy or release debug behavior was changed to obtain observability.

After Close, original **config, device cache, key and both log files** were restored and all five SHA-256 hashes reverified. Selected IPv4 addresses/prefixes/origin, DHCP, DNS and routes matched the baseline. Every persistent firewall rule and all seven filter classes matched after canonical comparison of non-CIM/non-PowerShell properties. The earlier host attempt was also closed/restored before rebuilding. No PocketStream process or qualification Sandbox remains running; private session files and build outputs stay untracked.

## Remaining qualification

Positive candidate ICMP, DHCP confirmation Cancel and successful startup reconciliation, and independently observed raw position replies remain open. This host's policy cannot be migrated under the run's restrictions. The full [release procedure](privilege-v2-release-qualification.md) still requires full interactive install/uninstall, `/R`/queued-launch and continuous ownership timing, bootstrap-parent error propagation, actual partial-provider faults, listener enable/disable/nondefault-port/Any-reset and explicit-interface cases, physical binding/watchers/settings migration topology, cross-account/session/integrity ownership, physical native address/DHCP/restart writes/recovery, PTU presets/boundaries/timed stops, cable/reboot/resource/endurance and recording/relay checks, installed-package hardware/G3 and signed updates. A migration conflict is not partial-provider qualification; a virtual adapter is not a physical eligibility proof. These gates are pending, not waived or passed.
