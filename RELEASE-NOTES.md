# v0.6.7 camera test build

This local reliability checkpoint has software verification and a Windows application build. Physical camera, adapter, installer and resource qualification remains pending; it is not a hardware-qualified release.

## Privilege boundary v2-A.1: A1 and prerequisite proofs

The local main window now has an explicit application ACL with 46 command permissions and the required event, window, version, confirmation and updater permissions. Seventeen registrations and handlers and fifteen obsolete wrappers were removed. Scan completion continues to publish capabilities on the backend; the renderer no longer echoes them. The allowlist checker verifies registrations, build commands, capabilities, referenced wrappers and generated allow/deny payloads, with seeded drift tests.

The generated-context ACL proof and isolated native confirmation bridge passed. [Production workflow evidence](docs/runtime-evidence/privilege-v2-a1-continuation.md) separately records settings, both confirmation Cancel paths, discovery, live playback and corrected PTU role/query smoke against their exact artifacts. The PTU handoff fix preserves precautionary stop/retry and reports a motion alarm when dispatched movement remains unconfirmed; idle stale selections no longer raise that alarm. The corrected candidate reconnected to the verified PTU at `192.168.1.202` without the red toast and closed normally.

[Native prerequisites](docs/runtime-evidence/privilege-v2-native-prerequisites.md) passed for the fixed-script runner, caller abort, retained reconciliation, two-process exclusion and sole-owner crash recovery. Those primitives remained test-only at that checkpoint. Its recorded checks passed 764 ordinary Rust tests and four opt-in prerequisite fixtures; the frontend suite passed all 184 tests, including 29 PTU workflows. Typecheck, contracts, production frontend/release builds, formatting and Clippy passed as recorded.

The [A2 checkpoint](docs/runtime-evidence/privilege-v2-a2.md) integrates the fixed native policy, retained child/executor ownership, startup address recovery and dedicated machine-owner thread. Address operations reuse the existing identity, serialization, persistence and fake seams. DHCP and adapter restart have no nested RunAs fallback; the development host reports missing native access. Native read-only observations and the actual native failure helper have Windows process evidence; physical mutation qualification remains pending.

The [current integration checkpoint](docs/runtime-evidence/privilege-v2-a3.md) passed 784 ordinary Rust tests, seven explicit safe Windows process/read-only fixtures and 188 frontend tests, plus typecheck, contracts/build, formatting and Clippy. It implements program-scoped RTSP/SRT policy, preserved blocks, fixed installer maintenance, guarded in-place transactions, all-interface binding inventory, GUID settings migration and separate binding/firewall UI. `list_bind_interfaces` completes the 46-command end state. The optimized package was built and inspected, with its exact hashes/manifests recorded; it was not launched or installed.

The operator authorized deferring isolated Windows prerequisites until release qualification. This sequencing exception permits implementation and does not credit native tests as passed. Firewall/install/migration/transaction, native binding/cross-account matrices, native-write/partial-provider, positive candidate ICMP, cold-start retry, new-candidate hardware smoke, installed/G3 and resource gates remain pending. A4 and overall qualification remain incomplete. Earlier [A2 elevated camera/PTU smoke](docs/runtime-evidence/privilege-v2-a2.md), transient failures, recovery timing and restoration evidence remain historical and do not qualify this rebuild. The [deferred procedure](docs/runtime-evidence/privilege-v2-release-qualification.md) describes the remaining matrices. v2-B remains deferred; the release manifest still requests `requireAdministrator`, so renderer/media compromise still occurs in an elevated host. The [commit checkpoint](docs/runtime-evidence/privilege-v2-commit-checkpoint.md) remains historical.

## Re-streaming and camera transport

The merged build offers RTSP or SRT output with RTSP or UDP input. SRT runs as a listener with configurable port, latency, Stream ID and optional passphrase encryption, with a limit of 10 callers. SRT input is not implemented.

With Bind set to **All addresses**, the displayed re-stream URL uses an active physical LAN address, preferring Wi-Fi and then Ethernet. It excludes VPN, virtual, APIPA and camera-adopted addresses. The listener remains bound to all addresses in this mode; selecting eligible Ethernet, Wi-Fi or VPN binds it by stable interface GUID. The full IPv4 binding inventory includes addresses excluded from URL/QR selection; Windows rule status is reported separately.

Camera RTSP connections bind to the verified Ethernet interface and source address. Browser access uses the camera's actual web address and requires Windows to route it through the selected Ethernet adapter.

## Camera and Node addresses

Discovery, verification and control follow the selected physical Ethernet adapter. Cached entries need fresh MAC verification there before becoming Active. Capture matched by name or running unscoped is shown as degraded; its observations remain candidates until verified on that adapter.

Device identity uses MAC evidence on the selected Ethernet adapter, so a camera is not discarded merely because its IP matches a PC address on Wi-Fi. A matching PC address is marked as a conflict and identifies the owning adapter. Clicking the camera IP checks current ownership and routing, even if the displayed warning has not refreshed yet.

Turning off the Wi-Fi radio can leave Windows selecting that disconnected adapter for its retained IP. The marker then says **IP still reserved by PC**, and the tooltip and click error explain how to fully disable the adapter in Windows Network Connections (`Win+R` → `ncpa.cpl`). Once Windows releases the address, the warning clears automatically. While the conflicting adapter is disabled, use the camera page to change its IP to an unused address, then re-enable the adapter. A dormant address routed elsewhere does not keep the conflict warning active.

The Host card and discovery worker react promptly to native link changes. Hardware negotiation before Windows reports Ethernet as connected can still take several seconds.

APIPA camera addresses (169.254.0.0/16) are excluded from discovery, subnet adoption and control. Configure such cameras with a usable non-APIPA address using vendor tools. All APIPA Nodes are hidden, including historical rows. Saved APIPA host addresses and stored history are retained.

## Host binding lifetime

Committed host bindings persist across app exit, adapter loss/return, app restart and Windows reboot. Removing a Node does not remove its host binding. Remove a binding explicitly in Hosts; its saved removal intent prevents later reconciliation from restoring it. DHCP mode skips static reapplication and new automatic adoption. Returning to a static mode reasserts retained binding intent.

Scratch addresses and final automatic adds that have not committed are temporary. New temporary operations save exact adapter MAC/address/prefix ownership before the Windows add. Restart and adapter-return cleanup use that ownership and retain it when an OS outcome is ambiguous. Committing a binding transfers ownership in the same config save. External, manually claimed and committed addresses are protected.

Temporary addresses left by builds predating this ownership tracking cannot safely be identified by their IP alone. Review those addresses manually; this build does not guess and delete them.

Primary, saved secondary and unmanaged address removal, and DHCP mode changes, now wait for the native confirmation result. Cancelling leaves the configuration intact. A stale saved entry with missing legacy ownership can be removed when the address is confirmed absent, without deleting an address from another adapter.

## Verification

Release preparation updates the native SRT library to 1.5.7 for the newly disclosed handshake vulnerability. The compiler, source recipe, DLL hashes and source archives are pinned, with a fresh [security review](docs/runtime-evidence/g3-security-review-2026-10-23.md). Dependency binaries and corresponding sources can be verified from authenticated GitHub drafts; the build does not publish them.

The baseline local Windows regression run passed Rust and frontend suites, TypeScript, UI contracts, formatting, Clippy and the production frontend build. Current v2-A.1 results and pending gates are recorded separately in the qualification record linked above. Windows test executables receive their Common Controls manifest at build time, so the standard Cargo test command needs no manual patch. CI and release checks run the complete frontend suite through `npm test`.

On the tested Windows setup, switching off the Wi-Fi radio retained the conflicting local route and HTTP access timed out. Fully disabling the Wi-Fi adapter selected Ethernet instead; the camera returned HTTP 200 and its page opened. This targeted check does not complete the broader hardware qualification below.

## Rollback

**Rollback to previous builds is unsafe even when they can parse the config.** Older builds ignore saved removal intent and temporary ownership. They may restore a binding the user removed or leave a temporary address behind. Parsing compatibility does not preserve these lifetime rules. Keep a config backup and record actual Windows addresses/DHCP state before any planned downgrade; review them with the older build stopped.

## Qualification still required

The draft build verifies the complete uploaded dependency-source asset set even while that source release is unpublished. Installed draft verification records `draft_ready=true`; full `g3_complete` remains false until the dependency-source prerelease is published. Publish that source prerelease before manually publishing the application, and rerun the default G3 check for final publication evidence. The SRT binary dependency is also staged as a draft for review. The build workflow publishes none of these releases.

The automated checks cover logic and simulated failure boundaries. Elevated Windows hardware runs must still establish capture-source matching on the reference ASIX adapter, selected-Ethernet proof with overlapping Wi-Fi subnets, cable-loss and freshness timing, crash/reboot address lifetime, DHCP transitions, recovery/recording behavior and native notice/video interaction.

Resource qualification must include at least 20 cable cycles, five camera reboots behind a switch and 60 minutes of playback with representative recording and relay. Measure the app, WebView2 and child processes together. The switch reboot fixture remains required even for planned direct-attach deployment. Record date, adapter/camera identities, build identity, timings and log excerpts in the qualification notes; these hardware checks are pending.
