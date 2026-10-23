# v0.6.7 camera test build

This local reliability checkpoint has software verification and a Windows application build. Physical camera, adapter, installer and resource qualification remains pending; it is not a hardware-qualified release.

## Re-streaming and camera transport

The merged build offers RTSP or SRT output with RTSP or UDP input. SRT runs as a listener with configurable port, latency, Stream ID and optional passphrase encryption, with a limit of 10 callers. SRT input is not implemented.

With VPN set to **None**, the displayed re-stream URL uses an active physical LAN address, preferring Wi-Fi and then Ethernet. It excludes VPN, virtual, APIPA and camera-adopted addresses. The listener remains bound to all addresses in this mode; explicitly selecting a VPN binds it to that adapter's address.

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

The local Windows regression run passes 777 Rust tests with two hardware-dependent tests ignored, plus 151 frontend tests. TypeScript, UI contracts, formatting, Clippy and the production frontend build pass. Windows test executables now receive their Common Controls manifest at build time, so the standard Cargo test command needs no manual patch. CI and release checks now run the complete frontend suite through `npm test`.

On the tested Windows setup, switching off the Wi-Fi radio retained the conflicting local route and HTTP access timed out. Fully disabling the Wi-Fi adapter selected Ethernet instead; the camera returned HTTP 200 and its page opened. This targeted check does not complete the broader hardware qualification below.

## Rollback

**Rollback to previous builds is unsafe even when they can parse the config.** Older builds ignore saved removal intent and temporary ownership. They may restore a binding the user removed or leave a temporary address behind. Parsing compatibility does not preserve these lifetime rules. Keep a config backup and record actual Windows addresses/DHCP state before any planned downgrade; review them with the older build stopped.

## Qualification still required

The draft build verifies the complete uploaded dependency-source asset set even while that source release is unpublished. Installed draft verification records `draft_ready=true`; full `g3_complete` remains false until the dependency-source prerelease is published. Publish that source prerelease before manually publishing the application, and rerun the default G3 check for final publication evidence. The build workflow publishes neither release.

The automated checks cover logic and simulated failure boundaries. Elevated Windows hardware runs must still establish capture-source matching on the reference ASIX adapter, selected-Ethernet proof with overlapping Wi-Fi subnets, cable-loss and freshness timing, crash/reboot address lifetime, DHCP transitions, recovery/recording behavior and native notice/video interaction.

Resource qualification must include at least 20 cable cycles, five camera reboots behind a switch and 60 minutes of playback with representative recording and relay. Measure the app, WebView2 and child processes together. The switch reboot fixture remains required even for planned direct-attach deployment. Record date, adapter/camera identities, build identity, timings and log excerpts in the qualification notes; these hardware checks are pending.
