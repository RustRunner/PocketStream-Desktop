# v0.6.7 camera test build

This local reliability checkpoint has software verification and a Windows application build. Physical camera, adapter, installer and resource qualification remains pending; it is not a hardware-qualified release.

## Camera and Node addresses

Discovery, verification and control follow the selected physical Ethernet adapter. Cached entries need fresh MAC verification there before becoming Active. Capture matched by name or running unscoped is shown as degraded; its observations remain candidates until verified on that adapter.

APIPA camera addresses (169.254.0.0/16) are excluded from discovery, subnet adoption and control. Configure such cameras with a usable non-APIPA address using vendor tools. All APIPA Nodes are hidden, including historical rows. Saved APIPA host addresses and stored history are retained.

## Host binding lifetime

Committed host bindings persist across app exit, adapter loss/return, app restart and Windows reboot. Removing a Node does not remove its host binding. Remove a binding explicitly in Hosts; its saved removal intent prevents later reconciliation from restoring it. DHCP mode skips static reapplication and new automatic adoption. Returning to a static mode reasserts retained binding intent.

Scratch addresses and final automatic adds that have not committed are temporary. New temporary operations save exact adapter MAC/address/prefix ownership before the Windows add. Restart and adapter-return cleanup use that ownership and retain it when an OS outcome is ambiguous. Committing a binding transfers ownership in the same config save. External, manually claimed and committed addresses are protected.

Temporary addresses left by builds predating this ownership tracking cannot safely be identified by their IP alone. Review those addresses manually; this build does not guess and delete them.

## Rollback

**Rollback to previous builds is unsafe even when they can parse the config.** Older builds ignore saved removal intent and temporary ownership. They may restore a binding the user removed or leave a temporary address behind. Parsing compatibility does not preserve these lifetime rules. Keep a config backup and record actual Windows addresses/DHCP state before any planned downgrade; review them with the older build stopped.

## Qualification still required

The automated checks cover logic and simulated failure boundaries. Elevated Windows hardware runs must still establish capture-source matching on the reference ASIX adapter, selected-Ethernet proof with overlapping Wi-Fi subnets, cable-loss and freshness timing, crash/reboot address lifetime, DHCP transitions, recovery/recording behavior and native notice/video interaction.

Resource qualification must include at least 20 cable cycles, five camera reboots behind a switch and 60 minutes of playback with representative recording and relay. Measure the app, WebView2 and child processes together. The switch reboot fixture remains required even for planned direct-attach deployment. Record date, adapter/camera identities, build identity, timings and log excerpts in the qualification notes; these hardware checks are pending.
