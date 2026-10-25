# Deferred Windows qualification procedure

These checks require a disposable, isolated Windows fixture. Do not run installation, uninstallation, firewall mutation, address/DHCP changes or fault injection on the development PC. Automated policy fakes and generated-installer inspection do not satisfy these checks. A4 and overall v2-A qualification remain incomplete.

The operator authorized implementing firewall/install/binding integration before the isolated prerequisites on 24 October 2026. This is a sequencing exception, not a passing result. Earlier [prerequisite](privilege-v2-native-prerequisites.md) and [application/hardware](privilege-v2-a2.md) evidence remains historical evidence for its recorded images.

## Artifact and fixture preparation

1. Use the candidate identified by [the integration record](privilege-v2-a3.json). Hash the executable, installer, generated NSIS, expanded NSIS, template and transaction include. Record the source-input digest, Windows build, PowerShell 5.1 version, NSIS version, account, logon session and token integrity. The local inspection package is unsigned and has updater-artifact creation disabled; signed update/G3 closure is a separate release gate.
2. Snapshot a clean Windows VM. Provide two accounts and separate interactive logon sessions for ownership tests, physical/virtual Ethernet, Wi-Fi and VPN/virtual adapters for binding tests, and camera/PTU hardware for the production matrix. Save native addresses/prefixes, DHCP, DNS, routes, adapters and complete firewall rules/filters before each scenario. Keep the fixture's state and snapshots separate from this PC's profile.
3. Reproduce safe build checks using the repository's GStreamer SDK/runtime setup:

   ```powershell
   npm.cmd ci
   npm.cmd run typecheck
   npm.cmd test
   npm.cmd run build
   # From src-tauri, with POCKETSTREAM_RELEASE unset:
   cargo test --lib --locked
   cargo clippy --all-targets --no-deps --locked -- -D warnings
   cargo fmt --check
   ```

4. For an unsigned inspection package, set `POCKETSTREAM_RELEASE=1` and run:

   ```powershell
   npm.cmd run tauri -- build --bundles nsis --no-sign --ci --config '{"bundle":{"createUpdaterArtifacts":false}}' -- --locked
   npm.cmd run check:installer:generated
   ```

   The latter command trace-compiles the actual generated script with the cached NSIS compiler and MUI logging enabled, then checks the expanded callback paths. It does not run the installer. Preserve `target/release/nsis/x64/installer.nsi`, `installer.compile.log` and `compile-inspection.json` alongside the executable/installer hashes. Extract resource `#1` using Windows SDK `mt.exe`; the host must contain `requireAdministrator` and Common Controls v6. Extract the package without executing it. Record staged and embedded executable hashes separately: this pinned toolchain patches `__TAURI_BUNDLE_TYPE_VAR_UNK` to `__TAURI_BUNDLE_TYPE_VAR_NSS` in the package. Require every other byte to match and qualify the exact intended image.

## Firewall and maintenance matrix — isolated fixture only

Use an elevated Windows PowerShell 5.1 session. Derive the executable from the protected install root, never from renderer input. Preserve the native `firewall-maintenance-*.json` journals, the installer's `pocketstream-maintenance.json` and any incomplete `pocketstream-transaction.json`, installer details and before/after snapshots. The installer leaves these diagnostic files when removing application files.

For each rule snapshot, retain the rule plus `Get-NetFirewallApplicationFilter`, `Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter`, `Get-NetFirewallInterfaceFilter`, `Get-NetFirewallInterfaceTypeFilter`, `Get-NetFirewallServiceFilter` and `Get-NetFirewallSecurityFilter`. Record query failures explicitly; a failed query is not an empty policy store. Check Enabled and every intended filter, including Program, interface, Any reset, security/bypass flags and unrelated restrictions.

| Scenario | Setup and action | Required observation |
|---|---|---|
| Fresh install | Clean snapshot; choose a fresh child of Program Files. Run the candidate without `/R`. Repeat interactively, `/P`, `/S`, and `/S /UPDATE`. | Both exact v2 names exist in `PocketStream.Desktop.Managed.v2`, disabled, exact canonical Program, Inbound/Allow/Profile Any; TCP 8554 and UDP 8890; unrestricted remote ports/addresses; no unrelated restrictions. No GUI/media/profile initialization by maintenance. |
| Listener lifecycle | Start RTSP and SRT separately using nondefault ports. Stop, replace protocol, induce a bind failure, and race Stop with Start/recovery. | Preflight precedes policy enable; only the current generation enables; retired/failed generations disable; stale cleanup never disables a newer rule. Card reports verified local scope and automation outcome separately. A block or other Windows policy can still prevent traffic. |
| Explicit interface | Bind to a GUID-selected adapter, rename it, remove its address, disconnect/reconnect, then select All addresses. | Fresh identity and alias verification, unavailable on absence/replacement/ambiguity, no implicit Any fallback; Any reset removes the old interface filter. Verify actual listener socket addresses. |
| Preserved denies | Before install/runtime, create an inbound Block with the candidate Program and a `Query User` display name; also retain unrelated blocks. | The exact blocks and all their filters survive install, ensure, stop and uninstall. Relevant application block native names appear as preserved policy. |
| Legacy upgrade | Install actual v0.6.7 first. Exercise each output independently and both; create custom-port and duplicate-display-name historical rules. Include disabled rules and an already program-scoped matching legacy shape. Upgrade without launching the new app. | Every recognized broad candidate is disabled and read back before disabled templates are prepared. Only recognized candidates are removed. No enabled broad legacy allow remains on a successful migration. Record native names/prior shapes. |
| Migration convention | Add a manually created clone indistinguishable from the documented historical shape. | It is also disabled/removed; record that this is a migration convention, not a historical ownership marker. |
| Foreign/unrecognized | Seed a historical display name scoped to another Program; separately seed an unrecognized broad shape (for example Private profile). Seed an exact v2 native name owned by another Program/group. | Foreign rules remain intact. Unrecognized broad/colliding rules cause explicit incomplete migration, a nonzero status and preserved diagnostics; no hardened-install claim. |
| Partial/repeated recovery | Resume from broad rules disabled but not removed, one template present, and a prior incomplete maintenance record. Inject a controlled failure after policy/filter application in a test-only fixture build, then run the unmodified candidate again. | Failed verification leaves owned rules disabled or explicitly Uncertain. No broad rule is re-enabled. Retry is idempotent. Preserve the fault build's different source/binary hashes and injected step; fake-provider coverage alone does not qualify actual Windows partial-provider behavior. |
| Startup recovery | Enable exact owned rules, terminate a lone fixture host so all owner handles close, then start the candidate. Also test failed observation and ownership conflict. | Fresh startup reconciles stale enables without relying on WAIT_ABANDONED; unknown effects keep conflicting writes unavailable. Normal successful startup can enable only a later current listener generation. |
| Standalone uninstall | With no host running, use the registered standalone uninstaller; repeat relevant modes and include remaining recognized legacy rules. | Fixed uninstall maintenance runs before deleting the executable. Only this Program/group's exact v2 rules and recognized legacy rules are removed; foreign rules and every Block remain. Nonzero maintenance prevents deletion and is visible in silent mode. |
| Strict entry | Run malformed/unknown maintenance arguments, unelevated development maintenance, and maintenance from an unprotected image/root. | Bounded structured error and nonzero exit; no GUI, user log/config initialization, nested RunAs or firewall mutation. |

The native partial-provider fault mechanism must be identified and recorded on the isolated fixture. A simulated failure before any write, an ordinary conflict, or successful fake cleanup must not be relabeled as a real partial-provider result. Add/Remove/Static/DHCP/DNS/route/renew/restart postconditions and caller-abort uncertainty remain separate pending address-operation gates.

## Installer ownership and every exit path

For each interactive, passive, silent and updater mode, test fresh install, same-version reinstall, upgrade, preflight Busy, cancellation before file changes, file-replacement failure, maintenance failure and normal completion. Use `/D=` last when specifying a destination. Keep installation in the registered protected root during upgrades; relocation and unsupported/MSI predecessors require standalone uninstall first.

Observe both global mutexes and process/file activity throughout the transaction, including initialization, early checks, pages, replacement, maintenance, finish-page shortcut callbacks, cancellation and failure. A host in another account/session/copy must return InstallerBusy while InstallGate is held. An existing host must finish/exit within the bounded wait or the installer must abort before replacement. A legacy v0.6.7 process must be detected; test a restart immediately before replacement and file-in-use failure. No process-kill or previous-uninstaller child may appear. A maintenance child must acquire HostOwner while its parent retains InstallGate; it must not reacquire InstallGate.

Check that every terminal path releases its gate. Interactive launch is queued until all finish-page file callbacks complete; silent/updater `/R` launch also follows release. Failures after replacement began must report incomplete installation, preserve diagnostics and make no rollback claim. The static/compiled-trace contract is supporting evidence, not proof of native handle ownership or callback timing.

## Binding and settings matrix

Keep camera Ethernet unchanged while adding/removing/changing a Wi-Fi, VPN and non-VPN virtual address. Include multiple addresses, an adopted secondary, APIPA and loopback. Compare the card's wildcard inventory to unfiltered IPv4 IP Helper state and actual IPv4 listeners. Confirm the shared notification worker coalesces bursts and the existing fallback/retry path publishes changes even when selected-camera refresh fails. Inject an observation failure: inventory must become Unknown and recover from a later successful observation.

For explicit binds, verify GUID persistence across alias rename, index/address changes and restart. Reuse an old alias on another adapter: a saved GUID must not follow it. Test legacy alias-only settings with unique, missing and ambiguous resolution; unavailable legacy selections remain unavailable until the operator chooses again, including after restart. Test a save failure: migration must not be published in memory before persistence succeeds. Race enumeration/resolution against protocol switch, Stop and topology revision changes; late work must not publish a stale binding or policy result. Confirm URL/QR selection excludes adopted/APIPA addresses while wildcard exposure still lists them.

## Hardware and release closure

Repeat the production settings save/readback, both confirmation Cancel paths, discovery/selected-adapter identity proof, **positive ICMP inside this candidate**, visible live playback, PTU role/position/limits and individually recorded user-operated directions/Home/stop, then normal Close and complete process exit. Preflight pending recovery and automatic adoption, use existing bindings when qualifying read-only workflows, disable re-streaming for that smoke, preserve profile files, and verify file/native-state restoration. Record transient failures and playback recovery duration separately from total interruption. Repeat affected workflows against every rebuilt image; the earlier optimized image's smoke does not qualify this candidate. Cold-start cached-role retry, presets, limits/boundaries, timed stop behavior, cable/reboot, endurance, installed-package/G3 and signed update closure remain pending until actually exercised.

Record each result as passed, failed or pending, with exact hashes/commands and cleanup observations. Retain unsuccessful attempts. v2-B helper transport, Grant access, update preparation and host manifest demotion remain deferred; the 46-command contract and administrator release manifest are required throughout v2-A.
