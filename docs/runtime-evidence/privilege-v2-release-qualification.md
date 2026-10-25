# Windows release qualification procedure

The current work is a [bounded development checkpoint](privilege-v2-development-checkpoint.md). The operator stopped full A4 qualification; only demonstrated fixes and the requested listener fixture regression continue. This procedure remains a future requirement, not the current execution plan.

These checks require a disposable, isolated Windows fixture. Windows Sandbox can qualify the supported subset after its prerequisites pass; missing services or unsupported device/session behavior remain pending. Do not run installation, uninstallation, firewall mutation, address/DHCP changes or fault injection on the development PC. Automated policy fakes and generated-installer inspection do not satisfy these checks. A4 and overall v2-A qualification remain incomplete.

The [latest qualification record](privilege-v2-final-qualification.md) reports 28 passing Sandbox scenarios and limited elevated camera/PTU smoke against its exact rebuilt images, with failures and remaining gates preserved. The matrix below remains the full release requirement; passing a subset does not close it.

The operator authorized implementing firewall/install/binding integration before the isolated prerequisites on 24 October 2026. This is a sequencing exception, not a passing result. Earlier [prerequisite](privilege-v2-native-prerequisites.md) and [application/hardware](privilege-v2-a2.md) evidence remains historical evidence for its recorded images.

## Artifact and fixture preparation

1. Use the latest candidate identified by [the consolidated qualification record](privilege-v2-final-qualification.json). Its hash-named artifacts supersede the normal output aliases in the historical integration/review records. Hash the executable, installer, generated NSIS, expanded NSIS, template and transaction include. Verify all recorded application/validation source inputs and the separate qualification fixtures. Record the source-input digest, Windows build, PowerShell 5.1 version, NSIS version, account, logon session and token integrity. The local inspection package is unsigned and has updater-artifact creation disabled; signed update/G3 closure is a separate release gate.
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

## Reusable Windows Sandbox fixture

The [resume checkpoint](privilege-v2-sandbox-resume.md) preserves the original launcher and restart prerequisite. Its old package is historical. The generator now defaults to the consolidated record and performs only file/hash/resource/package inspection on the host:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-privilege-sandbox.ps1 -Mode Preflight
# To include the supported automated subset after the same guest preflight:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-privilege-sandbox.ps1 -Mode Supported
```

Supply `-LegacyInstaller <path> -LegacySha256 <independently recorded hash>` to include an actual predecessor upgrade. The recorded predecessor is `src-tauri/target/v0.6.7-release-download/PocketStream.Desktop_0.6.7_x64-setup.exe`, SHA-256 `35e2d0a4eff03cd4f5bac95e15315b088873298318ffcf3ae6ab63b2f99e90af`; verify it independently before reuse. Each invocation requires a new run directory and preserves earlier attempts. The generated `.wsb` maps only installer/script inputs read-only and a dedicated sibling results directory writable. It disables clipboard, audio/video and printer redirection. Networking uses Sandbox's virtual switch so the unmodified candidate can obtain its WebView2 prerequisite; no registry spoof or fake prerequisite is used. These options follow [Microsoft's configuration contract](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

If Sandbox is disabled, an administrator can run `Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart`, following [Microsoft's installation instructions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install). Record `RestartNeeded`. Save the launcher, evidence and resume instructions and obtain operator confirmation before restarting; enabling the feature does not establish that Sandbox can boot.

The guest script first verifies its real WDAGUtilityAccount token, a different computer identity, fixed mapping paths, read-only access and every input hash. It rejects host execution, including its mutex-helper modes. Before native scenarios it records PowerShell 5.1/x64/elevation, BFE/MpsSvc/Winmgmt, trusted system modules, the firewall provider, adapters and WebView2/installer bootstrap prerequisites. Missing or stopped required services/modules stop the matrix with pending results. Virtual adapters do not satisfy physical-adapter eligibility; the production selector is unchanged.

The primary subset covers protected destination refusal, interactive welcome Cancel, fresh silent/passive/updater install, silent/passive/updater reinstall without relaunch, strict entry refusal, legacy/custom/duplicate/disabled/program-scoped rule migration, repeated recovery, preserved Block/foreign rules and filters, migration conflict/collision failure and retry, HostOwner Busy, image-in-use refusal, standalone silent/passive uninstall and installation afterward. An independently hashed predecessor enables a real installer upgrade with explicitly seeded historical rule shapes. Complete native rule/filter and adapter/address/DHCP/DNS/route snapshots and protected journals accompany each scenario. The installed executable and extracted payload are independently hashed. Every new run remains pending until its own exported results establish the outcome.

After the primary run passes and reports no installed image/registration/owned rules, run the supplemental fixture **inside that same Sandbox only**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\PocketStreamQualification\Inputs\Invoke-PrivilegeSandboxFailures.ps1
```

It rechecks real guest identity, elevation, services, immutable inputs and script hashes, then reuses the primary fixture's actual functions. It holds one installed DLL open, selects Ignore only on the PID/text-bound extraction dialog, verifies failure exit 71/diagnostics, repairs, tests a verified copied uninstaller child with a locked payload, and repairs/uninstalls again. Do not substitute this direct child result for bootstrap-parent propagation. The tested continuation used a separately hashed read-only supplemental mapping; new launchers include the script in their read-only input manifest.

The full matrix below still applies. Full interactive install/uninstall, relaunch/continuous ownership timing, queued launch, bootstrap-parent error propagation, actual partial-provider injection, physical adapter changes, multiple accounts/sessions and installed hardware are not replaced by these subsets. Exported success for one subset must not mark those gates passed. Before closing Sandbox, verify every `results.json`, transcript, per-process record, before/after snapshot, journal and post-run input hash exists on the host's dedicated results mapping; hash and retain the complete export. Verify no product process/image/registration/owned rule remains. The fixture leaves Sandbox open for inspection and does not delete host results.

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
