#Requires -Version 5.1
<#
.SYNOPSIS
Runs PocketStream's G2 SRT caller-admission gate.

.DESCRIPTION
Builds a dedicated Rust/GStreamer example harness, isolates it to the staged
G1-R runtime, and proves the srtsink callback ABI and strict pending-plus-active
caller cap before production SRT listener code is permitted.

The gate verifies the exact G1-R libsrt.dll hash and version, the complete
seven-file SRT closure, caller-connecting authentication gating, callback
rejection, successful signal ordering and address correlation, Stream ID
delivery, library-level password failures, ten-second pending expiry,
same-address refresh, and the ten-caller cap.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\verify-g2-srt.ps1
#>

[CmdletBinding()]
param(
    [string]$GStreamerRoot = $env:GSTREAMER_1_0_ROOT_MSVC_X86_64,
    [string]$BundleRoot,
    [string]$G1EvidencePath,
    [string]$EvidencePath,
    [string]$HarnessPath,
    [switch]$KeepWorkDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'gstreamer-manifest.psd1'
$HarnessSourcePath = Join-Path $ProjectDir 'src-tauri\examples\g2_srt_admission.rs'
$CargoManifestPath = Join-Path $ProjectDir 'src-tauri\Cargo.toml'
$CargoLockPath = Join-Path $ProjectDir 'src-tauri\Cargo.lock'
if ([string]::IsNullOrWhiteSpace($G1EvidencePath)) {
    $G1EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g1-r-srt-1.5.7.json'
}
$Manifest = Import-PowerShellDataFile $ManifestPath
$Srt = $Manifest.PatchedSrt
$BuildHarness = [string]::IsNullOrWhiteSpace($HarnessPath)

if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'G2 must run on 64-bit Windows.'
}
if ($BuildHarness -and [string]::IsNullOrWhiteSpace($GStreamerRoot)) {
    throw 'GStreamerRoot is required to compile the G2 harness against GStreamer 1.26.11.'
}
if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $BundleRoot = Join-Path $ProjectDir 'src-tauri\resources\gstreamer'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g2-srt-admission-1.5.7.json'
}

if (-not [string]::IsNullOrWhiteSpace($GStreamerRoot)) {
    $GStreamerRoot = [System.IO.Path]::GetFullPath($GStreamerRoot).TrimEnd('\', '/')
}
$BundleRoot = [System.IO.Path]::GetFullPath($BundleRoot).TrimEnd('\', '/')
$EvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
$BundleBin = Join-Path $BundleRoot 'bin'
$BundlePlugins = Join-Path $BundleRoot 'lib\gstreamer-1.0'
$StagedSrtPath = Join-Path $BundleBin 'libsrt.dll'
$ExpectedPluginPath = Join-Path $BundlePlugins 'gstsrt.dll'
$SdkBin = if ($BuildHarness) { Join-Path $GStreamerRoot 'bin' } else { $null }
$SdkPkgConfig = if ($BuildHarness) { Join-Path $GStreamerRoot 'lib\pkgconfig' } else { $null }
$SdkInspectPath = if ($BuildHarness) { Join-Path $SdkBin 'gst-inspect-1.0.exe' } else { $null }
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pocketstream-g2-{0}" -f [Guid]::NewGuid().ToString('N'))
$EmptyPluginDir = Join-Path $WorkDir 'no-system-plugins'
$RawHarnessPath = Join-Path $WorkDir 'harness-result.json'
$RegistryPath = Join-Path $WorkDir 'registry.bin'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ([string]$Actual -cne [string]$Expected) {
        throw "$Description mismatch: expected '$Expected', got '$Actual'."
    }
}

function Assert-PathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $actualFull = [System.IO.Path]::GetFullPath($Actual).TrimEnd('\', '/')
    $expectedFull = [System.IO.Path]::GetFullPath($Expected).TrimEnd('\', '/')
    if (-not $actualFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description mismatch: expected '$expectedFull', got '$actualFull'."
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Restore-ProcessEnvironment {
    param([Parameter(Mandatory = $true)][hashtable]$Values)
    foreach ($name in $Values.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Values[$name], 'Process')
    }
}

$environmentNames = @(
    'Path',
    'GSTREAMER_1_0_ROOT_MSVC_X86_64',
    'PKG_CONFIG_PATH',
    'GST_PLUGIN_PATH',
    'GST_PLUGIN_PATH_1_0',
    'GST_PLUGIN_SYSTEM_PATH',
    'GST_PLUGIN_SYSTEM_PATH_1_0',
    'GST_REGISTRY',
    'GST_REGISTRY_1_0',
    'GST_REGISTRY_FORK',
    'GST_DEBUG'
)
$savedEnvironment = @{}
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    Write-Host 'G2: validating the G1-R dependency boundary...' -ForegroundColor Cyan
    foreach ($requiredFile in @(
        $ManifestPath,
        $HarnessSourcePath,
        $CargoManifestPath,
        $CargoLockPath,
        $G1EvidencePath,
        $StagedSrtPath,
        $ExpectedPluginPath
    )) {
        Assert-True -Condition (Test-Path -LiteralPath $requiredFile -PathType Leaf) `
            -Message "Required G2 input is missing: $requiredFile"
    }
    if ($BuildHarness) {
        Assert-True -Condition (Test-Path -LiteralPath (Join-Path $SdkPkgConfig 'gstreamer-1.0.pc') -PathType Leaf) `
            -Message "GStreamer 1.26.11 development metadata is missing below $GStreamerRoot"
        Assert-True -Condition (Test-Path -LiteralPath $SdkInspectPath -PathType Leaf) `
            -Message "GStreamer inspection tool is missing below $GStreamerRoot"
        Assert-Equal -Actual (Get-Sha256 -Path $SdkInspectPath) -Expected $Srt.GstInspectSha256 `
            -Description 'G2 compile SDK gst-inspect SHA256'
    }

    Assert-Equal -Actual (Get-Sha256 -Path $StagedSrtPath) -Expected $Srt.DllSha256 `
        -Description 'Staged G2 libsrt.dll SHA256'
    foreach ($relativePath in @($Srt.StagedClosure.Keys | Sort-Object)) {
        $nativeRelativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $fullPath = Join-Path $BundleRoot $nativeRelativePath
        Assert-True -Condition (Test-Path -LiteralPath $fullPath -PathType Leaf) `
            -Message "G1-R staged closure file is missing: $relativePath"
        Assert-Equal -Actual (Get-Sha256 -Path $fullPath) -Expected $Srt.StagedClosure[$relativePath] `
            -Description "G1-R staged closure $relativePath SHA256"
    }

    $g1Evidence = Get-Content -LiteralPath $G1EvidencePath -Raw | ConvertFrom-Json
    Assert-Equal -Actual $g1Evidence.gate -Expected 'G1-R' -Description 'Prerequisite evidence gate'
    Assert-Equal -Actual $g1Evidence.result -Expected 'pass' -Description 'Prerequisite G1-R result'
    Assert-True -Condition ([bool]$g1Evidence.g1_r_complete) -Message 'Committed G1-R evidence is incomplete.'
    Assert-Equal -Actual $g1Evidence.staged_runtime.libsrt_sha256 -Expected $Srt.DllSha256 `
        -Description 'G1-R evidence libsrt.dll SHA256'
    Assert-Equal -Actual $g1Evidence.staged_runtime.srt_getversion_hex -Expected $Srt.RuntimeVersionHex `
        -Description 'G1-R evidence srt_getversion'

    if ($BuildHarness) {
        Write-Host 'G2: compiling the Rust/GStreamer admission harness...' -ForegroundColor Cyan
        $cargo = Get-Command cargo.exe -ErrorAction Stop
        $env:GSTREAMER_1_0_ROOT_MSVC_X86_64 = "$GStreamerRoot\"
        $env:PKG_CONFIG_PATH = $SdkPkgConfig
        $env:Path = "$SdkBin;$($savedEnvironment['Path'])"
        $savedErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $cargo.Source build --manifest-path $CargoManifestPath --example g2_srt_admission --locked
            $cargoExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorActionPreference
        }
        if ($cargoExitCode -ne 0) {
            throw "G2 Rust harness build failed with exit $cargoExitCode."
        }
        $HarnessPath = Join-Path $ProjectDir 'src-tauri\target\debug\examples\g2_srt_admission.exe'
    }
    $HarnessPath = [System.IO.Path]::GetFullPath($HarnessPath)
    Assert-True -Condition (Test-Path -LiteralPath $HarnessPath -PathType Leaf) `
        -Message "G2 harness executable is missing: $HarnessPath"
    $rustcCommand = Get-Command rustc.exe -ErrorAction Stop
    $cargoCommand = Get-Command cargo.exe -ErrorAction Stop
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $rustcVersionLines = @(& $rustcCommand.Source --version 2>&1 | ForEach-Object { $_.ToString() })
        $cargoVersionLines = @(& $cargoCommand.Source --version 2>&1 | ForEach-Object { $_.ToString() })
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    $rustcVersion = @($rustcVersionLines | Where-Object { $_ -match '^rustc\s' } | Select-Object -First 1) -join ''
    $cargoVersion = @($cargoVersionLines | Where-Object { $_ -match '^cargo\s' } | Select-Object -First 1) -join ''
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($rustcVersion)) `
        -Message 'Could not read the rustc version for G2 evidence.'
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($cargoVersion)) `
        -Message 'Could not read the cargo version for G2 evidence.'

    New-Item -ItemType Directory -Force -Path $EmptyPluginDir | Out-Null

    Write-Host 'G2: running callback and strict-admission probes in the staged runtime...' -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
    [Environment]::SetEnvironmentVariable(
        'Path',
        "$BundleBin;$env:SystemRoot\System32;$env:SystemRoot",
        'Process'
    )
    $env:GST_PLUGIN_PATH = $BundlePlugins
    $env:GST_PLUGIN_PATH_1_0 = $BundlePlugins
    $env:GST_PLUGIN_SYSTEM_PATH = $EmptyPluginDir
    $env:GST_PLUGIN_SYSTEM_PATH_1_0 = $EmptyPluginDir
    $env:GST_REGISTRY = $RegistryPath
    $env:GST_REGISTRY_1_0 = $RegistryPath
    $env:GST_REGISTRY_FORK = 'no'
    $env:GST_DEBUG = '1'

    foreach ($nativeArgument in @($StagedSrtPath, $RawHarnessPath)) {
        if ($nativeArgument.Contains('"')) {
            throw "G2 harness paths may not contain a double quote: $nativeArgument"
        }
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $HarnessPath
    $startInfo.Arguments = "--libsrt `"$StagedSrtPath`" --output `"$RawHarnessPath`""
    $startInfo.WorkingDirectory = $BundleBin
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'Failed to start the G2 Rust admission harness.'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(120000)) {
        $process.Kill()
        [void]$process.WaitForExit(10000)
        throw 'G2 admission harness exceeded its 120-second process deadline.'
    }
    $harnessStdout = $stdoutTask.GetAwaiter().GetResult()
    $harnessStderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        throw "G2 admission harness failed with exit $($process.ExitCode).`n$harnessStdout`n$harnessStderr"
    }
    Assert-True -Condition (Test-Path -LiteralPath $RawHarnessPath -PathType Leaf) `
        -Message 'G2 harness did not write its result JSON.'
    $raw = Get-Content -LiteralPath $RawHarnessPath -Raw | ConvertFrom-Json

    Assert-Equal -Actual $raw.result -Expected 'pass' -Description 'Rust harness result'
    Assert-Equal -Actual $raw.runtime.gstreamer_version -Expected 'GStreamer 1.26.11' `
        -Description 'Isolated GStreamer version'
    Assert-Equal -Actual $raw.runtime.srt_plugin_version -Expected '1.26.11' `
        -Description 'Isolated SRT plugin version'
    Assert-Equal -Actual $raw.runtime.srt_getversion_hex -Expected $Srt.RuntimeVersionHex `
        -Description 'G2 staged srt_getversion result'
    Assert-Equal -Actual $raw.runtime.isolated_plugin_negative_control -Expected 'opusdec absent' `
        -Description 'G2 plugin isolation negative control'
    Assert-PathEqual -Actual $raw.runtime.srt_plugin_filename -Expected $ExpectedPluginPath `
        -Description 'Loaded G2 SRT plugin path'
    Assert-Equal -Actual $raw.constants.client_limit -Expected 10 -Description 'G2 client limit'
    Assert-Equal -Actual $raw.constants.pending_ttl_seconds -Expected 10 -Description 'G2 pending TTL'

    $auth = $raw.scenarios.authentication_gate
    Assert-True -Condition ([bool]$auth.callback_requires_authentication) `
        -Message 'caller-connecting was not gated by authentication=true.'
    Assert-Equal -Actual $auth.caller_connecting_count -Expected 0 `
        -Description 'authentication=false caller-connecting count'
    Assert-Equal -Actual $auth.caller_added_count -Expected 1 `
        -Description 'authentication=false caller-added count'
    Assert-Equal -Actual $auth.caller_removed_count -Expected 1 `
        -Description 'authentication=false caller-removed count'

    $rejection = $raw.scenarios.application_rejection
    Assert-True -Condition ([bool]$rejection.false_return_prevented_add) `
        -Message 'A caller-connecting false return did not prevent caller-added.'
    Assert-Equal -Actual $rejection.caller_added_signals -Expected 0 `
        -Description 'Application-rejected caller-added count'
    Assert-True -Condition ([bool]$rejection.client_failed) `
        -Message 'Application-rejected caller did not fail.'

    $lifecycle = $raw.scenarios.successful_lifecycle
    Assert-Equal -Actual ($lifecycle.ordering -join ',') `
        -Expected 'caller-connecting,caller-added,caller-removed' `
        -Description 'Successful caller signal ordering'
    Assert-Equal -Actual ($lifecycle.caller_added_unused_values -join ',') -Expected '0' `
        -Description 'caller-added integer ABI argument'
    Assert-Equal -Actual ($lifecycle.caller_removed_unused_values -join ',') -Expected '0' `
        -Description 'caller-removed integer ABI argument'
    Assert-True -Condition ([bool]$lifecycle.canonical_key_equal_across_signals) `
        -Message 'Successful caller signals did not share one canonical remote key.'
    Assert-True -Condition ([bool]$lifecycle.stream_id_delivered_byte_for_byte) `
        -Message 'Stream ID changed before caller-connecting.'
    Assert-Equal -Actual $lifecycle.active_after_removal -Expected 0 `
        -Description 'Active count after successful removal'

    $passwords = $raw.scenarios.password_failures_and_pending_ttl
    Assert-True -Condition ([bool]$passwords.wrong_passphrase_client_failed) `
        -Message 'Wrong passphrase did not fail in libsrt.'
    Assert-True -Condition ([bool]$passwords.missing_passphrase_client_failed) `
        -Message 'Missing passphrase did not fail in libsrt.'
    Assert-Equal -Actual $passwords.application_rejections_for_library_failures -Expected 0 `
        -Description 'Application rejections for library password failures'
    Assert-Equal -Actual $passwords.caller_rejected_signals_for_library_failures -Expected 0 `
        -Description 'caller-rejected signals for library password failures'
    Assert-Equal -Actual $passwords.active_during_library_failures -Expected 0 `
        -Description 'Active callers during password failures'
    Assert-True -Condition ([int]$passwords.pending_before_expiry -ge 3) `
        -Message 'Password failures did not leave the expected pending reservations.'
    Assert-True -Condition ([int]$passwords.repeated_same_key_refreshes -ge 1) `
        -Message 'A repeated remote socket did not refresh its reservation.'
    Assert-True -Condition (
        [int]$passwords.expired_on_next_admission -ge [int]$passwords.pending_before_expiry
    ) -Message 'Failed-handshake reservations did not expire before the next admission.'
    Assert-Equal -Actual $passwords.correct_passphrase_active_after_expiry -Expected 1 `
        -Description 'Correct caller count after pending expiry'
    Assert-Equal -Actual $passwords.active_after_removal -Expected 0 `
        -Description 'Active count after post-expiry caller removal'

    $capacity = $raw.scenarios.strict_capacity
    Assert-Equal -Actual $capacity.simultaneous_attempts -Expected 11 `
        -Description 'Concurrent capacity attempts'
    Assert-Equal -Actual $capacity.admitted_before_cap -Expected 10 `
        -Description 'Callers admitted before cap'
    Assert-True -Condition ([bool]$capacity.eleventh_application_rejected) `
        -Message 'The eleventh caller was not rejected by the application admission callback.'
    Assert-True -Condition ([bool]$capacity.eleventh_caller_rejected_signal) `
        -Message 'The eleventh caller did not emit caller-rejected.'
    Assert-Equal -Actual $capacity.maximum_pending_plus_active -Expected 10 `
        -Description 'Maximum pending-plus-active occupancy'
    Assert-Equal -Actual $capacity.active_at_cap -Expected 10 `
        -Description 'Active caller count at cap'
    Assert-True -Condition ([bool]$capacity.slot_reused_after_removal) `
        -Message 'A removed caller slot could not be reused.'
    Assert-Equal -Actual $capacity.active_after_teardown -Expected 0 `
        -Description 'Active count after capacity teardown'

    $evidence = [ordered]@{
        schema_version = 1
        gate = 'G2'
        result = 'pass'
        g2_complete = $true
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        dependency_boundary = [ordered]@{
            prerequisite_gate = 'G1-R'
            g1_evidence_sha256 = Get-Sha256 -Path $G1EvidencePath
            release_tag = $Srt.ReleaseTag
            archive_sha256 = $Srt.ArchiveSha256
            libsrt_sha256 = Get-Sha256 -Path $StagedSrtPath
            srt_getversion_hex = $raw.runtime.srt_getversion_hex
            staged_closure_files = @($Srt.StagedClosure.Keys).Count
        }
        harness = [ordered]@{
            script_sha256 = Get-Sha256 -Path $MyInvocation.MyCommand.Path
            rust_source_sha256 = Get-Sha256 -Path $HarnessSourcePath
            executable_sha256 = Get-Sha256 -Path $HarnessPath
            built_from_source_in_this_run = $BuildHarness
            compile_sdk = if ($BuildHarness) { 'GStreamer 1.26.11 MSVC x86_64' } else { 'prebuilt harness supplied' }
            manifest_sha256 = Get-Sha256 -Path $ManifestPath
            cargo_lock_sha256 = Get-Sha256 -Path $CargoLockPath
            powershell_version = $PSVersionTable.PSVersion.ToString()
            rustc_version = $rustcVersion.Trim()
            cargo_version = $cargoVersion.Trim()
        }
        isolated_runtime = [ordered]@{
            gstreamer_version = $raw.runtime.gstreamer_version
            srt_plugin_version = $raw.runtime.srt_plugin_version
            srt_plugin_path = 'lib/gstreamer-1.0/gstsrt.dll'
            srt_getversion_hex = $raw.runtime.srt_getversion_hex
            isolated_plugin_negative_control = $raw.runtime.isolated_plugin_negative_control
            required_elements = $raw.runtime.required_elements
        }
        admission_contract = [ordered]@{
            authentication_required_for_connecting_callback = $true
            callback_false_is_pre_accept_rejection = $true
            canonical_remote_identity = 'IP address plus UDP port'
            caller_added_integer_argument = 'unused and always zero'
            pending_ttl_seconds = 10
            pending_plus_active_limit = 10
            password_verification_owner = 'libsrt after application callback'
            post_accept_cap_fallback = $false
        }
        scenarios = $raw.scenarios
    }

    Write-Utf8NoBom -Path $EvidencePath -Value (($evidence | ConvertTo-Json -Depth 16) + "`n")
    Write-Host "G2 passed; evidence written to $EvidencePath" -ForegroundColor Green
} finally {
    Restore-ProcessEnvironment -Values $savedEnvironment
    if ($KeepWorkDirectory) {
        Write-Host "G2 work directory retained at $WorkDir" -ForegroundColor Yellow
    } elseif (Test-Path -LiteralPath $WorkDir) {
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
        $resolvedWork = [System.IO.Path]::GetFullPath($WorkDir).TrimEnd('\', '/')
        $expectedPrefix = $tempRoot + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedWork.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove G2 work directory outside the system temp root: $resolvedWork"
        }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}
