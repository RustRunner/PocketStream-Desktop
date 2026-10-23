#Requires -Version 5.1
<#
.SYNOPSIS
Runs PocketStream's G1-R gate against the exact staged SRT runtime.

.DESCRIPTION
Validates the canonical dependency release and its provenance, compares the
staged SRT 1.5.7 DLL with stock GStreamer 1.26.11 at the PE import/export
boundary, re-derives the seven-file dependency closure, loads the SRT and
MPEG-TS plugins with system plugins hidden, and exercises transport behavior
over loopback.

The default run includes the required eleven-minute, zero-caller continuous-
buffer soak and writes committed-form evidence. -Smoke permits a shorter soak
for harness validation, but marks the result as incomplete and can never be
used as G1-R evidence.

This script intentionally does not connect caller signals or test admission
callbacks. Those concurrency and ABI questions belong exclusively to G2.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\verify-g1r-srt.ps1

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\verify-g1r-srt.ps1 `
    -GStreamerRoot C:\gstreamer\1.0\msvc_x86_64 `
    -Smoke -SoakSeconds 5 -EvidencePath $env:TEMP\g1-r-smoke.json
#>

[CmdletBinding()]
param(
    [string]$GStreamerRoot = $env:GSTREAMER_1_0_ROOT_MSVC_X86_64,
    [string]$BundleRoot,
    [string]$EvidencePath,
    [string]$DumpbinPath,
    [ValidateRange(1, 86400)]
    [int]$SoakSeconds = 660,
    [switch]$Smoke,
    [switch]$AllowDraftDependencyRelease,
    [switch]$KeepWorkDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'gstreamer-manifest.psd1'
$RecipePatchPath = Join-Path $ScriptDir 'patches\cerbero-srt-1.5.7.patch'
$Manifest = Import-PowerShellDataFile $ManifestPath
$Srt = $Manifest.PatchedSrt

if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'G1-R must run on 64-bit Windows.'
}
if (-not $Smoke -and $SoakSeconds -lt 660) {
    throw 'A complete G1-R run requires at least 660 seconds of zero-caller soak. Use -Smoke only to validate the harness with a shorter soak.'
}
if ([string]::IsNullOrWhiteSpace($GStreamerRoot)) {
    throw 'GStreamerRoot is required. Point it at the pinned GStreamer 1.26.11 MSVC x86_64 SDK root.'
}
if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $BundleRoot = Join-Path $ProjectDir 'src-tauri\resources\gstreamer'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    if ($Smoke) {
        $EvidencePath = Join-Path ([System.IO.Path]::GetTempPath()) 'pocketstream-g1-r-smoke.json'
    } else {
        $EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g1-r-srt-1.5.7.json'
    }
}

$GStreamerRoot = [System.IO.Path]::GetFullPath($GStreamerRoot).TrimEnd('\', '/')
$BundleRoot = [System.IO.Path]::GetFullPath($BundleRoot).TrimEnd('\', '/')
$EvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
$BundleBin = Join-Path $BundleRoot 'bin'
$BundlePlugins = Join-Path $BundleRoot 'lib\gstreamer-1.0'
$SdkBin = Join-Path $GStreamerRoot 'bin'
$StockSrtPath = Join-Path $SdkBin 'libsrt.dll'
$StagedSrtPath = Join-Path $BundleBin 'libsrt.dll'
$SdkInspectPath = Join-Path $SdkBin 'gst-inspect-1.0.exe'
$SdkLaunchPath = Join-Path $SdkBin 'gst-launch-1.0.exe'
$IsolatedInspectPath = Join-Path $BundleBin 'gst-inspect-1.0.exe'
$IsolatedLaunchPath = Join-Path $BundleBin 'gst-launch-1.0.exe'
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pocketstream-g1-r-{0}" -f [Guid]::NewGuid().ToString('N'))
$EmptyPluginDir = Join-Path $WorkDir 'no-system-plugins'
$ArtifactDir = Join-Path $WorkDir 'artifact'
$DownloadedArchive = Join-Path $WorkDir $Srt.ArchiveFile
$ReleaseJsonPath = Join-Path $WorkDir 'release.json'

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

function Assert-StringArrayEqual {
    param(
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $actualNormalized = @($Actual | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $expectedNormalized = @($Expected | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $delta = @(Compare-Object -ReferenceObject $expectedNormalized -DifferenceObject $actualNormalized)
    if ($delta.Count -ne 0) {
        $details = @($delta | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
        throw "$Description differs:`n$($details -join "`n")"
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit $LASTEXITCODE`: $FilePath $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return $output
}

function Resolve-Dumpbin {
    if (-not [string]::IsNullOrWhiteSpace($script:DumpbinPath)) {
        $candidate = [System.IO.Path]::GetFullPath($script:DumpbinPath)
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "dumpbin.exe was not found at $candidate"
        }
        return $candidate
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'vswhere.exe was not found; Visual Studio C++ tools are required for G1-R PE inspection.'
    }
    $matches = @(& $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find '**\Hostx64\x64\dumpbin.exe' 2>$null)
    if ($matches.Count -eq 0) {
        throw 'dumpbin.exe was not found in the installed Visual Studio C++ tools.'
    }
    return [string]$matches[0]
}

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)
    $headers = Invoke-NativeCapture -FilePath $script:ResolvedDumpbin -Arguments @('/HEADERS', $Path)
    if (-not ($headers -match '^\s*8664 machine \(x64\)\s*$')) {
        throw "PE image is not x64 (machine 8664): $Path"
    }
    return 'x86_64'
}

function Get-PeImports {
    param([Parameter(Mandatory = $true)][string]$Path)
    $output = Invoke-NativeCapture -FilePath $script:ResolvedDumpbin -Arguments @('/DEPENDENTS', $Path)
    return @($output | ForEach-Object {
        if ($_ -match '^\s+([A-Za-z0-9._+-]+\.dll)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
}

function Get-PeExports {
    param([Parameter(Mandatory = $true)][string]$Path)
    $output = Invoke-NativeCapture -FilePath $script:ResolvedDumpbin -Arguments @('/EXPORTS', $Path)
    return @($output | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
}

function Get-ImportedSrtSymbols {
    param([Parameter(Mandatory = $true)][string]$Path)
    $output = Invoke-NativeCapture -FilePath $script:ResolvedDumpbin -Arguments @('/IMPORTS', $Path)
    return @($output | ForEach-Object {
        if ($_ -match '^\s+[0-9A-Fa-f]+\s+(srt_[A-Za-z0-9_]+)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
}

function Invoke-CurlDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination,
        [string[]]$Headers = @()
    )
    $arguments = @('-fsSL', '--retry', '3', '--retry-delay', '3')
    foreach ($header in $Headers) {
        $arguments += @('-H', $header)
    }
    $arguments += @('-o', $Destination, $Url)
    & $script:CurlPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Download failed with exit $LASTEXITCODE`: $Url"
    }
}

function Get-ZipEntryText {
    param(
        [Parameter(Mandatory = $true)][System.IO.Compression.ZipArchive]$Archive,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $entries = @($Archive.Entries | Where-Object { $_.FullName -ceq $Name })
    if ($entries.Count -ne 1) {
        throw "Dependency archive must contain exactly one root '$Name' entry."
    }
    $reader = New-Object System.IO.StreamReader($entries[0].Open())
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
    }
}

function Get-FreeUdpPort {
    do {
        $socket = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Dgram,
            [System.Net.Sockets.ProtocolType]::Udp
        )
        try {
            $socket.ExclusiveAddressUse = $true
            $socket.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)))
            $port = ([System.Net.IPEndPoint]$socket.LocalEndPoint).Port
        } finally {
            $socket.Dispose()
        }
    } while ($script:UsedPorts.ContainsKey($port))
    $script:UsedPorts[$port] = $true
    return $port
}

function Test-UdpBind {
    param(
        [Parameter(Mandatory = $true)][System.Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port
    )
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp
    )
    try {
        $socket.ExclusiveAddressUse = $true
        $socket.Bind((New-Object System.Net.IPEndPoint($Address, $Port)))
        return [pscustomobject][ordered]@{
            success = $true
            socket_error = $null
            native_error = $null
        }
    } catch [System.Net.Sockets.SocketException] {
        return [pscustomobject][ordered]@{
            success = $false
            socket_error = $_.Exception.SocketErrorCode.ToString()
            native_error = $_.Exception.ErrorCode
        }
    } finally {
        $socket.Dispose()
    }
}

function Start-UdpHolder {
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp
    )
    $socket.ExclusiveAddressUse = $true
    $socket.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)))
    return [pscustomobject]@{
        Socket = $socket
        Port = ([System.Net.IPEndPoint]$socket.LocalEndPoint).Port
    }
}

function Start-GstProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$TraceSrt
    )
    foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            throw "Internal G1-R harness argument requires unsupported quoting: '$argument'"
        }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Executable
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $BundleBin
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $debugLog = Join-Path $WorkDir "$Name.gst.log"
    if ($TraceSrt) {
        $startInfo.EnvironmentVariables['GST_DEBUG'] = 'srtobject:5'
        $startInfo.EnvironmentVariables['GST_DEBUG_FILE'] = $debugLog
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start isolated GStreamer process '$Name'."
    }
    $run = [pscustomobject]@{
        Name = $Name
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
        DebugLog = $debugLog
    }
    [void]$script:LiveProcesses.Add($run)
    return $run
}

function Get-CompletedGstResult {
    param([Parameter(Mandatory = $true)][object]$Run)
    $Run.Process.WaitForExit()
    return [pscustomobject][ordered]@{
        name = $Run.Name
        exit_code = $Run.Process.ExitCode
        stdout = $Run.StdoutTask.GetAwaiter().GetResult()
        stderr = $Run.StderrTask.GetAwaiter().GetResult()
    }
}

function Wait-GstProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Run,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )
    if (-not $Run.Process.WaitForExit($TimeoutMilliseconds)) {
        [void](Stop-GstProcess -Run $Run)
        throw "Isolated GStreamer process '$($Run.Name)' timed out after $TimeoutMilliseconds ms."
    }
    return Get-CompletedGstResult -Run $Run
}

function Stop-GstProcess {
    param([Parameter(Mandatory = $true)][object]$Run)
    if (-not $Run.Process.HasExited) {
        $Run.Process.Kill()
    }
    return Get-CompletedGstResult -Run $Run
}

function Assert-GstProcessAlive {
    param(
        [Parameter(Mandatory = $true)][object]$Run,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $Run.Process.Refresh()
    if ($Run.Process.HasExited) {
        $result = Get-CompletedGstResult -Run $Run
        throw "$Description exited unexpectedly with code $($result.exit_code).`n$($result.stderr)"
    }
}

function Start-SrtListener {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [AllowNull()][string]$Passphrase = $null,
        [int]$NumBuffers = -1,
        [switch]$TraceSrt
    )
    $arguments = @(
        '-q',
        'fakesrc', 'is-live=true', 'sync=true', 'sizetype=fixed',
        'sizemax=1316', 'filltype=zero', 'datarate=131600'
    )
    if ($NumBuffers -ge 0) {
        $arguments += "num-buffers=$NumBuffers"
    }
    $arguments += @(
        '!', 'queue', '!',
        'srtsink', 'mode=listener', "localaddress=$Address", "localport=$Port",
        'wait-for-connection=false', 'latency=20'
    )
    if ($null -ne $Passphrase) {
        $arguments += @("passphrase=$Passphrase", 'pbkeylen=16')
    }
    return Start-GstProcess -Name $Name -Executable $IsolatedLaunchPath -Arguments $arguments -TraceSrt:$TraceSrt
}

function Wait-SrtAcceptedCallers {
    param([object]$Listener, [int]$Count)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Assert-GstProcessAlive -Run $Listener -Description 'Fan-out listener while accepting callers'
        if (Test-Path -LiteralPath $Listener.DebugLog) {
            $stream = [IO.File]::Open($Listener.DebugLog, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = New-Object IO.StreamReader($stream)
            try { $log = $reader.ReadToEnd() } finally { $reader.Dispose() }
            if ([regex]::Matches($log, 'Accept to connect \d+').Count -ge $Count) { return }
        }
        Start-Sleep -Milliseconds 50
    } while ($timer.ElapsedMilliseconds -lt 8000)
    throw "Fan-out listener did not accept $Count callers within eight seconds."
}

function Start-SrtClient {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Port,
        [AllowNull()][string]$Passphrase = $null,
        [int]$NumBuffers = 30
    )
    $arguments = @(
        '-q', 'srtsrc', 'mode=caller', "uri=srt://127.0.0.1:$Port",
        'latency=20', 'poll-timeout=250', 'auto-reconnect=false'
    )
    if ($NumBuffers -ge 0) {
        $arguments += "num-buffers=$NumBuffers"
    }
    if ($null -ne $Passphrase) {
        $arguments += @("passphrase=$Passphrase", 'pbkeylen=16')
    }
    $arguments += @('!', 'fakesink', 'sync=false')
    return Start-GstProcess -Name $Name -Executable $IsolatedLaunchPath -Arguments $arguments
}

function Invoke-SrtClient {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Port,
        [AllowNull()][string]$Passphrase = $null,
        [int]$NumBuffers = 30,
        [int]$TimeoutMilliseconds = 12000
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $run = Start-SrtClient -Name $Name -Port $Port -Passphrase $Passphrase -NumBuffers $NumBuffers
    $result = Wait-GstProcess -Run $run -TimeoutMilliseconds $TimeoutMilliseconds
    $stopwatch.Stop()
    return [pscustomobject][ordered]@{
        exit_code = $result.exit_code
        elapsed_seconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
        stderr = $result.stderr
    }
}

function Get-SrtRuntimeVersion {
    param([Parameter(Mandatory = $true)][string]$DllPath)

    if (-not ('PocketStream.G1R.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PocketStream.G1R
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr module);
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int SrtGetVersion();
}
'@
    }

    $module = [IntPtr]::Zero
    try {
        $module = [PocketStream.G1R.NativeMethods]::LoadLibraryW($DllPath)
        if ($module -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "LoadLibraryW failed for staged libsrt.dll with Win32 error $code."
        }
        $address = [PocketStream.G1R.NativeMethods]::GetProcAddress($module, 'srt_getversion')
        if ($address -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "GetProcAddress(srt_getversion) failed with Win32 error $code."
        }
        $delegate = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $address,
            [type][PocketStream.G1R.SrtGetVersion]
        )
        return $delegate.Invoke()
    } finally {
        if ($module -ne [IntPtr]::Zero) {
            [void][PocketStream.G1R.NativeMethods]::FreeLibrary($module)
        }
    }
}

$script:LiveProcesses = New-Object System.Collections.ArrayList
$script:UsedPorts = @{}
$script:ResolvedDumpbin = $null
$script:CurlPath = $null
$copiedProbeTools = $false
$udpHolder = $null
$originalPath = $env:Path
$originalEnvironment = @{}
foreach ($name in @(
    'GST_PLUGIN_PATH', 'GST_PLUGIN_PATH_1_0',
    'GST_PLUGIN_SYSTEM_PATH', 'GST_PLUGIN_SYSTEM_PATH_1_0',
    'GST_REGISTRY', 'GST_REGISTRY_1_0', 'GST_REGISTRY_FORK', 'GST_DEBUG'
)) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    Write-Host 'G1-R: validating immutable inputs and staged files...' -ForegroundColor Cyan
    foreach ($directory in @($BundleBin, $BundlePlugins, $SdkBin)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            throw "Required runtime directory is missing: $directory"
        }
    }
    foreach ($file in @(
        $ManifestPath, $RecipePatchPath, $StockSrtPath, $StagedSrtPath,
        $SdkInspectPath, $SdkLaunchPath
    )) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Required G1-R input is missing: $file"
        }
    }
    if ((Test-Path -LiteralPath $IsolatedInspectPath) -or (Test-Path -LiteralPath $IsolatedLaunchPath)) {
        throw 'The staged bundle unexpectedly contains a GStreamer probe executable. Remove it before running G1-R.'
    }
    Assert-Equal -Actual (Get-Sha256 -Path $StagedSrtPath) -Expected $Srt.DllSha256 -Description 'Staged libsrt.dll SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path $StockSrtPath) -Expected $Srt.StockDllSha256 -Description 'Stock GStreamer 1.26.11 libsrt.dll SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path $SdkInspectPath) -Expected $Srt.GstInspectSha256 -Description 'Pinned gst-inspect-1.0.exe SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path $SdkLaunchPath) -Expected $Srt.GstLaunchSha256 -Description 'Pinned gst-launch-1.0.exe SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path $RecipePatchPath) -Expected $Srt.RecipePatchSha256 -Description 'Tracked SRT recipe patch SHA256'

    New-Item -ItemType Directory -Path $WorkDir | Out-Null
    New-Item -ItemType Directory -Path $EmptyPluginDir | Out-Null
    New-Item -ItemType Directory -Path $ArtifactDir | Out-Null

    $curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curlCommand) {
        throw 'curl.exe is required to verify the canonical G1-R dependency release.'
    }
    $script:CurlPath = $curlCommand.Source
    $releaseApiUrl = "https://api.github.com/repos/RustRunner/PocketStream-Desktop/releases/tags/$($Srt.ReleaseTag)"
    if ($AllowDraftDependencyRelease) {
        $releaseIdText = @(& gh release view $Srt.ReleaseTag --repo RustRunner/PocketStream-Desktop --json databaseId) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Dependency draft lookup failed.' }
        $releaseId = [long]($releaseIdText | ConvertFrom-Json).databaseId
        & gh api "repos/RustRunner/PocketStream-Desktop/releases/$releaseId" | Set-Content -LiteralPath $ReleaseJsonPath -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw 'Dependency draft metadata lookup failed.' }
    } else {
        Invoke-CurlDownload -Url $releaseApiUrl -Destination $ReleaseJsonPath `
            -Headers @('Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28')
    }
    $release = Get-Content -LiteralPath $ReleaseJsonPath -Raw | ConvertFrom-Json
    Assert-Equal -Actual $release.tag_name -Expected $Srt.ReleaseTag -Description 'Canonical dependency release tag'
    Assert-True -Condition ([bool]$release.prerelease) -Message 'Canonical dependency release is not marked as a prerelease.'
    Assert-True -Condition ($AllowDraftDependencyRelease -or -not [bool]$release.draft) -Message 'Canonical dependency release is still a draft.'
    Assert-True -Condition (-not ([string]$release.tag_name).StartsWith('v', [StringComparison]::OrdinalIgnoreCase)) `
        -Message 'Canonical dependency release tag must not match the application v* namespace.'
    $releaseAssets = @($release.assets | Where-Object { $_.name -ceq $Srt.ArchiveFile })
    Assert-True -Condition ($releaseAssets.Count -eq 1) -Message 'Canonical dependency release must contain exactly one manifest-pinned archive asset.'
    $releaseAsset = $releaseAssets[0]
    if ([bool]$release.draft) {
        $draftAssetUrl = [string]$releaseAsset.browser_download_url
        Assert-True -Condition ($draftAssetUrl.StartsWith('https://github.com/RustRunner/PocketStream-Desktop/releases/download/untagged-', [StringComparison]::Ordinal) -and
            $draftAssetUrl.EndsWith('/' + $Srt.ArchiveFile, [StringComparison]::Ordinal)) `
            -Message 'Unexpected dependency draft asset URL.'
    } else {
        Assert-Equal -Actual $releaseAsset.browser_download_url -Expected $Srt.AssetUrl -Description 'Canonical dependency asset URL'
    }
    $digestProperty = $releaseAsset.PSObject.Properties['digest']
    if ($null -ne $digestProperty -and -not [string]::IsNullOrWhiteSpace([string]$digestProperty.Value)) {
        Assert-Equal -Actual ([string]$digestProperty.Value).ToLowerInvariant() `
            -Expected "sha256:$($Srt.ArchiveSha256)" -Description 'GitHub dependency asset digest'
    }

    if ($AllowDraftDependencyRelease) {
        & gh release download $Srt.ReleaseTag --repo RustRunner/PocketStream-Desktop `
            --pattern $Srt.ArchiveFile --output $DownloadedArchive
        if ($LASTEXITCODE -ne 0) { throw 'Dependency draft download failed.' }
    } else {
        Invoke-CurlDownload -Url $Srt.AssetUrl -Destination $DownloadedArchive
    }
    Assert-Equal -Actual (Get-Sha256 -Path $DownloadedArchive) -Expected $Srt.ArchiveSha256 -Description 'Clean dependency archive download SHA256'

    $archive = [System.IO.Compression.ZipFile]::OpenRead($DownloadedArchive)
    try {
        $expectedEntries = @('SHA256SUMS.txt', 'exports.txt', 'imports.txt', 'libsrt.dll', 'provenance.json') | Sort-Object
        $actualEntries = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        Assert-StringArrayEqual -Actual $actualEntries -Expected $expectedEntries -Description 'Canonical dependency archive entries'
        $provenanceText = Get-ZipEntryText -Archive $archive -Name 'provenance.json'
        $provenance = $provenanceText | ConvertFrom-Json
    } finally {
        $archive.Dispose()
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($DownloadedArchive, $ArtifactDir)
    Assert-Equal -Actual (Get-Sha256 -Path (Join-Path $ArtifactDir 'libsrt.dll')) -Expected $Srt.DllSha256 -Description 'Clean dependency archive inner libsrt.dll SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path (Join-Path $ArtifactDir 'provenance.json')) `
        -Expected ((Get-Content -LiteralPath (Join-Path $ArtifactDir 'SHA256SUMS.txt')) | Where-Object { $_ -match '  provenance\.json$' } | ForEach-Object { ($_ -split '\s+')[0] }) `
        -Description 'Dependency provenance SHA256SUMS entry'
    foreach ($artifactFile in @('libsrt.dll', 'imports.txt', 'exports.txt')) {
        $sumLine = @(Get-Content -LiteralPath (Join-Path $ArtifactDir 'SHA256SUMS.txt') | Where-Object { $_ -match "  $([regex]::Escape($artifactFile))$" })
        Assert-True -Condition ($sumLine.Count -eq 1) -Message "SHA256SUMS.txt must contain exactly one $artifactFile entry."
        Assert-Equal -Actual (Get-Sha256 -Path (Join-Path $ArtifactDir $artifactFile)) `
            -Expected (($sumLine[0] -split '\s+')[0]) -Description "Dependency $artifactFile SHA256SUMS entry"
    }

    Assert-Equal -Actual $provenance.schema_version -Expected 1 -Description 'Dependency provenance schema'
    Assert-Equal -Actual $provenance.component.version -Expected $Srt.Version -Description 'Dependency provenance SRT version'
    Assert-Equal -Actual $provenance.component.expected_runtime_version_hex -Expected $Srt.RuntimeVersionHex -Description 'Dependency provenance runtime version'
    Assert-Equal -Actual $provenance.component.source_archive_sha256 -Expected $Srt.SourceArchiveSha256 -Description 'Dependency provenance source archive SHA256'
    Assert-Equal -Actual $provenance.cerbero.version -Expected $Manifest.PinnedVersion -Description 'Dependency provenance Cerbero version'
    Assert-Equal -Actual $provenance.cerbero.commit -Expected $Srt.CerberoCommit -Description 'Dependency provenance Cerbero commit'
    Assert-Equal -Actual $provenance.cerbero.patched_recipe_git_blob -Expected $Srt.PatchedRecipeBlob -Description 'Dependency provenance patched recipe blob'
    Assert-Equal -Actual $provenance.cerbero.recipe_patch_sha256 -Expected $Srt.RecipePatchSha256 -Description 'Dependency provenance recipe patch SHA256'
    Assert-True -Condition (-not [bool]$provenance.cerbero.srt_can_msvc) -Message 'Dependency provenance unexpectedly reports an MSVC SRT build.'
    Assert-Equal -Actual $provenance.artifact.file -Expected 'libsrt.dll' -Description 'Dependency provenance artifact filename'
    Assert-Equal -Actual $provenance.artifact.sha256 -Expected $Srt.DllSha256 -Description 'Dependency provenance artifact SHA256'
    Assert-Equal -Actual $provenance.artifact.architecture -Expected 'x86_64' -Description 'Dependency provenance artifact architecture'
    Assert-Equal -Actual $provenance.toolchain.mingw_compiler_sha256 -Expected $Srt.MinGwCompilerSha256 -Description 'Dependency provenance MinGW compiler SHA256'
    Assert-True -Condition (([string]$provenance.toolchain.mingw_compiler_version) -match '14\.2\.0') -Message 'Dependency provenance does not identify the pinned GCC 14.2.0 toolchain.'
    Assert-Equal -Actual $provenance.import_contract.baseline_runtime_url -Expected $Srt.StockRuntimeUrl -Description 'Dependency provenance stock runtime URL'
    Assert-Equal -Actual $provenance.import_contract.baseline_runtime_sha256 -Expected $Srt.StockRuntimeSha256 -Description 'Dependency provenance stock runtime SHA256'

    $script:ResolvedDumpbin = Resolve-Dumpbin
    $stagedArchitecture = Get-PeArchitecture -Path $StagedSrtPath
    $stockArchitecture = Get-PeArchitecture -Path $StockSrtPath
    $stagedImports = @(Get-PeImports -Path $StagedSrtPath)
    $stockImports = @(Get-PeImports -Path $StockSrtPath)
    $artifactImports = @(Get-Content -LiteralPath (Join-Path $ArtifactDir 'imports.txt') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-StringArrayEqual -Actual $stagedImports -Expected $stockImports -Description 'Staged versus stock libsrt.dll imports'
    Assert-StringArrayEqual -Actual $stagedImports -Expected $artifactImports -Description 'Staged versus published libsrt.dll imports'
    Assert-StringArrayEqual -Actual $stagedImports -Expected @($provenance.artifact.imports) -Description 'Staged versus provenance libsrt.dll imports'

    $stagedExports = @(Get-PeExports -Path $StagedSrtPath)
    $stockExports = @(Get-PeExports -Path $StockSrtPath)
    $requiredExports = @('srt_cleanup', 'srt_getversion', 'srt_listen_callback', 'srt_startup')
    foreach ($requiredExport in $requiredExports) {
        Assert-True -Condition ($stagedExports -ccontains $requiredExport) -Message "Staged libsrt.dll is missing required export $requiredExport."
    }
    $missingStockExports = @($stockExports | Where-Object { $stagedExports -cnotcontains $_ })
    Assert-True -Condition ($missingStockExports.Count -eq 0) `
        -Message "Staged libsrt.dll does not preserve stock exports: $($missingStockExports -join ', ')"

    $closureEvidence = @()
    $closureImports = @{}
    $systemImportPattern = '^(api-ms-win-.*|KERNEL32|WS2_32|WSOCK32|ADVAPI32|CRYPT32|USER32|VCRUNTIME140(_1)?)\.dll$'
    foreach ($relativePath in @($Srt.StagedClosure.Keys | Sort-Object)) {
        $nativeRelativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $fullPath = Join-Path $BundleRoot $nativeRelativePath
        Assert-True -Condition (Test-Path -LiteralPath $fullPath -PathType Leaf) -Message "Staged closure file is missing: $relativePath"
        Assert-Equal -Actual (Get-Sha256 -Path $fullPath) -Expected $Srt.StagedClosure[$relativePath] -Description "Staged closure $relativePath SHA256"
        $architecture = Get-PeArchitecture -Path $fullPath
        $imports = @(Get-PeImports -Path $fullPath)
        $closureImports[$relativePath] = $imports
        foreach ($import in $imports) {
            if ($import -notmatch $systemImportPattern -and -not (Test-Path -LiteralPath (Join-Path $BundleBin $import) -PathType Leaf)) {
                throw "Re-derived SRT closure has an unresolved non-system import: $relativePath -> $import"
            }
        }
        $versionInfo = (Get-Item -LiteralPath $fullPath).VersionInfo
        $closureEvidence += [pscustomobject][ordered]@{
            path = $relativePath
            sha256 = Get-Sha256 -Path $fullPath
            architecture = $architecture
            file_version = if ([string]::IsNullOrWhiteSpace($versionInfo.FileVersion)) { $null } else { $versionInfo.FileVersion }
            product_version = if ([string]::IsNullOrWhiteSpace($versionInfo.ProductVersion)) { $null } else { $versionInfo.ProductVersion }
            direct_imports = $imports
        }
    }
    $expectedSrtClosureImports = @('libcrypto-3-x64.dll', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll')
    $actualSrtClosureImports = @($closureImports['bin/libsrt.dll'] | Where-Object { $_ -notmatch $systemImportPattern })
    Assert-StringArrayEqual -Actual $actualSrtClosureImports -Expected $expectedSrtClosureImports -Description 'Re-derived non-system libsrt.dll closure'
    Assert-True -Condition ($closureImports['lib/gstreamer-1.0/gstsrt.dll'] -icontains 'libsrt.dll') -Message 'gstsrt.dll does not import the exact libsrt.dll filename.'
    $gstsrtImportedSymbols = @(Get-ImportedSrtSymbols -Path (Join-Path $BundlePlugins 'gstsrt.dll'))
    $missingPluginSymbols = @($gstsrtImportedSymbols | Where-Object { $stagedExports -cnotcontains $_ })
    Assert-True -Condition ($missingPluginSymbols.Count -eq 0) `
        -Message "Staged libsrt.dll is missing symbols imported by gstsrt.dll: $($missingPluginSymbols -join ', ')"

    Write-Host 'G1-R: isolating the staged runtime and probing plugins...' -ForegroundColor Cyan
    Copy-Item -LiteralPath $SdkInspectPath -Destination $IsolatedInspectPath
    Copy-Item -LiteralPath $SdkLaunchPath -Destination $IsolatedLaunchPath
    $copiedProbeTools = $true

    # Normalize a duplicate PATH/Path inherited from some launchers, then use
    # only the staged DLL directory and Windows. A machine-wide GStreamer SDK
    # can no longer satisfy a missing transitive dependency.
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
    $env:GST_REGISTRY = Join-Path $WorkDir 'registry.bin'
    $env:GST_REGISTRY_1_0 = $env:GST_REGISTRY
    $env:GST_REGISTRY_FORK = 'no'
    $env:GST_DEBUG = '1'

    $versionRun = Start-GstProcess -Name 'gst-version' -Executable $IsolatedInspectPath -Arguments @('--version')
    $versionResult = Wait-GstProcess -Run $versionRun -TimeoutMilliseconds 15000
    Assert-Equal -Actual $versionResult.exit_code -Expected 0 -Description 'Isolated gst-inspect version probe exit code'
    Assert-True -Condition (($versionResult.stdout + $versionResult.stderr) -match 'GStreamer\s+1\.26\.11') -Message 'Isolated gst-inspect does not report GStreamer 1.26.11.'

    $negativeRun = Start-GstProcess -Name 'plugin-negative-control' -Executable $IsolatedInspectPath -Arguments @('--exists', 'opusdec')
    $negativeResult = Wait-GstProcess -Run $negativeRun -TimeoutMilliseconds 15000
    Assert-True -Condition ($negativeResult.exit_code -ne 0) -Message 'Plugin isolation failed: non-bundled opusdec is visible.'
    $requiredElements = @('fakesrc', 'queue', 'fakesink', 'mpegtsmux', 'srtsink', 'srtsrc')
    foreach ($element in $requiredElements) {
        $elementRun = Start-GstProcess -Name "plugin-$element" -Executable $IsolatedInspectPath -Arguments @('--exists', $element)
        $elementResult = Wait-GstProcess -Run $elementRun -TimeoutMilliseconds 15000
        Assert-Equal -Actual $elementResult.exit_code -Expected 0 -Description "Isolated $element plugin probe exit code"
    }
    $srtInspectRun = Start-GstProcess -Name 'srtsink-contract' -Executable $IsolatedInspectPath -Arguments @('srtsink')
    $srtInspectResult = Wait-GstProcess -Run $srtInspectRun -TimeoutMilliseconds 15000
    Assert-Equal -Actual $srtInspectResult.exit_code -Expected 0 -Description 'Isolated srtsink inspection exit code'
    $srtInspectText = $srtInspectResult.stdout + $srtInspectResult.stderr
    foreach ($contractName in @(
        'gstsrt.dll', 'authentication', 'wait-for-connection', 'passphrase',
        'pbkeylen', 'localaddress', 'localport', 'caller-connecting',
        'caller-added', 'caller-removed'
    )) {
        Assert-True -Condition ($srtInspectText -match [regex]::Escape($contractName)) -Message "Isolated srtsink inspection is missing '$contractName'."
    }

    $runtimeVersion = Get-SrtRuntimeVersion -DllPath $StagedSrtPath
    $runtimeVersionHex = '0x{0:X6}' -f $runtimeVersion
    Assert-Equal -Actual $runtimeVersionHex -Expected $Srt.RuntimeVersionHex -Description 'Exact staged srt_getversion result'

    Write-Host 'G1-R: testing explicit passwordless SRT transfer...' -ForegroundColor Cyan
    $passwordlessPort = Get-FreeUdpPort
    $passwordlessListener = Start-SrtListener -Name 'passwordless-listener' -Address '127.0.0.1' -Port $passwordlessPort
    Start-Sleep -Milliseconds 750
    Assert-GstProcessAlive -Run $passwordlessListener -Description 'Passwordless listener'
    $boundProbe = Test-UdpBind -Address ([System.Net.IPAddress]::Loopback) -Port $passwordlessPort
    Assert-True -Condition (-not $boundProbe.success) -Message 'Passwordless listener did not hold its requested UDP bind.'
    $passwordlessClient = Invoke-SrtClient -Name 'passwordless-client' -Port $passwordlessPort
    Assert-Equal -Actual $passwordlessClient.exit_code -Expected 0 -Description 'Passwordless SRT client transfer exit code'
    $null = Stop-GstProcess -Run $passwordlessListener
    $passwordlessRebind = Test-UdpBind -Address ([System.Net.IPAddress]::Loopback) -Port $passwordlessPort
    Assert-True -Condition ([bool]$passwordlessRebind.success) -Message 'Passwordless listener did not release its UDP port during teardown.'

    Write-Host 'G1-R: testing encrypted handshakes, rejection, fan-out, and removal...' -ForegroundColor Cyan
    $testPassphrase = 'PocketStream-G1R-Transport-Key'
    $encryptedPort = Get-FreeUdpPort
    $encryptedListener = Start-SrtListener -Name 'encrypted-listener' -Address '127.0.0.1' -Port $encryptedPort -Passphrase $testPassphrase
    Start-Sleep -Milliseconds 750
    Assert-GstProcessAlive -Run $encryptedListener -Description 'Encrypted listener'
    $correctClient = Invoke-SrtClient -Name 'correct-passphrase-client' -Port $encryptedPort -Passphrase $testPassphrase
    Assert-Equal -Actual $correctClient.exit_code -Expected 0 -Description 'Correct-passphrase SRT client transfer exit code'
    $wrongClient = Invoke-SrtClient -Name 'wrong-passphrase-client' -Port $encryptedPort -Passphrase 'PocketStream-G1R-Wrong-Key'
    Assert-True -Condition ($wrongClient.exit_code -ne 0) -Message 'Wrong-passphrase SRT caller unexpectedly received the requested buffers.'
    $missingClient = Invoke-SrtClient -Name 'missing-passphrase-client' -Port $encryptedPort
    Assert-True -Condition ($missingClient.exit_code -ne 0) -Message 'Missing-passphrase SRT caller unexpectedly received the requested buffers.'
    Assert-GstProcessAlive -Run $encryptedListener -Description 'Encrypted listener after rejected handshakes'
    $recoveryClient = Invoke-SrtClient -Name 'post-rejection-correct-client' -Port $encryptedPort -Passphrase $testPassphrase
    Assert-Equal -Actual $recoveryClient.exit_code -Expected 0 -Description 'Post-rejection correct-passphrase transfer exit code'
    Assert-GstProcessAlive -Run $encryptedListener -Description 'Encrypted listener after rejection recovery'
    $null = Stop-GstProcess -Run $encryptedListener

    # Use a fresh listener for fan-out. Rejected native handshakes can remain
    # transiently represented in libsrt's own backlog; that pending-capacity
    # timing is deliberately a G2 concern, not part of this transport gate.
    $fanoutPort = Get-FreeUdpPort
    $fanoutListener = Start-SrtListener -Name 'fanout-listener' -Address '127.0.0.1' -Port $fanoutPort -Passphrase $testPassphrase -TraceSrt
    Start-Sleep -Milliseconds 750
    Assert-GstProcessAlive -Run $fanoutListener -Description 'Fan-out listener'
    $fanoutA = Start-SrtClient -Name 'fanout-client-a' -Port $fanoutPort -Passphrase $testPassphrase -NumBuffers 500
    # GStreamer's listener has a one-handshake backlog. Establish each caller
    # before the next handshake, then verify simultaneous active transfers.
    Wait-SrtAcceptedCallers -Listener $fanoutListener -Count 1
    $fanoutB = Start-SrtClient -Name 'fanout-client-b' -Port $fanoutPort -Passphrase $testPassphrase -NumBuffers 500
    Wait-SrtAcceptedCallers -Listener $fanoutListener -Count 2
    Start-Sleep -Seconds 1
    Assert-GstProcessAlive -Run $fanoutA -Description 'First concurrent SRT caller'
    Assert-GstProcessAlive -Run $fanoutB -Description 'Second concurrent SRT caller'
    $null = Stop-GstProcess -Run $fanoutA
    Assert-GstProcessAlive -Run $fanoutListener -Description 'Fan-out listener after ungraceful caller removal'
    $replacementClient = Invoke-SrtClient -Name 'post-removal-client' -Port $fanoutPort -Passphrase $testPassphrase -NumBuffers 100
    Assert-Equal -Actual $replacementClient.exit_code -Expected 0 -Description 'Post-removal replacement caller exit code'
    Assert-GstProcessAlive -Run $fanoutB -Description 'Remaining caller during replacement transfer'
    $fanoutBResult = Wait-GstProcess -Run $fanoutB -TimeoutMilliseconds 10000
    Assert-Equal -Actual $fanoutBResult.exit_code -Expected 0 -Description 'Remaining fan-out caller exit code'
    Assert-GstProcessAlive -Run $fanoutListener -Description 'Fan-out listener after fan-out test'
    $null = Stop-GstProcess -Run $fanoutListener

    Write-Host 'G1-R: testing post-teardown bind diagnostics...' -ForegroundColor Cyan
    $udpHolder = Start-UdpHolder
    $conflictPort = $udpHolder.Port
    $conflictRun = Start-SrtListener -Name 'port-conflict-listener' -Address '127.0.0.1' -Port $conflictPort
    $conflictResult = Wait-GstProcess -Run $conflictRun -TimeoutMilliseconds 8000
    Assert-True -Condition ($conflictResult.exit_code -ne 0) -Message 'SRT listener unexpectedly started on an exclusively occupied UDP port.'
    $conflictProbe = Test-UdpBind -Address ([System.Net.IPAddress]::Loopback) -Port $conflictPort
    Assert-True -Condition (-not $conflictProbe.success) -Message 'Post-teardown diagnostic probe failed to identify the occupied UDP port.'
    Assert-Equal -Actual $conflictProbe.socket_error -Expected 'AddressAlreadyInUse' -Description 'Occupied-port diagnostic classification'
    $udpHolder.Socket.Dispose()
    $udpHolder = $null
    $releasedConflictProbe = Test-UdpBind -Address ([System.Net.IPAddress]::Loopback) -Port $conflictPort
    Assert-True -Condition ([bool]$releasedConflictProbe.success) -Message 'Occupied-port diagnostic test did not release its UDP reservation.'

    $invalidAddress = [System.Net.IPAddress]::Parse('192.0.2.1')
    $invalidPort = Get-FreeUdpPort
    $invalidRun = Start-SrtListener -Name 'invalid-address-listener' -Address $invalidAddress.ToString() -Port $invalidPort
    $invalidResult = Wait-GstProcess -Run $invalidRun -TimeoutMilliseconds 8000
    Assert-True -Condition ($invalidResult.exit_code -ne 0) -Message 'SRT listener unexpectedly started on the unassigned TEST-NET address.'
    $invalidProbe = Test-UdpBind -Address $invalidAddress -Port $invalidPort
    Assert-True -Condition (-not $invalidProbe.success) -Message 'Post-teardown diagnostic probe failed to identify the invalid local address.'
    Assert-Equal -Actual $invalidProbe.socket_error -Expected 'AddressNotAvailable' -Description 'Invalid-address diagnostic classification'

    Write-Host ("G1-R: running zero-caller continuous-buffer soak for {0} seconds..." -f $SoakSeconds) -ForegroundColor Cyan
    $soakPort = Get-FreeUdpPort
    $soakBufferCount = $SoakSeconds * 100
    $soakStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $soakRun = Start-SrtListener -Name 'zero-caller-soak' -Address '127.0.0.1' -Port $soakPort -NumBuffers $soakBufferCount
    $nextProgress = 30
    $soakDeadline = $SoakSeconds + 30
    while (-not $soakRun.Process.WaitForExit(1000)) {
        $elapsed = [int][Math]::Floor($soakStopwatch.Elapsed.TotalSeconds)
        if ($elapsed -ge $nextProgress) {
            Write-Host ("  zero-caller soak: {0}/{1} seconds" -f $elapsed, $SoakSeconds)
            $nextProgress += 30
        }
        if ($soakStopwatch.Elapsed.TotalSeconds -gt $soakDeadline) {
            [void](Stop-GstProcess -Run $soakRun)
            throw "Zero-caller soak did not consume $soakBufferCount continuous buffers within $soakDeadline seconds."
        }
    }
    $soakStopwatch.Stop()
    $soakResult = Get-CompletedGstResult -Run $soakRun
    Assert-Equal -Actual $soakResult.exit_code -Expected 0 -Description 'Zero-caller soak pipeline exit code'
    Assert-True -Condition ($soakStopwatch.Elapsed.TotalSeconds -ge ($SoakSeconds * 0.95)) `
        -Message 'Zero-caller soak completed too quickly to prove clocked continuous-buffer operation.'

    $evidence = [ordered]@{
        schema_version = 1
        gate = 'G1-R'
        result = if ($Smoke) { 'smoke-pass' } else { 'pass' }
        g1_r_complete = (-not [bool]$Smoke)
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        harness = [ordered]@{
            script_sha256 = Get-Sha256 -Path $MyInvocation.MyCommand.Path
            manifest_sha256 = Get-Sha256 -Path $ManifestPath
            powershell_version = $PSVersionTable.PSVersion.ToString()
            dumpbin_file_version = (Get-Item -LiteralPath $script:ResolvedDumpbin).VersionInfo.FileVersion
        }
        canonical_release = [ordered]@{
            tag = [string]$release.tag_name
            prerelease = [bool]$release.prerelease
            draft = [bool]$release.draft
            html_url = [string]$release.html_url
            asset_name = [string]$releaseAsset.name
            asset_url = [string]$releaseAsset.browser_download_url
            archive_sha256 = $Srt.ArchiveSha256
            inner_dll_sha256 = $Srt.DllSha256
            clean_download_verified = $true
        }
        provenance = [ordered]@{
            srt_version = [string]$provenance.component.version
            source_archive_sha256 = [string]$provenance.component.source_archive_sha256
            cerbero_version = [string]$provenance.cerbero.version
            cerbero_commit = [string]$provenance.cerbero.commit
            patched_recipe_blob = [string]$provenance.cerbero.patched_recipe_git_blob
            recipe_patch_sha256 = [string]$provenance.cerbero.recipe_patch_sha256
            srt_can_msvc = [bool]$provenance.cerbero.srt_can_msvc
            mingw_compiler_sha256 = [string]$provenance.toolchain.mingw_compiler_sha256
            mingw_compiler_version = [string]$provenance.toolchain.mingw_compiler_version
            stock_runtime_url = [string]$provenance.import_contract.baseline_runtime_url
            stock_runtime_sha256 = [string]$provenance.import_contract.baseline_runtime_sha256
        }
        staged_runtime = [ordered]@{
            gstreamer_version = $Manifest.PinnedVersion
            libsrt_sha256 = Get-Sha256 -Path $StagedSrtPath
            srt_getversion_hex = $runtimeVersionHex
            architecture = $stagedArchitecture
            stock_architecture = $stockArchitecture
            stock_libsrt_sha256 = Get-Sha256 -Path $StockSrtPath
            staged_imports = $stagedImports
            stock_imports_match = $true
            staged_export_count = $stagedExports.Count
            stock_export_count = $stockExports.Count
            all_stock_exports_preserved = $true
            required_exports = $requiredExports
            gstsrt_imported_srt_symbols = $gstsrtImportedSymbols
            isolated_plugin_negative_control = 'opusdec absent'
            isolated_elements = $requiredElements
        }
        replacement_closure = $closureEvidence
        behavior = [ordered]@{
            explicit_passwordless_transfer = [ordered]@{
                passed = $true
                received_buffers = 30
                listener_released_port = [bool]$passwordlessRebind.success
            }
            encrypted_transfer = [ordered]@{
                passed = $true
                pbkeylen_bytes = 16
                correct_passphrase_received_buffers = 30
                wrong_passphrase_rejected = $true
                missing_passphrase_rejected = $true
                correct_caller_after_rejections_received_buffers = 30
            }
            fan_out_and_removal = [ordered]@{
                passed = $true
                concurrent_callers = 2
                removed_caller_termination = 'ungraceful'
                remaining_caller_received_buffers = 500
                replacement_caller_received_buffers = 100
            }
            bind_diagnostics = [ordered]@{
                passed = $true
                occupied_port = [ordered]@{
                    gstreamer_state_change_failed = $true
                    socket_error = $conflictProbe.socket_error
                    native_error = $conflictProbe.native_error
                    rebind_after_holder_release = [bool]$releasedConflictProbe.success
                }
                invalid_local_address = [ordered]@{
                    address_class = 'TEST-NET-1 unassigned local address'
                    gstreamer_state_change_failed = $true
                    socket_error = $invalidProbe.socket_error
                    native_error = $invalidProbe.native_error
                }
            }
            zero_caller_soak = [ordered]@{
                passed = $true
                required_seconds = 660
                configured_seconds = $SoakSeconds
                measured_seconds = [Math]::Round($soakStopwatch.Elapsed.TotalSeconds, 3)
                continuous_buffers = $soakBufferCount
                buffers_per_second = 100
                wait_for_connection = $false
            }
        }
        scope_boundary = [ordered]@{
            g2_callback_or_admission_signals_exercised = $false
            note = 'Caller callback ordering, authentication=true behavior, identity correlation, and pending/active admission caps remain reserved for G2.'
        }
        security_review = [ordered]@{
            record = $Manifest.SecurityReview.RecordPath
            reviewed_at = $Manifest.SecurityReview.ReviewedAt
        }
    }

    $evidenceParent = Split-Path -Parent $EvidencePath
    if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $evidenceParent | Out-Null
    }
    $evidenceJson = $evidence | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($EvidencePath, $evidenceJson + "`r`n", (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ''
    if ($Smoke) {
        Write-Host 'G1-R harness smoke passed; the shortened soak is not gate evidence.' -ForegroundColor Yellow
    } else {
        Write-Host 'G1-R passed against the exact staged SRT 1.5.7 runtime.' -ForegroundColor Green
    }
    Write-Host "  libsrt.dll: $($Srt.DllSha256)"
    Write-Host "  srt_getversion: $runtimeVersionHex"
    Write-Host "  evidence: $EvidencePath"
} finally {
    if ($null -ne $udpHolder) {
        $udpHolder.Socket.Dispose()
    }
    foreach ($run in @($script:LiveProcesses)) {
        try {
            if (-not $run.Process.HasExited) {
                [void](Stop-GstProcess -Run $run)
            }
        } catch {
            Write-Warning "Failed to stop G1-R child process '$($run.Name)': $_"
        }
    }
    if ($copiedProbeTools) {
        Remove-Item -LiteralPath $IsolatedInspectPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $IsolatedLaunchPath -Force -ErrorAction SilentlyContinue
    }
    [Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
    [Environment]::SetEnvironmentVariable('Path', $originalPath, 'Process')
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
    if (-not $KeepWorkDirectory -and (Test-Path -LiteralPath $WorkDir -PathType Container)) {
        $resolvedWorkDir = [System.IO.Path]::GetFullPath($WorkDir).TrimEnd('\', '/')
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + '\'
        if ($resolvedWorkDir.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path -Leaf $resolvedWorkDir) -match '^pocketstream-g1-r-[0-9a-f]{32}$') {
            Remove-Item -LiteralPath $resolvedWorkDir -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Refusing to remove unexpected G1-R work directory: $resolvedWorkDir"
        }
    } elseif ($KeepWorkDirectory) {
        Write-Host "G1-R work directory retained: $WorkDir" -ForegroundColor DarkYellow
    }
}
