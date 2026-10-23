#Requires -Version 5.1
<#
.SYNOPSIS
Verifies PocketStream's final staged and installed native dependency closure.

.DESCRIPTION
G3 binds the final 76-file runtime to the completed G1-R and G2 evidence,
validates the complete source/notices/security contract, and loads the staged
and installed runtimes with only their own DLL and plugin paths visible.

-StagedOnly is an intentionally incomplete CI/development mode. It proves the
staging half of the gate but writes result "staged-pass" and g3_complete=false.
A complete pass requires a real NSIS-installed application root, its installer,
and the published corresponding-source prerelease.

-AllowDraftSourceRelease verifies authenticated draft asset hashes as well.
An installed artifact with unpublished sources writes result "draft-pass" and
draft_ready=true, while g3_complete remains false until sources are published.
#>

[CmdletBinding()]
param(
    [string]$GStreamerRoot = $env:GSTREAMER_1_0_ROOT_MSVC_X86_64,
    [string]$BundleRoot,
    [string]$InstalledAppRoot,
    [string]$InstallerPath,
    [string]$G1EvidencePath,
    [string]$G2EvidencePath,
    [string]$EvidencePath,
    [string]$DependencyCacheDir,
    [switch]$StagedOnly,
    [switch]$SkipPublishedSourceCheck,
    [switch]$AllowDraftSourceRelease,
    [switch]$KeepWorkDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'gstreamer-manifest.psd1'
$CheckThirdPartyPath = Join-Path $ScriptDir 'check-third-party.ps1'
$MirrorSourcePath = Join-Path $ScriptDir 'mirror-gstreamer-src.ps1'
$TauriConfigPath = Join-Path $ProjectDir 'src-tauri\tauri.conf.json'
$PackagePath = Join-Path $ProjectDir 'package.json'
$RepositoryLicenseRoot = Join-Path $ProjectDir 'src-tauri\resources\licenses'
$Manifest = Import-PowerShellDataFile $ManifestPath
$Srt = $Manifest.PatchedSrt
$SourcePolicyPath = Join-Path $ScriptDir 'source-release-policy.ps1'
. $SourcePolicyPath

if ($AllowDraftSourceRelease -and $SkipPublishedSourceCheck) {
    throw 'Draft source verification cannot be combined with skipping the source check.'
}

if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'G3 must run on 64-bit Windows.'
}
if ($StagedOnly) {
    if (-not [string]::IsNullOrWhiteSpace($InstalledAppRoot) -or
        -not [string]::IsNullOrWhiteSpace($InstallerPath)) {
        throw '-StagedOnly cannot accept InstalledAppRoot or InstallerPath.'
    }
} else {
    if ([string]::IsNullOrWhiteSpace($InstalledAppRoot) -or
        [string]::IsNullOrWhiteSpace($InstallerPath)) {
        throw 'A complete G3 run requires InstalledAppRoot and InstallerPath. Use -StagedOnly for an incomplete staging check.'
    }
    if ($SkipPublishedSourceCheck) {
        throw '-SkipPublishedSourceCheck is permitted only with the incomplete -StagedOnly mode.'
    }
}

if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $BundleRoot = Join-Path $ProjectDir 'src-tauri\resources\gstreamer'
}
if ([string]::IsNullOrWhiteSpace($G1EvidencePath)) {
    $G1EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g1-r-srt-1.5.6.json'
}
if ([string]::IsNullOrWhiteSpace($G2EvidencePath)) {
    $G2EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g2-srt-admission-1.5.6.json'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    if ($StagedOnly) {
        $EvidencePath = Join-Path ([System.IO.Path]::GetTempPath()) 'pocketstream-g3-staged.json'
    } else {
        $EvidencePath = Join-Path $ProjectDir 'docs\runtime-evidence\g3-srt-1.5.6.json'
    }
}

if (-not [string]::IsNullOrWhiteSpace($GStreamerRoot)) {
    $GStreamerRoot = [System.IO.Path]::GetFullPath($GStreamerRoot).TrimEnd('\', '/')
}
$BundleRoot = [System.IO.Path]::GetFullPath($BundleRoot).TrimEnd('\', '/')
$G1EvidencePath = [System.IO.Path]::GetFullPath($G1EvidencePath)
$G2EvidencePath = [System.IO.Path]::GetFullPath($G2EvidencePath)
$EvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
if (-not $StagedOnly) {
    $InstalledAppRoot = [System.IO.Path]::GetFullPath($InstalledAppRoot).TrimEnd('\', '/')
    $InstallerPath = [System.IO.Path]::GetFullPath($InstallerPath)
    if ($InstalledAppRoot -ieq $ProjectDir -or
        (Join-Path $InstalledAppRoot 'resources\gstreamer') -ieq $BundleRoot) {
        throw 'InstalledAppRoot must be a distinct installed application tree, not the repository staging tree.'
    }
}

$SdkInspectPath = $null
$SdkLaunchPath = $null
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pocketstream-g3-{0}" -f [Guid]::NewGuid().ToString('N'))
$EmptyPluginDir = Join-Path $WorkDir 'no-system-plugins'
$ProbeInspectPath = Join-Path $WorkDir 'gst-inspect-1.0.exe'
$ProbeLaunchPath = Join-Path $WorkDir 'gst-launch-1.0.exe'

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CanonicalTextSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $text = [System.IO.File]::ReadAllText($Path, $encoding).Replace("`r`n", "`n").Replace("`r", "`n")
    $bytes = $encoding.GetBytes($text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
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

function Assert-ExactStringSet {
    param(
        [Parameter(Mandatory = $true)][object[]]$Actual,
        [Parameter(Mandatory = $true)][object[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object)
    if (($actualValues -join "`n") -cne ($expectedValues -join "`n")) {
        $delta = @(Compare-Object -CaseSensitive `
            -ReferenceObject $expectedValues -DifferenceObject $actualValues)
        $details = @($delta | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
        throw "$Description differs:`n$($details -join "`n")"
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Save-ProcessEnvironment {
    $values = @{}
    foreach ($name in @(
        'Path', 'GST_PLUGIN_PATH', 'GST_PLUGIN_PATH_1_0',
        'GST_PLUGIN_SYSTEM_PATH', 'GST_PLUGIN_SYSTEM_PATH_1_0',
        'GST_REGISTRY', 'GST_REGISTRY_1_0', 'GST_REGISTRY_FORK', 'GST_DEBUG'
    )) {
        $values[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    return $values
}

function Restore-ProcessEnvironment {
    param([Parameter(Mandatory = $true)][hashtable]$Values)
    [Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
    foreach ($name in $Values.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Values[$name], 'Process')
    }
}

function Set-IsolatedRuntimeEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$RegistryPath
    )
    $bin = Join-Path $RuntimeRoot 'bin'
    $plugins = Join-Path $RuntimeRoot 'lib\gstreamer-1.0'
    [Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
    [Environment]::SetEnvironmentVariable(
        'Path',
        "$bin;$env:SystemRoot\System32;$env:SystemRoot",
        'Process'
    )
    $env:GST_PLUGIN_PATH = $plugins
    $env:GST_PLUGIN_PATH_1_0 = $plugins
    $env:GST_PLUGIN_SYSTEM_PATH = $EmptyPluginDir
    $env:GST_PLUGIN_SYSTEM_PATH_1_0 = $EmptyPluginDir
    $env:GST_REGISTRY = $RegistryPath
    $env:GST_REGISTRY_1_0 = $RegistryPath
    $env:GST_REGISTRY_FORK = 'no'
    $env:GST_DEBUG = '1'
}

function Invoke-ProbeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [ValidateRange(1, 300000)][int]$TimeoutMilliseconds = 30000
    )
    $quotedArguments = foreach ($argument in $Arguments) {
        if ($argument.Contains('"')) {
            throw "Probe argument contains an unsupported quote: $argument"
        }
        if ($argument -match '\s') {
            '"' + $argument + '"'
        } else {
            $argument
        }
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $quotedArguments -join ' '
    $startInfo.WorkingDirectory = $WorkDir
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start probe process: $FilePath"
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
        $process.Kill()
        [void]$process.WaitForExit(10000)
        throw "Probe process timed out after $TimeoutMilliseconds ms: $FilePath $($Arguments -join ' ')"
    }
    return [pscustomobject][ordered]@{
        exit_code = $process.ExitCode
        stdout = $stdout.GetAwaiter().GetResult()
        stderr = $stderr.GetAwaiter().GetResult()
    }
}

function Resolve-Dumpbin {
    $onPath = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($onPath) {
        return $onPath.Source
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'vswhere.exe was not found; Visual Studio C++ tools are required for G3 import inspection.'
    }
    $matches = @(& $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find '**\Hostx64\x64\dumpbin.exe' 2>$null)
    if ($matches.Count -eq 0) {
        throw 'dumpbin.exe was not found in the installed Visual Studio C++ tools.'
    }
    return [string]$matches[0]
}

function Get-PeImports {
    param([Parameter(Mandatory = $true)][string]$Path)
    $output = @(& $script:DumpbinPath /DEPENDENTS $Path 2>&1 |
        ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin /DEPENDENTS failed for $Path with exit $LASTEXITCODE."
    }
    return @($output | ForEach-Object {
        if ($_ -match '^\s+([A-Za-z0-9._+-]+\.dll)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
}

function Get-SrtRuntimeVersion {
    param([Parameter(Mandatory = $true)][string]$DllPath)
    if (-not ('PocketStream.G3.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PocketStream.G3
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
        $module = [PocketStream.G3.NativeMethods]::LoadLibraryW($DllPath)
        if ($module -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "LoadLibraryW failed for $DllPath with Win32 error $code."
        }
        $address = [PocketStream.G3.NativeMethods]::GetProcAddress($module, 'srt_getversion')
        if ($address -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "GetProcAddress(srt_getversion) failed with Win32 error $code."
        }
        $delegate = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $address,
            [type][PocketStream.G3.SrtGetVersion]
        )
        return $delegate.Invoke()
    } finally {
        if ($module -ne [IntPtr]::Zero) {
            [void][PocketStream.G3.NativeMethods]::FreeLibrary($module)
        }
    }
}

function Get-FreeUdpPort {
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp
    )
    try {
        $socket.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)))
        return ([System.Net.IPEndPoint]$socket.LocalEndPoint).Port
    } finally {
        $socket.Dispose()
    }
}

function Get-PinnedProbeTools {
    $candidateInspect = $null
    $candidateLaunch = $null
    if (-not [string]::IsNullOrWhiteSpace($GStreamerRoot)) {
        $candidateInspect = Join-Path $GStreamerRoot 'bin\gst-inspect-1.0.exe'
        $candidateLaunch = Join-Path $GStreamerRoot 'bin\gst-launch-1.0.exe'
    }
    if ($candidateInspect -and $candidateLaunch -and
        (Test-Path -LiteralPath $candidateInspect -PathType Leaf) -and
        (Test-Path -LiteralPath $candidateLaunch -PathType Leaf) -and
        (Get-Sha256 -Path $candidateInspect) -ceq $Srt.GstInspectSha256 -and
        (Get-Sha256 -Path $candidateLaunch) -ceq $Srt.GstLaunchSha256) {
        return [pscustomobject][ordered]@{
            inspect = $candidateInspect
            launch = $candidateLaunch
            origin = 'hash-pinned machine SDK'
            runtime_msi_sha256 = [string]$Srt.StockRuntimeSha256
        }
    }

    if ([string]::IsNullOrWhiteSpace($DependencyCacheDir)) {
        if (-not [string]::IsNullOrWhiteSpace($env:POCKETSTREAM_DEPENDENCY_CACHE)) {
            $cacheRoot = $env:POCKETSTREAM_DEPENDENCY_CACHE
        } else {
            $cacheRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'pocketstream-dependencies'
        }
    } else {
        $cacheRoot = $DependencyCacheDir
    }
    $cacheRoot = [System.IO.Path]::GetFullPath($cacheRoot).TrimEnd('\', '/')
    if (Test-Path -LiteralPath $cacheRoot -PathType Leaf) {
        throw "Dependency cache path is a file: $cacheRoot"
    }
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
    $msiFile = [System.IO.Path]::GetFileName(([System.Uri]$Srt.StockRuntimeUrl).AbsolutePath)
    $msiPath = Join-Path $cacheRoot $msiFile
    if (Test-Path -LiteralPath $msiPath -PathType Leaf) {
        Assert-Equal -Actual (Get-Sha256 -Path $msiPath) -Expected $Srt.StockRuntimeSha256 `
            -Description 'Cached pinned GStreamer runtime MSI SHA256'
    } else {
        $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (-not $curl) {
            throw 'curl.exe is required to acquire the pinned GStreamer probe tools.'
        }
        $downloadPath = "$msiPath.$PID.$([Guid]::NewGuid().ToString('N')).download"
        try {
            Write-Host 'G3: acquiring probe tools from the pinned 1.26.11 runtime MSI...' -ForegroundColor Cyan
            & $curl.Source -fsSL --retry 3 --retry-delay 5 `
                -o $downloadPath $Srt.StockRuntimeUrl
            if ($LASTEXITCODE -ne 0) {
                throw "Pinned GStreamer runtime download failed with exit $LASTEXITCODE."
            }
            Assert-Equal -Actual (Get-Sha256 -Path $downloadPath) `
                -Expected $Srt.StockRuntimeSha256 `
                -Description 'Downloaded pinned GStreamer runtime MSI SHA256'
            Move-Item -LiteralPath $downloadPath -Destination $msiPath
        } finally {
            if (Test-Path -LiteralPath $downloadPath -PathType Leaf) {
                Remove-Item -LiteralPath $downloadPath -Force
            }
        }
    }

    $extractRoot = Join-Path $WorkDir 'pinned-runtime-msi'
    New-Item -ItemType Directory -Path $extractRoot | Out-Null
    $process = Start-Process -FilePath msiexec.exe -Wait -PassThru -NoNewWindow `
        -ArgumentList @('/a', $msiPath, '/qn', "TARGETDIR=$extractRoot")
    if ($process.ExitCode -ne 0) {
        throw "Administrative extraction of the pinned runtime MSI failed with exit $($process.ExitCode)."
    }
    $inspectMatches = @(Get-ChildItem -LiteralPath $extractRoot -Recurse -File `
        -Filter 'gst-inspect-1.0.exe')
    $launchMatches = @(Get-ChildItem -LiteralPath $extractRoot -Recurse -File `
        -Filter 'gst-launch-1.0.exe')
    Assert-True -Condition ($inspectMatches.Count -eq 1) `
        -Message 'Pinned runtime MSI extraction did not contain exactly one gst-inspect-1.0.exe.'
    Assert-True -Condition ($launchMatches.Count -eq 1) `
        -Message 'Pinned runtime MSI extraction did not contain exactly one gst-launch-1.0.exe.'
    Assert-Equal -Actual (Get-Sha256 -Path $inspectMatches[0].FullName) `
        -Expected $Srt.GstInspectSha256 -Description 'MSI-extracted gst-inspect SHA256'
    Assert-Equal -Actual (Get-Sha256 -Path $launchMatches[0].FullName) `
        -Expected $Srt.GstLaunchSha256 -Description 'MSI-extracted gst-launch SHA256'
    return [pscustomobject][ordered]@{
        inspect = $inspectMatches[0].FullName
        launch = $launchMatches[0].FullName
        origin = 'manifest-pinned runtime MSI administrative extraction'
        runtime_msi_sha256 = Get-Sha256 -Path $msiPath
    }
}

function Get-ClosureIndexSha256 {
    param([Parameter(Mandatory = $true)][hashtable]$Closure)
    $lines = foreach ($relativePath in @($Closure.Keys | Sort-Object)) {
        "$($Closure[$relativePath])  $relativePath"
    }
    return Get-TextSha256 -Text (($lines -join "`n") + "`n")
}

function Get-BundleLayoutEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $runtimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\', '/')
    $runtimeBin = Join-Path $runtimeRoot 'bin'
    $runtimePlugins = Join-Path $runtimeRoot 'lib\gstreamer-1.0'
    foreach ($requiredDirectory in @($runtimeRoot, $runtimeBin, $runtimePlugins)) {
        Assert-True -Condition (Test-Path -LiteralPath $requiredDirectory -PathType Container) `
            -Message "$Label runtime directory is missing: $requiredDirectory"
    }

    $actualPaths = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File |
        ForEach-Object {
            $_.FullName.Substring($runtimeRoot.Length + 1).Replace('\', '/')
        } | Sort-Object)
    $expectedPaths = @($Manifest.BundleClosure.Keys | Sort-Object)
    Assert-ExactStringSet -Actual $actualPaths -Expected $expectedPaths `
        -Description "$Label bundle file set"

    $fileEvidence = @()
    foreach ($relativePath in $expectedPaths) {
        $nativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $fullPath = Join-Path $runtimeRoot $nativePath
        $hash = Get-Sha256 -Path $fullPath
        Assert-Equal -Actual $hash -Expected $Manifest.BundleClosure[$relativePath] `
            -Description "$Label $relativePath SHA256"
        $item = Get-Item -LiteralPath $fullPath
        $fileName = [System.IO.Path]::GetFileName($relativePath)
        $component = [string]$Manifest.DllComponents[$fileName]
        $metadata = $Manifest.ComponentMetadata[$component]
        $fileEvidence += [pscustomobject][ordered]@{
            path = $relativePath
            sha256 = $hash
            bytes = [long]$item.Length
            component = $component
            component_version = [string]$metadata.Version
            build_origin = [string]$metadata.BuildOrigin
            file_version = if ([string]::IsNullOrWhiteSpace($item.VersionInfo.FileVersion)) { $null } else { $item.VersionInfo.FileVersion }
            product_version = if ([string]::IsNullOrWhiteSpace($item.VersionInfo.ProductVersion)) { $null } else { $item.VersionInfo.ProductVersion }
        }
    }

    Assert-True -Condition (-not (Test-Path -LiteralPath (Join-Path $runtimeBin 'srt.dll'))) `
        -Message "$Label bundle contains prohibited srt.dll."
    Assert-True -Condition ($Manifest.BundleClosure.Values -cnotcontains $Srt.StockDllSha256) `
        -Message 'The full bundle lock contains the prohibited stock SRT 1.5.4 hash.'

    $libcryptoConsumers = @()
    foreach ($relativePath in $expectedPaths) {
        $nativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $imports = Get-PeImports -Path (Join-Path $runtimeRoot $nativePath)
        if (@($imports | Where-Object { $_ -ieq 'libcrypto-3-x64.dll' }).Count -gt 0) {
            $libcryptoConsumers += $relativePath
        }
    }
    Assert-ExactStringSet -Actual $libcryptoConsumers -Expected @('bin/libsrt.dll') `
        -Description "$Label libcrypto consumer set"

    $savedEnvironment = Save-ProcessEnvironment
    try {
        $registryPath = Join-Path $WorkDir ("registry-$Label.bin")
        Set-IsolatedRuntimeEnvironment -RuntimeRoot $runtimeRoot -RegistryPath $registryPath

        $versionProbe = Invoke-ProbeProcess -FilePath $ProbeInspectPath -Arguments @('--version')
        Assert-Equal -Actual $versionProbe.exit_code -Expected 0 `
            -Description "$Label isolated GStreamer version probe exit code"
        $versionText = $versionProbe.stdout + $versionProbe.stderr
        Assert-True -Condition ($versionText -match "GStreamer\s+$([regex]::Escape($Manifest.PinnedVersion))") `
            -Message "$Label isolated probe did not report GStreamer $($Manifest.PinnedVersion)."

        $negativeProbe = Invoke-ProbeProcess -FilePath $ProbeInspectPath -Arguments @('--exists', 'opusdec')
        Assert-True -Condition ($negativeProbe.exit_code -ne 0) `
            -Message "$Label plugin isolation failed: non-bundled opusdec is visible."

        $requiredElements = @(
            'queue', 'tee', 'appsink', 'appsrc', 'rtspsrc', 'rtph264depay',
            'rtppcmudepay', 'rtppcmadepay', 'h264parse', 'mpegtsmux', 'srtsink',
            'mulawdec', 'alawdec', 'audioconvert', 'audioresample', 'volume',
            'autoaudiosink', 'wasapi2sink', 'directsoundsink', 'avdec_h264',
            'x264enc', 'mp4mux'
        )
        foreach ($element in $requiredElements) {
            $elementProbe = Invoke-ProbeProcess -FilePath $ProbeInspectPath `
                -Arguments @('--exists', $element)
            Assert-Equal -Actual $elementProbe.exit_code -Expected 0 `
                -Description "$Label isolated $element probe exit code"
        }

        $srtProbe = Invoke-ProbeProcess -FilePath $ProbeInspectPath -Arguments @('srtsink')
        Assert-Equal -Actual $srtProbe.exit_code -Expected 0 `
            -Description "$Label isolated srtsink inspection exit code"
        $srtText = ($srtProbe.stdout + $srtProbe.stderr).Replace('/', '\')
        $expectedPluginPath = Join-Path $runtimePlugins 'gstsrt.dll'
        Assert-True -Condition ($srtText.IndexOf(
            $expectedPluginPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -ge 0) -Message "$Label srtsink loaded outside its own plugin directory."
        foreach ($contractName in @(
            'authentication', 'wait-for-connection', 'passphrase', 'pbkeylen',
            'localaddress', 'localport', 'caller-connecting', 'caller-added',
            'caller-removed'
        )) {
            Assert-True -Condition ($srtText -match [regex]::Escape($contractName)) `
                -Message "$Label srtsink contract is missing '$contractName'."
        }

        $runtimeVersion = Get-SrtRuntimeVersion -DllPath (Join-Path $runtimeBin 'libsrt.dll')
        $runtimeVersionHex = '0x{0:X6}' -f $runtimeVersion
        Assert-Equal -Actual $runtimeVersionHex -Expected $Srt.RuntimeVersionHex `
            -Description "$Label srt_getversion"

        $port = Get-FreeUdpPort
        $launchProbe = Invoke-ProbeProcess -FilePath $ProbeLaunchPath -Arguments @(
            '-q', 'fakesrc', 'num-buffers=25', 'sizetype=fixed', 'sizemax=1316',
            'filltype=zero', '!', 'queue', '!', 'srtsink', 'mode=listener',
            'localaddress=127.0.0.1', "localport=$port", 'wait-for-connection=false',
            'latency=20'
        ) -TimeoutMilliseconds 30000
        Assert-Equal -Actual $launchProbe.exit_code -Expected 0 `
            -Description "$Label isolated SRT listener pipeline exit code"

        return [pscustomobject][ordered]@{
            label = $Label
            root = $runtimeRoot
            file_count = $fileEvidence.Count
            closure_index_sha256 = Get-ClosureIndexSha256 -Closure $Manifest.BundleClosure
            files = $fileEvidence
            gstreamer_version = $Manifest.PinnedVersion
            libsrt_sha256 = Get-Sha256 -Path (Join-Path $runtimeBin 'libsrt.dll')
            srt_getversion_hex = $runtimeVersionHex
            loaded_srt_plugin = 'lib/gstreamer-1.0/gstsrt.dll'
            libcrypto_consumers = $libcryptoConsumers
            isolated_plugin_negative_control = 'opusdec absent'
            required_elements = $requiredElements
            srt_listener_pipeline = 'pass'
            path_policy = 'bundle bin plus Windows system directories only'
            plugin_policy = 'bundle plugin directory; empty system plugin directory'
        }
    } finally {
        Restore-ProcessEnvironment -Values $savedEnvironment
    }
}

function Get-LicenseClosureEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$LicenseRoot,
        [switch]$RequireGeneratedRustNotice
    )
    $licenseRoot = [System.IO.Path]::GetFullPath($LicenseRoot).TrimEnd('\', '/')
    $repositoryRoot = [System.IO.Path]::GetFullPath($RepositoryLicenseRoot).TrimEnd('\', '/')
    $relativePaths = @('THIRD-PARTY-NOTICES.md')
    $relativePaths += @(Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'texts') -File |
        ForEach-Object { "texts/$($_.Name)" } | Sort-Object)
    if ($RequireGeneratedRustNotice) {
        $relativePaths += 'generated/THIRD-PARTY-RUST.md'
    }
    $records = @()
    foreach ($relativePath in $relativePaths) {
        $nativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $expectedPath = Join-Path $repositoryRoot $nativePath
        $actualPath = Join-Path $licenseRoot $nativePath
        Assert-True -Condition (Test-Path -LiteralPath $expectedPath -PathType Leaf) `
            -Message "Staged license resource is missing: $expectedPath"
        Assert-True -Condition (Test-Path -LiteralPath $actualPath -PathType Leaf) `
            -Message "Installed license resource is missing: $actualPath"
        $expectedHash = Get-Sha256 -Path $expectedPath
        $actualHash = Get-Sha256 -Path $actualPath
        Assert-Equal -Actual $actualHash -Expected $expectedHash `
            -Description "License resource $relativePath SHA256"
        $records += [pscustomobject][ordered]@{
            path = $relativePath
            sha256 = $actualHash
        }
    }
    return $records
}

function Get-SourceReleaseEvidence {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        throw 'curl.exe is required to verify the published G3 source release.'
    }
    if ($AllowDraftSourceRelease) {
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if (-not $gh) { throw 'Authenticated GitHub CLI is required to verify source drafts.' }
        $releaseIdText = @(& $gh.Source release view $Manifest.SourceRelease.Tag `
            --repo RustRunner/PocketStream-Desktop --json databaseId) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Source draft lookup failed.' }
        $releaseId = [long]($releaseIdText | ConvertFrom-Json).databaseId
        $releaseText = @(& $gh.Source api "repos/RustRunner/PocketStream-Desktop/releases/$releaseId") -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Source draft metadata lookup failed.' }
    } else {
        $apiUrl = "https://api.github.com/repos/RustRunner/PocketStream-Desktop/releases/tags/$($Manifest.SourceRelease.Tag)"
        $releaseText = @(& $curl.Source -fsSL `
            -H 'Accept: application/vnd.github+json' `
            -H 'X-GitHub-Api-Version: 2022-11-28' $apiUrl 2>&1 |
            ForEach-Object { $_.ToString() }) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "Published source release lookup failed with exit $LASTEXITCODE`: $apiUrl`n$releaseText"
        }
    }
    $release = $releaseText | ConvertFrom-Json
    Assert-SourceReleaseMetadata -SourceManifest $Manifest.SourceRelease `
        -Release $release -AllowDraft:$AllowDraftSourceRelease

    $latestApiUrl = 'https://api.github.com/repos/RustRunner/PocketStream-Desktop/releases/latest'
    $latestText = @(& $curl.Source -fsSL `
        -H 'Accept: application/vnd.github+json' `
        -H 'X-GitHub-Api-Version: 2022-11-28' $latestApiUrl 2>&1 |
        ForEach-Object { $_.ToString() }) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "Latest application release lookup failed with exit $LASTEXITCODE."
    }
    $latest = $latestText | ConvertFrom-Json
    Assert-True -Condition ([string]$latest.tag_name -ne [string]$release.tag_name) `
        -Message 'The source prerelease incorrectly replaced releases/latest.'
    Assert-True -Condition ([string]$latest.tag_name -match '^[vV]') `
        -Message "releases/latest does not identify an application v* tag: $($latest.tag_name)"

    return [pscustomobject][ordered]@{
        verified = $true
        published = -not [bool]$release.draft
        tag = [string]$release.tag_name
        html_url = [string]$release.html_url
        asset_count = $Manifest.SourceRelease.Assets.Count + 1
        index_sha256 = [string]$Manifest.SourceRelease.IndexSha256
        latest_application_tag = [string]$latest.tag_name
    }
}

function Get-SourceInventoryEvidence {
    $records = @()
    foreach ($assetId in @($Manifest.SourceRelease.Assets.Keys | Sort-Object)) {
        $asset = $Manifest.SourceRelease.Assets[$assetId]
        $records += [pscustomobject][ordered]@{
            id = [string]$assetId
            version = [string]$asset.Version
            source_tag = [string]$asset.SourceTag
            file = [string]$asset.File
            sha256 = [string]$asset.Sha256
            upstream = if ($asset.ContainsKey('Url')) { [string]$asset.Url } else { [string]$asset.RepositoryPath }
        }
    }
    return $records
}

function Get-SecurityReviewEvidence {
    $review = $Manifest.SecurityReview
    $recordPath = [System.IO.Path]::GetFullPath((Join-Path $ProjectDir $review.RecordPath))
    Assert-True -Condition (Test-Path -LiteralPath $recordPath -PathType Leaf) `
        -Message "G3 security review record is missing: $recordPath"
    Assert-Equal -Actual (Get-CanonicalTextSha256 -Path $recordPath) `
        -Expected $review.CanonicalTextSha256 -Description 'G3 security review canonical SHA256'
    Assert-Equal -Actual $review.SrtVersion -Expected $Srt.Version `
        -Description 'Security-review SRT version'
    Assert-Equal -Actual $review.SrtDllSha256 -Expected $Srt.DllSha256 `
        -Description 'Security-review libsrt.dll SHA256'
    Assert-Equal -Actual $review.OpenSslVersion -Expected $Manifest.ComponentMetadata.openssl.Version `
        -Description 'Security-review OpenSSL version'
    Assert-Equal -Actual $review.OpenSslDllSha256 `
        -Expected $Manifest.BundleClosure['bin/libcrypto-3-x64.dll'] `
        -Description 'Security-review libcrypto SHA256'

    $reviewDate = [DateTime]::ParseExact(
        [string]$review.ReviewedAt,
        'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal
    )
    $ageDays = [int][Math]::Floor(([DateTime]::UtcNow.Date - $reviewDate.Date).TotalDays)
    Assert-True -Condition ($ageDays -ge 0) -Message 'G3 security review date is in the future.'
    Assert-True -Condition ($ageDays -le [int]$review.MaxAgeDays) `
        -Message "G3 security review is $ageDays days old; maximum is $($review.MaxAgeDays)."

    $reviewText = Get-Content -LiteralPath $recordPath -Raw
    foreach ($requiredText in @(
        @($review.RequiredAdvisoryIds) + @(
            [string]$review.OpenSslAdvisoryUrl,
            [string]$review.SrtDllSha256,
            [string]$review.OpenSslDllSha256
        )
    )) {
        Assert-True -Condition ($reviewText.Contains([string]$requiredText)) `
            -Message "G3 security review does not contain required reference '$requiredText'."
    }

    return [pscustomobject][ordered]@{
        record = [string]$review.RecordPath
        canonical_text_sha256 = [string]$review.CanonicalTextSha256
        reviewed_at = [string]$review.ReviewedAt
        age_days = $ageDays
        maximum_age_days = [int]$review.MaxAgeDays
        srt_version = [string]$review.SrtVersion
        libsrt_sha256 = [string]$review.SrtDllSha256
        openssl_version = [string]$review.OpenSslVersion
        libcrypto_sha256 = [string]$review.OpenSslDllSha256
        disposition = 'pass with scoped OpenSSL reachability decision'
    }
}

$baselineEnvironment = Save-ProcessEnvironment
$script:DumpbinPath = $null
try {
    Write-Host 'G3: validating committed closure, evidence, and compliance inputs...' -ForegroundColor Cyan
    foreach ($requiredFile in @(
        $ManifestPath, $CheckThirdPartyPath, $MirrorSourcePath, $TauriConfigPath,
        $PackagePath, $G1EvidencePath, $G2EvidencePath
    )) {
        Assert-True -Condition (Test-Path -LiteralPath $requiredFile -PathType Leaf) `
            -Message "Required G3 input is missing: $requiredFile"
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CheckThirdPartyPath
    if ($LASTEXITCODE -ne 0) {
        throw "Third-party closure check failed with exit $LASTEXITCODE."
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $MirrorSourcePath -ValidateManifestOnly
    if ($LASTEXITCODE -ne 0) {
        throw "Source manifest validation failed with exit $LASTEXITCODE."
    }

    $tauriConfig = Get-Content -LiteralPath $TauriConfigPath -Raw | ConvertFrom-Json
    $requiredResourceGlobs = @(
        'resources/gstreamer/bin/*',
        'resources/gstreamer/lib/gstreamer-1.0/*',
        'resources/licenses/THIRD-PARTY-NOTICES.md',
        'resources/licenses/texts/*',
        'resources/licenses/generated/*'
    )
    foreach ($resourceGlob in $requiredResourceGlobs) {
        Assert-True -Condition (@($tauriConfig.bundle.resources) -ccontains $resourceGlob) `
            -Message "Tauri bundle resources omit '$resourceGlob'."
    }
    Assert-Equal -Actual $tauriConfig.bundle.windows.nsis.installMode -Expected 'perMachine' `
        -Description 'NSIS install mode'

    $g1Evidence = Get-Content -LiteralPath $G1EvidencePath -Raw | ConvertFrom-Json
    $g2Evidence = Get-Content -LiteralPath $G2EvidencePath -Raw | ConvertFrom-Json
    Assert-Equal -Actual $g1Evidence.gate -Expected 'G1-R' -Description 'G1-R evidence gate'
    Assert-Equal -Actual $g1Evidence.result -Expected 'pass' -Description 'G1-R evidence result'
    Assert-True -Condition ([bool]$g1Evidence.g1_r_complete) `
        -Message 'G1-R evidence is incomplete.'
    Assert-Equal -Actual $g2Evidence.gate -Expected 'G2' -Description 'G2 evidence gate'
    Assert-Equal -Actual $g2Evidence.result -Expected 'pass' -Description 'G2 evidence result'
    Assert-True -Condition ([bool]$g2Evidence.g2_complete) -Message 'G2 evidence is incomplete.'
    Assert-Equal -Actual $g2Evidence.dependency_boundary.g1_evidence_sha256 `
        -Expected (Get-Sha256 -Path $G1EvidencePath) `
        -Description 'G2 prerequisite G1-R evidence SHA256'

    foreach ($evidenceHash in @(
        [string]$g1Evidence.staged_runtime.libsrt_sha256,
        [string]$g1Evidence.canonical_release.inner_dll_sha256,
        [string]$g2Evidence.dependency_boundary.libsrt_sha256
    )) {
        Assert-Equal -Actual $evidenceHash -Expected $Srt.DllSha256 `
            -Description 'G1-R/G2/libsrt dependency boundary SHA256'
    }
    Assert-Equal -Actual $g1Evidence.staged_runtime.srt_getversion_hex `
        -Expected $Srt.RuntimeVersionHex -Description 'G1-R srt_getversion'
    Assert-Equal -Actual $g2Evidence.dependency_boundary.srt_getversion_hex `
        -Expected $Srt.RuntimeVersionHex -Description 'G2 srt_getversion'
    Assert-Equal -Actual $g2Evidence.dependency_boundary.archive_sha256 `
        -Expected $Srt.ArchiveSha256 -Description 'G2 dependency archive SHA256'

    $g1Closure = @{}
    foreach ($item in @($g1Evidence.replacement_closure)) {
        $g1Closure[[string]$item.path] = [string]$item.sha256
    }
    Assert-ExactStringSet -Actual @($g1Closure.Keys) `
        -Expected @($Srt.StagedClosure.Keys) -Description 'G1-R replacement closure paths'
    foreach ($relativePath in $Srt.StagedClosure.Keys) {
        Assert-Equal -Actual $g1Closure[$relativePath] `
            -Expected $Srt.StagedClosure[$relativePath] `
            -Description "G1-R replacement closure $relativePath SHA256"
    }

    $securityEvidence = Get-SecurityReviewEvidence
    $sourceInventory = Get-SourceInventoryEvidence
    if ($SkipPublishedSourceCheck) {
        $publishedSourceEvidence = [pscustomobject][ordered]@{
            verified = $false
            published = $false
            reason = 'explicitly skipped by incomplete staged-only run'
            tag = [string]$Manifest.SourceRelease.Tag
            asset_count = $Manifest.SourceRelease.Assets.Count + 1
            index_sha256 = [string]$Manifest.SourceRelease.IndexSha256
        }
    } else {
        Write-Host 'G3: verifying complete-source release assets and publication status...' -ForegroundColor Cyan
        $publishedSourceEvidence = Get-SourceReleaseEvidence
    }

    New-Item -ItemType Directory -Path $WorkDir | Out-Null
    New-Item -ItemType Directory -Path $EmptyPluginDir | Out-Null
    $probeTools = Get-PinnedProbeTools
    $SdkInspectPath = [string]$probeTools.inspect
    $SdkLaunchPath = [string]$probeTools.launch
    Copy-Item -LiteralPath $SdkInspectPath -Destination $ProbeInspectPath
    Copy-Item -LiteralPath $SdkLaunchPath -Destination $ProbeLaunchPath
    $script:DumpbinPath = Resolve-Dumpbin

    Write-Host 'G3: exercising exact staged bundle in isolation...' -ForegroundColor Cyan
    $stagedBundleEvidence = Get-BundleLayoutEvidence -RuntimeRoot $BundleRoot -Label 'staged'
    $stagedLicenseEvidence = Get-LicenseClosureEvidence -LicenseRoot $RepositoryLicenseRoot

    $installedPackageEvidence = $null
    if (-not $StagedOnly) {
        Assert-True -Condition (Test-Path -LiteralPath $InstallerPath -PathType Leaf) `
            -Message "NSIS installer is missing: $InstallerPath"
        Assert-True -Condition (Test-Path -LiteralPath $InstalledAppRoot -PathType Container) `
            -Message "Installed application root is missing: $InstalledAppRoot"
        $installedExecutable = Join-Path $InstalledAppRoot 'pocketstream-desktop.exe'
        Assert-True -Condition (Test-Path -LiteralPath $installedExecutable -PathType Leaf) `
            -Message "Installed application executable is missing: $installedExecutable"
        $installedRuntimeRoot = Join-Path $InstalledAppRoot 'resources\gstreamer'
        Write-Host 'G3: exercising NSIS-installed bundle in isolation...' -ForegroundColor Cyan
        $installedBundleEvidence = Get-BundleLayoutEvidence `
            -RuntimeRoot $installedRuntimeRoot -Label 'installed'
        Assert-Equal -Actual $installedBundleEvidence.closure_index_sha256 `
            -Expected $stagedBundleEvidence.closure_index_sha256 `
            -Description 'Installed/staged closure index SHA256'
        $installedLicenseRoot = Join-Path $InstalledAppRoot 'resources\licenses'
        $installedLicenseEvidence = Get-LicenseClosureEvidence `
            -LicenseRoot $installedLicenseRoot -RequireGeneratedRustNotice
        $applicationVersion = (Get-Content -LiteralPath $PackagePath -Raw |
            ConvertFrom-Json).version
        $installedPackageEvidence = [pscustomobject][ordered]@{
            installer_path = $InstallerPath
            installer_sha256 = Get-Sha256 -Path $InstallerPath
            installer_bytes = [long](Get-Item -LiteralPath $InstallerPath).Length
            application_root = $InstalledAppRoot
            application_version = [string]$applicationVersion
            executable_path = 'pocketstream-desktop.exe'
            executable_sha256 = Get-Sha256 -Path $installedExecutable
            executable_file_version = (Get-Item -LiteralPath $installedExecutable).VersionInfo.FileVersion
            bundle = $installedBundleEvidence
            licenses = $installedLicenseEvidence
        }
    }

    $completion = Get-G3CompletionState -StagedOnly ([bool]$StagedOnly) `
        -SourceVerified ([bool]$publishedSourceEvidence.verified) `
        -SourcePublished ([bool]$publishedSourceEvidence.published)
    $g3Complete = $completion.complete
    $evidence = [ordered]@{
        schema_version = 1
        gate = 'G3'
        result = $completion.result
        g3_complete = $g3Complete
        draft_ready = $completion.draft_ready
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        dependency_boundary = [ordered]@{
            prerequisite_gates = @('G1-R', 'G2')
            g1_evidence_sha256 = Get-Sha256 -Path $G1EvidencePath
            g2_evidence_sha256 = Get-Sha256 -Path $G2EvidencePath
            dependency_release_tag = [string]$Srt.ReleaseTag
            dependency_archive_sha256 = [string]$Srt.ArchiveSha256
            libsrt_sha256 = [string]$Srt.DllSha256
            srt_getversion_hex = [string]$Srt.RuntimeVersionHex
            stock_srt_sha256_prohibited = [string]$Srt.StockDllSha256
        }
        harness = [ordered]@{
            script_sha256 = Get-Sha256 -Path $MyInvocation.MyCommand.Path
            manifest_sha256 = Get-Sha256 -Path $ManifestPath
            third_party_check_sha256 = Get-Sha256 -Path $CheckThirdPartyPath
            source_mirror_script_sha256 = Get-Sha256 -Path $MirrorSourcePath
            source_policy_script_sha256 = Get-Sha256 -Path $SourcePolicyPath
            powershell_version = $PSVersionTable.PSVersion.ToString()
            dumpbin_file_version = (Get-Item -LiteralPath $script:DumpbinPath).VersionInfo.FileVersion
            gst_inspect_sha256 = Get-Sha256 -Path $SdkInspectPath
            gst_launch_sha256 = Get-Sha256 -Path $SdkLaunchPath
            probe_tool_origin = [string]$probeTools.origin
            probe_runtime_msi_sha256 = [string]$probeTools.runtime_msi_sha256
        }
        runtime_contract = [ordered]@{
            gstreamer_version = [string]$Manifest.PinnedVersion
            declared_file_count = $Manifest.BundleClosure.Count
            closure_index_sha256 = Get-ClosureIndexSha256 -Closure $Manifest.BundleClosure
            component_count = $Manifest.ComponentMetadata.Count
            staged_bundle = $stagedBundleEvidence
        }
        compliance = [ordered]@{
            source_release = $publishedSourceEvidence
            source_inventory = $sourceInventory
            source_asset_count = $sourceInventory.Count
            security_review = $securityEvidence
            staged_licenses = $stagedLicenseEvidence
            notices_and_metadata_check = 'pass'
        }
        installed_package = $installedPackageEvidence
        incomplete_reason = $completion.incomplete_reason
    }

    $evidenceParent = Split-Path -Parent $EvidencePath
    if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $evidenceParent | Out-Null
    }
    Write-Utf8NoBom -Path $EvidencePath `
        -Value (($evidence | ConvertTo-Json -Depth 16) + "`n")
    if ($g3Complete) {
        Write-Host "G3 passed; final evidence written to $EvidencePath" -ForegroundColor Green
    } elseif ($completion.draft_ready) {
        Write-Host "G3 draft artifact passed; source publication pending. Evidence: $EvidencePath" -ForegroundColor Yellow
    } else {
        Write-Host "G3 staged check passed (incomplete by design); evidence written to $EvidencePath" -ForegroundColor Yellow
    }
} finally {
    Restore-ProcessEnvironment -Values $baselineEnvironment
    if ($KeepWorkDirectory) {
        Write-Host "G3 work directory retained at $WorkDir" -ForegroundColor Yellow
    } elseif (Test-Path -LiteralPath $WorkDir -PathType Container) {
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
        $resolvedWork = [System.IO.Path]::GetFullPath($WorkDir).TrimEnd('\', '/')
        $expectedPrefix = $tempRoot + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedWork.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove G3 work directory outside the system temp root: $resolvedWork"
        }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}
