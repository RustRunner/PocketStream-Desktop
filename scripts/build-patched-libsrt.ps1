#Requires -Version 5.1
<#
.SYNOPSIS
Builds PocketStream's pinned SRT 1.5.6 drop-in with GStreamer Cerbero 1.26.11.

.DESCRIPTION
Checks out the exact Cerbero 1.26.11 commit, applies the tracked two-line SRT
recipe patch, preserves Cerbero's mixed MSVC/MinGW build path, builds SRT, and
packages libsrt.dll with machine-readable provenance.

The host prerequisites from Cerbero's tools/bootstrap-windows.ps1 must already
be installed. The first Cerbero bootstrap can take several hours. This script
never enables Cerbero's global mingw variant: OpenSSL stays on the normal MSVC
path while srt.recipe's can_msvc=False selects Cerbero's matching MinGW
toolchain for libsrt.dll.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\build-patched-libsrt.ps1

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\build-patched-libsrt.ps1 -SkipBootstrap

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File scripts\build-patched-libsrt.ps1 -PrepareOnly
#>
[CmdletBinding()]
param(
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) 'pocketstream-libsrt-1.5.6'),
    [string]$OutDir,
    [string]$DumpbinPath,
    [switch]$SkipBootstrap,
    [switch]$PrepareOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$CerberoRepository = 'https://github.com/GStreamer/cerbero.git'
$CerberoCommit = 'cebb549ade5b73048fc29be5a45332246f1c14f6'
$CerberoVersion = '1.26.11'
$SrtVersion = '1.5.6'
$SrtVersionNumber = 0x010506
$SrtSourceUrl = 'https://github.com/Haivision/srt/archive/v1.5.6.tar.gz'
$SrtSourceSha256 = '2c4980c2c4cfd142d21b829d939dc51db9c6628af5967fff62fd7290769569c7'
$StockRuntimeUrl = 'https://gstreamer.freedesktop.org/data/pkg/windows/1.26.11/msvc/gstreamer-1.0-msvc-x86_64-1.26.11.msi'
$StockRuntimeSha256 = '31cbc21fa0950b5c1e79c80959b2799805cb05a7a35953a13a9f790776137605'

# Git blob IDs are over normalized LF content, so this also detects an
# accidental recipe edit regardless of the checkout's core.autocrlf setting.
$OriginalRecipeBlob = 'd34b2a34e5bb8c375b1869e0e5d2fc8ba4f2e984'
$PatchedRecipeBlob = '80037d6b64bda97413e143ffb58b8604b9c5ad9b'

# Exact dependency table from the stock GStreamer 1.26.11 libsrt.dll. A
# changed import is a review event: it may alter both ABI compatibility and
# the installer dependency closure.
$ExpectedImports = @(
    'api-ms-win-crt-convert-l1-1-0.dll'
    'api-ms-win-crt-environment-l1-1-0.dll'
    'api-ms-win-crt-heap-l1-1-0.dll'
    'api-ms-win-crt-locale-l1-1-0.dll'
    'api-ms-win-crt-math-l1-1-0.dll'
    'api-ms-win-crt-private-l1-1-0.dll'
    'api-ms-win-crt-runtime-l1-1-0.dll'
    'api-ms-win-crt-stdio-l1-1-0.dll'
    'api-ms-win-crt-string-l1-1-0.dll'
    'api-ms-win-crt-time-l1-1-0.dll'
    'KERNEL32.dll'
    'libcrypto-3-x64.dll'
    'libgcc_s_seh-1.dll'
    'libstdc++-6.dll'
    'libwinpthread-1.dll'
    'WS2_32.dll'
    'WSOCK32.dll'
)

$RequiredExports = @(
    'srt_cleanup'
    'srt_getversion'
    'srt_listen_callback'
    'srt_startup'
)

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Write-Ascii {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    [System.IO.File]::WriteAllText($Path, $Value, [System.Text.Encoding]::ASCII)
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = @(& $FilePath @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $details = ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')`n$details"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Test-GitObject {
    param(
        [Parameter(Mandatory = $true)][string]$Checkout,
        [Parameter(Mandatory = $true)][string]$Object
    )
    & git.exe -C $Checkout cat-file -e $Object 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Resolve-PythonLauncher {
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        try {
            $versionOutput = @(Invoke-NativeCapture -FilePath $py.Source -Arguments @('-3', '--version'))
            $version = ($versionOutput -join ' ').Trim()
            if ($version -match 'Python\s+(\d+\.\d+(?:\.\d+)?)' -and [version]$Matches[1] -ge [version]'3.7') {
                return [pscustomobject]@{
                    Path = $py.Source
                    PrefixArguments = @('-3')
                    Version = $version
                }
            }
        } catch {
            Write-Verbose "The Python launcher could not start Python 3: $_"
        }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        try {
            $versionOutput = @(Invoke-NativeCapture -FilePath $python.Source -Arguments @('--version'))
            $version = ($versionOutput -join ' ').Trim()
            if ($version -match 'Python\s+(\d+\.\d+(?:\.\d+)?)' -and [version]$Matches[1] -ge [version]'3.7') {
                return [pscustomobject]@{
                    Path = $python.Source
                    PrefixArguments = @()
                    Version = $version
                }
            }
        } catch {
            Write-Verbose "python.exe could not start: $_"
        }
    }

    throw 'Python 3.7 or newer was not found. Run Cerbero tools/bootstrap-windows.ps1 from an elevated PowerShell first.'
}

function Resolve-Dumpbin {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        $resolved = Get-FullPath -Path $RequestedPath
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "dumpbin.exe was not found at the requested path: $resolved"
        }
        return $resolved
    }

    $onPath = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($onPath) {
        return $onPath.Source
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $matches = Invoke-NativeCapture -FilePath $vswhere -Arguments @(
            '-latest',
            '-products', '*',
            '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
            '-find', 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe'
        )
        $candidate = $matches | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
        if ($candidate) {
            return (Get-FullPath -Path $candidate)
        }
    }

    throw 'dumpbin.exe was not found. Install the Visual Studio C++ x64 build tools or pass -DumpbinPath.'
}

function Invoke-Cerbero {
    param(
        [Parameter(Mandatory = $true)]$Python,
        [Parameter(Mandatory = $true)][string]$Checkout,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $launcher = Join-Path $Checkout 'cerbero-uninstalled'
    $pythonArguments = @($Python.PrefixArguments) + @($launcher) + $Arguments
    Push-Location $Checkout
    try {
        Invoke-Native -FilePath $Python.Path -Arguments $pythonArguments
    } finally {
        Pop-Location
    }
}

function Get-RecipeBlob {
    param([Parameter(Mandatory = $true)][string]$Checkout)
    $blob = Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'hash-object', '--path=recipes/srt.recipe', 'recipes/srt.recipe'
    )
    return ($blob -join '').Trim()
}

function Prepare-CerberoCheckout {
    param(
        [Parameter(Mandatory = $true)][string]$Checkout,
        [Parameter(Mandatory = $true)][string]$PatchPath
    )

    if (-not (Test-Path -LiteralPath $Checkout)) {
        Write-Host "Cloning Cerbero into $Checkout" -ForegroundColor Cyan
        Invoke-Native -FilePath 'git.exe' -Arguments @(
            'clone', '--filter=blob:none', '--depth=1', '--branch', $CerberoVersion,
            $CerberoRepository, $Checkout
        )
    }

    if (-not (Test-Path -LiteralPath (Join-Path $Checkout '.git'))) {
        throw "Cerbero checkout path exists but is not a Git repository: $Checkout"
    }

    $originOutput = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'remote', 'get-url', 'origin'
    ))
    $origin = ($originOutput -join '').Trim()
    if ($origin.TrimEnd('/') -ne $CerberoRepository.TrimEnd('/')) {
        throw "Cerbero origin mismatch: expected $CerberoRepository, got $origin"
    }

    $commitObject = "${CerberoCommit}^{commit}"
    if (-not (Test-GitObject -Checkout $Checkout -Object $commitObject)) {
        Write-Host "Fetching pinned Cerbero commit $CerberoCommit" -ForegroundColor Cyan
        Invoke-Native -FilePath 'git.exe' -Arguments @(
            '-C', $Checkout, 'fetch', '--depth=1', 'origin', $CerberoCommit
        )
    }

    $currentCommitOutput = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'rev-parse', 'HEAD'
    ))
    $currentCommit = ($currentCommitOutput -join '').Trim()
    if ($currentCommit -ne $CerberoCommit) {
        $statusBeforeCheckout = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
            '-C', $Checkout, 'status', '--short', '--untracked-files=no'
        ) | Where-Object { $_ })
        if ($statusBeforeCheckout.Count -ne 0) {
            throw 'Refusing to change commits in a Cerbero checkout with tracked modifications.'
        }
        Invoke-Native -FilePath 'git.exe' -Arguments @(
            '-C', $Checkout, 'checkout', '--detach', $CerberoCommit
        )
    }

    $verifiedCommitOutput = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'rev-parse', 'HEAD'
    ))
    $verifiedCommit = ($verifiedCommitOutput -join '').Trim()
    if ($verifiedCommit -ne $CerberoCommit) {
        throw "Cerbero commit mismatch: expected $CerberoCommit, got $verifiedCommit"
    }

    $upstreamBlobOutput = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'rev-parse', "${CerberoCommit}:recipes/srt.recipe"
    ))
    $upstreamBlob = ($upstreamBlobOutput -join '').Trim()
    if ($upstreamBlob -ne $OriginalRecipeBlob) {
        throw "Pinned Cerbero recipe blob mismatch: expected $OriginalRecipeBlob, got $upstreamBlob"
    }

    $status = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'status', '--short', '--untracked-files=no'
    ) | Where-Object { $_ })
    $currentBlob = Get-RecipeBlob -Checkout $Checkout

    if ($status.Count -eq 0 -and $currentBlob -eq $OriginalRecipeBlob) {
        Invoke-Native -FilePath 'git.exe' -Arguments @('-C', $Checkout, 'apply', '--check', $PatchPath)
        Invoke-Native -FilePath 'git.exe' -Arguments @('-C', $Checkout, 'apply', $PatchPath)
    } elseif ($status.Count -eq 1 -and $status[0] -eq ' M recipes/srt.recipe' -and $currentBlob -eq $PatchedRecipeBlob) {
        Write-Host 'Pinned SRT recipe patch is already applied.' -ForegroundColor DarkYellow
    } else {
        $statusText = if ($status.Count -eq 0) { '(clean)' } else { $status -join ', ' }
        throw "Unexpected Cerbero checkout state: $statusText (recipe blob $currentBlob)"
    }

    $patchedBlob = Get-RecipeBlob -Checkout $Checkout
    if ($patchedBlob -ne $PatchedRecipeBlob) {
        throw "Patched Cerbero recipe blob mismatch: expected $PatchedRecipeBlob, got $patchedBlob"
    }

    $finalStatus = @(Invoke-NativeCapture -FilePath 'git.exe' -Arguments @(
        '-C', $Checkout, 'status', '--short', '--untracked-files=no'
    ) | Where-Object { $_ })
    if ($finalStatus.Count -ne 1 -or $finalStatus[0] -ne ' M recipes/srt.recipe') {
        throw "The recipe patch changed unexpected tracked files: $($finalStatus -join ', ')"
    }

    Invoke-Native -FilePath 'git.exe' -Arguments @('-C', $Checkout, 'diff', '--check')

    $recipePath = Join-Path $Checkout 'recipes\srt.recipe'
    $recipeText = [System.IO.File]::ReadAllText($recipePath)
    $requiredRecipeLines = @(
        "version = '1.5.6'"
        "url = 'https://github.com/Haivision/srt/archive/v%(version)s.tar.gz'"
        "tarball_checksum = '$SrtSourceSha256'"
        'can_msvc = False'
        "configure_options = '-DUSE_ENCLIB=openssl -DENABLE_APPS=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 '"
    )
    foreach ($line in $requiredRecipeLines) {
        if (-not $recipeText.Contains($line)) {
            throw "Patched recipe is missing required content: $line"
        }
    }
}

function Get-PeDetails {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$Dumpbin
    )

    $headers = Invoke-NativeCapture -FilePath $Dumpbin -Arguments @('/HEADERS', $DllPath)
    if (-not ($headers -match '^\s*8664 machine \(x64\)\s*$')) {
        throw 'libsrt.dll is not an x64 PE image (dumpbin did not report machine 8664).'
    }

    $dependentOutput = Invoke-NativeCapture -FilePath $Dumpbin -Arguments @('/DEPENDENTS', $DllPath)
    $imports = @($dependentOutput | ForEach-Object {
        if ($_ -match '^\s+([A-Za-z0-9._+-]+\.dll)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)

    $expectedNormalized = @($ExpectedImports | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $actualNormalized = @($imports | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $delta = @(Compare-Object -ReferenceObject $expectedNormalized -DifferenceObject $actualNormalized)
    if ($delta.Count -ne 0) {
        $details = $delta | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }
        throw "libsrt.dll import table differs from the pinned GStreamer 1.26.11 contract:`n$($details -join "`n")"
    }

    $exportOutput = Invoke-NativeCapture -FilePath $Dumpbin -Arguments @('/EXPORTS', $DllPath)
    $exports = @($exportOutput | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$') {
            $Matches[1]
        }
    } | Sort-Object -Unique)
    foreach ($requiredExport in $RequiredExports) {
        if ($exports -notcontains $requiredExport) {
            throw "libsrt.dll is missing required export: $requiredExport"
        }
    }

    return [pscustomobject]@{
        Imports = $imports
        Exports = $exports
    }
}

function Get-SrtRuntimeVersion {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$DependencyDir
    )

    if (-not ('PocketStream.LibsrtProbe.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PocketStream.LibsrtProbe
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

    $previousPath = $env:PATH
    $module = [IntPtr]::Zero
    try {
        $env:PATH = "$DependencyDir;$previousPath"
        $module = [PocketStream.LibsrtProbe.NativeMethods]::LoadLibraryW($DllPath)
        if ($module -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "LoadLibraryW failed for libsrt.dll with Win32 error $code"
        }

        $address = [PocketStream.LibsrtProbe.NativeMethods]::GetProcAddress($module, 'srt_getversion')
        if ($address -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "GetProcAddress(srt_getversion) failed with Win32 error $code"
        }

        $delegate = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            $address,
            [type][PocketStream.LibsrtProbe.SrtGetVersion]
        )
        return $delegate.Invoke()
    } finally {
        if ($module -ne [IntPtr]::Zero) {
            [void][PocketStream.LibsrtProbe.NativeMethods]::FreeLibrary($module)
        }
        $env:PATH = $previousPath
    }
}

if (-not [Environment]::Is64BitOperatingSystem -or $env:OS -ne 'Windows_NT') {
    throw 'This build must run on 64-bit Windows to match GStreamer 1.26.11 win64.'
}

if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    throw 'git.exe was not found on PATH.'
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$patchPath = Join-Path $scriptDir 'patches\cerbero-srt-1.5.6.patch'
if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
    throw "Tracked Cerbero recipe patch is missing: $patchPath"
}

$workRootFull = Get-FullPath -Path $WorkRoot
$pathRoot = [System.IO.Path]::GetPathRoot($workRootFull).TrimEnd('\', '/')
if ($workRootFull -eq $pathRoot) {
    throw "WorkRoot must not be a filesystem root: $workRootFull"
}
if ($workRootFull -match '\s') {
    throw "Cerbero's Windows build path must not contain spaces: $workRootFull"
}

if (-not $OutDir) {
    $OutDir = Join-Path $workRootFull 'out'
}
$outDirFull = Get-FullPath -Path $OutDir
$checkoutDir = Join-Path $workRootFull 'cerbero'
$cerberoHome = Join-Path $workRootFull 'cerbero-home'
$localConfig = Join-Path $workRootFull 'pocketstream-srt.cbc'
$packageStaging = Join-Path $workRootFull 'package-staging'

New-Item -ItemType Directory -Force -Path $workRootFull | Out-Null
Prepare-CerberoCheckout -Checkout $checkoutDir -PatchPath $patchPath

Write-Host "Cerbero commit: $CerberoCommit" -ForegroundColor Green
Write-Host "SRT recipe:      $SrtVersion / $SrtSourceSha256" -ForegroundColor Green
Write-Host 'Toolchain mode:  Visual Studio default with recipe-scoped MinGW' -ForegroundColor Green

if ($PrepareOnly) {
    Write-Host 'Preparation validation complete; build intentionally skipped.' -ForegroundColor Green
    return
}

$python = Resolve-PythonLauncher
$dumpbin = Resolve-Dumpbin -RequestedPath $DumpbinPath

$cerberoHomeForPython = $cerberoHome.Replace('\', '/')
if ($cerberoHomeForPython.Contains("'")) {
    throw "Cerbero home cannot contain a single quote: $cerberoHome"
}
Write-Utf8NoBom -Path $localConfig -Value "home_dir = r'$cerberoHomeForPython'`n"

$commonCerberoArguments = @(
    '-c', $localConfig,
    '-c', (Join-Path $checkoutDir 'config\win64.cbc'),
    '-v', 'visualstudio'
)

if (-not $SkipBootstrap) {
    Write-Host 'Bootstrapping Cerbero build tools and the pinned MinGW toolchain...' -ForegroundColor Cyan
    Invoke-Cerbero -Python $python -Checkout $checkoutDir -Arguments ($commonCerberoArguments + @('bootstrap'))
}

Write-Host 'Building the patched SRT recipe and dependencies...' -ForegroundColor Cyan
Invoke-Cerbero -Python $python -Checkout $checkoutDir -Arguments ($commonCerberoArguments + @('build', 'srt'))

$prefixBin = Join-Path $cerberoHome 'dist\msvc_x86_64\bin'
$libsrtPath = Join-Path $prefixBin 'libsrt.dll'
$wrongNamePath = Join-Path $prefixBin 'srt.dll'
if (-not (Test-Path -LiteralPath $libsrtPath -PathType Leaf)) {
    throw "Expected Cerbero output was not produced: $libsrtPath"
}
if (Test-Path -LiteralPath $wrongNamePath -PathType Leaf) {
    throw "Unexpected srt.dll found beside libsrt.dll; the GStreamer 1.26.11 drop-in filename contract is ambiguous: $wrongNamePath"
}

$sourceArchive = Join-Path $cerberoHome 'sources\local\srt-1.5.6\v1.5.6.tar.gz'
if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) {
    throw "Cerbero's fetched SRT source archive was not found at the expected path: $sourceArchive"
}
$sourceHash = Get-Sha256 -Path $sourceArchive
if ($sourceHash -ne $SrtSourceSha256) {
    throw "SRT source SHA256 mismatch: expected $SrtSourceSha256, got $sourceHash"
}

$peDetails = Get-PeDetails -DllPath $libsrtPath -Dumpbin $dumpbin
$runtimeVersion = Get-SrtRuntimeVersion -DllPath $libsrtPath -DependencyDir $prefixBin
if ($runtimeVersion -ne $SrtVersionNumber) {
    throw ('srt_getversion mismatch: expected 0x{0:X6}, got 0x{1:X6}' -f $SrtVersionNumber, $runtimeVersion)
}

$runtimeDependencyNames = @(
    'libcrypto-3-x64.dll'
    'libgcc_s_seh-1.dll'
    'libstdc++-6.dll'
    'libwinpthread-1.dll'
)
$runtimeDependencies = @()
foreach ($dependencyName in $runtimeDependencyNames) {
    $dependencyPath = Join-Path $prefixBin $dependencyName
    if (-not (Test-Path -LiteralPath $dependencyPath -PathType Leaf)) {
        throw "Required libsrt runtime dependency is missing from the Cerbero prefix: $dependencyName"
    }
    $dependencyVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dependencyPath)
    $runtimeDependencies += [ordered]@{
        file = $dependencyName
        sha256 = Get-Sha256 -Path $dependencyPath
        file_version = $dependencyVersion.FileVersion
        product_version = $dependencyVersion.ProductVersion
    }
}

$compilerPath = Join-Path $cerberoHome 'mingw\multilib\bin\x86_64-w64-mingw32-g++.exe'
if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    throw "Pinned Cerbero MinGW compiler was not found at the expected path: $compilerPath"
}
$compilerVersion = Invoke-NativeCapture -FilePath $compilerPath -Arguments @('--version')
$gitVersion = Invoke-NativeCapture -FilePath 'git.exe' -Arguments @('--version')
$dumpbinVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dumpbin)

if (Test-Path -LiteralPath $packageStaging) {
    $stagingItem = Get-Item -LiteralPath $packageStaging -Force
    if (($stagingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a package staging reparse point: $packageStaging"
    }
    Remove-Item -LiteralPath $packageStaging -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageStaging | Out-Null
New-Item -ItemType Directory -Force -Path $outDirFull | Out-Null

$packagedDll = Join-Path $packageStaging 'libsrt.dll'
$importsFile = Join-Path $packageStaging 'imports.txt'
$exportsFile = Join-Path $packageStaging 'exports.txt'
$provenanceFile = Join-Path $packageStaging 'provenance.json'
$sumsFile = Join-Path $packageStaging 'SHA256SUMS.txt'

Copy-Item -LiteralPath $libsrtPath -Destination $packagedDll
Write-Ascii -Path $importsFile -Value (($peDetails.Imports -join "`n") + "`n")
Write-Ascii -Path $exportsFile -Value (($peDetails.Exports -join "`n") + "`n")

$dllVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($packagedDll)
$provenance = [ordered]@{
    schema_version = 1
    component = [ordered]@{
        name = 'SRT'
        version = $SrtVersion
        expected_runtime_version_hex = ('0x{0:X6}' -f $SrtVersionNumber)
        source_url = $SrtSourceUrl
        source_archive_sha256 = $sourceHash
    }
    cerbero = [ordered]@{
        repository = $CerberoRepository
        version = $CerberoVersion
        commit = $CerberoCommit
        config = 'config/win64.cbc'
        variants = @('visualstudio')
        srt_can_msvc = $false
        patched_recipe_git_blob = $PatchedRecipeBlob
        recipe_patch_sha256 = Get-Sha256 -Path $patchPath
    }
    artifact = [ordered]@{
        file = 'libsrt.dll'
        sha256 = Get-Sha256 -Path $packagedDll
        architecture = 'x86_64'
        file_version = $dllVersion.FileVersion
        product_version = $dllVersion.ProductVersion
        imports = @($peDetails.Imports)
        exports_sha256 = Get-Sha256 -Path $exportsFile
    }
    import_contract = [ordered]@{
        baseline = 'stock GStreamer 1.26.11 MSVC x86_64 libsrt.dll'
        baseline_runtime_url = $StockRuntimeUrl
        baseline_runtime_sha256 = $StockRuntimeSha256
    }
    runtime_dependencies = $runtimeDependencies
    toolchain = [ordered]@{
        mingw_compiler_file = 'x86_64-w64-mingw32-g++.exe'
        mingw_compiler_sha256 = Get-Sha256 -Path $compilerPath
        mingw_compiler_version = ($compilerVersion -join "`n").Trim()
        dumpbin_file_version = $dumpbinVersion.FileVersion
        python_version = $python.Version
        git_version = ($gitVersion -join ' ').Trim()
        powershell_version = $PSVersionTable.PSVersion.ToString()
        operating_system = [Environment]::OSVersion.VersionString
    }
}

$provenanceJson = ($provenance | ConvertTo-Json -Depth 8) + "`n"
Write-Utf8NoBom -Path $provenanceFile -Value $provenanceJson

$sumEntries = @('libsrt.dll', 'imports.txt', 'exports.txt', 'provenance.json') | ForEach-Object {
    "$(Get-Sha256 -Path (Join-Path $packageStaging $_))  $_"
}
Write-Ascii -Path $sumsFile -Value (($sumEntries -join "`n") + "`n")

$archiveName = "pocketstream-libsrt-$SrtVersion-gstreamer-$CerberoVersion-windows-x86_64.zip"
$archivePath = Join-Path $outDirFull $archiveName
$archiveHashPath = "$archivePath.sha256"
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
if (Test-Path -LiteralPath $archiveHashPath) {
    Remove-Item -LiteralPath $archiveHashPath -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $packageStaging,
    $archivePath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)
$archiveHash = Get-Sha256 -Path $archivePath
Write-Ascii -Path $archiveHashPath -Value "$archiveHash  $archiveName`n"

Write-Host ''
Write-Host 'Patched libsrt artifact is ready.' -ForegroundColor Green
Write-Host "  Archive:       $archivePath"
Write-Host "  Archive SHA256: $archiveHash"
Write-Host "  libsrt SHA256:  $(Get-Sha256 -Path $packagedDll)"
Write-Host ('  SRT version:     0x{0:X6}' -f $runtimeVersion)
