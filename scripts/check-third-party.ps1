# check-third-party.ps1
# Verifies that the third-party license notices cover everything the
# application distributes. Needs no GStreamer install — it checks the
# committed manifest, notices, and license texts against each other:
#
#   1. every DLL in gstreamer-manifest.psd1 maps to a component, and every
#      mapped component has a '## <component>' entry in the notices file
#   2. every notices entry references at least one license text under
#      resources/licenses/texts/, and every referenced text exists
#   3. every runtime npm dependency (package.json "dependencies") has a
#      notices entry
#   4. the notices file references the corresponding-source release tag
#      for the pinned GStreamer version
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/check-third-party.ps1
#         (works under Windows PowerShell 5.1 and pwsh alike)
# Exit:   0 = all checks pass, 1 = one or more failures (all listed)

$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$Manifest   = Import-PowerShellDataFile (Join-Path $ScriptDir "gstreamer-manifest.psd1")

$NoticesPath = Join-Path $ProjectDir "src-tauri\resources\licenses\THIRD-PARTY-NOTICES.md"
$TextsDir    = Join-Path $ProjectDir "src-tauri\resources\licenses\texts"
$PackagePath = Join-Path $ProjectDir "package.json"

foreach ($required in @($NoticesPath, $TextsDir, $PackagePath)) {
    if (-not (Test-Path $required)) {
        Write-Error "Missing required path: $required"
        exit 1
    }
}

$Notices  = Get-Content $NoticesPath -Raw
$failures = @()

# ── 1. Manifest DLLs → components → notices entries ──────────────────

$allDlls = @($Manifest.CoreDlls) + @($Manifest.Plugins)
foreach ($dll in $allDlls) {
    if (-not $Manifest.DllComponents.ContainsKey($dll)) {
        $failures += "manifest: '$dll' has no DllComponents entry"
    }
}
foreach ($key in $Manifest.DllComponents.Keys) {
    if ($allDlls -notcontains $key) {
        $failures += "manifest: DllComponents entry '$key' is not in CoreDlls or Plugins"
    }
}

$components = $Manifest.DllComponents.Values | Sort-Object -Unique
foreach ($component in $components) {
    if ($Notices -notmatch "(?m)^## $([regex]::Escape($component))\s*$") {
        $failures += "notices: no '## $component' entry"
    }
}

# ── 2. Every notices entry references an existing license text ───────

$sections = [regex]::Matches($Notices, '(?ms)^## (\S+)\s*$(.*?)(?=^## |\z)')
foreach ($section in $sections) {
    $name = $section.Groups[1].Value
    $body = $section.Groups[2].Value
    $refs = [regex]::Matches($body, 'texts/([\w\.\-]+)') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    if (-not $refs) {
        $failures += "notices: entry '$name' references no license text"
        continue
    }
    foreach ($ref in $refs) {
        if (-not (Test-Path (Join-Path $TextsDir $ref))) {
            $failures += "notices: entry '$name' references missing text '$ref'"
        }
    }
}

# ── 3. Runtime npm dependencies have notices entries ─────────────────

$package = Get-Content $PackagePath -Raw | ConvertFrom-Json
if ($package.dependencies) {
    foreach ($dep in $package.dependencies.PSObject.Properties.Name) {
        if ($Notices -notmatch "(?m)^## $([regex]::Escape($dep))\s*$") {
            $failures += "notices: no '## $dep' entry for npm dependency"
        }
    }
}

# ── 4. Corresponding-source tag matches the pinned version ───────────

$sourceTag = "gst-src-$($Manifest.PinnedVersion)"
if ($Notices -notmatch [regex]::Escape($sourceTag)) {
    $failures += "notices: no reference to the corresponding-source tag '$sourceTag'"
}

# ── Result ────────────────────────────────────────────────────────────

if ($failures.Count -gt 0) {
    Write-Host "`nThird-party notices check FAILED ($($failures.Count)):" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    Write-Error "Third-party notices are out of sync with what the app distributes."
    exit 1
}

Write-Host "Third-party notices check passed: $($allDlls.Count) DLLs across $($components.Count) components, npm deps covered, source tag '$sourceTag' referenced." -ForegroundColor Green
