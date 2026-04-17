#!/usr/bin/env pwsh
# scripts/bump-version.ps1 — bump the project version atomically.
#
# Updates all three source-of-truth version files in lockstep:
#   - package.json              (npm version)
#   - src-tauri/tauri.conf.json (Tauri config, ships with the app)
#   - src-tauri/Cargo.toml      (Rust package version)
#
# Then runs `cargo check` so Cargo.lock picks up the new version and
# any mismatch surfaces immediately instead of biting a future release.
#
# Usage:
#   pwsh ./scripts/bump-version.ps1 0.2.5
#   pwsh ./scripts/bump-version.ps1 -Version 0.2.5 -NoCheck  # skip cargo check

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Version,

    [switch]$NoCheck
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

# Validate semver-ish X.Y.Z. Reject anything else up front — a typo here
# silently propagates to the release tag and GitHub release name.
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Host "ERROR: Version must look like 0.2.5 (got '$Version')" -ForegroundColor Red
    exit 1
}

Write-Host "Bumping version to $Version" -ForegroundColor Cyan

# ── package.json ─────────────────────────────────────────────────────
$pkgPath = Join-Path $repoRoot "package.json"
$pkg = Get-Content $pkgPath -Raw
$pkgNew = $pkg -replace '("version"\s*:\s*")[^"]+(")', "`${1}$Version`${2}"
if ($pkg -eq $pkgNew) {
    Write-Host "WARN: package.json version unchanged" -ForegroundColor Yellow
} else {
    Set-Content -Path $pkgPath -Value $pkgNew -NoNewline
    Write-Host "  package.json              -> $Version" -ForegroundColor Green
}

# ── src-tauri/tauri.conf.json ────────────────────────────────────────
$confPath = Join-Path $repoRoot "src-tauri/tauri.conf.json"
$conf = Get-Content $confPath -Raw
$confNew = $conf -replace '("version"\s*:\s*")[^"]+(")', "`${1}$Version`${2}"
if ($conf -eq $confNew) {
    Write-Host "WARN: tauri.conf.json version unchanged" -ForegroundColor Yellow
} else {
    Set-Content -Path $confPath -Value $confNew -NoNewline
    Write-Host "  src-tauri/tauri.conf.json -> $Version" -ForegroundColor Green
}

# ── src-tauri/Cargo.toml ─────────────────────────────────────────────
# Only match the [package] version, not dependency version lines.
$cargoPath = Join-Path $repoRoot "src-tauri/Cargo.toml"
$cargo = Get-Content $cargoPath -Raw
$cargoNew = $cargo -replace '(?m)^(version\s*=\s*")[^"]+(")', "`${1}$Version`${2}"
if ($cargo -eq $cargoNew) {
    Write-Host "WARN: Cargo.toml version unchanged" -ForegroundColor Yellow
} else {
    Set-Content -Path $cargoPath -Value $cargoNew -NoNewline
    Write-Host "  src-tauri/Cargo.toml      -> $Version" -ForegroundColor Green
}

# ── Update Cargo.lock ────────────────────────────────────────────────
# cargo check is the canonical way to refresh Cargo.lock. Skipping this
# means the next `cargo build` discovers the stale lock and updates it
# on its own — but we'd rather bundle the Cargo.lock bump into the same
# commit as the version change for a clean history.
if (-not $NoCheck) {
    Write-Host ""
    Write-Host "Running cargo check to refresh Cargo.lock..." -ForegroundColor Cyan
    Push-Location "$repoRoot/src-tauri"
    try {
        cargo check --quiet
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: cargo check failed — review the output above" -ForegroundColor Red
            exit 1
        }
    } finally {
        Pop-Location
    }
    Write-Host "OK" -ForegroundColor Green
}

Write-Host ""
Write-Host "Version bumped to $Version." -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  git add package.json src-tauri/tauri.conf.json src-tauri/Cargo.toml src-tauri/Cargo.lock"
Write-Host "  git commit -m `"Bump version to $Version`""
Write-Host "  git tag v$Version"
Write-Host "  git push origin main v$Version"
Write-Host "  npm run tauri build"
