#!/usr/bin/env pwsh
# scripts/check.ps1 — local mirror of .github/workflows/ci.yml
#
# Runs the same checks CI runs, in the same order. cargo test, fmt, and
# clippy are all blocking — anything that fails locally will fail in CI.
#
# Usage:
#   pwsh ./scripts/check.ps1            # run everything
#   pwsh ./scripts/check.ps1 -Quick     # skip frontend build + clippy

param(
    [switch]$Quick
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

$failed = @()
$warned = @()

function Step {
    param(
        [string]$Name,
        [scriptblock]$Block,
        [switch]$Informational
    )
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    try {
        & $Block
        if ($LASTEXITCODE -ne 0) {
            if ($Informational) {
                Write-Host "WARN ($Name returned $LASTEXITCODE)" -ForegroundColor Yellow
                $script:warned += $Name
            } else {
                Write-Host "FAIL ($Name returned $LASTEXITCODE)" -ForegroundColor Red
                $script:failed += $Name
            }
        } else {
            Write-Host "OK" -ForegroundColor Green
        }
    } catch {
        if ($Informational) {
            Write-Host "WARN ($Name threw: $_)" -ForegroundColor Yellow
            $script:warned += $Name
        } else {
            Write-Host "FAIL ($Name threw: $_)" -ForegroundColor Red
            $script:failed += $Name
        }
    }
}

# ── Frontend build (mirrors `frontend` job) ────────────────────────
if (-not $Quick) {
    Step "Frontend build" {
        Push-Location $repoRoot
        try { npm run build } finally { Pop-Location }
    }
}

# ── Rust tests (mirrors `rust` job — blocking step) ────────────────
Step "cargo test" {
    Push-Location "$repoRoot/src-tauri"
    try { cargo test --lib } finally { Pop-Location }
}

# ── Format check (mirrors `cargo fmt` — blocking) ─────────────────
Step "cargo fmt --check" {
    Push-Location "$repoRoot/src-tauri"
    try { cargo fmt --check } finally { Pop-Location }
}

# ── Clippy (mirrors `cargo clippy` — blocking, -D warnings) ───────
if (-not $Quick) {
    Step "cargo clippy" {
        Push-Location "$repoRoot/src-tauri"
        try { cargo clippy --all-targets --no-deps -- -D warnings } finally { Pop-Location }
    }
}

# ── Summary ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "---------------------------------------------------"
if ($failed.Count -gt 0) {
    Write-Host "FAILED: $($failed -join ', ')" -ForegroundColor Red
    if ($warned.Count -gt 0) {
        Write-Host "WARN:   $($warned -join ', ')" -ForegroundColor Yellow
    }
    exit 1
}
if ($warned.Count -gt 0) {
    Write-Host "All blocking checks passed." -ForegroundColor Green
    Write-Host "Informational warnings: $($warned -join ', ')" -ForegroundColor Yellow
    exit 0
}
Write-Host "All checks passed clean." -ForegroundColor Green
exit 0
