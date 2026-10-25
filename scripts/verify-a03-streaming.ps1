param(
    [Parameter(Mandatory = $true)][ValidateSet(7, 8, 9, 10)][int]$Slice,
    [switch]$DesktopBuild
)
# Ordinary source/unit/development-build gates only. Never enables fixtures.
$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$evidence = Join-Path $repoRoot 'docs/runtime-evidence/a03-streaming'
$results = @()
function Invoke-Gate {
    param([string]$Name, [string]$Directory, [scriptblock]$Command)
    Push-Location $Directory
    $started = Get-Date
    $log = Join-Path $evidence "slice-$Slice-$Name.txt"
    try {
        & $Command *> $log
        $code = $LASTEXITCODE
        $raw = [IO.File]::ReadAllText($log)
        [IO.File]::WriteAllText($log, ($raw -replace '(?m)[ \t]+$', ''), [Text.UTF8Encoding]::new($false))
        $script:results += [pscustomobject]@{ gate = $Name; exit_code = $code; seconds = ((Get-Date) - $started).TotalSeconds }
        $script:results | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $evidence "slice-$Slice-gates.json")
        Write-Output "$Name exit=$code"
    } finally { Pop-Location }
}
Invoke-Gate 'rust' "$repoRoot/src-tauri" { cargo test --lib --locked }
Invoke-Gate 'fmt' "$repoRoot/src-tauri" { cargo fmt --check }
Invoke-Gate 'clippy' "$repoRoot/src-tauri" { cargo clippy --all-targets --no-deps --locked -- -D warnings }
Invoke-Gate 'frontend' $repoRoot { npm.cmd test }
Invoke-Gate 'typecheck' $repoRoot { npm.cmd run typecheck }
Invoke-Gate 'contracts' $repoRoot { npm.cmd run check:contracts }
Invoke-Gate 'build' $repoRoot { npm.cmd run build }
if ($DesktopBuild) { Invoke-Gate 'desktop-build' "$repoRoot/src-tauri" { cargo build --locked } }
if ($results | Where-Object { $_.exit_code -ne 0 }) { exit 1 }
