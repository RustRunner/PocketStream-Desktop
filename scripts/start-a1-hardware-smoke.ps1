<# Operator qualification launcher, not an application helper/entry mode.
   Run elevated with the fixed context produced under target/privilege-a1.
   It closes the installed host cooperatively before launching the exact A1
   release artifact. Output remains disabled. No installer/firewall calls. #>
param([Parameter(Mandatory=$true)][string]$ContextPath)
$ErrorActionPreference = 'Stop'
$context = Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
$recordPath = Join-Path (Split-Path -Parent $ContextPath) 'launch-result.json'
$record = [ordered]@{ status='pending'; at_utc=[DateTime]::UtcNow.ToString('o'); diagnostic=$null }
$profileChanged = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -ne $context.expected_sid) {
        throw 'Use the same interactive account with elevation; no state was changed.'
    }
    $exe = (Resolve-Path -LiteralPath $context.executable).Path
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $context.sha256) { throw 'A1 artifact hash mismatch.' }
    $record['artifact'] = [ordered]@{ path=$exe; sha256=$context.sha256; profile='release'; elevated=$true; manifest='requireAdministrator' }
    $oldHosts = @(Get-Process -Name 'pocketstream-desktop' -ErrorAction SilentlyContinue)
    if ($oldHosts.Count -gt 1) { throw 'Multiple hosts are already running; no replacement or launch attempted.' }
    foreach ($old in $oldHosts) {
        if ($old.Path -ne $context.installed_executable -or (Get-FileHash -LiteralPath $old.Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $context.installed_sha256) {
            throw 'An unexpected host is running; no close request was sent.'
        }
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        $closed = $false
        if ($old.MainWindowHandle -ne [IntPtr]::Zero) {
            $root = [Windows.Automation.AutomationElement]::FromHandle($old.MainWindowHandle)
            $buttons = $root.FindAll([Windows.Automation.TreeScope]::Descendants,
                (New-Object Windows.Automation.PropertyCondition ([Windows.Automation.AutomationElement]::ControlTypeProperty),([Windows.Automation.ControlType]::Button)))
            $close = @($buttons | Where-Object { $_.Current.AutomationId -eq 'btn-close' -or ($_.Current.Name -eq 'Close' -and -not $_.Current.IsOffscreen) }) | Select-Object -First 1
            if ($close) { $close.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke(); $closed=$true }
        }
        if (-not $closed) { $closed = $old.CloseMainWindow() }
        if (-not $closed -or -not $old.WaitForExit(25000)) { throw 'Installed host is Busy or did not exit cooperatively; no force-kill, profile change or second host launch.' }
        $record['previous_host'] = [ordered]@{ pid=$old.Id; sha256=$context.installed_sha256; cooperative_exit=$true }
    }
    $profile = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'PocketStream\config.toml'
    $backup = Join-Path (Split-Path -Parent $ContextPath) 'private-original-config.toml'
    Copy-Item -LiteralPath $profile -Destination $backup
    $text = [IO.File]::ReadAllText($profile)
    $section = [regex]::Match($text, '(?ms)^\[rtsp_server\]\r?\n.*?(?=^\[|\z)')
    $enabled = [regex]::Match($section.Value, '(?m)^enabled\s*=\s*(true|false)\s*$')
    if (-not $section.Success -or -not $enabled.Success) { throw 'No exact output-enable field found; profile was not changed.' }
    $updatedSection = [regex]::Replace($section.Value, '(?m)^enabled\s*=\s*(true|false)\s*$', 'enabled = false')
    $updated = $text.Substring(0,$section.Index) + $updatedSection + $text.Substring($section.Index+$section.Length)
    # Keep all pending/retained binding records and credentials intact. This
    # launch uses the current real profile; only listener enablement is changed.
    [IO.File]::WriteAllText($profile, $updated, (New-Object Text.UTF8Encoding $false))
    $profileChanged = $true
    $qualificationHash = (Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant()
    $record['profile'] = [ordered]@{ path=$profile; private_backup=$backup; before_sha256=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant(); original_output_enabled=($enabled.Groups[1].Value -eq 'true'); qualification_output_enabled=$false; restoration='pending until this controlled hardware session ends' }
    $adapter = Get-NetAdapter -Name 'Ethernet' -ErrorAction Stop
    $record['adapter'] = [ordered]@{ alias=[string]$adapter.Name; mac=[string]$adapter.MacAddress; guid=[string]$adapter.InterfaceGuid; index=[int]$adapter.ifIndex; status=[string]$adapter.Status }
    $record['native_addresses_before'] = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex | Select-Object IPAddress,PrefixLength,PrefixOrigin)
    if (@(Get-Process -Name 'pocketstream-desktop' -ErrorAction SilentlyContinue).Count) { throw 'A host started during preflight; A1 launch cancelled.' }
    $app = Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Normal -PassThru
    $record['application_pid'] = $app.Id
    $record.status = 'running: exact A1 release artifact; interactive hardware smoke pending'
} catch {
    $record.diagnostic = $_.Exception.Message
    $record.status = 'pending: launch/preflight did not complete'
    if ($profileChanged -and -not $record.Contains('application_pid') -and -not @(Get-Process -Name 'pocketstream-desktop' -ErrorAction SilentlyContinue).Count) {
        if ((Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant() -eq $qualificationHash) {
            Copy-Item -LiteralPath $backup -Destination $profile -Force
            $record['launch_failure_profile_restored'] = $true
        }
    }
} finally {
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding UTF8
}
if ($record.diagnostic) { exit 1 }
