#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ProbePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSha256,
    [switch]$AllowStartupProvider
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -cne 'DESKTOP-PI5BMJR'){throw 'Wrong authorized fixture'}
if(!(Test-Path -LiteralPath $ProbePath -PathType Leaf) -or (Get-FileHash -LiteralPath $ProbePath).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'Probe identity mismatch'}
if(Get-Process pocketstream-desktop -ErrorAction SilentlyContinue){throw 'Close PocketStream normally before this diagnostic'}
$program='C:\Program Files\PocketStream Desktop\pocketstream-desktop.exe'
if((Get-FileHash -LiteralPath $program).Hash.ToLowerInvariant() -cne 'd16e25af6b8a9cf61caaa95dd5095833f41388eb09fd1863b044091e48ac04be'){throw 'Installed baseline identity changed'}
if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Enabled administrator token required; not B-S1 evidence'}
$names=@('PocketStream.RTSP.Inbound.v2','PocketStream.SRT.Inbound.v2')
function Digest($value) {
    $json=ConvertTo-Json -InputObject $value -Depth 12 -Compress
    return [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','').ToLowerInvariant()
}
function Snapshot {
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $managed=@(foreach($name in $names){
        $rows=@($rules | Where-Object Name -eq $name)
        if($rows.Count -ne 1){throw 'Expected exactly two installed managed rules'}
        $rule=$rows[0]
        $app=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object Program,Package)
        if([string]$rule.Enabled -ne 'False' -or [string]$rule.Action -ne 'Allow' -or [string]$rule.Direction -ne 'Inbound' -or $rule.Group -cne 'PocketStream.Desktop.Managed.v2' -or $app.Count -ne 1 -or $app[0].Program -ine $program){throw 'Expected disabled installed-image owned rules; no changes attempted'}
        [ordered]@{
            rule=$rule | Select-Object Name,DisplayName,Group,Enabled,Direction,Action,Profile,EdgeTraversalPolicy,Platform,LooseSourceMapping,LocalOnlyMapping,RemoteDynamicKeywordAddresses
            application=$app
            port=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object Protocol,LocalPort,RemotePort,DynamicTarget)
            address=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object LocalAddress,RemoteAddress)
            interface=@($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop | Select-Object InterfaceAlias)
            interface_type=@($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop | Select-Object InterfaceType)
            service=@($rule | Get-NetFirewallServiceFilter -ErrorAction Stop | Select-Object Service)
            security=@($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop | Select-Object Authentication,Encryption,LocalUser,RemoteUser,RemoteMachine,OverrideBlockRules)
        }
    })
    $network=[ordered]@{
        adapters=@(Get-NetAdapter -InterfaceIndex 13,18 | Select-Object ifIndex,InterfaceGuid,MacAddress,Status | Sort-Object ifIndex)
        addresses=@(Get-NetIPAddress -InterfaceIndex 13,18 -AddressFamily IPv4 | Select-Object InterfaceIndex,IPAddress,PrefixLength,PrefixOrigin,SkipAsSource | Sort-Object InterfaceIndex,IPAddress)
        routes=@(Get-NetRoute -InterfaceIndex 13,18 -AddressFamily IPv4 | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Sort-Object InterfaceIndex,DestinationPrefix,NextHop)
    }
    return [ordered]@{utc=[DateTime]::UtcNow.ToString('o');rules=$rules.Count;rule_metadata_sha256=(Digest @($rules | Select-Object Name,DisplayName,Group,Enabled,Direction,Action,Profile | Sort-Object Name));managed=$managed;managed_sha256=(Digest $managed);network_sha256=(Digest $network);network=$network}
}
$before=Snapshot
'PROBE_BEFORE='+(ConvertTo-Json -InputObject $before -Depth 12 -Compress)
$exitCode=1
try {
    if($AllowStartupProvider){
        $env:POCKETSTREAM_FIREWALL_PROVIDER_PROBE='approved-disabled-installed-rules'
        & $ProbePath --ignored --exact network::native_runner::qualify_firewall_startup_provider --nocapture
    } else {
        $env:POCKETSTREAM_READ_ONLY_FIREWALL_PROBE='1'
        & $ProbePath --ignored --exact network::native_runner::qualify_firewall_startup_read_only --nocapture
    }
    $exitCode=$LASTEXITCODE
} finally {
    $after=Snapshot
    'PROBE_AFTER='+(ConvertTo-Json -InputObject $after -Depth 12 -Compress)
    if($before.rule_metadata_sha256 -cne $after.rule_metadata_sha256 -or $before.managed_sha256 -cne $after.managed_sha256 -or $before.network_sha256 -cne $after.network_sha256){throw 'Observation changed: stop, preserve evidence, do not retry or repair automatically'}
}
exit $exitCode
