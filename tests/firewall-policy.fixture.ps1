# Pure provider fake. Never imports NetSecurity or calls Windows policy.
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
$root=Split-Path -Parent $PSScriptRoot
$source=[IO.File]::ReadAllText((Join-Path $root 'src-tauri/src/network/firewall-policy-v2.ps1'))
$source=[regex]::Replace($source,'(?s)# @TRUSTED_IMPORTS_BEGIN@.*?# @TRUSTED_IMPORTS_END@','try { $data=$script:testData')
$source=$source.Replace('[Console]::Out.WriteLine(','Write-Output (').Replace('exit 0','return').Replace('exit 71','return')
$policy=[scriptblock]::Create($source)
$program='C:\Program Files\PocketStream Desktop\pocketstream-desktop.exe'
$roles=@(
    @{role='rtsp';name='PocketStream.RTSP.Inbound.v2';display_name='PocketStream RTSP Server';protocol='TCP';port=8554},
    @{role='srt';name='PocketStream.SRT.Inbound.v2';display_name='PocketStream SRT Server';protocol='UDP';port=8890})
function Assert($condition,[string]$reason) { if (!$condition) { throw $reason } }
function Reset {
    $script:rules=[Collections.Generic.List[object]]::new()
    $script:writeCount=0; $script:failSet=0; $script:failQuery=$false
    $script:adapter=[pscustomobject]@{InterfaceGuid='{01234567-89ab-cdef-0123-456789abcdef}';MacAddress='00-11-22-33-44-55';ifIndex=15;Status='Up';Name='Renamed Ethernet'}
}
function Rule([string]$name,[int]$role=0,[string]$program='Any',[string]$enabled='True') {
    return [pscustomobject]@{Name=$name;DisplayName=$roles[$role].display_name;Group='';Program=$program;Enabled=$enabled;
        Direction='Inbound';Action='Allow';Profile='Any';Protocol=$roles[$role].protocol;LocalPort=@('9123');RemotePort=@('Any');
        LocalAddress=@('Any');RemoteAddress=@('Any');InterfaceAlias=@('Any');InterfaceType='Any';Service='Any';Package='Any';
        OverrideBlockRules=$false;LooseSourceMapping=$false;LocalOnlyMapping=$false;DynamicTarget='Any';Platform=@('Any');RemoteDynamicKeywordAddresses=@();
        EdgeTraversalPolicy='Block';Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}
}
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore) if($script:failQuery){throw 'fake query failure'}; return $script:rules.ToArray() }
function Get-NetAdapter { [CmdletBinding()]param([switch]$IncludeHidden) return $script:adapter }
foreach($name in @('Application','Port','Address','Interface','InterfaceType','Service','Security')) {
    Set-Item -LiteralPath ('Function:Get-NetFirewall'+$name+'Filter') -Value {
        [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject) process {return $InputObject}
    }
}
function Set-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,$NewDisplayName,$Direction,$Action,$Enabled,$Profile,$Program,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$InterfaceAlias,$InterfaceType,$Service,$Package,$EdgeTraversalPolicy,$Authentication,$Encryption,$LocalUser,$RemoteUser,$RemoteMachine,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping,$DynamicTarget)
    process {
        $script:writeCount++
        if($script:failSet -eq $script:writeCount){throw 'fake partial filter failure'}
        foreach($key in $PSBoundParameters.Keys){if($key -eq 'NewDisplayName'){$InputObject.DisplayName=$NewDisplayName} elseif($key -notin @('InputObject','ErrorAction')){$InputObject.$key=$PSBoundParameters[$key]}}
    }
}
function New-NetFirewallRule {
    [CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Program,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$InterfaceAlias,$InterfaceType,$Service,$Package,$EdgeTraversalPolicy,$Authentication,$Encryption,$LocalUser,$RemoteUser,$RemoteMachine,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping,$DynamicTarget)
    # Creation before disabling *all* legacy allows is a policy regression.
    Assert (@($script:rules | Where-Object {$_.Program -eq 'Any' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' -and $_.DisplayName -in $roles.display_name}).Count -eq 0) 'Enabled broad allow survived template creation'
    $row=Rule $Name
    foreach($key in $PSBoundParameters.Keys){if($key -notin @('PolicyStore','ErrorAction')){$row.$key=$PSBoundParameters[$key]}}
    $script:rules.Add($row);$script:writeCount++
    return $row
}
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$script:writeCount++;$null=$script:rules.Remove($InputObject)} }
function Run([string]$mode,[string]$role='rtsp',[int]$port=13554,$identity=$null) {
    $script:testData=@{version=2;program=$program;group='PocketStream.Desktop.Managed.v2';roles=$roles;operation=@{mode=$mode;role=$role;port=$port;interface=$identity}}
    $result=& $policy
    return $result | ConvertFrom-Json
}
$passed=[Collections.Generic.List[string]]::new()
Reset
$script:rules.Add((Rule 'legacy-tcp-1'));$script:rules.Add((Rule 'legacy-tcp-2'));$script:rules.Add((Rule 'legacy-srt' 1 'Any' 'False'));$script:rules.Add((Rule 'legacy-program-scoped' 1 $program))
$block=Rule 'Query User deny';$block.Action='Block';$block.Program=$program;$script:rules.Add($block)
$foreign=Rule 'foreign' 0 'C:\Other\app.exe';$script:rules.Add($foreign)
$r=Run install
Assert $r.ok ('Migration failed: '+($r | ConvertTo-Json -Depth 10))
Assert ($script:rules.Count -eq 4) 'Duplicate/custom-port legacy rules were not removed'
Assert ($script:rules.Contains($block) -and $block.Enabled -eq 'True' -and $script:rules.Contains($foreign)) 'Foreign/block rules changed'
Assert (@($script:rules | Where-Object {$_.Group -eq $script:testData.group -and $_.Enabled -eq 'False' -and $_.Program -eq $program}).Count -eq 2) 'Install templates not disabled/program scoped'
Assert ($r.records.Count -eq 4) 'Prior migration shapes not retained'
Assert (Run install).ok 'Repeated install failed'
$passed.Add('custom ports, duplicate/disabled legacy rules, both protocols, disabled templates, repeat install, preserved block/foreign rules')
$identity=@{guid='01234567-89ab-cdef-0123-456789abcdef';index=15;mac='00:11:22:33:44:55';alias='Old alias'}
$r=Run ensure rtsp 13554 $identity
Assert ($r.ok -and $r.outcome.state -eq 'applied' -and $r.outcome.observed_block_rules[0] -eq 'Query User deny') ('Explicit ensure/block observation failed: '+($r | ConvertTo-Json -Depth 12))
$owned=@($script:rules | Where-Object {$_.Name -eq $roles[0].name})[0];$owned.Name=$owned.Name.ToUpperInvariant()
Assert ($owned.InterfaceAlias -eq 'Renamed Ethernet' -and $owned.Enabled -eq 'True') 'Native identity did not follow rename'
Assert (Run ensure).ok 'Any reset failed'
Assert ($owned.InterfaceAlias -eq 'Any' -and $owned.Program -eq $program -and $owned.LocalAddress -eq 'Any') 'Any reset/readback mismatch'
$passed.Add('explicit GUID/rename resolution and complete Any reset')
Assert (Run startup).ok 'Startup reconciliation failed'
Assert ($owned.Enabled -eq 'False') 'Startup left stale enabled rule'
Assert (Run uninstall).ok 'Uninstall failed'
Assert ($script:rules.Count -eq 2 -and $script:rules.Contains($block) -and $script:rules.Contains($foreign)) 'Uninstall ownership failure'
$passed.Add('startup disable and exact uninstall preservation')
Reset;$script:failQuery=$true;$r=Run install
Assert (!$r.ok -and $script:writeCount -eq 0) 'Query failure became empty success'
$passed.Add('query failure differs from zero matches')
Reset;$bad=Rule 'odd-broad';$bad.Profile='Private';$script:rules.Add($bad);$r=Run install
Assert (!$r.ok -and $bad.Enabled -eq 'True' -and $script:writeCount -eq 0) 'Unrecognized broad shape was guessed'
$passed.Add('unrecognized legacy shape is an unresolved conflict')
Reset;$foreign=Rule $roles[0].name 0 'C:\Other\app.exe';$foreign.Group='PocketStream.Desktop.Managed.v2';$script:rules.Add($foreign);$r=Run install
Assert (!$r.ok -and $foreign.Enabled -eq 'True') 'Native name collision overwrote another program'
$passed.Add('exact native name foreign-program collision fails closed')
Reset;Assert (Run install).ok 'Fixture setup';$script:writeCount=0;$script:failSet=2;$r=Run ensure
Assert (!$r.ok -and @($script:rules | Where-Object {$_.Enabled -eq 'True'}).Count -eq 0) 'Partial filter failure left enabled rule'
$script:failSet=0;Assert (Run install).ok 'Partial migration retry not idempotent'
$passed.Add('partial filter failure stays disabled and retry is idempotent')
Reset;$script:adapter.Name='Wildcard*';$r=Run ensure rtsp 13554 $identity
Assert (!$r.ok -and $script:writeCount -eq 0) 'Wildcard alias widened to Any'
$passed.Add('unsupported alias grammar never widens explicit binding')
[Console]::Out.WriteLine((@{passed=$passed.ToArray();native_policy_mutations=0;provider='pure fake'} | ConvertTo-Json -Compress))
