# Pure provider fake. Never imports NetSecurity or calls Windows policy.
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
$root=Split-Path -Parent $PSScriptRoot
$source=[IO.File]::ReadAllText((Join-Path $root 'src-tauri/src/network/firewall-policy-v2.ps1'))
$source=[regex]::Replace($source,'(?s)# @TRUSTED_IMPORTS_BEGIN@.*?# @TRUSTED_IMPORTS_END@','try { function Import-Trusted($module) { $script:imports.Add($module) }; $data=$script:testData')
$source=$source.Replace('[Console]::Out.WriteLine(','Write-Output (').Replace('exit 0','return').Replace('exit 71','return')
$policy=[scriptblock]::Create($source)
$program='C:\Program Files\PocketStream Desktop\pocketstream-desktop.exe'
$roles=@(
    @{role='rtsp';name='PocketStream.RTSP.Inbound.v2';display_name='PocketStream RTSP Server';protocol='TCP';port=8554},
    @{role='srt';name='PocketStream.SRT.Inbound.v2';display_name='PocketStream SRT Server';protocol='UDP';port=8890})
$script:packageBindings=0
function Assert($condition,[string]$reason) { if (!$condition) { throw $reason } }
function Reset {
    $script:rules=[Collections.Generic.List[object]]::new()
    $script:writeCount=0; $script:failSet=0; $script:failQuery=$false; $script:failRemove=$false
    $script:fullQueries=0; $script:namedQueries=0; $script:filterReads=0
    $script:filteredQueries=0; $script:rewrites=0; $script:events=[Collections.Generic.List[string]]::new(); $script:imports=[Collections.Generic.List[string]]::new()
    $script:failAfterEnable=$false; $script:failCleanup=$false; $script:enableThenThrow=$false; $script:enabledWrite=$false; $script:emptyBlocks=$false; $script:foreignBlockFailure=$false
    $script:failNamedQuery=$false; $script:foreignNotFound=$false; $script:changeReadback=$false; $script:restorePackage=$false
    $script:adapter=[pscustomobject]@{InterfaceGuid='{01234567-89ab-cdef-0123-456789abcdef}';MacAddress='00-11-22-33-44-55';ifIndex=15;Status='Up';Name='Renamed Ethernet'}
}
function Rule([string]$name,[int]$role=0,[string]$program='Any',[string]$enabled='True') {
    return [pscustomobject]@{Name=$name;DisplayName=$roles[$role].display_name;Group='';Program=$program;Enabled=$enabled;
        Direction='Inbound';Action='Allow';Profile='Any';Protocol=$roles[$role].protocol;LocalPort=@('9123');RemotePort=@('Any');
        LocalAddress=@('Any');RemoteAddress=@('Any');InterfaceAlias=@('Any');InterfaceType='Any';Service='Any';Package='';
        OverrideBlockRules=$false;LooseSourceMapping=$false;LocalOnlyMapping=$false;DynamicTarget='Any';Platform=@('Any');RemoteDynamicKeywordAddresses=@();
        EdgeTraversalPolicy='Block';Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}
}
function Enforced($row) { return $row.Enabled -eq 'True' -and [string]$row.Package -ceq '' }
function Get-NetFirewallRule {
    [CmdletBinding()]param($PolicyStore,[string]$Name,$Action,$Direction,$DisplayName)
    if($script:failQuery){throw 'fake query failure'}
    if($Name) {
        $script:namedQueries++
        if($script:enabledWrite -and $script:failAfterEnable){$script:failAfterEnable=$false;throw 'fake enabled readback failure'}
        if($script:failNamedQuery){throw 'genuine named provider failure'}
        if($script:foreignNotFound){$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Management.Automation.ItemNotFoundException]::new('provider object unavailable'),'ProviderQueryFailure',[Management.Automation.ErrorCategory]::ObjectNotFound,$Name))}
        $matches=@($script:rules | Where-Object { $_.Name -like $Name })
        if(!$matches.Count) {
            $err=[Management.Automation.ErrorRecord]::new([Management.Automation.ItemNotFoundException]::new('missing name'),'CmdletizationQuery_NotFound_InstanceID',[Management.Automation.ErrorCategory]::ObjectNotFound,$Name)
            $PSCmdlet.ThrowTerminatingError($err)
        }
        if($script:changeReadback -and $script:namedQueries -eq 2){$matches[0].Enabled='True'}
        return $matches
    }
    if($Action -or $Direction -or $DisplayName) {
        $script:filteredQueries++;$script:events.Add('blocks')
        if($script:foreignBlockFailure){$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Management.Automation.ItemNotFoundException]::new('foreign block query failure'),'ProviderQueryFailure',[Management.Automation.ErrorCategory]::ObjectNotFound,$Action))}
        if($script:emptyBlocks){$PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Management.Automation.ItemNotFoundException]::new('no matching block'),'CmdletizationQuery_NotFound',[Management.Automation.ErrorCategory]::ObjectNotFound,$Action))}
        return @($script:rules | Where-Object { (!$Action -or $_.Action -eq $Action) -and (!$Direction -or $_.Direction -eq $Direction) -and (!$DisplayName -or $_.DisplayName -eq $DisplayName) })
    }
    $script:fullQueries++;$script:events.Add('full')
    return $script:rules.ToArray()
}
function Get-NetAdapter { [CmdletBinding()]param([switch]$IncludeHidden) return $script:adapter }
foreach($name in @('Application','Port','Address','Interface','InterfaceType','Service','Security')) {
    Set-Item -LiteralPath ('Function:Get-NetFirewall'+$name+'Filter') -Value {
        [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject) process {$script:filterReads++;return $InputObject}
    }
}
function Set-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,$NewDisplayName,$Direction,$Action,$Enabled,$Profile,$Program,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$InterfaceAlias,$InterfaceType,$Service,$Package,$EdgeTraversalPolicy,$Authentication,$Encryption,$LocalUser,$RemoteUser,$RemoteMachine,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping,$DynamicTarget)
    process {
        if($PSBoundParameters.ContainsKey('Package')){$script:packageBindings++}
        if($NewDisplayName){$script:rewrites++}
        $script:writeCount++
        if($Enabled -eq 'False' -and $script:enabledWrite -and $script:failCleanup){throw 'fake cleanup failure'}
        if($script:failSet -eq $script:writeCount){throw 'fake partial filter failure'}
        foreach($key in $PSBoundParameters.Keys){if($key -eq 'NewDisplayName'){$InputObject.DisplayName=$NewDisplayName} elseif($key -notin @('InputObject','ErrorAction')){$InputObject.$key=$PSBoundParameters[$key]}}
        if($script:restorePackage){$InputObject.Package='Any'}
        if($Enabled -eq 'True'){$script:enabledWrite=$true;$script:events.Add('enable');if($script:enableThenThrow){throw 'fake enable mutated before failure'}}
    }
}
function New-NetFirewallRule {
    [CmdletBinding()]param($PolicyStore,$Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Program,$Protocol,$LocalPort,$RemotePort,$LocalAddress,$RemoteAddress,$InterfaceAlias,$InterfaceType,$Service,$Package,$EdgeTraversalPolicy,$Authentication,$Encryption,$LocalUser,$RemoteUser,$RemoteMachine,$OverrideBlockRules,$LooseSourceMapping,$LocalOnlyMapping,$DynamicTarget)
    if($PSBoundParameters.ContainsKey('Package')){$script:packageBindings++}
    # Installer creation must follow disabling every legacy allow. Runtime
    # ensure intentionally preserves legacy rules introduced after startup.
    if($script:testData.operation.mode -eq 'install') {
        Assert (@($script:rules | Where-Object {$_.Program -eq 'Any' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' -and $_.DisplayName -in $roles.display_name}).Count -eq 0) 'Enabled broad allow survived template creation'
    }
    $row=Rule $Name
    foreach($key in $PSBoundParameters.Keys){if($key -notin @('PolicyStore','ErrorAction')){$row.$key=$PSBoundParameters[$key]}}
    $script:rules.Add($row);$script:writeCount++
    return $row
}
function Remove-NetFirewallRule { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject) process {
    $script:writeCount++
    if ($script:failRemove) { throw 'fake removal failure with unknown provider outcome' }
    $null=$script:rules.Remove($InputObject)
} }
function Run([string]$mode,[string]$role='rtsp',[int]$port=13554,$identity=$null) {
    $script:testData=@{version=2;program=$program;group='PocketStream.Desktop.Managed.v2';roles=$roles;operation=@{mode=$mode;role=$role;port=$port;interface=$identity}}
    $result=& $policy
    return $result | ConvertFrom-Json
}
$passed=[Collections.Generic.List[string]]::new()
Reset
$legacy=Rule 'legacy-tcp-1';$legacy.Package='Any';$script:rules.Add($legacy)
$legacy=Rule 'legacy-tcp[2]*?`';$legacy.Package='*';$script:rules.Add($legacy)
$script:rules.Add((Rule 'legacy-srt' 1 'Any' 'False'));$script:rules.Add((Rule 'legacy-program-scoped' 1 $program))
$block=Rule 'Query User deny';$block.Action='Block';$block.Program=$program;$script:rules.Add($block)
$foreign=Rule 'foreign' 0 'C:\Other\app.exe';$script:rules.Add($foreign)
$r=Run install
Assert $r.ok ('Migration failed: '+($r | ConvertTo-Json -Depth 10))
Assert ($script:rules.Count -eq 4) 'Duplicate/custom-port legacy rules were not removed'
Assert ($script:rules.Contains($block) -and $block.Enabled -eq 'True' -and $script:rules.Contains($foreign)) 'Foreign/block rules changed'
Assert (@($script:rules | Where-Object {$_.Group -eq $script:testData.group -and $_.Enabled -eq 'False' -and $_.Program -eq $program -and $_.Package -ceq ''}).Count -eq 2) 'Install templates not disabled/program scoped/package free'
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
Reset;Assert (Run install).ok 'Fixture setup';Assert (Run ensure).ok 'Fixture start'
$owned=@($script:rules | Where-Object {$_.Name -eq $roles[0].name})[0]
$bad=Rule 'unrelated-legacy-conflict' 1;$bad.Profile='Private';$script:rules.Add($bad)
$block=Rule 'Query User preserved' 0 $program;$block.Action='Block';$script:rules.Add($block)
$foreign=Rule 'foreign-preserved' 0 'C:\Other\app.exe';$script:rules.Add($foreign)
$r=Run disable
Assert ($r.ok -and $owned.Enabled -eq 'False') 'Unrelated legacy conflict stranded the stopped listener allow'
Assert ($bad.Enabled -eq 'True' -and $block.Enabled -eq 'True' -and $foreign.Enabled -eq 'True') 'Stop changed unowned rules'
Assert (Run ensure).ok 'Mid-session legacy conflict blocked ensure'
Assert ($bad.Enabled -eq 'True') 'Ensure changed the mid-session legacy conflict'
Assert (!(Run startup).ok -and !(Run install).ok) 'Startup/install accepted a legacy conflict'
$passed.Add('stop disables only its owned role despite unrelated legacy conflicts')
Reset;$script:rules.Add((Rule 'legacy-removal-failure'));$script:failRemove=$true;$r=Run install
Assert (!$r.ok -and $r.outcome.uncertain) 'Cleaning the last template hid an unresolved legacy removal'
Assert (@($script:rules | Where-Object {$_.Enabled -eq 'True'}).Count -eq 0) 'Failed migration re-enabled a rule'
$script:failRemove=$false;Assert (Run install).ok 'Migration removal retry failed'
$passed.Add('partial migration remains uncertain until all native effects are reconciled')
Reset;Assert (Run install).ok 'Load fixture setup'
foreach($i in 1..602){$other=Rule ('unrelated-'+$i) 0 'C:\Other\app.exe';$other.DisplayName='Other product';$script:rules.Add($other)}
$block=Rule 'preserved-block' 0 $program;$block.Action='Block';$script:rules.Add($block)
foreach($sample in @('cold policy pass','warm policy pass')) {
    $script:writeCount=0;$script:fullQueries=0;$script:namedQueries=0;$script:filterReads=0
    $r=Run startup
    Assert $r.ok ($sample+' failed')
    Assert ($script:rules.Count -eq 605 -and $block.Enabled -eq 'True') 'Substantial existing policy was changed'
    Assert ($script:fullQueries -eq 1 -and $script:filterReads -eq 2) 'Startup repeated full inventories or light ownership reads'
    Assert ($script:writeCount -eq 0 -and !$r.mutated) 'Startup rewrote already-disabled rules'
    Assert ($script:namedQueries -eq 4) 'Startup omitted fresh exact-name readback'
}
$passed.Add('cold/warm startup with 605 rules uses one legacy inventory, two application filters, fresh readback and no redundant disabled writes')
Reset;$r=Run startup
Assert ($r.ok -and $script:namedQueries -eq 2 -and $script:writeCount -eq 0) 'Exact missing name did not remain distinct from provider failure'
$script:failNamedQuery=$true;$r=Run startup
Assert (!$r.ok -and $script:writeCount -eq 0) 'Genuine named-query failure became empty success'
$script:failNamedQuery=$false;$script:foreignNotFound=$true;$r=Run startup
Assert (!$r.ok -and $script:writeCount -eq 0) 'Unrelated ObjectNotFound became an empty rule set'
$passed.Add('exact ObjectNotFound is empty; genuine targeted provider failure fails closed')
Reset;Assert (Run install).ok 'Readback fixture setup';$script:namedQueries=0;$script:writeCount=0;$script:changeReadback=$true
$r=Run startup
Assert (!$r.ok -and $script:writeCount -eq 0) 'Concurrent enable passed a cached disabled observation'
$passed.Add('already-disabled startup still requires fresh disabled readback')
Reset;Assert (Run install).ok 'Conflict fixture setup'
$script:rules[0].Action='Block';$script:rules[0].Enabled='True';$script:rules[1].Enabled='True';$script:writeCount=0
$r=Run startup
Assert (!$r.ok -and $script:rules[0].Enabled -eq 'True' -and $script:rules[1].Enabled -eq 'False' -and $script:writeCount -eq 1) 'Conflict changed a Block or stranded another owned allow'
$passed.Add('startup preserves exact-name Block conflict while disabling the other stale owned allow')
Reset;Assert (Run install).ok 'Upgrade fixture setup'
$prior=@($script:rules.ToArray());foreach($row in $prior){$row.Package='Any'}
$block=Rule 'upgrade-block' 0 $program;$block.Action='Block';$script:rules.Add($block)
$foreign=Rule 'upgrade-foreign' 1 'C:\Other\app.exe';$script:rules.Add($foreign)
$r=Run install
Assert ($r.ok -and @($r.records | Where-Object {$_.repaired_template}).Count -eq 2) 'Upgrade did not record both repairs'
Assert (@($prior | Where-Object {$script:rules.Contains($_)}).Count -eq 0) 'Upgrade reused defective templates'
Assert (@($script:rules | Where-Object {$_.Group -eq $script:testData.group -and $_.Enabled -eq 'False' -and $_.Package -ceq ''}).Count -eq 2) 'Upgrade templates not repaired/disabled'
Assert ($script:rules.Contains($block) -and $block.Enabled -eq 'True' -and $script:rules.Contains($foreign)) 'Upgrade changed block/foreign rules'
$passed.Add('upgrade removes/recreates both defective templates and preserves other rules')
foreach($role in @('rtsp','srt')) {
    Reset;Assert (Run install).ok 'Runtime repair setup';$index=if($role -eq 'rtsp'){0}else{1}
    $prior=$script:rules[$index];$prior.Package='Any'
    $r=Run ensure $role $roles[$index].port
    $row=@($script:rules | Where-Object {$_.Name -eq $roles[$index].name})[0]
    Assert ($r.ok -and $r.outcome.verified_shape -and $r.outcome.action -eq 'updated' -and (Enforced $row)) 'Defective template passed as unchanged or unenforced'
    Assert (!$script:rules.Contains($prior) -and $r.records[0].repaired_template -eq $row.Name) 'Runtime repair skipped remove/create'
}
$passed.Add('both runtime roles repair a default template before enabling')
foreach($package in @('*','S-1-15-2-1')) {
    Reset;Assert (Run install).ok 'Other package setup';$script:rules[0].Package=$package
    $r=Run install
    Assert ($r.ok -and $r.records[0].prior_package -ceq $package -and @($script:rules | Where-Object {$_.Package -cne ''}).Count -eq 0) 'Non-empty package was trusted'
}
$passed.Add('wildcard and SID packages also require repair')
Reset;Assert (Run install).ok 'Concurrent package setup';$script:rules[0].Package='Any';$script:restorePackage=$true
$r=Run ensure
Assert (!$r.ok -and @($script:rules | Where-Object {$_.Enabled -eq 'True'}).Count -eq 0) 'Concurrent package write passed enabled readback'
$passed.Add('enabled readback rejects a concurrent package change')
Reset;Assert (Run install).ok 'Repair failure setup';$script:rules[0].Package='Any';$script:rules[0].Enabled='True';$script:failRemove=$true
$r=Run ensure
Assert (!$r.ok -and !$r.outcome.uncertain -and @($script:rules | Where-Object {$_.Enabled -eq 'True'}).Count -eq 0) 'Repair failure left an enabled rule or wrong uncertainty'
$passed.Add('repair removal failure verifies the role disabled')
Reset;Assert (Run install).ok 'Startup defect setup';$prior=$script:rules[0];$prior.Package='Any';$prior.Enabled='True';$script:writeCount=0;$script:filterReads=0
$r=Run startup
Assert ($r.ok -and $prior.Enabled -eq 'False' -and $prior.Package -eq 'Any' -and $script:rules.Contains($prior)) 'Startup repaired instead of disabling'
Assert ($script:writeCount -eq 1 -and $script:filterReads -eq 2 -and $r.records[0].defective_template -eq $prior.Name) 'Startup defect diagnostic added reads/writes'
$passed.Add('startup detects defective templates with the light ownership read and only disables')
foreach($explicit in @($false,$true)) {
    Reset;Assert (Run install).ok 'Lean ensure setup'
    $bind=if($explicit){$identity}else{$null};$alias=if($explicit){$script:adapter.Name}else{'Any'}
    if($explicit){$script:rules[0].InterfaceAlias=$alias}
    $script:fullQueries=0;$script:filterReads=0;$script:writeCount=0;$script:rewrites=0
    $r=Run ensure rtsp 8554 $bind
    Assert ($r.ok -and $r.outcome.action -eq 'unchanged' -and $script:fullQueries -eq 0 -and $script:filteredQueries -eq 1) 'Lean ensure enumerated a full store'
    Assert ($script:filterReads -eq (9+[int]$explicit) -and $script:writeCount -eq 1 -and $script:rewrites -eq 0) 'Unchanged ensure repeated shape or rewrite'
    Assert (($script:imports -contains 'NetAdapter') -eq $explicit) 'NetAdapter import did not follow explicit identity'
    Assert ($script:events.IndexOf('blocks') -lt $script:events.IndexOf('enable')) 'Block observation followed enable'
}
$passed.Add('unchanged ensure has one shape, minimal enabled readback, filtered blocks and conditional imports')
Reset;Assert (Run install).ok 'Changed port setup';$script:filterReads=0;$script:rewrites=0;$script:writeCount=0
$r=Run ensure rtsp 13554
Assert ($r.ok -and $r.outcome.action -eq 'updated' -and $script:rewrites -eq 1 -and $script:filterReads -eq 16) 'Changed port did not use one rewrite and readback'
$passed.Add('changed port rewrites once and reads the full template back once')
Reset;Assert (Run install).ok 'Light disable setup';$script:rules[0].Enabled='True';$script:filterReads=0;$script:fullQueries=0;$script:namedQueries=0
$r=Run disable
Assert ($r.ok -and $script:filterReads -eq 1 -and $script:fullQueries -eq 0 -and $script:namedQueries -eq 2) 'Disable did not use light ownership and fresh disabled readback'
$passed.Add('disable uses one application filter and fresh exact readback')
foreach($cleanupFails in @($false,$true)) {
    foreach($enableThrows in @($false,$true)) {
        Reset;Assert (Run install).ok 'Unchanged failure setup';$script:failAfterEnable=!$enableThrows;$script:enableThenThrow=$enableThrows;$script:failCleanup=$cleanupFails
        $r=Run ensure rtsp 8554
        Assert (!$r.ok -and $r.mutated -and $r.outcome.uncertain -eq $cleanupFails) 'Unchanged enable lost mutation/uncertainty bookkeeping'
        Assert (($script:rules[0].Enabled -eq 'True') -eq $cleanupFails) 'Unchanged enable cleanup state mismatch'
    }
}
$passed.Add('unchanged enable/readback failures always run cleanup with truthful uncertainty')
Reset;Assert (Run install).ok 'Block query setup';$script:emptyBlocks=$true
Assert (Run ensure rtsp 8554).ok 'Exact provider block not-found did not mean empty'
$script:emptyBlocks=$false;$script:foreignBlockFailure=$true;$r=Run ensure
Assert (!$r.ok -and $script:rules[0].Enabled -eq 'False') 'Foreign ObjectNotFound did not fail closed before enable'
$passed.Add('filtered blocks distinguish exact provider not-found from query failure')
foreach($mode in @('install','startup','ensure','disable','uninstall')) {
    Reset;$r=Run $mode
    Assert ($null -ne $r.timings_ms -and @($r.timings_ms.psobject.Properties).Count -le 16) 'Missing or unbounded timings'
    foreach($value in $r.timings_ms.psobject.Properties.Value){Assert ($value -is [ValueType] -and $value -ge 0) 'Timing is not a nonnegative integer'}
}
Reset;$script:failQuery=$true;$r=Run install
Assert (!$r.ok -and $null -ne $r.timings_ms) 'Handled failure omitted timings'
$passed.Add('bounded numeric timings accompany success and handled failures')
Assert ($script:packageBindings -eq 0) 'A New/Set call bound the Package parameter'
[Console]::Out.WriteLine((@{passed=$passed.ToArray();native_policy_mutations=0;provider='pure fake'} | ConvertTo-Json -Compress))
