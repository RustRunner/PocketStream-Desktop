# Fixed policy v2. JSON stdin is data; the executing image supplies the role table.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$stage = 'trusted_modules'
$script:mutated = $false
$records = [Collections.Generic.List[object]]::new()
$outcome = @{state='inactive'}
$script:touched = $null
$script:recordBytes = 0
function Is-Any($value) { return @($value).Count -eq 1 -and [string]$value -in @('Any','*') }
function Same-Program($value) { return [string]::Equals([string]$value, $data.program, [StringComparison]::OrdinalIgnoreCase) }
function All-Rules { return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop) }
function Exact($role) { return @(All-Rules | Where-Object { $_.Name -eq $role.name }) }
function Shape($rule) {
    $app = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $addr = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $iface = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
    $type = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
    $svc = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $sec = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
    if ($app.Count -ne 1 -or $port.Count -ne 1 -or $addr.Count -ne 1 -or $iface.Count -ne 1 -or $type.Count -ne 1 -or $svc.Count -ne 1 -or $sec.Count -ne 1) { throw 'Ambiguous filters' }
    return @{name=[string]$rule.Name;group=[string]$rule.Group;display=[string]$rule.DisplayName;enabled=[string]$rule.Enabled;
        direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile;program=[string]$app[0].Program;
        package=[string]$app[0].Package;protocol=[string]$port[0].Protocol;local_port=@($port[0].LocalPort);remote_port=@($port[0].RemotePort);
        local_address=@($addr[0].LocalAddress);remote_address=@($addr[0].RemoteAddress);interface=@($iface[0].InterfaceAlias);
        interface_type=[string]$type[0].InterfaceType;service=[string]$svc[0].Service;edge=[string]$rule.EdgeTraversalPolicy;
        authentication=[string]$sec[0].Authentication;encryption=[string]$sec[0].Encryption;local_user=[string]$sec[0].LocalUser;
        remote_user=[string]$sec[0].RemoteUser;remote_machine=[string]$sec[0].RemoteMachine;override_block=[string]$sec[0].OverrideBlockRules;
        platform=@($rule.Platform);loose_source=[string]$rule.LooseSourceMapping;local_only=[string]$rule.LocalOnlyMapping;
        dynamic_target=[string]$port[0].DynamicTarget;dynamic_addresses=@($rule.RemoteDynamicKeywordAddresses)}
}
function Unscoped($s) {
    return (Is-Any $s.remote_port) -and (Is-Any $s.local_address) -and (Is-Any $s.remote_address) -and
        (Is-Any $s.service) -and ($s.package -in @('Any','*','')) -and $s.interface_type -eq 'Any' -and
        $s.edge -eq 'Block' -and $s.authentication -eq 'NotRequired' -and $s.encryption -eq 'NotRequired' -and
        (Is-Any $s.local_user) -and (Is-Any $s.remote_user) -and (Is-Any $s.remote_machine) -and $s.override_block -eq 'False' -and
        $s.loose_source -eq 'False' -and $s.local_only -eq 'False' -and $s.dynamic_target -eq 'Any' -and
        @($s.platform | Where-Object { $_ -and $_ -ne 'Any' }).Count -eq 0 -and @($s.dynamic_addresses | Where-Object { $_ }).Count -eq 0
}
function Owned($s) { return $s.group -ceq $data.group -and (Same-Program $s.program) -and $s.action -eq 'Allow' -and $s.direction -eq 'Inbound' }
function Verified($s, $role, [int]$port, [string]$alias, [bool]$enabled) {
    return (Owned $s) -and $s.name -eq $role.name -and $s.display -ceq $role.display_name -and $s.profile -eq 'Any' -and
        $s.protocol -in @($role.protocol, $(if ($role.protocol -eq 'TCP') {'6'} else {'17'})) -and
        @($s.local_port).Count -eq 1 -and [string]$s.local_port -eq [string]$port -and (Unscoped $s) -and
        @($s.interface).Count -eq 1 -and [string]$s.interface -ceq $alias -and ($s.enabled -eq $(if ($enabled) {'True'} else {'False'}))
}
function Disable-Verified($rule) {
    $script:mutated = $true
    $rule | Set-NetFirewallRule -Enabled False -ErrorAction Stop
    $again = @(All-Rules | Where-Object { $_.Name -eq $rule.Name })
    if ($again.Count -ne 1 -or [string]$again[0].Enabled -ne 'False') { throw 'Disable readback failed' }
}
function Selected-Alias {
    if ($null -eq $data.operation.interface) { return 'Any' }
    $id = $data.operation.interface
    $all = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $matches = @($all | Where-Object { ([string]$_.InterfaceGuid).Trim('{}').ToLowerInvariant() -eq $id.guid -and
        ([string]$_.MacAddress).Replace('-',':').ToLowerInvariant() -eq $id.mac -and $_.ifIndex -eq $id.index })
    if ($matches.Count -ne 1 -or [string]$matches[0].Status -ne 'Up') { throw 'Bind identity unavailable' }
    $alias = [string]$matches[0].Name
    # InterfaceAlias accepts wildcard syntax; unsupported aliases fail closed.
    if ($alias.IndexOfAny([char[]]'*?[]') -ge 0 -or @($all | Where-Object { $_.Name -ceq $alias }).Count -ne 1) { throw 'Ambiguous interface alias' }
    return $alias
}
function Prepare($role, [int]$port, [string]$alias) {
    $rules = @(Exact $role)
    if ($rules.Count -gt 1) { throw 'Rule name collision' }
    $action = 'created'
    if ($rules.Count -eq 1) {
        $shape = Shape $rules[0]
        if (!(Owned $shape)) { throw 'Rule ownership conflict' }
        $action = 'updated'
        if (Verified $shape $role $port $alias $false) { $action = 'unchanged' }
        Disable-Verified $rules[0]
    }
    $script:touched = $role
    $script:mutated = $true
    $params = @{DisplayName=$role.display_name;Group=$data.group;Direction='Inbound';Action='Allow';Enabled='False';Profile='Any';
        Program=$data.program;Protocol=$role.protocol;LocalPort=$port;RemotePort='Any';LocalAddress='Any';RemoteAddress='Any';
        InterfaceAlias=$alias;InterfaceType='Any';Service='Any';Package='Any';EdgeTraversalPolicy='Block';
        Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any';
        OverrideBlockRules=$false;LooseSourceMapping=$false;LocalOnlyMapping=$false;DynamicTarget='Any';ErrorAction='Stop'}
    if ($rules.Count -eq 0) { New-NetFirewallRule -PolicyStore PersistentStore -Name $role.name @params | Out-Null }
    else {
        # Group is an ownership marker, not a writable InputObject parameter.
        $params.Remove('Group'); $params.Remove('DisplayName')
        $params.NewDisplayName=$role.display_name
        $rules[0] | Set-NetFirewallRule @params
    }
    $read = @(Exact $role)
    if ($read.Count -ne 1 -or !(Verified (Shape $read[0]) $role $port $alias $false)) { throw 'Shape readback failed' }
    return $action
}
function Legacy {
    $found = [Collections.Generic.List[object]]::new()
    foreach ($rule in @(All-Rules)) {
        foreach ($role in $data.roles) {
            if ($rule.DisplayName -cne $role.display_name -or $rule.Name -eq $role.name -or [string]$rule.Action -eq 'Block') { continue }
            $s = Shape $rule
            if (!(Is-Any $s.program) -and !(Same-Program $s.program)) { continue }
            $validPort = @($s.local_port).Count -eq 1 -and [string]$s.local_port -match '^\d{1,5}$' -and [int][string]$s.local_port -ge 1 -and [int][string]$s.local_port -le 65535
            if ($s.action -ne 'Allow' -or $s.direction -ne 'Inbound' -or $s.profile -ne 'Any' -or !$validPort -or
                $s.protocol -notin @($role.protocol, $(if ($role.protocol -eq 'TCP') {'6'} else {'17'})) -or !(Unscoped $s) -or !(Is-Any $s.interface)) { throw 'Legacy migration conflict' }
            if ($records.Count -ge 60) { throw 'Too many migration records' }
            $encoded=$s | ConvertTo-Json -Depth 8 -Compress
            $bytes=[Text.Encoding]::UTF8.GetByteCount($encoded)
            if ($bytes -gt 4096 -or ($script:recordBytes+$bytes) -gt 16000) { throw 'Migration diagnostics exceed the bounded result' }
            $script:recordBytes+=$bytes
            $records.Add($s)
            $found.Add($rule)
        }
    }
    return $found.ToArray()
}
# @TRUSTED_IMPORTS_BEGIN@
try {
    $moduleRoot = [IO.Path]::Combine($env:SystemRoot,'System32','WindowsPowerShell','v1.0','Modules')
    foreach ($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetSecurity')) {
        Import-Module -Name ([IO.Path]::Combine($moduleRoot,$module,($module+'.psd1'))) -ErrorAction Stop
    }
    $stage = 'input'
    $data = [Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
    if ($data.version -ne 2 -or @($data.roles).Count -ne 2 -or $data.operation.mode -notin @('startup','install','uninstall','ensure','disable') -or
        ![IO.Path]::IsPathRooted($data.program) -or $data.program.Length -gt 32700) { throw 'Invalid policy input' }
    $stage = 'access'
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $outcome = @{state='unavailable';reason='Administrator access is required for Windows rule automation'}
        throw 'Native access unavailable'
    }
    # @TRUSTED_IMPORTS_END@
    $stage = 'inventory'
    $mode = $data.operation.mode
    if ($mode -eq 'startup') {
        # A migration conflict must not strand unrelated stale owned enables.
        $failed=$false
        foreach ($role in $data.roles) {
            try {
                $rules=@(Exact $role)
                if ($rules.Count -gt 1) { throw 'Rule collision' }
                foreach ($rule in $rules) {
                    if (!(Owned (Shape $rule))) { throw 'Rule ownership conflict' }
                    Disable-Verified $rule
                }
            } catch { $failed=$true }
        }
        if ($failed) { throw 'Startup ownership reconciliation incomplete' }
    }
    # Retiring one listener must not depend on unrelated migration candidates.
    # Install/ensure still inspect every candidate before preparing any allow.
    $legacy = @()
    if ($mode -ne 'disable') { $legacy = @(Legacy) }
    if ($mode -in @('install','uninstall')) {
        $stage = 'legacy_disable'
        foreach ($rule in $legacy) { Disable-Verified $rule }
    } elseif (@($legacy | Where-Object { [string]$_.Enabled -eq 'True' }).Count -gt 0) { throw 'Enabled legacy allow requires elevated installer migration' }
    $roles = @($data.roles)
    if ($mode -in @('ensure','disable')) {
        $roles = @($data.roles | Where-Object { $_.role -ceq $data.operation.role })
        if ($roles.Count -ne 1) { throw 'Unknown rule role' }
    }
    foreach ($role in $roles) {
        $stage = 'ownership'
        $rules = @(Exact $role)
        if ($rules.Count -gt 1) { throw 'Rule collision' }
        foreach ($rule in $rules) { if (!(Owned (Shape $rule))) { throw 'Rule ownership conflict' } }
        if ($mode -in @('startup','disable','uninstall')) {
            foreach ($rule in $rules) {
                $stage = 'disable'
                Disable-Verified $rule
                if ($mode -eq 'uninstall') { $stage='remove'; $rule | Remove-NetFirewallRule -ErrorAction Stop; if (@(Exact $role).Count -ne 0) { throw 'Remove readback failed' } }
            }
        } else {
            $stage = 'shape'
            $port = [int]$role.port
            $alias = 'Any'
            if ($mode -eq 'ensure') {
                $port = [int]$data.operation.port
                if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid port' }
                $alias = Selected-Alias
            }
            $action = Prepare $role $port $alias
            if ($mode -eq 'ensure') {
                $stage = 'enable'
                if ((Selected-Alias) -cne $alias) { throw 'Bind changed before enable' }
                $rule = @(Exact $role)[0]
                $rule | Set-NetFirewallRule -Enabled True -ErrorAction Stop
                $stage = 'enabled_readback'
                $read = @(Exact $role)
                if ($read.Count -ne 1 -or !(Verified (Shape $read[0]) $role $port $alias $true)) { throw 'Enabled readback failed' }
                $blocks = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Action -eq 'Block' -and [string]$_.Direction -eq 'Inbound' } | ForEach-Object {
                    $block = $_; $apps = @($block | Get-NetFirewallApplicationFilter -ErrorAction Stop)
                    if (@($apps | Where-Object { Same-Program $_.Program }).Count -gt 0) { [string]$block.Name }
                })
                if ($blocks.Count -gt 32) { throw 'Too many observed block rules' }
                $outcome = @{state='applied';rule_name=$role.name;action=$action;verified_shape=$true;observed_block_rules=$blocks}
            }
        }
    }
    if ($mode -in @('install','uninstall')) {
        $stage='legacy_remove'
        foreach ($rule in $legacy) {
            $rule | Remove-NetFirewallRule -ErrorAction Stop
            if (@(All-Rules | Where-Object { $_.Name -eq $rule.Name }).Count -ne 0) { throw 'Legacy removal readback failed' }
        }
    }
    $report=@{version=2;ok=$true;stage='verified';mutated=$mutated;outcome=$outcome;records=$records.ToArray()} | ConvertTo-Json -Depth 12 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($report) -gt 30000) { throw 'Policy result exceeds the bounded result' }
    [Console]::Out.WriteLine($report)
    exit 0
} catch {
    $uncertain = $mutated
    if ($null -ne $touched) {
        try {
            $rules = @(Exact $touched)
            if ($rules.Count -gt 1) { throw 'Cleanup rule collision' }
            foreach ($rule in $rules) {
                if (!(Owned (Shape $rule))) { throw 'Cleanup ownership conflict' }
                Disable-Verified $rule
            }
            # An ensure touches one role. Maintenance can also have unresolved
            # effects on other roles or legacy removals; this readback cannot
            # establish those postconditions.
            if ($mode -eq 'ensure') { $uncertain = $false }
        } catch { $uncertain = $true }
    }
    if ($outcome.state -ne 'unavailable') { $outcome = @{state='failed';stage=$stage;reason='Windows rule policy failed; inspect installer diagnostics or restart with administrator access';uncertain=$uncertain} }
    [Console]::Out.WriteLine((@{version=2;ok=$false;stage=$stage;mutated=$mutated;outcome=$outcome;records=$records.ToArray()} | ConvertTo-Json -Depth 12 -Compress))
    exit 71
}
