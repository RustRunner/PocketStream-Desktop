# Version 1. Fixed source; all operation data comes from bounded JSON stdin.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$stage = 'trusted_modules'
$mutated = $false
$steps = [Collections.Generic.List[object]]::new()
$resultData = $null
$script:nativeExit = $null
function Step([string]$name) { $steps.Add(@{name=$name;ok=$true;native_exit=$script:nativeExit}); $script:nativeExit=$null }
function Resolve-Selected {
    $all = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $matches = @($all | Where-Object {
        ([string]$_.InterfaceGuid).Trim('{}').ToLowerInvariant() -eq $data.identity.guid -and
        ([string]$_.MacAddress).Replace('-',':').ToLowerInvariant() -eq $data.identity.mac
    })
    if ($matches.Count -ne 1 -or $matches[0].ifIndex -ne $data.identity.index) { throw 'Identity changed' }
    $nic = $matches[0]
    if ($nic.Virtual -ne $false -or [string]$nic.MediaType -ne '802.3' -or
        [int]$nic.NdisPhysicalMedium -in @(1,8,9,10,12,13,20)) { throw 'Unsupported adapter' }
    if (@($all | Where-Object { $_.ifIndex -eq $nic.ifIndex -or $_.Name -ceq $nic.Name }).Count -ne 1) { throw 'Ambiguous adapter' }
    return $nic
}
function Read-State {
    $nic = Resolve-Selected
    # Query all then filter: a successful empty result differs from provider failure.
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex })
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex -and $_.DestinationPrefix -eq '0.0.0.0/0' })
    $mode = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex })
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex })
    if ($mode.Count -ne 1 -or $dns.Count -ne 1) { throw 'Ambiguous state' }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{' + $data.identity.guid + '}'
    $manual = [string](Get-ItemProperty -LiteralPath $key -ErrorAction Stop).NameServer
    return @{nic=$nic;addresses=$addresses;routes=$routes;dhcp=([string]$mode[0].Dhcp -eq 'Enabled');dns=@($dns[0].ServerAddresses);dnsManual=$manual}
}
function Native([string]$path, [string[]]$arguments) {
    try {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = $null
        $null = & $path @arguments 2>&1
        $code = $global:LASTEXITCODE
    } finally { $ErrorActionPreference = 'Stop' }
    $script:nativeExit = $code
    if ($code -isnot [int] -or $code -ne 0) { throw 'Required native step failed' }
}
function Check-Host([string]$address, [int]$prefix) {
    $ip = [Net.IPAddress]::Parse($address)
    $b = $ip.GetAddressBytes()
    if ($b.Length -ne 4 -or $prefix -lt 1 -or $prefix -gt 32 -or $b[0] -eq 0 -or $b[0] -eq 127 -or $b[0] -ge 224) { throw 'Invalid host' }
    if ($prefix -le 30) {
        $n = ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + $b[3]
        $size = [uint64][Math]::Pow(2,32-$prefix)
        if (($n % $size) -eq 0 -or ($n % $size) -eq ($size-1)) { throw 'Network or broadcast host' }
    }
}
function Compatible([string]$gateway, [string]$address, [int]$prefix) {
    if ($gateway -eq $address) { return $false }
    $a = ([Net.IPAddress]::Parse($address)).GetAddressBytes()
    $g = ([Net.IPAddress]::Parse($gateway)).GetAddressBytes()
    for ($i=0; $i -lt 4; $i++) {
        $bits = [Math]::Max(0,[Math]::Min(8,$prefix - 8*$i))
        $mask = 256 - [Math]::Pow(2,8-$bits)
        if (($a[$i] -band [int]$mask) -ne ($g[$i] -band [int]$mask)) { return $false }
    }
    return $true
}
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'PowerShell 5.1 required' }
    $system = [Environment]::SystemDirectory
    $moduleRoot = [IO.Path]::Combine($system,'WindowsPowerShell\v1.0\Modules')
    foreach ($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','CimCmdlets','NetAdapter','NetTCPIP','DnsClient')) {
        Import-Module -Name ([IO.Path]::Combine($moduleRoot,$module,($module+'.psd1'))) -ErrorAction Stop
    }
    $stage = 'payload'
    $raw = [Console]::In.ReadToEnd()
    if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 16384) { throw 'Oversized input' }
    $data = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    if ($data.version -ne 1 -or $data.kind -notin @('inventory','observe','add_address','remove_address','static_address','dhcp','restart','renew')) { throw 'Invalid schema' }
    foreach ($key in $data.PSObject.Properties.Name) { if ($key -notin @('version','kind','identity','address','prefix','automatic')) { throw 'Unknown field' } }
    if ($data.kind -eq 'inventory') {
        $stage = 'inventory'
        $allAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
        $resultData = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Status -in @('Up','Disconnected') } | ForEach-Object {
            $nic = $_
            @{Name=[string]$nic.Name;Guid=[string]$nic.InterfaceGuid;Index=[int]$nic.ifIndex;Description=[string]$nic.InterfaceDescription;
              MacAddress=[string]$nic.MacAddress;MediaType=[string]$nic.MediaType;PhysicalMediaType=[string]$nic.PhysicalMediaType;
              NdisPhysicalMedium=[int]$nic.NdisPhysicalMedium;Status=[string]$nic.Status;Virtual=[bool]$nic.Virtual;
              IPs=@($allAddresses | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex } | ForEach-Object { @{Address=$_.IPAddress;PrefixLength=[int]$_.PrefixLength} })}
        })
        Step 'inventory'
    } else {
        if ($null -eq $data.identity -or $data.identity.guid -notmatch '^[0-9a-f-]{36}$' -or $data.identity.mac -notmatch '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' -or $data.identity.index -lt 1) { throw 'Invalid identity' }
        foreach ($key in $data.identity.PSObject.Properties.Name) { if ($key -notin @('guid','mac','index','alias')) { throw 'Unknown identity field' } }
        $stage = 'access'
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($data.kind -ne 'observe' -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator access required' }
        $stage = 'preflight'
        $before = Read-State
        if ($data.kind -in @('add_address','remove_address','static_address')) { Check-Host $data.address $data.prefix }
        if ($data.kind -eq 'add_address' -and ($before.dhcp -or ($data.automatic -and $data.prefix -ne 24))) { throw 'Invalid address purpose' }
        if ($data.kind -in @('renew','dhcp')) {
            # ipconfig accepts wildcard adapter names; refuse unsupported grammar before any step.
            if ([string]$before.nic.Name -notmatch '^[\p{L}\p{N} _().-]{1,128}$') { throw 'Unsupported ipconfig adapter name' }
        }
        $stage = $data.kind
        switch ($data.kind) {
            'add_address' {
                $all = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -eq $data.address })
                if ($all.Count -gt 0) { throw 'Address already exists' }
                $nic = Resolve-Selected
                $mutated = $true
                New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $data.address -PrefixLength $data.prefix -ErrorAction Stop | Out-Null
                Step 'add_address'
            }
            'remove_address' {
                $matches = @($before.addresses | Where-Object { $_.IPAddress -eq $data.address })
                if ($matches.Count -gt 1 -or ($matches.Count -eq 1 -and $matches[0].PrefixLength -ne $data.prefix)) { throw 'Address prefix changed' }
                if ($matches.Count -eq 1) {
                    $null = Resolve-Selected
                    $mutated = $true
                    Remove-NetIPAddress -InputObject $matches[0] -Confirm:$false -ErrorAction Stop
                }
                Step 'remove_address'
            }
            'static_address' {
                if (@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -eq [string]$data.identity.index }).Count) { throw 'Ambiguous netsh index alias' }
                foreach ($address in $before.addresses) { Check-Host $address.IPAddress $address.PrefixLength }
                $gateways = @($before.routes | Where-Object { $_.NextHop -ne '0.0.0.0' } | ForEach-Object { $_.NextHop } | Sort-Object -Unique)
                if ($gateways.Count -gt 1) { throw 'Ambiguous gateway' }
                $gateway = 'none'
                if ($gateways.Count -eq 1) {
                    if (-not (Compatible $gateways[0] $data.address $data.prefix)) { throw 'Incompatible gateway preservation' }
                    $gateway = $gateways[0]
                }
                $nic = Resolve-Selected
                $maskBytes = [byte[]]@(0,0,0,0)
                for ($i=0; $i -lt 4; $i++) { $maskBytes[$i] = 256 - [Math]::Pow(2,8-[Math]::Max(0,[Math]::Min(8,$data.prefix-8*$i))) }
                $mask = ([Net.IPAddress]::new($maskBytes)).ToString()
                $stage = 'static_primary'
                $mutated = $true
                Native ([IO.Path]::Combine($system,'netsh.exe')) @('interface','ipv4','set','address',('name='+$nic.ifIndex),'source=static',('address='+$data.address),('mask='+$mask),('gateway='+$gateway),'store=persistent')
                Step 'static_primary'
                $stage = 'restore_secondaries'
                foreach ($address in $before.addresses) {
                    if ($address.IPAddress -eq $data.address) { continue }
                    $nic = Resolve-Selected
                    $current = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex -and $_.IPAddress -eq $address.IPAddress })
                    if ($current.Count -eq 0) { New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $address.IPAddress -PrefixLength $address.PrefixLength -ErrorAction Stop | Out-Null }
                }
                Step 'restore_secondaries'
            }
            'dhcp' {
                $stage = 'remove_manual_addresses'
                foreach ($address in $before.addresses) {
                    if ([string]$address.PrefixOrigin -ne 'Manual') { continue }
                    $null = Resolve-Selected
                    $mutated = $true
                    Remove-NetIPAddress -InputObject $address -Confirm:$false -ErrorAction Stop
                }
                Step 'remove_manual_addresses'
                $stage = 'remove_default_routes'
                foreach ($route in $before.routes) {
                    $null = Resolve-Selected
                    $mutated = $true
                    Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
                }
                Step 'remove_default_routes'
                $stage = 'enable_dhcp'
                $nic = Resolve-Selected
                $mutated = $true
                Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
                Step 'enable_dhcp'
                $stage = 'reset_dns'
                $nic = Resolve-Selected
                Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses -ErrorAction Stop
                Step 'reset_dns'
                $stage = 'renew_lease'
                $nic = Resolve-Selected
                Native ([IO.Path]::Combine($system,'ipconfig.exe')) @('/renew',[string]$nic.Name)
                Step 'renew_lease'
            }
            'renew' {
                if (-not $before.dhcp) { throw 'Adapter is static' }
                foreach ($action in @('/release','/renew')) {
                    $stage = if ($action -eq '/release') { 'release_lease' } else { 'renew_lease' }
                    $nic = Resolve-Selected
                    $mutated = $true
                    Native ([IO.Path]::Combine($system,'ipconfig.exe')) @($action,[string]$nic.Name)
                    Step $action
                }
            }
            'restart' {
                $nic = Resolve-Selected
                $mutated = $true
                Restart-NetAdapter -InputObject $nic -Confirm:$false -ErrorAction Stop
                Step 'restart_adapter'
            }
        }
        $stage = 'postcondition'
        $after = Read-State
        $matching = @($after.addresses | Where-Object { $_.IPAddress -eq $data.address -and $_.PrefixLength -eq $data.prefix })
        if ($data.kind -in @('add_address','static_address') -and ($matching.Count -ne 1 -or $after.dhcp)) { throw 'Address postcondition failed' }
        if ($data.kind -eq 'remove_address' -and @($after.addresses | Where-Object { $_.IPAddress -eq $data.address }).Count -ne 0) { throw 'Removal postcondition failed' }
        if ($data.kind -in @('dhcp','renew') -and -not $after.dhcp) { throw 'DHCP postcondition failed' }
        if ($data.kind -eq 'dhcp' -and @($after.addresses | Where-Object { [string]$_.PrefixOrigin -eq 'Manual' }).Count -ne 0) { throw 'Manual address survived DHCP' }
        if ($data.kind -eq 'dhcp') {
            if (@($after.routes | Where-Object { [string]$_.Protocol -eq 'NetMgmt' }).Count -ne 0) { throw 'Static default route survived DHCP' }
            if (-not [string]::IsNullOrWhiteSpace($after.dnsManual)) { throw 'Static DNS survived reset' }
            Step 'verify_dns_reset'
        }
        if ($data.kind -eq 'static_address') {
            foreach ($address in $before.addresses) {
                if ($address.IPAddress -eq $data.address) { continue }
                if (@($after.addresses | Where-Object { $_.IPAddress -eq $address.IPAddress -and $_.PrefixLength -eq $address.PrefixLength }).Count -ne 1) { throw 'Secondary not preserved' }
            }
            if ((@($before.dns) -join ',') -cne (@($after.dns) -join ',')) { throw 'DNS not preserved' }
            $actualGateways = @($after.routes | ForEach-Object { $_.NextHop } | Sort-Object -Unique)
            if (($gateway -eq 'none' -and $actualGateways.Count -ne 0) -or ($gateway -ne 'none' -and ($actualGateways.Count -ne 1 -or $actualGateways[0] -ne $gateway))) { throw 'Gateway not preserved' }
        }
        Step 'postcondition'
        $resultData = @{dhcp=$after.dhcp;addresses=@($after.addresses | ForEach-Object { @{address=$_.IPAddress;prefix=[int]$_.PrefixLength} });
            gateways=@($after.routes | ForEach-Object { [string]$_.NextHop });dns=@($after.dns);dns_manual=$after.dnsManual}
    }
    [Console]::Out.WriteLine((@{version=1;ok=$true;stage=$stage;mutated=$mutated;steps=@($steps.ToArray());data=$resultData} | ConvertTo-Json -Depth 8 -Compress))
    exit 0
} catch {
    if ($null -ne $script:nativeExit) { $steps.Add(@{name=$stage;ok=$false;native_exit=[int]$script:nativeExit}) }
    # Only fixed step labels leave the process; never provider messages or input.
    [Console]::Out.WriteLine((@{version=1;ok=$false;stage=$stage;mutated=$mutated;steps=@($steps.ToArray());data=$null} | ConvertTo-Json -Depth 4 -Compress))
    exit 71
}
