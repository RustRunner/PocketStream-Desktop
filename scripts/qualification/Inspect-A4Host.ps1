<# Read-only host inspection and private recovery copies. No application launch,
   network/firewall writes, installation or reboot. Never print profile contents. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RunRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$RunRoot=[IO.Path]::GetFullPath($RunRoot)
if(Test-Path -LiteralPath $RunRoot){throw 'Use a new run directory; preserve earlier evidence.'}
New-Item -ItemType Directory -Path $RunRoot|Out-Null
$report=[ordered]@{started_utc=[DateTime]::UtcNow.ToString('o');host_mutations=$false;candidate_launched=$false;status='inspection'}
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $report.account_sid=$identity.User.Value;$report.session=[Diagnostics.Process]::GetCurrentProcess().SessionId
 $report.elevated=(New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 & "$env:WINDIR\System32\whoami.exe" /groups | Set-Content -LiteralPath (Join-Path $RunRoot 'token-groups.txt') -Encoding UTF8
 $report.windows=Get-CimInstance Win32_OperatingSystem|Select-Object Caption,Version,BuildNumber,LastBootUpTime
 $report.powershell=$PSVersionTable.PSVersion.ToString()
 $report.product_processes=@(Get-CimInstance Win32_Process -Filter "Name='pocketstream-desktop.exe'"|Select-Object ProcessId,ExecutablePath)
 $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
 $wired=@($adapters|Where-Object {[string]$_.InterfaceGuid -eq '{812AD22F-3345-4817-B6D7-708D769E69AC}' -and $_.MacAddress -eq '40-C2-BA-CF-D5-75'})
 if($wired.Count -ne 1){throw 'Physical Ethernet identity is missing/ambiguous; no changes permitted.'}
 $report.ethernet=$wired|Select-Object Name,ifIndex,InterfaceGuid,MacAddress,Status,HardwareInterface
 $adapters|Export-Clixml -LiteralPath (Join-Path $RunRoot 'adapters.xml')
 foreach($pair in @(@('addresses','Get-NetIPAddress'),@('interfaces','Get-NetIPInterface'),@('dns','Get-DnsClientServerAddress'),@('routes','Get-NetRoute'))){@(& $pair[1] -ErrorAction Stop)|Export-Clixml -LiteralPath (Join-Path $RunRoot ($pair[0]+'.xml'))}
 $report.ethernet_addresses=@(Get-NetIPAddress -InterfaceIndex $wired[0].ifIndex -AddressFamily IPv4|Select-Object IPAddress,PrefixLength,PrefixOrigin,SkipAsSource)
 $report.ethernet_dhcp=[string](Get-NetIPInterface -InterfaceIndex $wired[0].ifIndex -AddressFamily IPv4).Dhcp
 $report.ethernet_dns=@(Get-DnsClientServerAddress -InterfaceIndex $wired[0].ifIndex -AddressFamily IPv4|ForEach-Object {$_.ServerAddresses})
 $report.default_routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4|Select-Object InterfaceIndex,InterfaceAlias,NextHop,RouteMetric)
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop);$rules|Export-Clixml -LiteralPath (Join-Path $RunRoot 'rules.xml')
 foreach($name in @('Application','Port','Address','Interface','InterfaceType','Service','Security')){$cmd='Get-NetFirewall'+$name+'Filter';@(& $cmd -All -PolicyStore PersistentStore -ErrorAction Stop)|Export-Clixml -LiteralPath (Join-Path $RunRoot ($name+'.xml'))}
 $report.product_policy=@($rules|Where-Object {$_.DisplayName -in @('PocketStream RTSP Server','PocketStream SRT Server','PocketStream RTSP') -or $_.Group -eq 'PocketStream.Desktop.Managed.v2'}|Select-Object Name,DisplayName,Group,Enabled,Direction,Action)
 $copies=Join-Path $RunRoot 'private-profile-backup';New-Item -ItemType Directory -Path $copies|Out-Null
 $roots=@((Join-Path $env:APPDATA 'PocketStream'),(Join-Path $env:LOCALAPPDATA 'PocketStream\logs'))
 $report.profile_files=@(foreach($root in $roots){if(Test-Path -LiteralPath $root){foreach($file in Get-ChildItem -LiteralPath $root -File -Recurse){$dest=Join-Path $copies ([Guid]::NewGuid().ToString()+'.backup');Copy-Item -LiteralPath $file.FullName -Destination $dest;[ordered]@{path=$file.FullName;backup=$dest;sha256=(Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant();bytes=$file.Length}}}})
 $config=Join-Path $env:APPDATA 'PocketStream\config.toml'
 if(Test-Path -LiteralPath $config){$text=[IO.File]::ReadAllText($config);$report.profile_preconditions=@{pending_empty=[regex]::IsMatch($text,'(?m)^pending_addresses\s*=\s*\[\]\s*$');static_auto=[regex]::IsMatch($text,'(?m)^network_mode\s*=\s*"static_auto"\s*$')}}
 $report.status='read-only inspection complete; no host mutation authorized by this record'
}catch{$report.status='inspection incomplete';$report.error=$_.Exception.Message;throw}
finally{$report.finished_utc=[DateTime]::UtcNow.ToString('o');$report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $RunRoot 'inspection.json') -Encoding UTF8}
