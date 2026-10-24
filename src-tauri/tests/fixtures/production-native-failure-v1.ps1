# Read-only qualification of the exact production Native function.
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module -Name ([IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$data=ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()) -ErrorAction Stop
if ($data.version -ne 1 -or $data.kind -ne 'production_native_failure') { exit 72 }
$script:nativeExit=$null
# @PRODUCTION_NATIVE_HELPER@
try {
    Native ([IO.Path]::Combine([Environment]::SystemDirectory,'ipconfig.exe')) @('/PocketStreamQualificationInvalidOption')
} catch {
    [Console]::Out.WriteLine((@{version=1;ok=$false;stage='required_native';native_exit=$script:nativeExit;ps_version=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json -Compress))
    exit 71
}
[Console]::Out.WriteLine('{"version":1,"ok":true,"stage":"unexpected_success"}')
exit 0
