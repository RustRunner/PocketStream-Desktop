# Installed-image startup reads only. Define after the trusted module imports so
# these functions shadow the provider writers. Never forward a mutation.
function Set-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,[string]$Enabled)
    process {
        if ($Enabled -ne 'False' -or [string]$InputObject.Enabled -ne 'False') { throw 'Read-only probe refuses a state change' }
        [Console]::Error.WriteLine(('intercepted_disabled_write='+$InputObject.Name))
    }
}
function New-NetFirewallRule { throw 'Read-only probe refuses creation' }
function Remove-NetFirewallRule { throw 'Read-only probe refuses removal' }
