# Version 1, A-S2 read-only fixture. Data arrives only as bounded UTF-8 JSON.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSModuleAutoLoadingPreference = 'None'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$stage = 'trusted_modules'
$nativeExit = $null
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Expected Windows PowerShell 5.1' }
    $system = [Environment]::SystemDirectory
    $moduleRoot = [IO.Path]::Combine($system, 'WindowsPowerShell\v1.0\Modules')
    $modules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets')
    $modulePaths = @()
    foreach ($module in $modules) {
        $path = [IO.Path]::Combine($moduleRoot, $module, ($module + '.psd1'))
        Import-Module -Name $path -ErrorAction Stop
        $modulePaths += $path
    }
    $stage = 'payload'
    $raw = [Console]::In.ReadToEnd()
    if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 16384) { throw 'Oversized input' }
    $data = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    if ($data.version -ne 1 -or $data.kind -notin @('echo','cmdlet_failure','native_failure','child_tree','flood_output') -or $data.value -isnot [string] -or $data.value.Length -gt 8192) { throw 'Invalid schema' }
    foreach ($property in $data.PSObject.Properties.Name) {
        if ($property -notin @('version','kind','value')) { throw 'Unknown field' }
    }
    switch ($data.kind) {
        'echo' {
            $stage = 'echo'
            $source = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([Environment]::GetCommandLineArgs()[-1]))
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
            if ($errors.Count) { throw 'Fixed source failed AST parsing' }
            $result = [ordered]@{version=1;ok=$true;stage='echo';value=$data.value;ast_text=$ast.Extent.Text;ps_version=$PSVersionTable.PSVersion.ToString();cwd=[Environment]::CurrentDirectory;autoload=$PSModuleAutoLoadingPreference;module_paths=$modulePaths}
            [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress -Depth 4))
        }
        'cmdlet_failure' {
            $stage = 'required_cmdlet'
            $null = Get-Item -LiteralPath ([IO.Path]::Combine($system,'PocketStream-qualification-required-absent-5f06a5b4')) -ErrorAction Stop
            $stage = 'unexpected_cmdlet_success'
            throw 'Required command unexpectedly succeeded'
        }
        'native_failure' {
            $stage = 'required_native'
            $ipconfig = [IO.Path]::Combine($system,'ipconfig.exe')
            # PS 5.1 wraps redirected native stderr in ErrorRecords. Required
            # native status comes from LASTEXITCODE after the process finishes.
            try {
                $ErrorActionPreference = 'Continue'
                $null = & $ipconfig /PocketStreamQualificationInvalidOption 2>&1
                $nativeExit = $LASTEXITCODE
            } finally { $ErrorActionPreference = 'Stop' }
            if ($nativeExit -isnot [int]) { $stage = 'required_native_unavailable'; throw 'Native exit status unavailable' }
            if ($nativeExit -ne 0) { throw 'Required native step failed' }
            $stage = 'unexpected_native_success'
            throw 'Required native step unexpectedly succeeded'
        }
        'child_tree' {
            $stage = 'child_tree'
            $childSource = '[System.Threading.Thread]::Sleep(30000)'
            $childEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childSource))
            $powershell = [IO.Path]::Combine($system,'WindowsPowerShell\v1.0\powershell.exe')
            $child = Start-Process -FilePath $powershell -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$childEncoded) -WindowStyle Hidden -PassThru -ErrorAction Stop
            [Console]::Out.WriteLine('{"version":1,"ok":true,"stage":"child_tree_ready"}')
            [Console]::Out.Flush()
            [Threading.Thread]::Sleep(30000)
        }
        'flood_output' {
            $stage = 'flood_output'
            [Console]::Out.Write(('o' * 40000))
            [Console]::Error.Write(('e' * 40000))
            [Console]::Out.WriteLine('{"version":1,"ok":true,"stage":"flood_output"}')
        }
    }
    exit 0
} catch {
    # Stage is a fixed code label; never echo payloads/provider messages.
    if ($stage -eq 'required_native' -and $null -ne $nativeExit) {
        [Console]::Out.WriteLine(('{"version":1,"ok":false,"stage":"required_native","native_exit":' + [int]$nativeExit + '}'))
    } else {
        [Console]::Out.WriteLine(('{"version":1,"ok":false,"stage":"' + $stage + '"}'))
    }
    exit 71
}
