# Build-time staging only; never invoked by the installed application.
function Assert-TsdemuxManifest {
    param([hashtable]$RootManifest, [string]$ProjectRoot)
    $demux = $RootManifest.PatchedTsdemux
    foreach ($name in @('ReleaseTag','ArchiveFile','ArchiveSha256','DllSha256','StockDllSha256','BaseCommit','SourceCommit','PatchPath','PatchSha256')) {
        if ([string]::IsNullOrWhiteSpace([string]$demux[$name])) { throw "Missing tsdemux pin: $name" }
    }
    if ($demux.ReleaseTag -notmatch '^deps-tsdemux-[a-zA-Z0-9._-]+$' -or
        $demux.ArchiveFile -cne 'pocketstream-tsdemux-1.26.11-bootstrap-1.zip') { throw 'Invalid tsdemux dependency identity' }
    foreach ($name in @('ArchiveSha256','DllSha256','StockDllSha256','PatchSha256')) {
        if ($demux[$name] -notmatch '^[a-f0-9]{64}$') { throw "Invalid tsdemux SHA-256: $name" }
    }
    foreach ($name in @('BaseCommit','SourceCommit')) {
        if ($demux[$name] -notmatch '^[a-f0-9]{40}$') { throw "Invalid tsdemux source commit: $name" }
    }
    if ($RootManifest.BundleClosure['lib/gstreamer-1.0/gstmpegtsdemux.dll'] -cne $demux.DllSha256) { throw 'Demux pin disagrees with complete runtime closure' }
    $prefix = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $patch = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $demux.PatchPath))
    if (!$patch.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $patch).Hash.ToLowerInvariant() -cne $demux.PatchSha256) { throw 'Demux patch provenance mismatch' }
}

function Get-VerifiedTsdemuxArchive {
    param([hashtable]$Demux, [string]$CacheDir, [switch]$AllowDraft)
    if (!$CacheDir) { $CacheDir = $env:POCKETSTREAM_DEPENDENCY_CACHE }
    if (!$CacheDir) { $CacheDir = Join-Path ([IO.Path]::GetTempPath()) 'pocketstream-dependencies' }
    $cache = [IO.Path]::GetFullPath($CacheDir)
    New-Item -ItemType Directory -Path $cache -Force | Out-Null
    $archive = Join-Path $cache $Demux.ArchiveFile
    if (Test-Path -LiteralPath $archive) {
        if ((Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() -cne $Demux.ArchiveSha256) { throw 'Tsdemux cache drift; existing file retained' }
        return $archive
    }
    $download = "$archive.$PID.$([Guid]::NewGuid().ToString('N')).download"
    try {
        if ($AllowDraft) {
            & gh release download $Demux.ReleaseTag --repo RustRunner/PocketStream-Desktop --pattern $Demux.ArchiveFile --output $download
        } else {
            $url = 'https://github.com/RustRunner/PocketStream-Desktop/releases/download/' + $Demux.ReleaseTag + '/' + $Demux.ArchiveFile
            & curl.exe -fsSL --retry 3 --retry-delay 5 -o $download $url
        }
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $download)) { throw 'Pinned tsdemux download failed' }
        if ((Get-FileHash -LiteralPath $download).Hash.ToLowerInvariant() -cne $Demux.ArchiveSha256) { throw 'Tsdemux archive SHA-256 mismatch' }
        if (Test-Path -LiteralPath $archive) { throw 'Tsdemux cache appeared during download' }
        Move-Item -LiteralPath $download -Destination $archive
    } finally {
        if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force }
    }
    return $archive
}

function Install-StagedTsdemux {
    param([string]$ArchivePath, [hashtable]$Demux, [string]$DestinationPlugin)
    if ((Get-FileHash -LiteralPath $ArchivePath).Hash.ToLowerInvariant() -cne $Demux.ArchiveSha256) { throw 'Tsdemux archive SHA-256 mismatch' }
    if ((Get-FileHash -LiteralPath $DestinationPlugin).Hash.ToLowerInvariant() -cne $Demux.StockDllSha256) { throw 'Expected original vendor demux before staging replacement' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        if (($names -join '|') -cne 'gstmpegtsdemux.dll|provenance.json|SHA256SUMS.txt') { throw 'Tsdemux ZIP must contain only its three exact root entries' }
        foreach ($entry in $zip.Entries) { if ($entry.Length -gt 1048576) { throw 'Unexpected tsdemux archive entry size' } }
        $reader = New-Object IO.StreamReader ($zip.GetEntry('provenance.json').Open())
        try { $provenance = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        if ($provenance.schema -ne 1 -or $provenance.base_commit -cne $Demux.BaseCommit -or
            $provenance.source_commit -cne $Demux.SourceCommit -or $provenance.patch_sha256 -cne $Demux.PatchSha256 -or
            $provenance.dll_sha256 -cne $Demux.DllSha256) { throw 'Tsdemux provenance does not match declared source and binary' }
        $reader = New-Object IO.StreamReader ($zip.GetEntry('SHA256SUMS.txt').Open())
        try { $sums = $reader.ReadToEnd() -split '\r?\n' } finally { $reader.Dispose() }
        if ($sums -cnotcontains ($Demux.DllSha256 + '  gstmpegtsdemux.dll')) { throw 'Tsdemux inner checksum missing' }
        $stream = $zip.GetEntry('gstmpegtsdemux.dll').Open(); $memory = New-Object IO.MemoryStream
        try { $stream.CopyTo($memory); $bytes = $memory.ToArray() } finally { $stream.Dispose(); $memory.Dispose() }
        $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLowerInvariant()
        if ($hash -cne $Demux.DllSha256) { throw 'Tsdemux inner DLL SHA-256 mismatch' }
        $oldLength = (Get-Item -LiteralPath $DestinationPlugin).Length
        [IO.File]::WriteAllBytes($DestinationPlugin,$bytes)
        if ((Get-FileHash -LiteralPath $DestinationPlugin).Hash.ToLowerInvariant() -cne $Demux.DllSha256) { throw 'Staged tsdemux readback mismatch' }
        return $bytes.Length - $oldLength
    } finally { $zip.Dispose() }
}
