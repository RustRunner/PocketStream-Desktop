# Shared metadata checks for published releases and explicitly allowed drafts.
function Assert-SourceReleaseMetadata {
    param(
        [Parameter(Mandatory = $true)][hashtable]$SourceManifest,
        [Parameter(Mandatory = $true)]$Release,
        [switch]$AllowDraft
    )
    if ($Release.tag_name -cne $SourceManifest.Tag -or -not $Release.prerelease) {
        throw 'Source release tag or prerelease status does not match the manifest.'
    }
    if ($Release.draft -and -not $AllowDraft) {
        throw 'Source release is still a draft; public-release verification requires published sources.'
    }
    if ($Release.draft) {
        $draftPrefix = 'https://github.com/RustRunner/PocketStream-Desktop/releases/tag/untagged-'
        if ($Release.html_url -cne $SourceManifest.Url -and
            -not ([string]$Release.html_url).StartsWith($draftPrefix, [StringComparison]::Ordinal)) {
            throw 'Unexpected source draft URL.'
        }
    } elseif ($Release.html_url -cne $SourceManifest.Url) {
        throw 'Published source release URL does not match the manifest.'
    }

    $expected = @{}
    foreach ($asset in $SourceManifest.Assets.Values) {
        $expected[[string]$asset.File] = [string]$asset.Sha256
    }
    $expected[[string]$SourceManifest.IndexFile] = [string]$SourceManifest.IndexSha256
    if (@($Release.assets).Count -ne $expected.Count) {
        throw 'Source release asset count does not match the complete source inventory.'
    }
    foreach ($name in $expected.Keys) {
        $matches = @($Release.assets | Where-Object { $_.name -ceq $name })
        if ($matches.Count -ne 1) {
            throw "Source release must contain exactly one '$name' asset."
        }
        if (([string]$matches[0].digest).ToLowerInvariant() -cne "sha256:$($expected[$name])") {
            throw "Source release asset '$name' SHA256 does not match the manifest."
        }
    }
}

function Get-G3CompletionState {
    param([bool]$StagedOnly, [bool]$SourceVerified, [bool]$SourcePublished)
    $draftReady = (-not $StagedOnly) -and $SourceVerified
    $complete = $draftReady -and $SourcePublished
    [pscustomobject]@{
        complete = $complete
        draft_ready = $draftReady
        result = if ($complete) { 'pass' } elseif ($draftReady) { 'draft-pass' } else { 'staged-pass' }
        incomplete_reason = if ($complete) { $null } elseif ($draftReady) {
            'Installed draft verified; publish the verified dependency-source prerelease before publishing the application.'
        } else {
            'Staged-only evidence cannot satisfy G3; published source and a real NSIS-installed layout remain mandatory.'
        }
    }
}
