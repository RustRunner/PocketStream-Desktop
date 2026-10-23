#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'source-release-policy.ps1')

$sourceFixture = @{
    Tag = 'deps-source-test'
    Url = 'https://github.com/RustRunner/PocketStream-Desktop/releases/tag/deps-source-test'
    IndexFile = 'SHA256SUMS.txt'
    IndexSha256 = ('b' * 64)
    Assets = @{ source = @{ File = 'source.tar.gz'; Sha256 = ('a' * 64) } }
}
function New-ReleaseFixture {
    param([bool]$Draft)
    [pscustomobject]@{
        tag_name = $sourceFixture.Tag
        prerelease = $true
        draft = $Draft
        html_url = if ($Draft) {
            'https://github.com/RustRunner/PocketStream-Desktop/releases/tag/untagged-test'
        } else { $sourceFixture.Url }
        assets = @(
            [pscustomobject]@{ name = 'source.tar.gz'; digest = ('sha256:' + ('a' * 64)) },
            [pscustomobject]@{ name = 'SHA256SUMS.txt'; digest = ('sha256:' + ('b' * 64)) }
        )
    }
}
function Assert-Rejected {
    param([scriptblock]$Action, [string]$Pattern)
    $rejected = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Expected rejection matching '$Pattern'" }
}

Assert-SourceReleaseMetadata -SourceManifest $sourceFixture -Release (New-ReleaseFixture $false)
$sourceDraft = New-ReleaseFixture $true
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $sourceDraft } 'still a draft'
Assert-SourceReleaseMetadata $sourceFixture $sourceDraft -AllowDraft
$taggedDraft = New-ReleaseFixture $true
$taggedDraft.html_url = $sourceFixture.Url
Assert-SourceReleaseMetadata $sourceFixture $taggedDraft -AllowDraft

$badHash = New-ReleaseFixture $true
$badHash.assets[0].digest = 'sha256:' + ('c' * 64)
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $badHash -AllowDraft } 'SHA256'
$badIndex = New-ReleaseFixture $true
$badIndex.assets[1].digest = 'sha256:' + ('c' * 64)
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $badIndex -AllowDraft } 'SHA256'
$missingAsset = New-ReleaseFixture $true
$missingAsset.assets = @($missingAsset.assets[0])
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $missingAsset -AllowDraft } 'asset count'
$duplicate = New-ReleaseFixture $true
$duplicate.assets[1] = $duplicate.assets[0]
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $duplicate -AllowDraft } 'exactly one'
$wrongTag = New-ReleaseFixture $true
$wrongTag.tag_name = 'unexpected'
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $wrongTag -AllowDraft } 'tag or prerelease'
$wrongUrl = New-ReleaseFixture $true
$wrongUrl.html_url = 'https://example.com/untagged-test'
Assert-Rejected { Assert-SourceReleaseMetadata $sourceFixture $wrongUrl -AllowDraft } 'draft URL'

$draftState = Get-G3CompletionState -StagedOnly $false -SourceVerified $true -SourcePublished $false
if ($draftState.complete -or -not $draftState.draft_ready -or $draftState.result -ne 'draft-pass') {
    throw 'An installed verified draft must be ready for review without claiming public-release completion.'
}
$publicState = Get-G3CompletionState -StagedOnly $false -SourceVerified $true -SourcePublished $true
if (-not $publicState.complete -or $publicState.result -ne 'pass') { throw 'Published complete release must pass.' }
foreach ($published in @($true, $false)) {
    $stagedState = Get-G3CompletionState -StagedOnly $true -SourceVerified $true -SourcePublished $published
    if ($stagedState.complete -or $stagedState.draft_ready) { throw 'Staged-only evidence cannot claim installed readiness.' }
}
$unverifiedState = Get-G3CompletionState -StagedOnly $false -SourceVerified $false -SourcePublished $true
if ($unverifiedState.complete -or $unverifiedState.draft_ready) { throw 'Unverified sources cannot pass either release gate.' }
Write-Host 'Source release policy passed: draft opt-in, complete hash coverage, and distinct draft/public readiness.'
