param(
 [Parameter(Mandatory)][string]$Source,
 [Parameter(Mandatory)][string]$Sdk,
 [Parameter(Mandatory)][string]$Evidence,
 [ValidateSet('stock','patched')][string]$Condition,
 [string]$BuildId
)
$ErrorActionPreference='Stop'
$Source=[IO.Path]::GetFullPath($Source)
$Sdk=[IO.Path]::GetFullPath($Sdk)
$Evidence=[IO.Path]::GetFullPath($Evidence)
$build=Join-Path $Evidence ('build/'+$(if($BuildId){$BuildId}else{$Condition}))
if(Test-Path -LiteralPath $build){throw "Preserve previous build: $build"}
New-Item -ItemType Directory -Path $build|Out-Null
$vs='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
Import-Module (Join-Path $vs 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
$compiler=(Get-Command cl.exe).Source
$headers=Join-Path $Sdk 'include'
$config=@'
#define VERSION "1.26.11-peer-bootstrap-offline.1"
#define PACKAGE "gst-plugins-bad"
#define GST_PACKAGE_NAME "GStreamer Bad Plug-ins (isolated offline peer)"
#define GST_PACKAGE_ORIGIN "https://gstreamer.freedesktop.org/"
#define GETTEXT_PACKAGE "gst-plugins-bad-1.0"
'@
[IO.File]::WriteAllText((Join-Path $build 'config.h'),$config)
$include=@($headers,"$headers/gstreamer-1.0","$headers/glib-2.0","$Sdk/lib/glib-2.0/include",$build)
$flags=@('/nologo','/std:c11','/MD','/O2','/Zi','/W3','/utf-8','/D_CRT_SECURE_NO_WARNINGS','/DGST_USE_UNSTABLE_API','/DHAVE_CONFIG_H')
$flags+=@($include|ForEach-Object{'/I'+$_})
$folder=Join-Path $Source 'subprojects/gst-plugins-bad/gst/mpegtsdemux'
$sources=@('mpegtspacketizer.c','mpegtsbase.c','mpegtsparse.c','tsdemux.c','gsttsdemux.c','pesparse.c')|ForEach-Object{Join-Path $folder $_}
$libs=@('gstreamer-1.0.lib','gstbase-1.0.lib','gstcodecparsers-1.0.lib','gstmpegts-1.0.lib','gsttag-1.0.lib','gstpbutils-1.0.lib','gstaudio-1.0.lib','gstvideo-1.0.lib','gobject-2.0.lib','glib-2.0.lib','gmodule-2.0.lib')
$arguments=$flags+@('/LD')+$sources+@('/link',('/LIBPATH:'+(Join-Path $Sdk 'lib')),('/OUT:'+(Join-Path $build 'gstmpegtsdemux.dll')))+$libs
$arguments|ConvertTo-Json|Set-Content (Join-Path $build 'compiler-arguments.json') -Encoding UTF8
Push-Location $build
try{
 & $compiler @arguments > build.stdout.log 2> build.stderr.log
 if($LASTEXITCODE -ne 0){throw "Plugin compile/link failed: $LASTEXITCODE"}
 $test=Join-Path $Source 'subprojects/gst-plugins-bad/tests/check/elements/mpegtsdemux.c'
 $testArgs=$flags+@($test,('/Fe:'+(Join-Path $build 'mpegtsdemux-check.exe')),'/link',('/LIBPATH:'+(Join-Path $Sdk 'lib')),'gstcheck-1.0.lib')+$libs
 $testArgs|ConvertTo-Json|Set-Content test-compiler-arguments.json -Encoding UTF8
 & $compiler @testArgs > test-build.stdout.log 2> test-build.stderr.log
 if($LASTEXITCODE -ne 0){throw "Check compile/link failed: $LASTEXITCODE"}
}finally{Pop-Location}
$runtime=Join-Path $Evidence ('runtime/'+$Condition)
Copy-Item -LiteralPath (Join-Path $build 'gstmpegtsdemux.dll') -Destination (Join-Path $runtime 'lib/gstreamer-1.0/gstmpegtsdemux.dll')
$receipt=[ordered]@{
 condition=$Condition;source=$Source;source_revision=(& git -c "safe.directory=$Source" -C $Source rev-parse HEAD);source_diff=(& git -c "safe.directory=$Source" -C $Source diff --stat);sdk=$Sdk;
 compiler=$compiler;compiler_sha256=(Get-FileHash -LiteralPath $compiler).Hash.ToLowerInvariant();compiler_version=(Get-Item -LiteralPath $compiler).VersionInfo.FileVersion;
 configuration=$config;arguments=$arguments;
 source_files=@($sources|ForEach-Object{[ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()}});
 outputs=@(Get-ChildItem -LiteralPath $build -File|Where-Object Extension -in @('.dll','.exe','.lib','.pdb')|ForEach-Object{[ordered]@{path=$_.FullName;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}})
}
$receipt|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $build 'identity.json') -Encoding UTF8
[pscustomobject]@{condition=$Condition;plugin_sha256=(Get-FileHash -LiteralPath (Join-Path $build 'gstmpegtsdemux.dll')).Hash.ToLowerInvariant();compiler_version=$receipt.compiler_version}|ConvertTo-Json
