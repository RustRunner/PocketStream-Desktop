const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
test('NSIS child can hash prerequisites despite incompatible inherited PowerShell module paths', {skip:process.platform!=='win32'}, async(t)=>{
  const {spawnSync}=require('node:child_process');
  const crypto=require('node:crypto');
  const os=require('node:os');
  const {nsisCompilerEnvironment}=await import('../scripts/check-installer.mjs');
  const moduleRoot=fs.mkdtempSync(path.join(os.tmpdir(),'pocketstream-nsis-modules-'));
  const utility=path.join(moduleRoot,'Microsoft.PowerShell.Utility');
  fs.mkdirSync(utility);
  const manifest=path.join(utility,'Microsoft.PowerShell.Utility.psd1');
  fs.writeFileSync(manifest,"@{ ModuleVersion='7.0.0.0'; PowerShellVersion='3.0'; CompatiblePSEditions=@('Core'); CmdletsToExport=@('Get-FileHash'); NestedModules='incompatible-utility.dll' }");
  t.after(()=>{fs.unlinkSync(manifest);fs.rmdirSync(utility);fs.rmdirSync(moduleRoot);});
  const inherited={...process.env,POCKETSTREAM_HASH_PROBE:__filename};
  const key=Object.keys(inherited).find(name=>name.toUpperCase()==='PSMODULEPATH') ?? 'PSModulePath';
  inherited[key]=`${moduleRoot};${inherited[key] ?? ''}`;
  const args=['-NoProfile','-NonInteractive','-Command',"$ErrorActionPreference='Stop'; (Get-FileHash -LiteralPath $env:POCKETSTREAM_HASH_PROBE -Algorithm SHA256).Hash"];
  const options={encoding:'utf8',windowsHide:true,timeout:30000};
  const broken=spawnSync('powershell.exe',args,{...options,env:inherited});
  assert.notEqual(broken.status,0,'negative control must reject the incompatible module search path');
  assert.match(broken.stderr,/Get-FileHash/);
  const isolated=spawnSync('powershell.exe',args,{...options,env:nsisCompilerEnvironment(inherited)});
  assert.equal(isolated.status,0,isolated.stderr || isolated.error?.message);
  assert.equal(isolated.stdout.trim().toLowerCase(),crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'));
});

test('installer source and independently seeded destructive path drift',async()=>{
  const {checkInstaller,checkRepository}=await import('../scripts/check-installer.mjs');
  const read=p=>fs.readFileSync(path.join(__dirname,'..',p),'utf8');
  const source=read('src-tauri/installer/installer.nsi'),hooks=read('src-tauri/installer/transaction.nsh');
  assert.deepEqual(checkRepository(),[]);
  for(const seed of [source+'\nCall PageLeaveReinstall\n',source+'\nnsis_tauri_utils::KillProcess "pocketstream-desktop.exe"\n',source.replace('  !insertmacro PS_ACQUIRE_TRANSACTION',''),source.replace('PS_MAINTENANCE "uninstall"','PS_MISSING'),source.replace('StrCpy $PSLaunchRequested 1','nsis_tauri_utils::RunAsUser')]) {
    assert.notDeepEqual(checkInstaller(seed,hooks),[]);
  }
});
test('installer rejects ignored payload failures and stale install registration',async()=>{
  const {checkInstaller}=await import('../scripts/check-installer.mjs');
  const read=p=>fs.readFileSync(path.join(__dirname,'..',p),'utf8');
  const source=read('src-tauri/installer/installer.nsi'),hooks=read('src-tauri/installer/transaction.nsh');
  assert.deepEqual(checkInstaller(source,hooks),[]);
  for(const [from,to] of [
    ['PS_FAIL "Resource replacement failed','PS_MISSING "Resource replacement failed'],
    ['PS_FAIL "Uninstaller creation failed','PS_MISSING "Uninstaller creation failed'],
    ['PS_FAIL "Payload deletion failed','PS_MISSING "Payload deletion failed'],
    ['PS_FAIL "Executable deletion failed','PS_MISSING "Executable deletion failed'],
    ['DeleteRegValue SHCTX "${MANUPRODUCTKEY}" ""','; retained stale installation location'],
  ]) {
    assert.ok(source.includes(from),`fixture seed missing: ${from}`);
    assert.notDeepEqual(checkInstaller(source.replace(from,to),hooks),[],from);
  }
});
test('fresh protected destinations resolve without requiring an existing directory',async()=>{
  const {checkInstaller}=await import('../scripts/check-installer.mjs');
  const read=p=>fs.readFileSync(path.join(__dirname,'..',p),'utf8');
  const source=read('src-tauri/installer/installer.nsi'),hooks=read('src-tauri/installer/transaction.nsh');
  assert.deepEqual(checkInstaller(source,hooks),[]);
  const seeds=[
    hooks.replace(/System::Call 'kernel32::GetFullPathNameW[^\r\n]+/, 'GetFullPathName $INSTDIR $INSTDIR'),
    hooks.replace('${OrIf} $0 >= ${NSIS_MAX_STRLEN}', '; lost truncation check'),
    hooks.replace("${If} $1 != '$PROGRAMFILES64\\'", '${If} 0 = 1'),
    hooks.replace('GetFileAttributesW', 'MissingReparseCheck'),
  ];
  for(const seed of seeds){
    assert.notEqual(seed,hooks,'regression seed did not change the hook');
    assert.notDeepEqual(checkInstaller(source,seed),[]);
  }
});

test('installer retains ownership when a worker cannot release the GUI thread mutex',async()=>{
  const {checkInstaller}=await import('../scripts/check-installer.mjs');
  const read=p=>fs.readFileSync(path.join(__dirname,'..',p),'utf8');
  const source=read('src-tauri/installer/installer.nsi'),hooks=read('src-tauri/installer/transaction.nsh');
  assert.deepEqual(checkInstaller(source,hooks),[]);
  const oldRelease=`!macro PS_RELEASE_TRANSACTION
  System::Call 'kernel32::ReleaseMutex(p $PSInstallGate)'
  System::Call 'kernel32::CloseHandle(p $PSInstallGate)'
  StrCpy $PSInstallGate 0
!macroend`;
  const unsafe=hooks.replace(/!macro PS_RELEASE_TRANSACTION\s*\n[\s\S]*?!macroend/,oldRelease);
  assert.notDeepEqual(checkInstaller(source,unsafe),[]);
  assert.notDeepEqual(checkInstaller(source,hooks.replace('i.r4 ?e','i.r4')),[]);
});
