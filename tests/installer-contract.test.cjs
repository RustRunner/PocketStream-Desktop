const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
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
