const {test}=require('node:test');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const path=require('node:path');
test('fixed firewall policy against pure provider fakes',{skip:process.platform!=='win32'},()=>{
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'firewall-policy.fixture.ps1')],{encoding:'utf8',timeout:30000});
  assert.equal(result.status,0,result.stdout+result.stderr);
  const evidence=JSON.parse(result.stdout.trim());
  assert.equal(evidence.native_policy_mutations,0);
  assert.equal(evidence.passed.length,8);
});
