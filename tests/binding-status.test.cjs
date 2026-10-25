const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const ts=require('typescript');
async function load(file){
  const source=fs.readFileSync(path.join(__dirname,'..',file),'utf8');
  const output=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ES2022,target:ts.ScriptTarget.ES2022}}).outputText;
  return import(`data:text/javascript;base64,${Buffer.from(output).toString('base64')}`);
}
test('binding and firewall text keep local scope separate from policy and reachability',async()=>{
  const {formatBindScope,formatFirewallOutcome}=await load('src/lib/restream-format.ts');
  assert.equal(formatBindScope({kind:'all_addresses',family:'ipv4',topology_revision:7,addresses:[{id:'a',alias:'Hidden virtual',address:'169.254.1.2'},{id:'b',alias:'Loopback',address:'127.0.0.1'}]}),'Bound on all IPv4 addresses: 169.254.1.2 (Hidden virtual), 127.0.0.1 (Loopback)');
  assert.match(formatBindScope({kind:'unknown',reason:'Observation failed'}),/unknown: Observation failed/);
  assert.match(formatBindScope({kind:'interface',id:'a',alias:'Wi-Fi',address:'192.0.2.2',family:'ipv4',topology_revision:8}),/^Bound on Wi-Fi:/);
  assert.match(formatFirewallOutcome({state:'applied',rule_name:'owned',action:'updated',verified_shape:true,observed_block_rules:['Query User deny']}),/preserved Windows block rules: Query User deny/);
  assert.match(formatFirewallOutcome({state:'failed',stage:'readback',reason:'Unavailable',uncertain:true}),/reconciliation required/);
  assert.match(formatFirewallOutcome({state:'unavailable',reason:'Administrator access required'}),/unavailable/);
  assert.equal(formatFirewallOutcome({state:'inactive'}),'Windows rule inactive');
});
test('bind selections retain GUIDs, missing choices and independent protocol state',async()=>{
  const {buildRestreamBindOptions,selectedRestreamBindInterface,buildRestreamBindUpdate}=await load('src/lib/restream-settings.ts');
  const interfaces=[{id:'guid-a',alias:'Renamed Wi-Fi',kind:'wifi',address:'192.0.2.2'}];
  assert.deepEqual(buildRestreamBindOptions(interfaces,'guid-a').map(o=>o.value),['','guid-a']);
  assert.equal(buildRestreamBindOptions([], 'missing')[1].unavailable,true);
  const config={restream_protocol:'rtsp',rtsp_server:{enabled:true,port:8554,token:'0123456789abcdef',bind_interface:'Old Wi-Fi',bind_interface_id:'guid-a'},srt_server:{port:8890,latency_ms:125,stream_id:'',bind_interface:'Missing VPN',bind_interface_id:null}};
  assert.equal(selectedRestreamBindInterface(config),'guid-a');
  assert.equal(selectedRestreamBindInterface(config,'srt'),'legacy:Missing VPN');
  const update=buildRestreamBindUpdate(config,'srt','Renamed Wi-Fi','guid-a');
  assert.equal(update.srt_server.bind_interface_id,'guid-a');
  assert.equal(update.rtsp_server.bind_interface_id,'guid-a');
  assert.equal(buildRestreamBindUpdate(config,'rtsp','').rtsp_server.bind_interface_id,null);
});
