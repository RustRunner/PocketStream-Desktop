const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ts = require('typescript');
const source = fs.readFileSync(path.join(__dirname, '../src/lib/network.ts'), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const flush = async () => { for(let i=0;i<40;i++) await Promise.resolve(); };
const deferred = () => { let resolve,reject; const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
const IP='192.0.2.20', SUBNET='192.0.2.0/24', MAC='40:cd:3a:00:00:01';
function fixture() {
  const events=new Map(), elements=new Map(), calls={selection:0,bindings:0,mode:0,dhcp:0,writes:0}, feedback=[], removals=[];
  let now=0, throwRender=false;
  const iface={name:'Ethernet', display_name:'Ethernet', mac:MAC, is_up:true, is_ethernet:true, is_vpn:false,is_virtual:false,
    ips:[{address:'192.0.2.10',prefix:24,subnet:SUBNET},{address:IP,prefix:24,subnet:SUBNET}]};
  const selection={selected_mac:MAC,interface_index:7,adapter:iface,candidates:[iface],selection_required:false};
  const meta={adapter_mac:MAC,address:IP,prefix:24,desired:'present',applied:true,last_error:null};
  const adoptionMeta=new Map([[SUBNET,meta]]),adoptedSubnets=new Map([[SUBNET,IP]]);
  const state={config:{network_mode:'static_auto',selected_adapter_mac:MAC},activeInterface:iface,activeAdoptionId:null};
  function element(id='',dataset={}) {
    const handlers=new Map();let html='';
    const el={id,dataset,style:{},disabled:false,checked:false,value:'',open:false,buttons:[],textContent:'',className:'',
      addEventListener(type,fn){const list=handlers.get(type)||[];list.push(fn);handlers.set(type,list);},
      async fire(type,event={}){for(const fn of handlers.get(type)||[]) await fn({target:el,...event});},
      closest(selector){return selector==='.input-field'?null:el;},
      querySelector(){return null;},
      querySelectorAll(){return el.buttons;},
      close(){el.open=false;void el.fire('close');},
    };
    Object.defineProperty(el,'innerHTML',{get:()=>html,set(value){
      if(id==='#subnet-list' && throwRender){throwRender=false;throw Error('injected render failure');}
      html=value;el.buttons=[];
      if(id==='#static-iface')el.value=value.match(/<option value="([^"]*)"/)?.[1]??'';
      for(const match of value.matchAll(/<button[^>]*data-remove-(adopted|binding|ip)="([^"]*)"[^>]*>/g)) {
        const key=match[1]==='adopted'?'removeAdopted':match[1]==='binding'?'removeBinding':'removeIp';el.buttons.push(element('',{[key]:match[2]}));
      }
    }});
    return el;
  }
  const $=id=>{if(!elements.has(id))elements.set(id,element(id));return elements.get(id);};
  $('#static-iface').value='Ethernet';$('#add-sec-ip').value=IP;$('#add-sec-mask').value='255.255.255.0';
  const pending=[];
  const api={
    onEvent:async(name,fn)=>events.set(name,fn),
    getAdapterSelection:async()=>{calls.selection++;return selection;},
    getAdoptionState:async()=>{calls.bindings++;return {adopted_subnets:{[SUBNET]:IP},meta:{[SUBNET]:meta}};},
    getNetworkMode:async()=>{calls.mode++;return 'static_auto';},getDhcpState:async()=>{calls.dhcp++;return false;},
    addSecondaryIp:()=>{calls.writes++;const d=deferred();pending.push(d);return d.promise;},
    removeAdoptedSubnet:()=>{calls.writes++;const d=deferred();pending.push(d);return d.promise;},
    removeSecondaryIp:(name,ip)=>{calls.writes++;removals.push({name,ip});const d=deferred();pending.push(d);return d.promise;},
    selectAdapter:async()=>selection,
  };
  const deps={
    './tauri-api.ts':api,
    './state.ts':{$,$$:()=>[],state,adoptionMeta,adoptedSubnets,showToast:(msg,error)=>feedback.push({msg,error}),log(){},
      escapeHtml:s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;')},
    './devices.js':{renderArpDeviceList(){},resetDiscoveryStatus(){},hideDiscoveryStatus(){}},
    './streaming.js':{handleHardDisconnect(){},handleReconnect:async()=>{},showModalWithVideo:async d=>{d.open=true;}},
    './store.ts':{},'./errors.ts':{formatError:String},'./device-list.ts':{},
  };
  const exports={};
  vm.runInNewContext(compiled,{exports,require:name=>{assert(name in deps,name);return deps[name];},document:{
    querySelectorAll(){return [...elements.values()].filter(e=>['#static-iface','#btn-add-sec-ip','#ip-config-apply','#ip-mode-dhcp','#ip-mode-static-auto','#ip-mode-static-manual','#reset-adapter-confirm'].includes(e.id)).concat($('#subnet-list').buttons,$('#secondary-ip-list').buttons);}
  },window:{confirm:()=>true},performance:{now:()=>++now},setTimeout:()=>1,clearTimeout(){}});
  exports.setupIpConfigDialog();exports.setupInterfaceWatcher();events.get('adapter-selection-changed')(selection);
  exports.renderSubnetList();
  const reply=(extra={})=>({operation:1,outcome:'success',reason:null,view:{selection:{...selection,adapter:{...iface,ips:iface.ips.filter(i=>i.address!==IP)},candidates:[{...iface,ips:iface.ips.filter(i=>i.address!==IP)}]},identity:{guid:'guid-a',index:7,mac:MAC,alias:'Ethernet'},dhcp:false,observation_error:null,subnet:SUBNET,binding:{...meta,desired:'removed',applied:false},address:IP,prefix:24,mode:'static_auto'},...extra});
  return {exports,api,events,$,calls,pending,feedback,removals,state,selection,iface,adoptionMeta,adoptedSubnets,reply,
    failRender(){throwRender=true;},
    async hostRemove(){const btn=$('#subnet-list').buttons[0];assert(btn);return $('#subnet-list').fire('click',{target:btn});},
    setSelection(next){events.get('adapter-selection-changed')(next);},
  };
}

test('Configure stays usable during a fresh read and Add reaches the mutation handler',async()=>{
  const f=fixture(),read=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return read.promise;};
  const opening=f.$('#btn-ip-config').fire('click');await flush();
  assert.equal(f.$('#ip-config-dialog').open,true);
  assert.equal(f.$('#static-iface').value,'Ethernet');
  const add=f.$('#btn-add-sec-ip').fire('click');assert.equal(f.calls.writes,1);
  const reply=f.reply();reply.view.selection=f.selection;reply.view.subnet=null;reply.view.binding=null;
  f.pending[0].resolve(reply);await add;read.resolve(f.selection);await opening;await flush();
  assert.equal(f.calls.selection,1);assert.equal(f.$('#btn-add-sec-ip').disabled,false);
});

test('Unchanged events emitted by the selection query do not invalidate Configure or feed another fetch',async()=>{
  const f=fixture();
  f.api.getAdapterSelection=async()=>{
    f.calls.selection++;
    if(f.calls.selection<=3){f.setSelection({...f.selection});f.events.get('interface-status-changed')({...f.iface});}
    return f.selection;
  };
  await f.$('#btn-ip-config').fire('click');await flush();
  assert.equal(f.$('#static-iface').value,'Ethernet');
  assert.equal(f.calls.selection,1);assert.equal(f.calls.bindings,1);
  assert(f.$('#secondary-ip-list').innerHTML.includes(IP));
});

test('A genuine address event still retires an older interface read',async()=>{
  const f=fixture(),old=deferred(),ip='198.51.100.10';
  const current={...f.selection,adapter:{...f.iface,ips:[{address:ip,prefix:24,subnet:'198.51.100.0/24'}]}};
  current.candidates=[current.adapter];
  f.api.getAdapterSelection=()=>{f.calls.selection++;return f.calls.selection===1?old.promise:Promise.resolve(current);};
  const read=f.exports.refreshInterfaces();
  f.setSelection(current);f.events.get('interface-status-changed')(current.adapter);
  old.resolve(f.selection);await read;await flush();
  assert(f.state.activeInterface.ips.some(i=>i.address===ip));
  assert.equal(f.calls.selection,2,'one trailing read for the genuine change');
});

test('An unchanged self-emitted event after a verified mutation does not schedule a second fetch',async()=>{
  const f=fixture();const add=f.$('#btn-add-sec-ip').fire('click');
  const result=f.reply();result.view.selection=f.selection;result.view.subnet=null;result.view.binding=null;
  f.pending[0].resolve(result);await add;
  f.api.getAdapterSelection=async()=>{
    f.calls.selection++;
    if(f.calls.selection<=3){f.setSelection({...f.selection});f.events.get('interface-status-changed')({...f.iface});}
    return f.selection;
  };
  await f.exports.refreshInterfaces();await flush();
  assert.equal(f.calls.selection,1);assert.equal(f.calls.bindings,1);
});

test('Explicit removal of an observed host IP uses its exact address in either enumeration order',async()=>{
  for(const reverse of [false,true]){
    const f=fixture(),ip='198.51.100.10';
    f.iface.ips.push({address:ip,prefix:24,subnet:'198.51.100.0/24'});
    if(reverse)f.iface.ips.reverse();
    await f.$('#btn-ip-config').fire('click');
    const btn=f.$('#secondary-ip-list').buttons.find(b=>b.dataset.removeIp===ip);assert(btn);
    const one=btn.fire('click'),two=btn.fire('click');assert.equal(f.calls.writes,1);
    assert.equal(btn.disabled,true);assert.deepEqual(f.removals,[{name:'Ethernet',ip}]);
    const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.address=ip;
    reply.view.selection={...f.selection,adapter:{...f.iface,ips:f.iface.ips.filter(i=>i.address!==ip)},
      candidates:[{...f.iface,ips:f.iface.ips.filter(i=>i.address!==ip)}]};
    const before={...f.calls};f.pending[0].resolve(reply);await one;await two;await flush();
    assert(!f.$('#subnet-list').innerHTML.includes(ip));assert(!f.$('#secondary-ip-list').innerHTML.includes(ip));
    assert.equal(f.adoptionMeta.get(SUBNET).desired,'present');
    assert.equal(f.calls.selection,before.selection);assert.equal(f.$('#btn-add-sec-ip').disabled,false);
  }
});

test('The two unmanaged host IPs have Remove buttons and plain address labels',async()=>{
  for(const reverse of [false,true]){
    const f=fixture();f.adoptionMeta.clear();f.adoptedSubnets.clear();
    f.api.getAdoptionState=async()=>{f.calls.bindings++;return {adopted_subnets:{},meta:{}};};
    f.iface.ips=[{address:'10.3.1.10',prefix:24,subnet:'10.3.1.0/24'},
      {address:'192.168.1.100',prefix:24,subnet:'192.168.1.0/24'}];
    if(reverse)f.iface.ips.reverse();
    await f.$('#btn-ip-config').fire('click');
    const list=f.$('#secondary-ip-list');
    assert.equal(list.buttons.length,2);
    for(const ip of f.iface.ips){
      assert(list.buttons.some(btn=>btn.dataset.removeIp===ip.address));
      assert(list.innerHTML.includes(`<span>${ip.address}/24</span>`));
    }
    assert(!/ownership|reconciliation|applied/.test(list.innerHTML));
  }
});

test('SP10 double Add click acknowledges synchronously, disables both panels and issues one IPC',async()=>{
  const f=fixture();
  const first=f.$('#btn-add-sec-ip').fire('click');const second=f.$('#btn-add-sec-ip').fire('click');
  assert.equal(f.calls.writes,1);assert.equal(f.$('#ip-config-spinner').style.display,'');
  assert.equal(f.$('#static-iface').disabled,true);assert.equal(f.$('#ip-config-apply').disabled,true);
  assert.equal(f.$('#subnet-list').buttons[0].disabled,true);assert.equal(f.$('#host-title').style.pointerEvents,'none');
  const added=f.reply();added.view.selection=f.selection;added.view.binding=null;
  f.pending[0].resolve(added);await first;await second;
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);assert.equal(f.$('#ip-config-spinner').style.display,'none');
  assert.equal(f.calls.selection,0);assert.equal(f.calls.bindings,0);assert.equal(f.calls.dhcp,0);
});

test('SP10/SP11 Host removal paints Host and open dialog from one reply with zero follow-up reads',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  const before={...f.calls};const pending=f.hostRemove();await flush();
  assert.equal(f.calls.writes,1);assert.equal(f.$('#btn-add-sec-ip').disabled,true);
  f.pending[0].resolve(f.reply());await pending;await flush();
  assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
  assert(!f.$('#subnet-list').innerHTML.includes(IP));assert(!f.$('#secondary-ip-list').innerHTML.includes(IP));
  assert.equal(f.adoptionMeta.get(SUBNET).desired,'removed');assert(!f.adoptedSubnets.has(SUBNET));
  for(const name of ['selection','bindings','mode','dhcp'])assert.equal(f.calls[name],before[name],name);
});

test('SP10 adapter A/B/A retires the old success even when the final MAC matches',async()=>{
  const f=fixture();const pending=f.hostRemove();await flush();
  f.setSelection({...f.selection,selected_mac:'40:cd:3a:00:00:02',interface_index:8});f.setSelection(f.selection);
  f.pending[0].resolve(f.reply());await pending;await flush();
  assert.equal(f.feedback.length,0,'no stale success');assert.equal(f.adoptionMeta.get(SUBNET).desired,'present');
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);
});

for(const kind of ['IPC','render'])test(`SP10 ${kind} failure always releases controls and shows actionable feedback`,async()=>{
  const f=fixture();const pending=f.hostRemove();await flush();
  if(kind==='IPC')f.pending[0].reject(Error('injected IPC failure'));
  else {f.failRender();f.pending[0].resolve(f.reply());}
  await pending;await flush();assert.equal(f.$('#btn-add-sec-ip').disabled,false);assert.equal(f.$('#ip-config-apply').disabled,false);
  assert.equal(f.$('#ip-config-spinner').style.display,'none');assert(f.feedback.at(-1).error);
});

test('SP10 close/reopen does not abandon a running removal or resurrect an older dialog fetch',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');const pending=f.hostRemove();await flush();
  await f.$('#ip-config-cancel').fire('click');assert.equal(f.$('#ip-config-dialog').open,false);
  await f.$('#btn-ip-config').fire('click');assert.equal(f.$('#ip-config-dialog').open,true);
  // Reopen queued one ordinary refresh, not another write. Make its actual read match Windows.
  const result=f.reply();f.api.getAdapterSelection=async()=>{f.calls.selection++;return result.view.selection;};
  f.api.getAdoptionState=async()=>{f.calls.bindings++;return {adopted_subnets:{},meta:{[SUBNET]:result.view.binding}};};
  f.pending[0].resolve(result);await pending;await flush();await flush();
  assert.equal(f.calls.writes,1);assert(!f.$('#secondary-ip-list').innerHTML.includes(IP));
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);
});

test('SP11 overlapping ordinary refresh calls share one flight and at most one trailing cycle',async()=>{
  const f=fixture(),first=deferred(),last=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return f.calls.selection===1?first.promise:last.promise;};
  const a=f.exports.refreshInterfaces(),b=f.exports.refreshHostBindings(),c=f.exports.refreshIpDialogIfOpen();
  f.$('#ip-config-dialog').open=true;
  const d=f.exports.refreshIpDialogIfOpen();
  assert.equal(f.calls.selection,1);first.resolve(f.selection);await a;await b;await c;await d;await flush();
  assert.equal(f.calls.selection,2);last.resolve(f.selection);await flush();assert.equal(f.calls.selection,2);
});

test('SP11 older fetch result and failure cannot overwrite a mutation reply or report operation failure',async()=>{
  for(const reject of [false,true]) {
    const f=fixture(),old=deferred();f.api.getAdapterSelection=()=>{f.calls.selection++;return old.promise;};
    const read=f.exports.refreshInterfaces(),pending=f.hostRemove();await flush();
    f.pending[0].resolve(f.reply());await pending;await flush();
    if(reject)old.reject(Error('old provider failure'));else old.resolve(f.selection);
    await read;await flush();assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
    assert.equal(f.adoptionMeta.get(SUBNET).desired,'removed');assert(!f.feedback.some(x=>x.error));
    assert.equal(f.calls.selection,1,'reply did not initiate another fetch');
  }
});

test('SP11 callback burst during a mutation defers one native refresh and cannot overwrite its reply',async()=>{
  const f=fixture();const pending=f.hostRemove();await flush();const result=f.reply();
  f.api.getAdapterSelection=async()=>{f.calls.selection++;return result.view.selection;};
  f.api.getAdoptionState=async()=>{f.calls.bindings++;return {adopted_subnets:{},meta:{[SUBNET]:result.view.binding}};};
  for(let i=0;i<20;i++){f.setSelection(f.selection);f.events.get('interface-status-changed')(f.iface);}
  assert.equal(f.calls.selection,0);f.pending[0].resolve(result);await pending;await flush();await flush();
  assert.equal(f.calls.selection,1);assert.equal(f.calls.bindings,1);assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
});

test('SP10 unknown observation retains last known addresses and pending row without false success',async()=>{
  const f=fixture();const pending=f.hostRemove();await flush();const result=f.reply({outcome:'pending',reason:'Verification failed'});
  result.view.observation_error='Native unavailable';result.view.selection={...f.selection,adapter:null,interface_index:null};result.view.binding.applied=true;result.view.binding.last_error='Verification failed';
  f.pending[0].resolve(result);await pending;await flush();assert(f.state.activeInterface.ips.some(i=>i.address===IP));
  assert.equal(f.adoptionMeta.get(SUBNET).applied,true);assert.equal(f.feedback.at(-1).error,true);
});

test('SP11 stale post-reply events trigger one current read and cannot repaint old IPs',async()=>{
  const f=fixture();const pending=f.hostRemove();await flush();f.pending[0].resolve(f.reply());await pending;await flush();
  const fresh=deferred();f.api.getAdapterSelection=()=>{f.calls.selection++;return fresh.promise;};
  f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{[SUBNET]:f.reply().view.binding}});
  for(let i=0;i<12;i++){f.setSelection(f.selection);f.events.get('interface-status-changed')(f.iface);}
  assert(!f.state.activeInterface.ips.some(i=>i.address===IP));await flush();assert.equal(f.calls.selection,1);
  fresh.resolve(f.reply().view.selection);await flush();assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
});

test('SP10 close/reopen retires old dialog-open continuations and pending fetches',async()=>{
  const f=fixture(),old=deferred(),current=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return f.calls.selection===1?old.promise:current.promise;};
  const first=f.$('#btn-ip-config').fire('click');await flush();await f.$('#ip-config-cancel').fire('click');
  const second=f.$('#btn-ip-config').fire('click');await flush();
  const pending=f.hostRemove();await flush();const result=f.reply();f.pending[0].resolve(result);await pending;await flush();
  f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{[SUBNET]:result.view.binding}});
  old.resolve(f.selection);await first;await second;await flush();
  assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
  current.resolve(result.view.selection);await flush();assert(!f.$('#secondary-ip-list').innerHTML.includes(IP));
  assert.equal(f.calls.writes,1);assert.equal(f.$('#btn-add-sec-ip').disabled,false);
});

test('SP10 IP Config removal double click shares the same busy guard and coherent reply',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');const before={...f.calls};
  const btn=f.$('#secondary-ip-list').buttons[0];assert(btn);
  const one=btn.fire('click'),two=btn.fire('click');assert.equal(f.calls.writes,1);
  f.pending[0].resolve(f.reply());await one;await two;assert(!f.$('#subnet-list').innerHTML.includes(IP));
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);assert.equal(f.calls.selection,before.selection);
});

test('SP07 APIPA Node visibility excludes every status without changing history or saved Host addresses',()=>{
  const f=fixture();
  f.adoptionMeta.set('169.254.0.0/16',{address:'169.254.20.99',prefix:16,adapter_mac:MAC,desired:'present',applied:false});
  f.exports.renderSubnetList();assert(f.$('#subnet-list').innerHTML.includes('169.254.20.99/16'));
  const module={};const code=fs.readFileSync(path.join(__dirname,'../src/lib/device-state.ts'),'utf8');
  vm.runInNewContext(ts.transpileModule(code,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,{exports:module,require:name=>{assert.equal(name,'./state.ts');return {state:f.state,adoptedSubnets:f.adoptedSubnets};}});
  const records=['live','verifying','offline','cached_only'].map(status=>({ip:'169.254.2.20',status}));records.push({ip:'192.0.2.30',status:'cached_only'});
  const history=JSON.stringify(records);assert.equal(module.visibleDevices(records).length,1);assert.equal(JSON.stringify(records),history);
  assert.equal(f.adoptionMeta.get('169.254.0.0/16').address,'169.254.20.99');
});
