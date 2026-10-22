const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ts = require('typescript');
const source = fs.readFileSync(path.join(__dirname, '../src/lib/network.ts'), 'utf8');
const compiled = ts.transpileModule(source + '\nexports.renderSelectionForTest = selection => { applySelection(selection); renderNetwork(); };', { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const flush = async () => { for(let i=0;i<40;i++) await Promise.resolve(); };
const deferred = () => { let resolve,reject; const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
const IP='192.0.2.20', SUBNET='192.0.2.0/24', MAC='40:cd:3a:00:00:01';
function fixture({initialSelection=true}={}) {
  const events=new Map(), elements=new Map(), calls={selection:0,bindings:0,mode:0,dhcp:0,writes:0,discoveryStops:0,discoveryStarts:0}, feedback=[], removals=[], transitions=[], additions=[];
  let now=0, throwRender=false;const timers=[];
  const iface={name:'Ethernet', display_name:'Ethernet', mac:MAC, is_up:true, is_ethernet:true, is_vpn:false,is_virtual:false,
    ips:[{address:'192.0.2.10',prefix:24,subnet:SUBNET},{address:IP,prefix:24,subnet:SUBNET}]};
  const selection={selected_mac:MAC,interface_index:7,adapter:iface,candidates:[iface],selection_required:false};
  const meta={adapter_mac:MAC,address:IP,prefix:24,desired:'present',applied:true,last_error:null};
  const adoptionMeta=new Map([[SUBNET,meta]]),adoptedSubnets=new Map([[SUBNET,IP]]);
  const state={config:{network_mode:'static_auto',selected_adapter_mac:MAC},activeInterface:initialSelection?iface:null,activeAdoptionId:null};
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
  const ui={confirm:()=>true};
  const api={
    onEvent:async(name,fn)=>events.set(name,fn),
    getAdapterSelection:async()=>{calls.selection++;return selection;},
    getAdoptionState:async()=>{calls.bindings++;return {adopted_subnets:{[SUBNET]:IP},meta:{[SUBNET]:meta}};},
    getNetworkMode:async()=>{calls.mode++;return 'static_auto';},getDhcpState:async()=>{calls.dhcp++;return false;},
    addSecondaryIp:(name,ip,mask)=>{calls.writes++;additions.push({name,ip,mask});const d=deferred();pending.push(d);return d.promise;},
    removeAdoptedSubnet:()=>{calls.writes++;const d=deferred();pending.push(d);return d.promise;},
    removeSecondaryIp:(name,ip,primary=false)=>{calls.writes++;removals.push(primary?{name,ip,primary}:{name,ip});const d=deferred();pending.push(d);return d.promise;},
    selectAdapter:async()=>selection,
    setNetworkMode:async request=>{transitions.push(request);return {mode:request.mode,warning:null};},
  };
  const deps={
    './tauri-api.ts':api,
    './state.ts':{$,$$:()=>[],state,adoptionMeta,adoptedSubnets,showToast:(msg,error)=>feedback.push({msg,error}),log(){},
      escapeHtml:s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;')},
    './devices.js':{renderArpDeviceList(){},resetDiscoveryStatus(){calls.discoveryStarts++;},hideDiscoveryStatus(){calls.discoveryStops++;}},
    './streaming.js':{handleHardDisconnect(){},handleReconnect:async()=>{},showModalWithVideo:async d=>{d.open=true;}},
    './store.ts':{},'./errors.ts':{formatError:String},'./device-list.ts':{},
  };
  const exports={};
  vm.runInNewContext(compiled,{exports,require:name=>{assert(name in deps,name);return deps[name];},document:{
    querySelectorAll(){return [...elements.values()].filter(e=>['#static-iface','#btn-add-sec-ip','#static-ip','#static-mask','#static-gateway','#primary-existing-ip','#btn-remove-primary-ip','#add-sec-ip','#add-sec-mask','#ip-mode-dhcp','#ip-mode-static-auto','#ip-mode-static-manual','#reset-adapter-confirm'].includes(e.id)).concat($('#subnet-list').buttons,$('#secondary-ip-list').buttons);}
  },window:ui,performance:{now:()=>++now},
    setTimeout(fn,ms){timers.push({fn,ms});return timers.length;},clearTimeout(id){timers[id-1]=null;}});
  exports.setupIpConfigDialog();exports.setupInterfaceWatcher();if(initialSelection)events.get('adapter-selection-changed')(selection);
  exports.renderSubnetList();
  const reply=(extra={})=>({operation:1,outcome:'success',reason:null,view:{selection:{...selection,adapter:{...iface,ips:iface.ips.filter(i=>i.address!==IP)},candidates:[{...iface,ips:iface.ips.filter(i=>i.address!==IP)}]},identity:{guid:'guid-a',index:7,mac:MAC,alias:'Ethernet'},dhcp:false,observation_error:null,subnet:SUBNET,binding:{...meta,desired:'removed',applied:false},address:IP,prefix:24,mode:'static_auto'},...extra});
  return {exports,api,events,$,calls,pending,feedback,removals,transitions,additions,ui,state,selection,iface,adoptionMeta,adoptedSubnets,reply,
    failRender(){throwRender=true;},
    runTimers(ms){timers.forEach((timer,index)=>{if(timer?.ms===ms){timers[index]=null;timer.fn();}});},
    async modalRemove(){
      if(!$('#ip-config-dialog').open){$('#ip-config-dialog').open=true;exports.renderSelectionForTest(selection);}
      const btn=$('#secondary-ip-list').buttons.find(b=>b.dataset.removeBinding===SUBNET);assert(btn);return btn.fire('click');
    },
    setSelection(next){events.get('adapter-selection-changed')(next);},
  };
}

test('IP Configuration has one Close action and no Cancel or Apply action',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
  const dialog=html.match(/<dialog id="ip-config-dialog"[\s\S]*?<\/dialog>/)[0];
  assert.match(dialog,/id="ip-config-close">Close<\/button>/);
  assert(!/ip-config-(cancel|apply)/.test(dialog));
});

test('Host card has no delete control while Configure retains exact-address Remove controls',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  assert.equal(f.$('#subnet-list').buttons.length,0);
  assert(!/data-remove|btn-remove|<button/.test(f.$('#subnet-list').innerHTML));
  assert(f.$('#secondary-ip-list').buttons.some(b=>b.dataset.removeBinding===SUBNET));
});

test('Primary edit carries the exact previous tuple and reopens with the saved primary, never as a secondary',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');
  const next={...f.selection,adapter:{...f.iface,ips:[f.iface.ips[1],{address:'198.51.100.10',prefix:24,subnet:'198.51.100.0/24'}]}};
  next.candidates=[next.adapter];
  f.api.setNetworkMode=async request=>{f.transitions.push(request);f.api.getAdapterSelection=async()=>next;return {mode:'static_auto',warning:null,primary_address:'198.51.100.10/24'};};
  await f.$('#ip-config-close').fire('click');
  assert.equal(f.transitions[0].previous_address,'192.0.2.10/24');
  assert.equal(f.calls.writes,0,'primary edit never calls Add Secondary');
  await f.$('#btn-ip-config').fire('click');
  assert.equal(f.$('#static-ip').value,'198.51.100.10');
  assert(!f.$('#secondary-ip-list').innerHTML.includes('198.51.100.10'));
  assert(f.$('#secondary-ip-list').innerHTML.includes(IP));
});

test('Explicit primary survives address reordering and additional unmanaged secondaries',async()=>{
  const f=fixture();f.state.config.primary_addresses={[MAC]:'192.0.2.10/24'};
  f.iface.ips.push({address:'203.0.113.10',prefix:24,subnet:'203.0.113.0/24'});f.iface.ips.reverse();
  await f.$('#btn-ip-config').fire('click');
  assert.equal(f.$('#static-ip').value,'192.0.2.10');
  assert(!f.$('#secondary-ip-list').innerHTML.includes('192.0.2.10'));
  assert(f.$('#secondary-ip-list').innerHTML.includes('203.0.113.10'));
});

test('Legacy ambiguous primary can be chosen explicitly without erasing the new address draft',async()=>{
  const f=fixture();f.adoptionMeta.clear();f.adoptedSubnets.clear();f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{}});
  await f.$('#btn-ip-config').fire('click');assert.equal(f.$('#primary-existing-field').style.display,'');
  f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');
  f.$('#primary-existing-ip').value='192.0.2.10/24';await f.$('#primary-existing-ip').fire('change');
  assert.equal(f.$('#static-ip').value,'198.51.100.10');
  await f.$('#ip-config-close').fire('click');
  assert.equal(f.transitions[0].previous_address,'192.0.2.10/24');
});

test('Primary Remove uses the same verified reply, clears its role and does not promote a secondary',async()=>{
  const f=fixture();f.state.config.primary_addresses={[MAC]:'192.0.2.10/24'};
  await f.$('#btn-ip-config').fire('click');const before={...f.calls};
  const remove=f.$('#btn-remove-primary-ip').fire('click');assert.equal(f.calls.writes,1);
  assert.equal(f.$('#btn-remove-primary-ip').disabled,true);assert.equal(f.$('#primary-existing-ip').disabled,true);
  assert.deepEqual(f.removals,[{name:'Ethernet',ip:'192.0.2.10',primary:true}]);
  const reply=f.reply();reply.view.address='192.0.2.10';reply.view.subnet=null;reply.view.binding=null;
  reply.view.primary_address='';reply.view.selection={...f.selection,adapter:{...f.iface,ips:[f.iface.ips[1]]},candidates:[{...f.iface,ips:[f.iface.ips[1]]}]};
  f.pending[0].resolve(reply);await remove;
  assert.equal(f.$('#static-ip').value,'');assert.equal(f.$('#btn-remove-primary-ip').style.display,'none');
  assert(f.$('#secondary-ip-list').innerHTML.includes(IP));
  for(const key of ['selection','bindings','mode','dhcp'])assert.equal(f.calls[key],before[key]);
  await f.$('#ip-config-close').fire('click');assert.equal(f.transitions.length,0);
});

test('Fresh adoption shows the green auto badge; restored, pending and ended attachments stay plain',async()=>{
  const f=fixture();await f.exports.refreshInterfaces();
  assert(!f.$('#subnet-list').innerHTML.includes('badge-auto'),'restored binding is plain');
  f.exports.sessionAdoptedSubnets.add(SUBNET);f.exports.renderSubnetList();
  assert(f.$('#subnet-list').innerHTML.includes('<span class="badge-auto">auto</span>'));
  assert.match(f.$('#subnet-list').innerHTML,/<span class="auto-ip-group"><span class="badge-auto">auto<\/span><span class="status-value">192\.0\.2\.20\/24<\/span>/);
  const meta=f.adoptionMeta.get(SUBNET);meta.applied=false;f.exports.renderSubnetList();
  assert(!f.$('#subnet-list').innerHTML.includes('badge-auto'),'pending is not applied');
  meta.applied=true;f.state.activeInterface={...f.iface,is_up:false};
  f.exports.sessionAdoptedSubnets.clear();f.exports.renderSubnetList();
  assert(!f.$('#subnet-list').innerHTML.includes('badge-auto'),'attachment badge expires');
  assert(f.$('#subnet-list').innerHTML.includes(IP),'saved address remains visible');
});

test('Completed removed history stays hidden before and after Ethernet link-up without hiding real 172 addresses',async()=>{
  const f=fixture(),subnet='172.26.95.0/24',address='172.26.95.99';
  f.adoptionMeta.set(subnet,{adapter_mac:MAC,address,prefix:24,desired:'removed',applied:false,last_error:null});
  f.api.getAdoptionState=async()=>({adopted_subnets:{[SUBNET]:IP},meta:Object.fromEntries(f.adoptionMeta)});
  for(const up of [false,true]){
    const adapter={...f.iface,is_up:up};
    f.api.getAdapterSelection=async()=>({...f.selection,adapter,candidates:[adapter]});
    await f.exports.refreshInterfaces();await f.$('#btn-ip-config').fire('click');
    assert(!f.$('#subnet-list').innerHTML.includes(address));
    assert(!f.$('#secondary-ip-list').innerHTML.includes(address));
    assert(f.$('#subnet-list').innerHTML.includes(f.iface.ips[0].address));
    assert(f.$('#subnet-list').innerHTML.includes(IP),'legitimate saved adoption is retained');
    assert(f.adoptionMeta.has(subnet),'history is retained');
  }
  f.iface.ips.push({address,prefix:24,subnet});
  f.exports.renderSelectionForTest(f.selection);
  assert(f.$('#subnet-list').innerHTML.includes(address),'an address actually assigned to Ethernet is visible');
  assert(f.$('#secondary-ip-list').innerHTML.includes(address));
  assert.equal(f.calls.writes,0);
});

test('Pending or failed removed bindings remain visible and removable in Configure',async()=>{
  for(const [applied,last_error] of [[true,null],[false,'Removal awaiting Windows confirmation']]){
    const f=fixture();Object.assign(f.adoptionMeta.get(SUBNET),{desired:'removed',applied,last_error});
    f.iface.ips=f.iface.ips.filter(ip=>ip.address!==IP);
    f.state.activeInterface={...f.iface,is_up:false};
    f.$('#ip-config-dialog').open=true;f.exports.renderSelectionForTest({...f.selection,adapter:f.state.activeInterface});
    assert(f.$('#subnet-list').innerHTML.includes(IP));
    assert(f.$('#secondary-ip-list').innerHTML.includes(IP));
    assert(f.$('#secondary-ip-list').buttons.some(btn=>btn.dataset.removeBinding===SUBNET));
    assert.equal(f.calls.writes,0);
  }
});

test('Closing an unchanged ambiguous or disconnected adapter does not write network settings',async()=>{
  for(const missing of [false,true]){
    const f=fixture();f.adoptionMeta.clear();f.adoptedSubnets.clear();
    f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{}});
    f.api.getAdapterSelection=async()=>missing?{...f.selection,interface_index:null,adapter:null,candidates:[]}:
      {...f.selection,adapter:{...f.iface,is_up:false}};
    await f.$('#btn-ip-config').fire('click');
    assert.equal(f.$('#static-ip').value,'');
    await f.$('#ip-config-close').fire('click');
    assert.equal(f.$('#ip-config-dialog').open,false);
    assert.equal(f.transitions.length,0);assert.equal(f.calls.writes,0);assert.equal(f.feedback.length,0);
  }
});

for(const field of ['mode','primary'])test(`Reverting ${field} edits permits closing an ambiguous adapter without a write`,async()=>{
  const f=fixture();f.adoptionMeta.clear();f.adoptedSubnets.clear();
  f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{}});
  await f.$('#btn-ip-config').fire('click');assert.equal(f.$('#static-ip').value,'');
  if(field==='mode'){
    f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-dhcp').checked=true;await f.$('#ip-mode-dhcp').fire('change');
    f.$('#ip-mode-dhcp').checked=false;f.$('#ip-mode-static-auto').checked=true;await f.$('#ip-mode-static-auto').fire('change');
  }else{
    f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');
    f.$('#static-ip').value='';await f.$('#static-ip').fire('input');
  }
  await f.$('#ip-config-close').fire('click');
  assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(f.transitions.length,0);assert.equal(f.feedback.length,0);
});

test('Close saves primary fields and mode once, then an unsubmitted secondary, before closing',async()=>{
  const f=fixture(),mode=deferred();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');
  f.$('#static-mask').value='255.255.255.0';f.$('#static-gateway').value='198.51.100.1';
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-static-manual').checked=true;
  await f.$('#ip-mode-static-manual').fire('change');f.$('#add-sec-ip').value='203.0.113.10';
  f.api.setNetworkMode=request=>{f.transitions.push(request);return mode.promise;};
  const close=f.$('#ip-config-close').fire('click');
  await f.$('#ip-config-close').fire('click');
  let prevented=false;await f.$('#ip-config-dialog').fire('cancel',{preventDefault(){prevented=true;}});
  assert(prevented);assert.equal(f.transitions.length,1);assert.equal(f.calls.writes,0);
  assert.equal(f.$('#ip-config-dialog').open,true);assert.equal(f.$('#static-ip').disabled,true);
  assert.equal(f.$('#ip-config-close').disabled,true);
  assert.deepEqual(JSON.parse(JSON.stringify(f.transitions[0])),{name:'Ethernet',mode:'static_manual',ip:'198.51.100.10',subnet_mask:'255.255.255.0',gateway:'198.51.100.1',previous_address:'192.0.2.10/24',confirmed:false});
  mode.resolve({mode:'static_manual',warning:null});await flush();
  assert.equal(f.calls.writes,1);assert.equal(f.$('#ip-config-dialog').open,true);
  assert.deepEqual(f.additions,[{name:'Ethernet',ip:'203.0.113.10',mask:'255.255.255.0'}]);
  const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.selection=f.selection;
  const before={...f.calls};f.pending[0].resolve(reply);await close;
  assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(f.$('#add-sec-ip').value,'');
  assert.equal(f.$('#static-ip').disabled,false);assert.equal(f.$('#ip-config-close').disabled,false);
  assert.equal(f.calls.selection,before.selection,'secondary reply adds no follow-up fetch');
});

test('Escape saves edits and an invalid or failed save leaves the dialog open with the draft intact',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='';await f.$('#static-ip').fire('input');
  let prevented=0;
  await f.$('#ip-config-dialog').fire('cancel',{preventDefault(){prevented++;}});await flush();
  assert.equal(prevented,1);assert.equal(f.transitions.length,0);assert.equal(f.$('#ip-config-dialog').open,true);
  assert.match(f.feedback.at(-1).msg,/address and mask/);
  f.$('#static-ip').value='198.51.100.10';f.api.setNetworkMode=async()=>{throw Error('native state unknown');};
  await f.$('#ip-config-dialog').fire('cancel',{preventDefault(){prevented++;}});await flush();
  assert.equal(prevented,2);assert.equal(f.$('#ip-config-dialog').open,true);
  assert.equal(f.$('#static-ip').value,'198.51.100.10');assert.equal(f.$('#ip-config-close').disabled,false);
  assert.equal(f.$('#static-ip').disabled,false);assert.match(f.feedback.at(-1).msg,/native state unknown/);
  f.api.setNetworkMode=async request=>{f.transitions.push(request);return {mode:request.mode,warning:null};};
  await f.$('#ip-config-dialog').fire('cancel',{preventDefault(){prevented++;}});await flush();
  assert.equal(f.transitions.length,1);assert.equal(f.$('#ip-config-dialog').open,false);
});

test('Closing with only a secondary address reuses its mutation reply without changing primary or fetching',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');const before={...f.calls};
  f.$('#add-sec-ip').value='203.0.113.10';
  const close=f.$('#ip-config-close').fire('click');assert.equal(f.calls.writes,1);
  assert.equal(f.transitions.length,0);
  const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.selection=f.selection;
  f.pending[0].resolve(reply);await close;await flush();
  assert.equal(f.$('#ip-config-dialog').open,false);
  for(const name of ['selection','bindings','mode','dhcp'])assert.equal(f.calls[name],before[name],name);
});

test('A failed or pending secondary save retains the entry and keeps Close available for retry',async()=>{
  for(const kind of ['error','pending']){
    const f=fixture();await f.$('#btn-ip-config').fire('click');f.$('#add-sec-ip').value='203.0.113.10';
    const close=f.$('#ip-config-close').fire('click');
    if(kind==='error')f.pending[0].reject(Error('write failed'));
    else {const reply=f.reply({outcome:'pending',reason:'adapter unavailable'});reply.view.observation_error='unknown';f.pending[0].resolve(reply);}
    await close;assert.equal(f.$('#ip-config-dialog').open,true);assert.equal(f.$('#add-sec-ip').value,'203.0.113.10');
    assert.equal(f.$('#ip-config-close').disabled,false);assert(f.feedback.at(-1).error);
  }
});

test('Adding with plus clears a verified entry so Close cannot add it twice',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');f.$('#add-sec-ip').value='203.0.113.10';
  const add=f.$('#btn-add-sec-ip').fire('click');
  const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.selection=f.selection;
  f.pending[0].resolve(reply);await add;await f.$('#ip-config-close').fire('click');
  assert.equal(f.calls.writes,1);assert.equal(f.transitions.length,0);assert.equal(f.$('#ip-config-dialog').open,false);
});

test('Draft primary, gateway and mode survive native refreshes and a secondary mutation reply',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='198.51.100.10';f.$('#static-gateway').value='198.51.100.1';await f.$('#static-gateway').fire('input');
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-static-manual').checked=true;await f.$('#ip-mode-static-manual').fire('change');
  await f.exports.refreshInterfaces();
  f.$('#add-sec-ip').value='203.0.113.10';const add=f.$('#btn-add-sec-ip').fire('click');
  const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.selection=f.selection;
  f.pending[0].resolve(reply);await add;
  assert.equal(f.$('#static-ip').value,'198.51.100.10');assert.equal(f.$('#static-gateway').value,'198.51.100.1');
  assert.equal(f.$('#ip-mode-static-manual').checked,true);assert.equal(f.$('#ip-mode-static-auto').checked,false);
});

test('A delayed DHCP read cannot overwrite a mode selected while Configure is opening',async()=>{
  const f=fixture(),dhcp=deferred();f.api.getDhcpState=()=>dhcp.promise;
  const opening=f.$('#btn-ip-config').fire('click');await flush();
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-static-manual').checked=true;await f.$('#ip-mode-static-manual').fire('change');
  dhcp.resolve(true);await opening;
  assert.equal(f.$('#ip-mode-static-manual').checked,true);assert.equal(f.$('#ip-mode-dhcp').checked,false);
});

test('Close preserves the existing DHCP warning and saves only after confirmation',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-dhcp').checked=true;await f.$('#ip-mode-dhcp').fire('change');
  f.api.setNetworkMode=async request=>{f.transitions.push(request);return {mode:request.confirmed?'dhcp':'static_auto',warning:request.confirmed?null:'DHCP may interrupt cameras'};};
  f.ui.confirm=()=>false;await f.$('#ip-config-close').fire('click');
  assert.equal(f.transitions.length,1);assert.equal(f.$('#ip-config-dialog').open,true);assert.equal(f.state.config.network_mode,'static_auto');
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-dhcp').checked=true;await f.$('#ip-mode-dhcp').fire('change');
  f.ui.confirm=()=>true;await f.$('#ip-config-close').fire('click');
  assert.deepEqual(f.transitions.map(r=>r.confirmed),[false,false,true]);
  assert.equal(f.transitions[2].ip,null);assert.equal(f.transitions[2].gateway,null);
  assert.equal(f.state.config.network_mode,'dhcp');assert.equal(f.$('#ip-config-dialog').open,false);
});

for(const initial of ['static_auto','static_manual'])for(const exit of ['Close','Escape'])
test(`Cancelling DHCP from ${initial} restores the active mode and allows ${exit} without another warning`,async()=>{
  const f=fixture();f.state.config.network_mode=initial;f.api.getNetworkMode=async()=>initial;
  f.exports.syncHostModeFromConfig();await f.$('#btn-ip-config').fire('click');
  f.$(`#ip-mode-${initial.replace('_','-')}`).checked=false;f.$('#ip-mode-dhcp').checked=true;
  await f.$('#ip-mode-dhcp').fire('change');let warnings=0;
  f.api.setNetworkMode=async request=>{f.transitions.push(request);assert.equal(request.confirmed,false);return {mode:initial,warning:'DHCP may interrupt cameras'};};
  f.ui.confirm=()=>{warnings++;return false;};const before={...f.calls};
  await f.$('#ip-config-close').fire('click');
  assert.equal(f.$('#ip-mode-dhcp').checked,false);
  assert.equal(f.$(`#ip-mode-${initial.replace('_','-')}`).checked,true);
  assert.equal(f.$('#ip-static-section').style.display,'');
  assert.equal(f.state.config.network_mode,initial);assert.equal(f.$('#ip-config-dialog').open,true);
  for(const id of ['#ip-config-close','#static-iface','#static-ip','#ip-mode-static-auto','#ip-mode-static-manual','#ip-mode-dhcp'])assert.equal(f.$(id).disabled,false,id);
  if(exit==='Close')await f.$('#ip-config-close').fire('click');
  else {let prevented=false;await f.$('#ip-config-dialog').fire('cancel',{preventDefault(){prevented=true;}});await flush();assert(prevented);}
  assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(warnings,1);assert.equal(f.transitions.length,1);
  for(const name of ['selection','bindings','mode','dhcp','writes','discoveryStops','discoveryStarts'])assert.equal(f.calls[name],before[name],name);
  assert.equal(f.feedback.length,0);
});

test('Confirmed mode round trips stop Manual discovery, restart it on exit and paint the reply before a slow refresh',async()=>{
  const f=fixture(),applied=[];let saved='static_auto';
  f.api.getNetworkMode=async()=>saved;
  f.api.getDhcpState=async()=>saved==='dhcp';
  f.api.setNetworkMode=async request=>{f.transitions.push(request);saved=request.mode;return {mode:saved,warning:null};};
  const modes=['static_manual','dhcp','static_auto','dhcp','static_manual','static_auto'];
  for(const next of modes){
    await f.$('#btn-ip-config').fire('click');
    for(const mode of ['dhcp','static_auto','static_manual'])f.$(`#ip-mode-${mode.replace('_','-')}`).checked=mode===next;
    await f.$(`#ip-mode-${next.replace('_','-')}`).fire('change');
    const before={...f.calls},previous=saved,old=f.api.getAdapterSelection,read=deferred();
    f.api.getAdapterSelection=()=>{f.calls.selection++;return read.promise;};
    const close=f.$('#ip-config-close').fire('click');await flush();
    assert.equal(f.state.config.network_mode,next);applied.push(next);
    assert.equal(f.$('#ip-mode').className,`status-value mode-${next==='dhcp'?'dhcp':next==='static_manual'?'manual':'static'}`);
    if(next==='dhcp')assert.match(f.$('#ip-mode').innerHTML,/DHCP — set static/);
    else assert.equal(f.$('#ip-mode').textContent,next==='static_manual'?'Static — manual nodes':'Static — auto-adopt ready');
    assert.equal(f.calls.discoveryStops,before.discoveryStops+(next==='static_manual'?1:0));
    read.resolve(f.selection);await close;f.api.getAdapterSelection=old;
    assert.equal(f.calls.discoveryStarts,before.discoveryStarts+(previous==='static_manual'&&next!=='static_manual'?1:0));
    assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(f.$('#ip-config-close').disabled,false);
  }
  assert.deepEqual(applied,modes);assert.equal(f.transitions.length,6);assert.equal(f.calls.writes,0);
});

test('A confirmed Manual reply retires an older refresh so it cannot repaint the Auto badge',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  const old=deferred();let saved='static_auto';
  f.api.getAdapterSelection=()=>{f.calls.selection++;return old.promise;};
  f.api.getNetworkMode=async()=>saved;
  const read=f.exports.refreshInterfaces();await flush();
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-static-manual').checked=true;
  await f.$('#ip-mode-static-manual').fire('change');
  f.api.setNetworkMode=async()=>{saved='static_manual';return {mode:saved,warning:null};};
  const close=f.$('#ip-config-close').fire('click');await flush();
  assert.equal(f.$('#ip-mode').textContent,'Static — manual nodes');
  assert.equal(f.calls.discoveryStops,1);
  old.resolve(f.selection);await read;await close;await flush();
  assert.equal(f.$('#ip-mode').textContent,'Static — manual nodes');
  assert.equal(f.state.config.network_mode,'static_manual');
  assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(f.$('#ip-config-close').disabled,false);
});

test('Cancelling DHCP preserves primary edits and Close saves them in the restored static mode',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');
  f.$('#ip-mode-static-auto').checked=false;f.$('#ip-mode-dhcp').checked=true;await f.$('#ip-mode-dhcp').fire('change');
  f.api.setNetworkMode=async request=>{f.transitions.push(request);return {mode:'static_auto',warning:request.mode==='dhcp'?'DHCP may interrupt cameras':null};};
  f.ui.confirm=()=>false;await f.$('#ip-config-close').fire('click');
  assert.equal(f.$('#static-ip').value,'198.51.100.10');assert.equal(f.$('#ip-mode-static-auto').checked,true);
  await f.$('#ip-config-close').fire('click');
  assert.deepEqual(f.transitions.map(request=>request.mode),['dhcp','static_auto']);
  assert.equal(f.transitions[1].ip,'198.51.100.10');assert.equal(f.transitions[1].confirmed,false);
  assert.equal(f.$('#ip-config-dialog').open,false);assert.equal(f.calls.discoveryStops,0);
});

test('An adapter change during mode save cannot submit the secondary entry to the new adapter',async()=>{
  const f=fixture(),mode=deferred();await f.$('#btn-ip-config').fire('click');
  f.$('#static-ip').value='198.51.100.10';await f.$('#static-ip').fire('input');f.$('#add-sec-ip').value='203.0.113.10';
  f.api.setNetworkMode=()=>mode.promise;const close=f.$('#ip-config-close').fire('click');
  const changed={...f.selection,selected_mac:'40:cd:3a:00:00:02',interface_index:8};
  f.setSelection(changed);f.api.getAdapterSelection=async()=>changed;
  mode.resolve({mode:'static_auto',warning:null});await close;
  assert.equal(f.calls.writes,0);assert.equal(f.$('#ip-config-dialog').open,true);
  assert.equal(f.$('#add-sec-ip').value,'203.0.113.10');assert.match(f.feedback.at(-1).msg,/adapter changed/);
});

test('A completed add from a closed dialog cannot clear an entry in a new dialog session',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');f.$('#add-sec-ip').value='203.0.113.10';
  const add=f.$('#btn-add-sec-ip').fire('click');f.$('#ip-config-dialog').close();
  await f.$('#btn-ip-config').fire('click');f.$('#add-sec-ip').value='203.0.113.10';
  const reply=f.reply();reply.view.subnet=null;reply.view.binding=null;reply.view.selection=f.selection;
  f.pending[0].resolve(reply);await add;await flush();
  assert.equal(f.$('#add-sec-ip').value,'203.0.113.10');assert.equal(f.$('#ip-config-dialog').open,true);
});

test('A disconnected adapter and both Host IP rows survive repeated refresh failures',async()=>{
  const f=fixture();const down={...f.selection,adapter:{...f.iface,is_up:false}};down.candidates=[down.adapter];
  f.api.getAdapterSelection=async()=>down;
  await f.exports.refreshInterfaces();
  f.api.getAdapterSelection=async()=>{throw Error('ARP capture cannot start while Ethernet is down');};
  for(let i=0;i<3;i++){
    await f.exports.refreshInterfaces();
    assert.equal(f.$('#iface-name').textContent,'Ethernet (Disconnected)');
    assert.equal(f.state.activeInterface.is_up,false);
    for(const ip of f.iface.ips)assert(f.$('#subnet-list').innerHTML.includes(ip.address));
  }
  assert.equal(f.state.config.network_mode,'static_auto');
});

test('Cold startup stays neutral during a delayed failed read and then paints the real adapter',async()=>{
  const f=fixture({initialSelection:false}),first=deferred();
  f.api.getAdapterSelection=()=>first.promise;
  const pending=f.exports.refreshInterfaces();
  assert.equal(f.$('#iface-name').textContent,'Checking Ethernet…');
  first.reject(Error('adapter provider changed during enumeration'));await pending;
  assert.equal(f.$('#iface-name').textContent,'Checking Ethernet…');
  assert.equal(f.state.activeInterface,null);assert.equal(f.feedback.length,0);
  f.api.getAdapterSelection=async()=>({...f.selection,adapter:{...f.iface,is_up:false}});
  await f.exports.refreshInterfaces();
  assert.equal(f.$('#iface-name').textContent,'Ethernet (Disconnected)');
  for(const ip of f.iface.ips)assert(f.$('#subnet-list').innerHTML.includes(ip.address));
  f.api.getAdapterSelection=async()=>f.selection;await f.exports.refreshInterfaces();
  assert.equal(f.$('#iface-name').textContent,'Ethernet');assert.equal(f.calls.writes,0);
});

test('Startup can paint a known disconnected selection when its first view query fails',async()=>{
  const f=fixture();f.state.activeInterface=null;
  const down={...f.selection,adapter:{...f.iface,is_up:false}};down.candidates=[down.adapter];
  f.setSelection(down);
  f.api.getAdapterSelection=async()=>{throw Error('late startup query failure');};
  await f.exports.refreshInterfaces();
  assert.equal(f.$('#iface-name').textContent,'Ethernet (Disconnected)');
  assert.equal(f.state.activeInterface.is_up,false);
  for(const ip of f.iface.ips)assert(f.$('#subnet-list').innerHTML.includes(ip.address));
});

test('A native down event fences an older up reply even without a selection event',async()=>{
  const f=fixture(),old=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return f.calls.selection===1?old.promise:Promise.reject(Error('new view unavailable'));};
  const read=f.exports.refreshInterfaces();
  f.events.get('interface-status-changed')({...f.iface,is_up:false});await flush();
  f.runTimers(2000);
  old.resolve(f.selection);await read;await flush();
  assert.equal(f.$('#iface-name').textContent,'Ethernet (Disconnected)');
  assert.equal(f.state.activeInterface.is_up,false);
  assert.equal(f.calls.selection,2);
  for(const ip of f.iface.ips)assert(f.$('#subnet-list').innerHTML.includes(ip.address));
});

test('A confirmed missing selected adapter is never resurrected by a later failed refresh',async()=>{
  const f=fixture();await f.exports.refreshInterfaces();
  const absent={...f.selection,adapter:null,interface_index:null,candidates:[]};
  f.setSelection(absent);f.api.getAdapterSelection=async()=>absent;
  await f.exports.refreshInterfaces();
  f.api.getAdapterSelection=async()=>{throw Error('native enumeration unavailable');};
  await f.exports.refreshInterfaces();
  assert.equal(f.state.activeInterface,null);
  assert.match(f.$('#iface-name').textContent,/unavailable/);
  assert(!f.$('#subnet-list').innerHTML.includes(f.iface.ips[0].address));
  assert(f.$('#subnet-list').innerHTML.includes(IP),'saved Host intent remains visible');
});

test('Configure stays usable during a fresh read and Add reaches the mutation handler',async()=>{
  const f=fixture(),read=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return read.promise;};
  const opening=f.$('#btn-ip-config').fire('click');await flush();
  assert.equal(f.$('#ip-config-dialog').open,true);
  assert.equal(f.$('#static-iface').value,'Ethernet');
  f.$('#add-sec-ip').value=IP;
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
  assert.equal(f.$('#static-iface').disabled,true);assert.equal(f.$('#ip-mode-static-auto').disabled,true);
  assert.equal(f.$('#ip-mode-static-auto').disabled,true);assert.equal(f.$('#host-title').style.pointerEvents,'none');
  const added=f.reply();added.view.selection=f.selection;added.view.binding=null;
  f.pending[0].resolve(added);await first;await second;
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);assert.equal(f.$('#ip-config-spinner').style.display,'none');
  assert.equal(f.calls.selection,0);assert.equal(f.calls.bindings,0);assert.equal(f.calls.dhcp,0);
});

test('SP10/SP11 Modal removal paints Host and open dialog from one reply with zero follow-up reads',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');
  const before={...f.calls};const pending=f.modalRemove();await flush();
  assert.equal(f.calls.writes,1);assert.equal(f.$('#btn-add-sec-ip').disabled,true);
  f.pending[0].resolve(f.reply());await pending;await flush();
  assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
  assert(!f.$('#subnet-list').innerHTML.includes(IP));assert(!f.$('#secondary-ip-list').innerHTML.includes(IP));
  assert.equal(f.adoptionMeta.get(SUBNET).desired,'removed');assert(!f.adoptedSubnets.has(SUBNET));
  for(const name of ['selection','bindings','mode','dhcp'])assert.equal(f.calls[name],before[name],name);
});

test('Removing the last Host IP clears both panels and an older interface fetch cannot restore it',async()=>{
  const f=fixture(),old=deferred();f.iface.ips=[f.iface.ips[1]];
  f.state.config.primary_addresses={[MAC]:''};
  f.api.getAdapterSelection=()=>{f.calls.selection++;return old.promise;};
  const read=f.exports.refreshInterfaces();const removal=f.modalRemove();await flush();
  assert(f.$('#subnet-list').innerHTML.includes(IP),'retain the address until removal is verified');
  const result=f.reply(),empty={...f.iface,ips:[]};
  result.view.selection={...f.selection,adapter:empty,candidates:[empty]};
  f.pending[0].resolve(result);await removal;await flush();
  assert.equal(f.state.activeInterface.ips.length,0);assert.equal(f.$('#subnet-list').innerHTML,'');
  assert(!f.$('#secondary-ip-list').innerHTML.includes(IP));
  assert(f.$('#secondary-ip-list').innerHTML.includes('No secondary IPs'));
  assert.equal(f.adoptionMeta.get(SUBNET).desired,'removed');
  assert.equal(f.adoptionMeta.get(SUBNET).applied,false);assert(!f.adoptedSubnets.has(SUBNET));
  const before={...f.calls};old.resolve(f.selection);await read;await flush();
  assert.equal(f.state.activeInterface.ips.length,0);assert.equal(f.$('#subnet-list').innerHTML,'');
  assert(!f.$('#secondary-ip-list').innerHTML.includes(IP),'stale fetch cannot repaint the modal');
  assert.equal(f.calls.writes,1);assert.equal(f.calls.selection,1);
  for(const name of ['selection','bindings','mode','dhcp'])assert.equal(f.calls[name],before[name],name);
  assert(!f.feedback.some(item=>item.error));
});

test('SP10 adapter A/B/A retires the old success even when the final MAC matches',async()=>{
  const f=fixture();const pending=f.modalRemove();await flush();
  f.setSelection({...f.selection,selected_mac:'40:cd:3a:00:00:02',interface_index:8});f.setSelection(f.selection);
  f.pending[0].resolve(f.reply());await pending;await flush();
  assert.equal(f.feedback.length,0,'no stale success');assert.equal(f.adoptionMeta.get(SUBNET).desired,'present');
  assert.equal(f.$('#btn-add-sec-ip').disabled,false);
});

for(const kind of ['IPC','render'])test(`SP10 ${kind} failure always releases controls and shows actionable feedback`,async()=>{
  const f=fixture();const pending=f.modalRemove();await flush();
  if(kind==='IPC')f.pending[0].reject(Error('injected IPC failure'));
  else {f.failRender();f.pending[0].resolve(f.reply());}
  await pending;await flush();assert.equal(f.$('#btn-add-sec-ip').disabled,false);assert.equal(f.$('#ip-mode-static-auto').disabled,false);
  assert.equal(f.$('#ip-config-spinner').style.display,'none');assert(f.feedback.at(-1).error);
});

test('SP10 close/reopen does not abandon a running removal or resurrect an older dialog fetch',async()=>{
  const f=fixture();await f.$('#btn-ip-config').fire('click');const pending=f.modalRemove();await flush();
  await f.$('#ip-config-close').fire('click');assert.equal(f.$('#ip-config-dialog').open,false);
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
    const read=f.exports.refreshInterfaces(),pending=f.modalRemove();await flush();
    f.pending[0].resolve(f.reply());await pending;await flush();
    if(reject)old.reject(Error('old provider failure'));else old.resolve(f.selection);
    await read;await flush();assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
    assert.equal(f.adoptionMeta.get(SUBNET).desired,'removed');assert(!f.feedback.some(x=>x.error));
    assert.equal(f.calls.selection,1,'reply did not initiate another fetch');
  }
});

test('SP11 callback burst during a mutation defers one native refresh and cannot overwrite its reply',async()=>{
  const f=fixture();const pending=f.modalRemove();await flush();const result=f.reply();
  f.api.getAdapterSelection=async()=>{f.calls.selection++;return result.view.selection;};
  f.api.getAdoptionState=async()=>{f.calls.bindings++;return {adopted_subnets:{},meta:{[SUBNET]:result.view.binding}};};
  for(let i=0;i<20;i++){f.setSelection(f.selection);f.events.get('interface-status-changed')(f.iface);}
  assert.equal(f.calls.selection,0);f.pending[0].resolve(result);await pending;await flush();await flush();
  assert.equal(f.calls.selection,1);assert.equal(f.calls.bindings,1);assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
});

test('SP10 unknown observation retains last known addresses and pending row without false success',async()=>{
  const f=fixture();const pending=f.modalRemove();await flush();const result=f.reply({outcome:'pending',reason:'Verification failed'});
  result.view.observation_error='Native unavailable';result.view.selection={...f.selection,adapter:null,interface_index:null};result.view.binding.applied=true;result.view.binding.last_error='Verification failed';
  f.pending[0].resolve(result);await pending;await flush();assert(f.state.activeInterface.ips.some(i=>i.address===IP));
  assert.equal(f.adoptionMeta.get(SUBNET).applied,true);assert.equal(f.feedback.at(-1).error,true);
});

test('SP11 stale post-reply events trigger one current read and cannot repaint old IPs',async()=>{
  const f=fixture();const pending=f.modalRemove();await flush();f.pending[0].resolve(f.reply());await pending;await flush();
  const fresh=deferred();f.api.getAdapterSelection=()=>{f.calls.selection++;return fresh.promise;};
  f.api.getAdoptionState=async()=>({adopted_subnets:{},meta:{[SUBNET]:f.reply().view.binding}});
  for(let i=0;i<12;i++){f.setSelection(f.selection);f.events.get('interface-status-changed')(f.iface);}
  assert(!f.state.activeInterface.ips.some(i=>i.address===IP));await flush();assert.equal(f.calls.selection,1);
  fresh.resolve(f.reply().view.selection);await flush();assert(!f.state.activeInterface.ips.some(i=>i.address===IP));
});

test('SP10 close/reopen retires old dialog-open continuations and pending fetches',async()=>{
  const f=fixture(),old=deferred(),current=deferred();
  f.api.getAdapterSelection=()=>{f.calls.selection++;return f.calls.selection===1?old.promise:current.promise;};
  const first=f.$('#btn-ip-config').fire('click');await flush();await f.$('#ip-config-close').fire('click');
  const second=f.$('#btn-ip-config').fire('click');await flush();
  const pending=f.modalRemove();await flush();const result=f.reply();f.pending[0].resolve(result);await pending;await flush();
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
