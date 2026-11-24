// Run with Node from any directory. Everything in this check uses in-memory replies.
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createContext,Script} from 'node:vm';
import {createHash} from 'node:crypto';

const root=fileURLToPath(new URL('../',import.meta.url));
async function collect(dir='') {
  const rows=[];
  for(const file of await readdir(path.join(root,dir),{withFileTypes:true})) {
    const name=path.posix.join(dir,file.name);
    if(file.isDirectory()) rows.push(...await collect(name));
    else rows.push([name,await readFile(path.join(root,name),'utf8')]);
  }
  return rows;
}
const files=new Map(await collect());
const forbidden=['ht'+'tp:'+'//','127'+'.0.0.1','local'+'host','perspec'+'tive','rotate'+'X','rotate'+'Y','preserve'+'-3d',
  'Secwiz '+'Virtual Machine','sam'+'ple'];
// Names that must never appear in the interface, kept as SHA-256 hashes of the lowercase word.
const restrictedNames=new Set(['095f26e6c7c467c5ecce3205a0dc90f6dc4868e8ddfe7a21829e91d47e386676',
  '5fb442a83c77104e238284409507382b51a2b48f7bf52819ed57039385d35afc','c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d',
  '09cf980b5ff304ac11b7f6d2c5c263da2a867425798ef5cc5d2ebcf55c4fcd23','693b286515bd1dd00865e7b60e4e53556537bbe4b1cc90ab608d94eb7c56fdc6']);
for(const [name,source] of files) {
  const firstParty = name === 'screens/vm.js' ? source.replace('ws://127'+'.0.0.1:', '') : source;
  for(const word of forbidden) assert.ok(!firstParty.toLowerCase().includes(word.toLowerCase()),name+' contains restricted text: '+word);
  for(const token of new Set(firstParty.toLowerCase().match(/[a-z]+/g)||[])) {
    assert.ok(!restrictedNames.has(createHash('sha256').update(token).digest('hex')),name+' contains a restricted name');
  }
  if(name.endsWith('.js')) new Script(source,{filename:name});
  if(name.startsWith('screens/')) {
    assert.doesNotMatch(source,/(?:\bS(?:VB)?\.data|\bSvmApi\.state|\b(?:D|data)\.(?:vms|networks|host|guard|events|caps))(?:\.[\w$]+|\[[^\]]+\])*\.(?:push|pop|splice|shift|unshift|reverse|sort)\s*\(/);
    assert.doesNotMatch(source,/(?:\bS(?:VB)?\.data|\bSvmApi\.state)(?:\.[\w$]+|\[[^\]]+\])+\s*(?:=(?!=)|\+\+|--|\+=|-=)/);
    assert.doesNotMatch(source,/\b(?:eval|Function)\s*\(|\.innerHTML\s*=/);
  }
}
const index=files.get('index.html');
assert.ok(index.includes('<title>Secwizt Virtual Machine</title>'));
for(const m of index.matchAll(/\b(?:src|href)="([^"]+)"/g)) assert.ok(files.has(m[1].replace(/^\//,'')),'Missing embedded file '+m[1]);
assert.doesNotMatch(index,/<script(?![^>]*\bsrc=)[^>]*>|\bon\w+\s*=/i);
const colours=new Map([...files.get('core/tokens.css').matchAll(/--([\w-]+):\s*#([\da-f]{6})\b/gi)].map(m=>[m[1],m[2]]));
function luminance(k) {
  const hex=colours.get(k); assert.ok(hex,k);
  return hex.match(/../g).map(s=>parseInt(s,16)/255).reduce((sum,v,i)=>
    sum+[.2126,.7152,.0722][i]*(v<=.04045?v/12.92:((v+.055)/1.055)**2.4),0);
}
const matrix={ink:['bg','sky-1','sky-2','sky-3','panel','panel-2'],muted:['bg','sky-1','sky-2','sky-3','panel','panel-2'],
  'blue-deep':['bg','sky-1','sky-2','sky-3','panel'],gold:['bg','sky-1','sky-2','sky-3','panel','panel-2','term-bg'],
  'term-fg':['term-bg'],warn:['panel','warn-bg'],'on-blue':['blue']};
let contrastPairs=0;
for(const [a,bs] of Object.entries(matrix)) for(const b of bs) {
  const x=luminance(a),y=luminance(b);
  assert.ok((.05+Math.max(x,y))/(.05+Math.min(x,y))>=4.5,a+' / '+b); contrastPairs++;
}

const timers=new Map(), calls=[], events=[], listeners=new Map();
let next=0, focused=true, refuse=false, running=false, publishes=0, holdFrame;
const hooks=prefix=>({
  addEventListener(type,fn){listeners.set(prefix+type,fn);},
  removeEventListener(type){listeners.delete(prefix+type);}
});
const doc={hidden:false,hasFocus:()=>focused,...hooks('doc:')};
const opaque='9G_q.1-opaque';
const guard={budgetPct:25,threadBudget:8,usedThreads:0,usedRamGb:0,placement:'advisory'};
function reply(body,status=200) {
  return {ok:status>=200&&status<300,status,json:async()=>structuredClone(body),headers:{get:()=>null}};
}
const fake=async (url,options={})=>{
  const method=options.method||'GET';
  assert.ok(url.startsWith('/api/v1/'));
  calls.push([method,url,options.body]);
  if(refuse && method!=='GET') return reply({error:{code:'refused',message:'A guest already holds those threads.'}},409);
  if(url==='/api/v1/health')return reply({status:'ok',version:'0.1.0'});
  if(url==='/api/v1/host')return reply({...guard,logical:32,eCores:[16,31],pCores:[0,15],ramGb:63});
  if(url==='/api/v1/guard')return reply(guard);
  if(url==='/api/v1/settings/qemu')return reply({available:false,path:null,version:null,reason:'Select the local engine in Settings.'});
  if(url==='/api/v1/machines/'+opaque+'/stop' && method==='POST'){running=false;events.push({id:4,kind:'stopped'});return reply({id:opaque});}
  if(url==='/api/v1/machines/'+opaque+'/thumbnail') { if(holdFrame) await holdFrame; return {ok:true,headers:{get:name=>({'x-width':'1','x-height':'1','x-pixel-format':'RGBA8'})[name]},arrayBuffer:async()=>Uint8Array.of(12,34,56,255).buffer}; }
  if(url==='/api/v1/machines')return reply([{id:opaque,name:'Guest',state:running?'running':'off',net:'nat'}]);
  if(url==='/api/v1/networks')return reply([{id:'nat',name:'NAT',mode:'NAT',addressSource:'Windows DHCP'}]);
  if(url==='/api/v1/machines/'+opaque+'/capabilities')return reply({Start:{available:!running,reason:'Already running.'},Thumbnail:{available:running,reason:'No active display.'}});
  if(url.startsWith('/api/v1/events?since='))return reply(events.filter(row=>row.id>Number(url.split('=')[1])));
  if(url==='/api/v1/machines/'+opaque+'/start'&&method==='POST'){running=true; events.push({id:1,kind:'started',message:'Guest started.'});return reply({id:opaque});}
  throw new Error('Unexpected fake request: '+url);
};
const posted=[];
const ctx={document:doc,fetch:fake,ipc:{postMessage:msg=>posted.push(JSON.parse(msg))},
  ImageData:class{constructor(data,width,height){Object.assign(this,{data,width,height});}},...hooks('win:'),setTimeout(fn,delay){const id=++next;timers.set(id,{fn,delay});return id;},
  clearTimeout(id){timers.delete(id);}};
ctx.window=ctx;createContext(ctx);
new Script(files.get('core/api.js'),{filename:'api.js'}).runInContext(ctx);
const api=ctx.SvmApi;
await api.start(()=>{publishes++;});
assert.equal(api.state.online,true);
assert.ok(Object.isFrozen(api.state.vms[0]));
assert.ok(Object.isFrozen(api.state.caps[opaque].Start));
assert.equal(api.state.vms[0].id,opaque);
assert.equal(api.state.caps[opaque].Start.available,true);
assert.equal(api.state.host.placement,'advisory');
assert.equal(api.state.health.version,'0.1.0');
assert.equal(api.state.qemu.available,false);
assert.equal(api.state.networks[0].subnet,undefined);
let rendered;const canvas={getContext:()=>({putImageData:frame=>{rendered=frame;}})};
const frameRequests=()=>calls.filter(row=>row[1].endsWith('/thumbnail')).length;
assert.equal(await api.thumbnail(opaque,canvas),false);assert.equal(frameRequests(),0);
const pick=api.native('pickIso');assert.equal(posted[0].action,'pickIso');
listeners.get('win:svm-native-result')({detail:{requestId:posted[0].requestId,ok:true,value:null}});
assert.equal(await pick,null);
const chooseExe=api.native('pickQemu');assert.equal(posted.at(-1).action,'pickQemu');
listeners.get('win:svm-native-result')({detail:{requestId:posted.at(-1).requestId,ok:true,value:null}});
assert.equal(await chooseExe,null);
await assert.rejects(api.native('shutdown'));
const before=api.state, beforeUpdates=publishes;
refuse=true;
await assert.rejects(api.action('POST',api.machinePath(opaque)+'/start',{}),e=>e.code==='refused'&&e.message==='A guest already holds those threads.');
assert.equal(api.state,before);assert.equal(publishes,beforeUpdates);refuse=false;
await api.action('POST',api.machinePath(opaque)+'/start',{});
assert.equal(api.state.vms[0].state,'running');assert.equal(api.state.events[0].id,1);
assert.equal(await api.thumbnail(opaque,canvas),true);
assert.deepEqual(Array.from(rendered.data),[12,34,56,255]);assert.deepEqual([canvas.width,canvas.height],[1,1]);
async function fire(expected) {
  assert.equal(timers.size,1);
  const [id,t]=timers.entries().next().value;
  assert.equal(t.delay,expected);timers.delete(id);await t.fn();
}
const count=calls.length;await fire(2000);
assert.deepEqual(calls.slice(count).map(x=>x[1]),['/api/v1/events?since=1']);
focused=false;listeners.get('win:blur')();await fire(10000);
const callCount=calls.length;doc.hidden=true;listeners.get('doc:visibilitychange')();
assert.equal(timers.size,0);assert.equal(callCount,calls.length);
doc.hidden=false;focused=true;listeners.get('doc:visibilitychange')();
events.push({id:2,kind:'state',message:'External state changed.'});running=false;
await fire(0);assert.equal(api.state.vms[0].state,'off');assert.equal(api.state.events.length,2);
running=true;events.push({id:3,kind:'started'});await api.load();
let releaseFrame;holdFrame=new Promise(resolve=>{releaseFrame=resolve;});
const pendingFrame=api.thumbnail(opaque,canvas);
const pendingStop=api.action('POST',api.machinePath(opaque)+'/stop',{});
const dispatched=frameRequests();
assert.equal(api.canThumbnail(opaque),false);assert.equal(await api.thumbnail(opaque,canvas),false);
assert.equal(frameRequests(),dispatched);assert.ok(!calls.some(row=>row[1].endsWith('/stop')));
releaseFrame();assert.equal(await pendingFrame,false);await pendingStop;
assert.equal(api.state.vms[0].state,'off');assert.equal(await api.thumbnail(opaque,canvas),false);
api.stop();assert.equal(timers.size,0);
// Check the actual animation scheduler without starting a desktop window.
const skyEvents=new Map(),skyFrames=new Map(),skyTimers=new Map();
const skyHooks=p=>({addEventListener:(name,fn)=>skyEvents.set(p+name,fn)});
let skyFocus=true,skyClock=10,seq=0;
const brush=new Proxy({createLinearGradient:()=>({addColorStop(){}})}, {get:(obj,name)=>obj[name]||(()=>{})});
const element={dataset:{fx:'on'},toggleAttribute(){}};
const skyDoc={documentElement:element,hidden:false,hasFocus:()=>skyFocus,...skyHooks('doc:'),
  createElement:()=>({getContext:()=>brush}),getElementById:()=>({append(){}})};
const sky={document:skyDoc,innerWidth:1000,innerHeight:650,devicePixelRatio:1,performance:{now:()=>skyClock},
  getComputedStyle:()=>({getPropertyValue:()=>'#436aad'}),...skyHooks('win:'),
  requestAnimationFrame:fn=>{const id=++seq;skyFrames.set(id,fn);return id;},cancelAnimationFrame:id=>skyFrames.delete(id),
  setTimeout:(fn,delay)=>{const id=++seq;skyTimers.set(id,{fn,delay});return id;},clearTimeout:id=>skyTimers.delete(id)};
sky.window=sky;new Script(files.get('core/sky.js')).runInNewContext(sky);
skyEvents.get('doc:DOMContentLoaded')();
assert.equal(skyFrames.size,1);
const [frameId,onFrame]=skyFrames.entries().next().value;skyFrames.delete(frameId);onFrame(skyClock);
assert.equal(sky.SVB_SKY_STATS.frames,1);
assert.ok([...skyTimers.values()][0].delay>=40);
skyFocus=false;skyEvents.get('win:blur')();
assert.equal(skyTimers.size+skyFrames.size,0);
skyDoc.hidden=true;skyEvents.get('doc:visibilitychange')();
skyFocus=true;skyEvents.get('win:focus')();assert.equal(skyFrames.size,0);
skyDoc.hidden=false;skyEvents.get('doc:visibilitychange')();assert.equal(skyFrames.size,1);
element.dataset.fx='off';skyEvents.get('win:svb-fx')();assert.equal(skyFrames.size+skyTimers.size,0);
// Exercise the Networks screen's actual setup button against a changing physical adapter.
const physical={id:'fixture-ethernet',name:'Fixture Ethernet',available:false,reasons:['Third-party binding (fixture_filter).','IPv6 is not bound.']};
const savedBridge={id:'wired',name:'Wired',mode:'Bridged',adapterId:physical.id,ready:false,bridgeCanSetup:false,
  bridgeReasons:physical.reasons,setupCommand:'initial setup'};
const networkData={vms:[],networks:[savedBridge],host:{}};
let networkScreen,networkTree,checkedBridge={...savedBridge},copied=[];
function tag(tag,attrs={},...children) {
  return {tag,attrs,children:children.flat(Infinity),append(...items){this.children.push(...items.flat(Infinity));}};
}
function walk(node) {
  return node&&typeof node==='object'?[node,...node.children.flatMap(walk)]:[node];
}
const networkApp={h:tag,data:networkData,view:'networks',vm(){},net(id){return networkData.networks.find(n=>n.id===id);},
  register(_,view){networkScreen=view;},facts(rows){return tag('dl',{},rows.map(([k,v])=>[k,v]));},
  async fill(el,read,draw){el.children=[draw(await read())];},toast(){},
  api:{segment:encodeURIComponent,get:async()=>({adapters:[physical]}),action:async()=>checkedBridge,native:async(_,data)=>{copied.push(data.text);}},
  render(){networkTree=tag('main');networkScreen.render(networkTree);}};
const screenDoc={documentElement:{toggleAttribute(){}},addEventListener(){},getElementById(){return {focus(){},form:{scrollIntoView(){}}};}};
new Script(files.get('screens/networks.js')).runInNewContext({document:screenDoc,window:{SVB:networkApp}});
const findButton=label=>walk(networkTree).find(n=>n?.tag==='button'&&n.children.includes(label));
networkApp.render();
assert.ok(!findButton('Copy bridge setup command'));
for(const reason of physical.reasons)assert.ok(walk(networkTree).includes(reason));
Object.assign(savedBridge,{bridgeCanSetup:true,bridgeReasons:[]});networkApp.render();
await new Promise(resolve=>setImmediate(resolve));assert.ok(!findButton('Copy bridge setup command'));
physical.available=true;networkApp.render();await new Promise(resolve=>setImmediate(resolve));
await findButton('Copy bridge setup command').attrs.onclick();assert.equal(copied.length,0);
checkedBridge={bridgeCanSetup:true,setupCommand:'verified setup'};
await findButton('Copy bridge setup command').attrs.onclick();assert.deepEqual(copied,['verified setup']);physical.available=false;
findButton('Add network').attrs.onclick();
const mode=walk(networkTree).find(n=>n?.attrs?.id==='network-mode');
mode.attrs.onchange({target:{value:'Bridged'}});
await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(networkTree).includes(physical.name));
for(const reason of physical.reasons)assert.ok(walk(networkTree).includes(reason));
assert.ok(findButton('Create network').attrs.disabled);
// Exercise the installed guest controls in the Library, Machine and Networks renderers.
function elementFor(type) {
  return Object.assign(tag(type,{}),{nodeType:1,isConnected:true,value:'',
    setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k] == null ? null : String(this.attrs[k]);},
    addEventListener(k,fn){this.attrs['on'+k]=fn;},
    replaceChildren(...items){this.children=items;},
    querySelector(selector){return selector.startsWith("#")?walk(this).find(item=>item?.attrs?.id===selector.slice(1)):undefined;},
    classList:{add(){},remove(){}}});
}
const shellDoc={...screenDoc,createElement:elementFor,createElementNS:(_,type)=>elementFor(type),createTextNode:value=>value,
  documentElement:{dataset:{fx:'off'},toggleAttribute(){}},
  getElementById:id=>id==='vector'?{content:{firstElementChild:{namespaceURI:'svg'}}}:Object.assign(elementFor('div'),{focus(){}})};
const guest={id:opaque,name:'Installed guest',os:'Debian',state:'running',net:'nat',ip:'192.0.2.42',addressSource:'reported by the guest'};
const capabilities=Object.fromEntries(['Pause','Shutdown','Restart','Stop','SendKeys'].map(key=>[key,{available:true}]));
const shellState={vms:[guest],networks:[{id:'nat',name:'NAT',mode:'NAT'}],host:{},caps:{[opaque]:capabilities},events:[]};
let timeoutOperation=false,allowCut=false,guestRequests=[],asks=[],observations=0;
const noticesFromGuest=[];
const bootMessage='Enter was sent to the machine.';
let openingConsole,chosenExe=null;
const reads=[];
let androidStorage=null;
let readyFixture=null;
let captureFixture=null, captureTimers=null;
const nativeCaptures=[];
const machineApi={state:shellState,segment:encodeURIComponent,machinePath:id=>'/v1/machines/'+id,
  native:async(name,data)=>{
    if(name==='captureViewerAvailable')return false;
    if(name==='showCaptureFile'){nativeCaptures.push(data);return null;}
    if(name==='pickIso')return 'C:\\fixture.iso';
    if(name==='pickQemu')return chosenExe;
    assert.equal(name,'openConsole');assert.equal(data.text,'beforeStart');await openingConsole;
  },
  notices:async()=>'Fixture notices',
  get:async path=>{reads.push(path);if(path==='/v1/ready')return readyFixture;if(captureFixture&&path.endsWith('/captures'))return captureFixture;if(path.endsWith('/agent'))return {present:true,version:'test',ip:'10.0.2.15'};if(androidStorage&&path.endsWith('/storage'))return androidStorage;return {disks:[],bootFirst:'system',bootDescription:'debian',canEditMedia:true,canEditBoot:true};},
  load:async()=>{observations++;},action:async(method,path,body)=>{
    guestRequests.push([method,path,body]);
    if(captureFixture&&path.endsWith('/captures'))return captureFixture={active:true,captures:[]};
    if(captureFixture&&path.endsWith('/captures/stop'))return captureFixture={active:false,captures:[
      {id:'capture-one',name:'capture-one.pcap',bytes:1024,stoppedBecause:'limit'},
      {id:'capture-two',name:'capture-two.pcap',bytes:2048,stoppedBecause:'low-disk-space'},
    ]};
    if(path==='/v1/settings/qemu')return shellState.qemu={available:true,path:body.path,version:'QEMU fixture',reason:null};
    if(timeoutOperation&&path.endsWith('/shutdown'))throw Object.assign(new Error('Guest did not answer in 25 seconds.'),{code:'guest_power_timeout'});
    if(path.endsWith('/restart'))return {state:'running',guestPowerStatus:'restart_requested'};
    if(path.endsWith('/keys'))return {sent:1,retried:false,layout:'us'};
    if(path==='/v1/machines')return {id:opaque};
    if(path.startsWith('/v1/ready/')&&path.endsWith('/launch'))return {machine:{id:'fixture-ready',name:body.name},password:body.generatePassword?'Generated-Fixture-23':undefined};
    if(path.endsWith('/linked-clones'))return {id:'fixture-child'};
    if(path.endsWith('/start')&&body.pressKeyAtBoot) {
      shellState.events.push({kind:'installer boot key',message:opaque+': '+bootMessage});
      return {bootKey:{sent:1,retried:true,message:bootMessage}};
    }
  }};
const shell={document:shellDoc,SvmApi:machineApi,addEventListener(){},requestAnimationFrame(){},ResizeObserver:class {observe(){} disconnect(){}},
  setTimeout(run,ms){if(captureTimers&&ms===0&&run.name==='poll')captureTimers.push(run);},clearTimeout(){}};
shell.window=shell;
const scope=createContext(shell);
for(const file of ['core/app.js','screens/transfers.js','screens/backups.js','screens/os_catalog.js','screens/app_catalog.js','screens/ready_images.js','screens/vm.js','screens/library.js','screens/networks.js','screens/newvm.js','screens/settings.js'])new Script(files.get(file)).runInContext(scope);
const app=shell.SVB;app.render=()=>{};app.toast=message=>noticesFromGuest.push(message);
app.dialog=async(title,body,confirm)=>{asks.push([title,walk(body).filter(x=>typeof x==='string').join(' '),confirm]);return allowCut;};
function screen(name,id=opaque) {const tree=elementFor('main');app.screens.get(name).render(tree,{id});return tree;}
function button(tree,label) {return walk(tree).find(item=>item?.tag==='button'&&item.children.includes(label));}
async function clickButton(tree,label) {
  const target=button(tree,label);assert.ok(target,label);
  target.attrs.onclick({stopPropagation(){},preventDefault(){}});
  await new Promise(resolve=>setImmediate(resolve));
}
const library=screen('library');await clickButton(library,'Show as list');
const list=screen('library'),machine=screen('vm');
for(const tree of [list,machine]) {
  for(const label of ['Shut down','Restart','Power off'])assert.ok(button(tree,label));
  assert.ok(walk(tree).includes('192.0.2.42 (reported by the guest)'));
}
assert.ok(!button(list,'Send Ctrl+Alt+Del'));
await clickButton(machine,'Send Ctrl+Alt+Del');
assert.equal(guestRequests.at(-1)[1],'/v1/machines/'+opaque+'/keys');
assert.equal(JSON.stringify(guestRequests.at(-1)[2]),'{"keys":["Ctrl+Alt+Del"]}');
assert.ok(noticesFromGuest.at(-1).startsWith('Ctrl+Alt+Del sent to the machine.'));
await clickButton(machine,'Restart');assert.ok(guestRequests.at(-1)[1].endsWith('/restart'));
assert.equal(noticesFromGuest.at(-1),'Installed guest accepted the restart request.');
const cuts=()=>guestRequests.filter(row=>row[1]==='/v1/machines/'+opaque+'/stop').length;
await clickButton(list,'Power off');assert.equal(asks.at(-1)[2],'Power off');assert.equal(cuts(),0);
allowCut=true;await clickButton(list,'Power off');assert.equal(cuts(),1);
allowCut=false;timeoutOperation=true;await clickButton(machine,'Shut down');
assert.equal(observations,1);assert.match(asks.at(-1)[1],/25 seconds/);assert.match(asks.at(-1)[1],/Unsaved/);assert.equal(cuts(),1);
allowCut=true;await clickButton(machine,'Shut down');assert.equal(cuts(),2);
for(const name of ['Shutdown','Restart'])capabilities[name]={available:false,reason:'Guest shutdown integration is disabled.'};
const denied=screen('vm');
assert.ok(!button(denied,'Shut down')&&!button(denied,'Restart'));
assert.ok(walk(denied).some(x=>typeof x==='string'&&x.includes('Guest shutdown integration is disabled.')));
await clickButton(denied,'Storage');const diskView=screen('vm');await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(diskView).includes('Installed system (debian)'));
for(const mode of ['NAT','Bridged']) {
  shellState.networks[0].mode=mode;
  guest.addressSource='reported by the guest';assert.ok(walk(screen('networks')).includes('192.0.2.42 (reported by the guest)'));
  guest.addressSource='not reported by the guest';assert.ok(walk(screen('networks')).includes('not reported by the guest'));
  assert.ok(!walk(screen('networks')).some(x=>typeof x==='string'&&x.includes('192.0.2.42')));
}
Object.assign(guest,{engine:'QEMU',family:'linux',addressSource:'guest agent',ip:'10.0.2.15'});
await clickButton(screen('vm'),'Guest tools');
await clickButton(screen('vm'),'Check guest agent');
assert.equal(noticesFromGuest.at(-1),'Guest agent test is running.');
assert.ok(reads.includes('/v1/machines/'+opaque+'/agent'));
await clickButton(screen('vm'),'Network');
assert.ok(walk(screen('vm')).includes('10.0.2.15'));
assert.ok(walk(screen('vm')).includes('Guest agent'));
assert.ok(walk(screen('library')).includes('10.0.2.15'));
const forward = {protocol:'tcp',hostPort:2222,guestPort:22};
const forwardAddress='127'+'.0.0.1';
Object.assign(guest,{registration:'registered',portForwardAddress:forwardAddress,portForwards:[forward]});
let networkView=screen('vm');
assert.ok(walk(networkView).includes('TCP '+forwardAddress+':2222 → guest port 22'));
assert.ok(!button(networkView,'Add port forward')&&!button(networkView,'Remove'));
guest.state='off';
networkView=screen('vm');
await clickButton(networkView,'Remove');
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['PATCH','/v1/machines/'+opaque,{portForwards:[]}]));
guest.portForwards=[];
networkView=screen('vm');
const forwardField=id=>walk(networkView).find(item=>item?.attrs?.id===id);
forwardField('forward-protocol').value='udp';
forwardField('forward-host-port').valueAsNumber=6580;
forwardField('forward-guest-port').valueAsNumber=68;
await walk(networkView).find(item=>item?.tag==='form').attrs.onsubmit({preventDefault(){}});
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['PATCH','/v1/machines/'+opaque,{portForwards:[
  {protocol:'udp',hostPort:6580,guestPort:68}
]}]));
Object.assign(guest,{state:'running',registration:'registered',portForwardAddress:undefined,portForwards:undefined});
captureFixture={active:false,captures:[]};
captureTimers=[];
const captureNetwork=screen('vm');
assert.equal(captureTimers.length,1);
await captureTimers.shift()();
const capField=walk(captureNetwork).find(item=>item?.attrs?.id==='capture-limit');
assert.ok(capField);
capField.valueAsNumber=1;
walk(captureNetwork).find(item=>item?.tag==='form').attrs.onsubmit({preventDefault(){}});
await new Promise(resolve=>setImmediate(resolve));
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['POST','/v1/machines/'+opaque+'/captures',{limitMiB:1}]));
assert.equal(captureFixture.active,true);
const activeCapture=screen('vm');
await captureTimers.shift()();
await clickButton(activeCapture,'Stop capture');
assert.equal(guestRequests.at(-1)[1],'/v1/machines/'+opaque+'/captures/stop');
const doneCapture=screen('vm');
assert.ok(walk(doneCapture).some(item=>typeof item==='string'&&item.includes('Size limit reached')));
assert.ok(walk(doneCapture).some(item=>typeof item==='string'&&item.includes('Free disk space fell below 2 GiB')));
await clickButton(doneCapture,'Show file');
assert.equal(JSON.stringify(nativeCaptures.at(-1)),JSON.stringify({id:opaque,text:'capture-one'}));
assert.ok(!button(doneCapture,'Open in Wireshark'));
captureTimers=null;
captureFixture=null;
guest.state='off';
Object.assign(capabilities,{CreateTemplate:{available:true},CreateLinkedClone:{available:false},RemoveTemplate:{available:false}});
await clickButton(screen('vm'),'Storage');
const templateRoute='/v1/machines/'+opaque+'/template';
await clickButton(screen('vm'),'Make template');
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['POST',templateRoute,{}]));
guest.template={disk:'system.qcow2',sha256:'0'.repeat(64),originallyReadOnly:false};
capabilities.CreateLinkedClone={available:true};
capabilities.RemoveTemplate={available:false,reason:'Another machine uses this template.'};
const templateScreen=screen('vm');
assert.ok(walk(templateScreen).some(item=>item?.attrs?.id==='template-read-only'));
assert.ok(Object.hasOwn(button(templateScreen,'Remove template').attrs,'disabled'));
assert.ok(walk(templateScreen).includes('Another machine uses this template.'));
allowCut='Linked fixture';
await clickButton(templateScreen,'New linked clone');
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['POST','/v1/machines/'+opaque+'/linked-clones',{name:'Linked fixture'}]));
capabilities.RemoveTemplate={available:true};
allowCut=true;
await clickButton(screen('vm'),'Remove template');
assert.equal(guestRequests.at(-1)[0],'DELETE');
assert.equal(guestRequests.at(-1)[1],templateRoute);
allowCut=false;
guest.template=undefined;
// Throwaway mode: the switch asks the service, and the labels say what happens to changes.
capabilities.EditThrowaway={available:true};
const throwawaySwitch=tree=>walk(tree).find(item=>item?.attrs?.id==='throwaway-switch');
const normalStorage=screen('vm');
assert.ok(!Object.hasOwn(throwawaySwitch(normalStorage).attrs,'checked')&&!Object.hasOwn(throwawaySwitch(normalStorage).attrs,'disabled'));
assert.ok(!walk(normalStorage).some(text => String(text).includes('Changes are discarded at power-off')));
const throwawayField={checked:true};
await throwawaySwitch(normalStorage).attrs.onchange({currentTarget:throwawayField});
assert.equal(JSON.stringify(guestRequests.at(-1)),JSON.stringify(['PATCH','/v1/machines/'+opaque,{throwaway:true}]));
assert.equal(throwawayField.checked,false);
guest.throwaway=true;
const throwawayStorage=screen('vm');
assert.ok(Object.hasOwn(throwawaySwitch(throwawayStorage).attrs,'checked'));
assert.ok(walk(throwawayStorage).some(text => String(text).includes('Changes are discarded at power-off while Secwiz VM is open')));
assert.ok(walk(screen('library')).includes('Throwaway'));
const stoppedOnly='Throwaway mode can be changed on a stopped QEMU or Hyper-V machine that is not a template.';
capabilities.EditThrowaway={available:false,reason:stoppedOnly};
guest.state='running';
const throwawayRun=screen('vm');
assert.ok(Object.hasOwn(throwawaySwitch(throwawayRun).attrs,'disabled'));
assert.ok(walk(throwawayRun).includes(stoppedOnly));
assert.ok(walk(throwawayRun).includes('Disk export is unavailable during a throwaway run.'));
guest.throwaway=undefined;
delete capabilities.EditThrowaway;
assert.ok(!walk(screen('library')).includes('Throwaway'));
guest.state='running';
guest.registration=undefined;
await clickButton(screen('vm'),'Guest tools');
guest.family='android';assert.ok(walk(screen('vm')).includes('Android guests have no guest agent.'));
Object.assign(guest,{engine:'Hyper-V',family:undefined,addressSource:'not reported by the guest',ip:'192.0.2.42'});
await clickButton(screen('vm'),'Storage');
guest.state='paused';const pausedView=screen('vm');assert.ok(!button(pausedView,'Send Ctrl+Alt+Del'));
allowCut=false;await clickButton(pausedView,'Power off');assert.equal(cuts(),2);
assert.match(asks.at(-1)[1],/briefly resumes this paused machine before cutting power/);assert.match(asks.at(-1)[1],/Unsaved/);
// Exercise installer key eligibility, the wizard's opt-out and both start entry points.
const bootChoice=tree=>walk(tree).find(node=>node?.tag==='label'&&node.children.includes('Automatically press Enter to boot from the installer image'))?.children[0];
Object.assign(guest,{state:'off',family:'windows',os:'Windows 10'});
const diskReason='The installer key requires an unused Windows machine with a new empty disk.';
Object.assign(capabilities,{Start:{available:true},Console:{available:true},PressKeyAtBoot:{available:false,reason:diskReason}});
assert.ok(!bootChoice(screen('library'))&&!bootChoice(screen('vm')));
assert.ok(walk(screen('vm')).includes(diskReason));
assert.ok(!walk(screen('library')).includes(diskReason));
await clickButton(screen('library'),'Start');
assert.equal(guestRequests.at(-1)[2].pressKeyAtBoot,false);
guest.family='linux';assert.ok(!walk(screen('vm')).includes(diskReason));
guest.family='windows';guest.state='running';assert.ok(!walk(screen('vm')).includes(diskReason));
guest.state='off';
capabilities.PressKeyAtBoot={available:true};
assert.ok(Object.hasOwn(bootChoice(screen('library')).attrs,'checked'));
assert.ok(Object.hasOwn(bootChoice(screen('vm')).attrs,'checked'));
Object.assign(shellState.host,{logical:8,ramGb:16,maxDiskGb:128});
shellState.networks[0].mode='NAT';
app.register('guard',{issue:()=>''});app.go=()=>{};
async function submitWizard(tree) {
  walk(tree).find(item=>item?.tag==='form').attrs.onsubmit({preventDefault(){},currentTarget:{querySelectorAll:()=>[]}});
  await new Promise(resolve=>setImmediate(resolve));
  return screen('newvm');
}
let wizard=screen('newvm');
const choices=walk(wizard).filter(item=>item?.tag==='input'&&item.attrs.name==='guest-system');
choices[2].attrs.onchange({});
wizard=screen('newvm');
walk(wizard).find(item=>item?.attrs?.id==='new-name').attrs.oninput({target:{value:'Installer test'}});
wizard=await submitWizard(wizard);
await clickButton(wizard,'Choose installer image');
for(let i=0;i<3;i++)wizard=await submitWizard(screen('newvm'));
assert.ok(Object.hasOwn(bootChoice(wizard).attrs,'checked'));
bootChoice(wizard).attrs.onchange({target:{checked:false}});
await submitWizard(wizard);
assert.equal(guestRequests.at(-1)[1],'/v1/machines');
assert.equal(guestRequests.at(-1)[2].family,'windows');
assert.equal(Object.hasOwn(bootChoice(screen('vm')).attrs,'checked'),false);
await clickButton(screen('library'),'Start');
assert.equal(guestRequests.at(-1)[2].pressKeyAtBoot,false);
assert.ok(Object.hasOwn(bootChoice(screen('vm')).attrs,'checked'));
let releaseConsole;openingConsole=new Promise(resolve=>{releaseConsole=resolve;});
const countStarts=()=>guestRequests.filter(row=>row[1].endsWith('/start')).length;
const firstCount=countStarts();
await clickButton(screen('vm'),'Start and open console');
assert.ok(walk(screen('vm')).includes('Starting the machine with the 12-second installer key window…'));
assert.ok(Object.hasOwn(button(screen('vm'),'Start and open console').attrs,'disabled'));
await clickButton(screen('library'),'Start');
assert.equal(countStarts(),firstCount);
releaseConsole();await new Promise(resolve=>setImmediate(resolve));
assert.equal(countStarts(),firstCount+1);assert.equal(guestRequests.at(-1)[2].pressKeyAtBoot,true);
assert.equal(noticesFromGuest.at(-1),bootMessage);
shellState.events.push({kind:'installer boot key',message:opaque+'2: another machine'});
assert.ok(walk(screen('vm')).includes('Last installer boot attempt · '+bootMessage));
// Configure an engine through the owner picker, then use its fixed Android profile.
shellState.online=true;
shellState.qemu={available:false,path:null,version:null,reason:'Choose the executable in Settings.'};
let android=screen('newvm');
walk(android).filter(node=>node?.attrs?.name==='guest-system')[4].attrs.onchange({});
android=screen('newvm');
const engineRadio=(tree,name)=>walk(tree).find(node=>node?.attrs?.name==='guest-engine'&&node.attrs.value===name);
assert.ok(Object.hasOwn(engineRadio(android,'Hyper-V').attrs,'checked'));
assert.ok(Object.hasOwn(engineRadio(android,'QEMU').attrs,'disabled'));
assert.ok(walk(android).includes('QEMU is not set up on this PC. Choose the executable in Settings.'));
const picks=()=>guestRequests.filter(row=>row[1]==='/v1/settings/qemu');
await clickButton(screen('settings'),'Choose and verify executable');assert.equal(picks().length,0);
chosenExe='C:\\verification\\qemu-system-x86_64.exe';
await clickButton(screen('settings'),'Choose and verify executable');
assert.equal(picks().length,1);assert.equal(picks()[0][0],'PUT');assert.equal(picks()[0][2].path,chosenExe);
assert.ok(walk(screen('settings')).includes('QEMU fixture'));
android=screen('newvm');
engineRadio(android,'QEMU').attrs.onchange({});
android=screen('newvm');
walk(android).find(item=>item?.attrs?.id==='new-name').attrs.oninput({target:{value:'Android fixture'}});
android=await submitWizard(android);
assert.ok(button(android,'Continue').disabled);
await clickButton(android,'Choose installer image');
android=await submitWizard(screen('newvm'));
assert.ok(!walk(android).some(item=>item?.attrs?.id==='new-cpu'||item?.attrs?.id==='new-ram'));
android=await submitWizard(android);assert.ok(walk(android).includes('QEMU user-mode NAT'));
android=await submitWizard(android);assert.ok(walk(android).includes('QEMU · WHPX required'));
await submitWizard(android);
const created=guestRequests.at(-1)[2];
assert.deepEqual([created.engine,created.family,created.vcpu,created.ramGb,created.net,created.secureBoot],['QEMU','android',1,2,'nat',false]);
assert.ok(created.diskGb>0&&created.isoPath);
Object.assign(guest,{engine:'QEMU',family:'android',registration:'registered'});
Object.assign(capabilities,{Console:{available:false,reason:'QEMU opens its own display.'},EditHardware:{available:false,reason:'Fixed QEMU hardware.'},
  EditStorage:{available:false,reason:'The QEMU disk and image are fixed.'},ListSnapshots:{available:false,reason:'Snapshots unavailable for this engine.'}});
const tab=async label=>{await clickButton(screen('vm'),label);return screen('vm');};
shellState.qemu.openSeparateWindow=false;
assert.ok(walk(await tab('Overview')).includes('Open the Console tab for the live display.'));
assert.ok(!walk(screen('vm')).some(text=>typeof text==='string'&&text.includes('Ctrl+Alt+G')));
assert.ok(walk(await tab('Console')).includes('Start the machine to see its guest display.'));
shellState.qemu.openSeparateWindow=true;
assert.ok(walk(await tab('Overview')).some(text=>typeof text==='string'&&text.includes('Ctrl+Alt+G')));
const hw=await tab('Hardware');assert.ok(walk(hw).includes('Fixed QEMU hardware.'));assert.ok(!button(hw,'Save hardware'));
const preSnapshots=reads.filter(path=>path.endsWith('/snapshots')).length;
assert.ok(walk(await tab('Snapshots')).includes('Snapshots unavailable for this engine.'));
assert.equal(reads.filter(path=>path.endsWith('/snapshots')).length,preSnapshots);
const storageView=await tab('Storage');await new Promise(resolve=>setImmediate(resolve));
assert.ok(!button(storageView,'Choose installer image'));assert.ok(walk(storageView).includes('The QEMU disk and image are fixed.'));
capabilities.EditStorage={available:true};
androidStorage={disks:[],isoPath:'C:/fixture.iso',originalInstaller:'C:/fixture.iso',bootFirst:'image',canEditMedia:true,canEditBoot:false};
const removable=await tab('Storage');await new Promise(resolve=>setImmediate(resolve));
await clickButton(removable,'Remove installer disc');assert.equal(guestRequests.at(-1)[2].isoPath,null);
androidStorage.isoPath=null;androidStorage.bootFirst='disk';
const ejected=await tab('Storage');await new Promise(resolve=>setImmediate(resolve));
await clickButton(ejected,'Reattach installer disc');assert.equal(guestRequests.at(-1)[2].isoPath,'C:/fixture.iso');
const qemuNetwork=walk(await tab('Network'));
assert.ok(qemuNetwork.includes('QEMU user-mode NAT'));
assert.ok(qemuNetwork.some(text=>typeof text==='string'&&text.includes('See all Wi-Fi networks and select VirtWifi')));

// A disk import keeps an unknown firmware choice open and accepts the supplied one.
const transfersCalled=[];
const choice='C:/fixture/import.vdi';
const previousNative=machineApi.native;
machineApi.native=async name=>name==='pickDisk'?choice:name==='pickExportFolder'?'C:/exports':previousNative(name);
machineApi.diskRequest=async(method,path,body)=>{
  transfersCalled.push([method,path,body]);
  if(path.endsWith('/inspect'))return {format:'vdi',bytes:8388608,firmware:null};
  if(method==='DELETE')return {id:'job1',kind:'import',state:'cancelling',percent:21};
  return {id:'job1',kind:path.endsWith('/import')?'import':'export',machineId:opaque,state:'running',percent:21};
};
let imported=screen('diskimport');
await clickButton(imported,'Choose disk');
imported=screen('diskimport');
assert.ok(walk(imported).includes('vdi'));
assert.ok(walk(imported).includes('Choose the firmware the original system used.'));
walk(imported).find(n=>n?.attrs?.id==='import-name').attrs.oninput({target:{value:'Imported Linux'}});
const firmware=walk(imported).find(n=>n?.tag==='select'&&walk(n).includes('Legacy BIOS · QEMU'));
firmware.attrs.onchange({target:{value:'uefi'}});
walk(imported).find(n=>n?.tag==='form').attrs.onsubmit({preventDefault(){}});
await new Promise(resolve=>setImmediate(resolve));
assert.equal(transfersCalled.at(-1)[2].firmware,'uefi');assert.equal(transfersCalled.at(-1)[2].path,choice);
await clickButton(imported,'Cancel conversion');assert.equal(transfersCalled.at(-1)[0],'DELETE');
const exp=app.exportDiskPanel({...guest,state:'off',registration:'registered',snaps:0});
await clickButton(exp,'Choose export folder');
walk(exp).find(n=>n?.tag==='form').attrs.onsubmit({preventDefault(){}});
await new Promise(resolve=>setImmediate(resolve));
assert.equal(transfersCalled.at(-1)[1],'/v1/transfers/export');assert.equal(transfersCalled.at(-1)[2].folder,'C:/exports');
assert.ok(!button(app.exportDiskPanel({...guest,state:'running'}),'Export disk'));
// A new Linux machine can choose BIOS, adjust hardware and proceed without an installer.
let legacy=screen('newvm');
walk(legacy).filter(node=>node?.attrs?.name==='guest-system')[0].attrs.onchange({});
legacy=screen('newvm');engineRadio(legacy,'QEMU').attrs.onchange({});
legacy=screen('newvm');walk(legacy).find(n=>n?.attrs?.id==='new-name').attrs.oninput({target:{value:'Legacy Linux'}});
legacy=await submitWizard(legacy);assert.ok(!button(legacy,'Continue').disabled);
legacy=await submitWizard(legacy);
const cpuField=walk(legacy).find(n=>n?.attrs?.id==='new-cpu'),ramField=walk(legacy).find(n=>n?.attrs?.id==='new-ram');
assert.equal(cpuField.attrs.max,'4');assert.equal(ramField.attrs.max,'8');
cpuField.attrs.oninput({target:{valueAsNumber:2}});ramField.attrs.oninput({target:{valueAsNumber:3}});
legacy=await submitWizard(legacy);legacy=await submitWizard(legacy);
assert.ok(walk(legacy).includes('QEMU · legacy BIOS · WHPX required'));
await submitWizard(legacy);
const bios=guestRequests.at(-1)[2];
assert.deepEqual([bios.engine,bios.family,bios.vcpu,bios.ramGb,bios.net,bios.secureBoot,bios.isoPath],['QEMU','linux',2,3,'nat',false,undefined]);
shellState.qemu.armAvailable=false;
let armTree=screen('newvm');
const armChoice=tree=>walk(tree).filter(node=>node?.attrs?.name==='guest-system')[5];
assert.ok(armChoice(armTree).attrs.disabled!==undefined);
shellState.qemu.armAvailable=true;
armChoice(screen('newvm')).attrs.onchange({});
armTree=screen('newvm');
assert.ok(walk(armTree).includes(app.armLabel)&&walk(armTree).includes(app.armHint));
assert.ok(!walk(armTree).some(node=>node?.attrs?.name==='guest-engine'&&node.attrs.value==='Hyper-V'));
walk(armTree).find(node=>node?.attrs?.id==='new-name').attrs.oninput({target:{value:'Arm installer test'}});
armTree=await submitWizard(armTree);
assert.ok(walk(armTree).some(value=>typeof value==='string'&&value.includes('arm64 UEFI installer')));
armTree=await submitWizard(armTree);
assert.equal(walk(armTree).find(node=>node?.attrs?.id==='new-cpu').attrs.max,'2');
assert.equal(walk(armTree).find(node=>node?.attrs?.id==='new-ram').attrs.max,'4');
armTree=await submitWizard(armTree);armTree=await submitWizard(armTree);
assert.ok(walk(armTree).includes(app.armLabel));
await submitWizard(armTree);
const armGuest=guestRequests.at(-1)[2];
assert.deepEqual([armGuest.engine,armGuest.architecture,armGuest.family,armGuest.vcpu,armGuest.ramGb],['QEMU','aarch64','linux',1,2]);
Object.assign(guest,{engine:'QEMU',architecture:'aarch64',family:'linux',accel:false});
assert.ok(walk(await tab('Hardware')).includes(app.armHint));
assert.ok(walk(await tab('Hardware')).includes(app.armLabel));
const customArm=walk(screen('newvm')).filter(node=>node?.attrs?.name==='guest-system').at(-1);
customArm.attrs.onchange({});
let custom=screen('newvm');
walk(custom).find(node=>node?.attrs?.id==='new-name').attrs.oninput({target:{value:'Custom Arm'}});
walk(custom).find(node=>node?.attrs?.id==='new-custom').attrs.oninput({target:{value:'Other aarch64'}});
custom=await submitWizard(custom);custom=await submitWizard(custom);
assert.equal(walk(custom).find(node=>node?.attrs?.id==='new-cpu').attrs.value,'1');

const installerId='debian-arm64-fixture', installerFile='debian-arm64-fixture.iso';
const wizardRoute='catalog/'+installerId;
let installerState='paused';
machineApi.catalog=async()=>({entries:[{
  id:installerId,name:'Debian',version:'13',edition:'Network installer',architecture:'aarch64',
  family:'linux',fileName:installerFile,engine:'QEMU',allowedEngines:['QEMU'],vcpu:1,ramGb:2,diskGb:16,
}],transfers:[{id:installerId,state:installerState}]});
const catalogWizard=()=>screen('newvm',wizardRoute);
catalogWizard();
await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(catalogWizard()).includes('The catalog installer needs to be verified before it can be used.'));
screen('newvm');
installerState='verified';
catalogWizard();
await new Promise(resolve=>setImmediate(resolve));
async function submitCatalog(tree) {
  walk(tree).find(node=>node?.tag==='form').attrs.onsubmit({preventDefault(){},currentTarget:{querySelectorAll:()=>[]}});
  await new Promise(resolve=>setImmediate(resolve));
}
let createFromCatalog=catalogWizard();
assert.ok(!walk(createFromCatalog).some(node=>node?.attrs?.name==='guest-system'));
await submitCatalog(createFromCatalog);
createFromCatalog=catalogWizard();
assert.ok(walk(createFromCatalog).includes(installerFile));
assert.ok(!button(createFromCatalog,'Choose installer image'));
await submitCatalog(createFromCatalog);
createFromCatalog=catalogWizard();
for(const [field,value] of [['cpu',2],['ram',3],['disk',12]]) {
  walk(createFromCatalog).find(node=>node?.attrs?.id==='new-'+field).attrs.oninput({target:{valueAsNumber:value}});
}
await submitCatalog(createFromCatalog);
await submitCatalog(catalogWizard());
createFromCatalog=catalogWizard();
assert.ok(walk(createFromCatalog).includes('2 vCPU · 3 GiB RAM'));
assert.ok(walk(createFromCatalog).includes('Stopped'));
await submitCatalog(createFromCatalog);
const [catalogMethod,catalogEndpoint,catalogPayload]=guestRequests.at(-1);
assert.equal(catalogMethod,'POST');
assert.equal(catalogEndpoint,'/v1/machines');
assert.deepEqual(JSON.parse(JSON.stringify(catalogPayload)),{
  name:'Debian 13 aarch64',net:'nat',vcpu:2,ramGb:3,diskGb:12,catalogId:installerId,engine:'QEMU',
});

Object.assign(guest,{engine:'Hyper-V',architecture:'x86_64',family:'windows',state:'running'});
let guestPasswordField, sentGuestCommand, cancelGuestCommand=false;
app.dialog=async (title,body)=>{
  assert.equal(title,'Run guest command');
  const field=id=>walk(body).find(node=>node?.attrs?.id===id);
  field('guest-command-user').value='synthetic-user';
  guestPasswordField=field('guest-command-password');
  assert.equal(guestPasswordField.attrs.type,'password');
  assert.ok(!guestPasswordField.attrs['data-draft']);
  guestPasswordField.value='synthetic-ui-only-password';
  field('guest-command-arguments').value='["hostname.exe"]';
  field('guest-command-timeout').value='30';
  return !cancelGuestCommand;
};
machineApi.guestRequest=async (id,operation,body)=>{
  assert.equal(id,opaque);
  if(operation==='ssh-key')return {publicKey:'ssh-ed25519 synthetic-public-line'};
  assert.equal(operation,'exec');
  sentGuestCommand=JSON.parse(JSON.stringify(body));
  return {channel:'powershell-direct',exitCode:0,stdout:'fixture guest'};
};
await clickButton(await tab('Guest tools'),'Run guest command');
assert.deepEqual(sentGuestCommand,{argv:['hostname.exe'],timeoutSec:30,
  credentials:{username:'synthetic-user',password:'synthetic-ui-only-password'}});
assert.equal(guestPasswordField.value,'');
assert.ok(walk(screen('vm')).includes('PowerShell Direct'));
assert.ok(walk(screen('vm')).includes('fixture guest'));
assert.ok(!walk(screen('vm')).includes('synthetic-ui-only-password'));
cancelGuestCommand=true;sentGuestCommand=null;
await clickButton(screen('vm'),'Run guest command');
assert.equal(sentGuestCommand,null);
assert.equal(guestPasswordField.value,'');
guest.family='linux';
await clickButton(screen('vm'),'Show SSH enrollment key');
// A textarea shows its text content; a value attribute would leave it empty in a real browser.
assert.ok(walk(screen('vm')).some(node=>node?.tag==='textarea'&&node.children.includes('ssh-ed25519 synthetic-public-line')&&!('value' in node.attrs)));


Object.assign(guest,{engine:'QEMU',family:'linux',state:'running'});
Object.assign(capabilities,{ListSnapshots:{available:true},Snapshot:{available:true},SnapshotWithMemory:{available:false}});
const previousGet=machineApi.get;
machineApi.get=async path=>path.endsWith('/snapshots')?
  [{id:'guest-checkpoint',name:'Snapshot during writes',parent:null,withMemory:false,consistency:'guest-quiesced'}]:previousGet(path);
const checkpoints=await tab('Snapshots');
await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(checkpoints).includes('Guest filesystems quiesced'));
assert.ok(walk(checkpoints).includes('Disk only'));
assert.ok(button(checkpoints,'Take snapshot'));
assert.ok(!walk(checkpoints).some(node=>node?.attrs?.id==='snapshot-memory'));
Object.assign(guest,{engine:'Hyper-V'});
capabilities.SnapshotWithMemory={available:true};
const diskOnlyByDefault=walk(screen('vm')).find(node=>node?.attrs?.id==='snapshot-memory');
assert.ok(diskOnlyByDefault&&!Object.hasOwn(diskOnlyByDefault.attrs,'checked'));

// Exercise encrypted backup controls through their normal Storage and Settings entry points.
let backupBusy = false, backupLast = null;
const snapshotFixture = {id:'a'.repeat(64),machineId:guest.id,time:'2026-11-20T18:00:00Z'};
const beforeBackups = machineApi.get;
machineApi.get = async path => path.startsWith('/v1/backups') ? {
  configured:true,snapshots:[snapshotFixture],current:backupBusy ? {kind:'backup',seconds:2} : null,last:backupLast
} : path === '/v1/settings/backup' ? {configured:true,hashes:{'restic.exe':'a'.repeat(64),'age.exe':'b'.repeat(64),'age-plugin-yubikey.exe':'c'.repeat(64)},paths:{tools:'tools',repository:'repo',identity:'key-file',encryptedPassword:'password-file'}} : beforeBackups(path);
async function backupTab() { const tree=await tab('Storage');await new Promise(resolve=>setImmediate(resolve));return tree; }
Object.assign(guest,{state:'off',registration:'registered',linkedFrom:'fixture-template',snaps:0,tpm:false});
const linkedBackup = await backupTab();
assert.ok(Object.hasOwn(button(linkedBackup,'Back up now').attrs,'disabled'));
assert.ok(walk(linkedBackup).some(v=>typeof v==='string' && v.includes('depend on their template')));
guest.linkedFrom=null;
const backupReady = await backupTab();
assert.ok(!Object.hasOwn(button(backupReady,'Back up now').attrs,'disabled'));
await clickButton(backupReady,'Back up now');
assert.ok(guestRequests.some(([m,p,b])=>m==='POST'&&p==='/v1/backups'&&b.machineId===guest.id));
backupBusy=true;
assert.ok(Object.hasOwn(button(await backupTab(),'Restore as a new machine').attrs,'disabled'));
backupBusy=false;
backupLast={kind:'restore',machineId:guest.id,state:'pending',message:'Waiting to clear the restore marker.'};
const pendingRestore=await backupTab();
assert.ok(walk(pendingRestore).includes(backupLast.message));
assert.ok(Object.hasOwn(button(pendingRestore,'Restore as a new machine').attrs,'disabled'));
backupLast={kind:'restore',machineId:guest.id,state:'failed',reason:'key_step',
  message:'The YubiKey step did not finish (PIN or touch). Nothing was restored. Try again.'};
assert.ok(walk(await backupTab()).includes(backupLast.message));
backupLast=null;
const settingsBackup=screen('settings');await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(settingsBackup).includes('Pinned SHA-256 values'));
assert.ok(walk(settingsBackup).includes('a'.repeat(64)));
await clickButton(settingsBackup,'Refresh backup list');
assert.ok(guestRequests.some(([m,p])=>m==='POST' && p==='/v1/backups/refresh'));
app.dialog=async()=>'Backup copy';
await clickButton(settingsBackup,'Restore as a new machine');
assert.ok(guestRequests.some(([m,p,b])=>m==='POST'&&p==='/v1/backups/restore'&&b.snapshotId===snapshotFixture.id&&b.name==='Backup copy'));
await clickButton(settingsBackup,'Pin tools and save backup settings');
assert.ok(guestRequests.some(([m,p,b])=>m==='PUT'&&p==='/v1/settings/backup'&&b.encryptedPassword==='password-file'));

Object.assign(guest,{engine:'QEMU',family:'linux',state:'running'});
const appCalls=[], appNavigation=[];
const expectedCommand=['/usr/bin/apt-get','install','git'];
machineApi.appCatalog=async()=>[
  {id:'git',name:'Git',category:'Developer',description:'Version control',licence:'GPL-2.0-only',
    publisher:'Git project',recipes:{debian:{label:'Distro'}}},
  {id:'ollama',name:'Ollama',category:'AI tools',description:'Local models',licence:'MIT',
    publisher:'Ollama',label:'Reference',recipes:{}},
];
machineApi.appMachines=async()=>[
  {id:'blocked',name:'Offline guest',family:'linux',engine:'QEMU',reason:'This isolated throwaway machine cannot reach package sources.'},
  {id:guest.id,name:guest.name,family:'linux',engine:'QEMU'},
];
machineApi.appPreview=async(...args)=>{
  appCalls.push(['preview',...args]);
  return {previewId:'preview-fixture',steps:[{title:'Install packages',argv:expectedCommand,timeoutSec:120}]};
};
machineApi.appRun=async(...args)=>{appCalls.push(['run',...args]);return {id:'preview-fixture'};};
machineApi.appJob=async()=>({id:'preview-fixture',app:'Git',state:'failed',message:'Step 1 failed. Install packages (exit code 87)',
  log:[{step:1,title:'Install packages',state:'failed',output:{stderr:'fixture failure'}}]});
app.go=(...args)=>appNavigation.push(args);
let confirmApp=false;
app.dialog=async(title,body,confirm)=>{
  if(confirm==='Continue') {
    const selector=walk(body).find(node=>node?.attrs?.id==='app-machine');
    assert.equal(selector.children.length,2);
    assert.ok(walk(body).some(text=>typeof text==='string'&&text.includes('isolated throwaway machine')));
    selector.value=guest.id;
    return true;
  }
  assert.equal(title,'Review guest commands');
  const commands=walk(body).find(node=>node?.tag==='textarea');
  assert.ok(Object.hasOwn(commands.attrs,'readonly'));
  assert.ok(commands.children[0].includes(JSON.stringify(expectedCommand,null,2)));
  assert.ok(['Install in ','Uninstall from '].some(prefix=>confirm===prefix+guest.name));
  return confirmApp;
};
const marketplace=screen('os-catalog');
await clickButton(marketplace,'Apps & AI tools');
const categoryFilter=walk(marketplace).find(node=>node?.attrs?.id==='app-catalog-category');
categoryFilter.value='AI tools'; categoryFilter.attrs.onchange({});
assert.ok(walk(marketplace).includes('Reference'));
assert.ok(!button(marketplace,'Install'));
categoryFilter.value=''; categoryFilter.attrs.onchange({});
const appSearch=walk(marketplace).find(node=>node?.attrs?.id==='app-catalog-search');
appSearch.value='git'; appSearch.attrs.oninput({});
assert.ok(!walk(marketplace).includes('Ollama'));
await clickButton(marketplace,'Install');
assert.deepEqual(appCalls.map(call=>call[0]),['preview']);
confirmApp=true;
await clickButton(marketplace,'Install');
assert.deepEqual(appCalls.map(call=>call[0]),['preview','preview','run']);
assert.equal(JSON.stringify(appCalls.at(-1)),JSON.stringify(['run',guest.id,'git','preview-fixture',{}]));
await clickButton(marketplace,'Uninstall');
assert.equal(appCalls.at(-2)[3],'uninstall');
assert.equal(JSON.stringify(appNavigation.at(-1)), JSON.stringify(['vm',{id:guest.id}]));
const machineWithAppLog=screen('vm');
await new Promise(resolve=>setImmediate(resolve));
assert.ok(walk(machineWithAppLog).some(node=>node?.textContent==='Git — Step 1 failed. Install packages (exit code 87)'));
assert.ok(walk(machineWithAppLog).includes('fixture failure'));
console.log('PASS · Marketplace sections, app search and category filters, guest checks, read-only command preview, explicit install and uninstall, and the machine app log.');

// Ready to run: the default Marketplace section, honest labels, Get, and Launch for both first-boot kinds.
const readyCalls=[];
const readyImage=(id,extra)=>({id,version:'1',edition:'Ready to run',note:'Fixture image.',sourceHost:'publisher.example',
  bytes:439484416,diskGb:20,spaceNeeded:4294967296,vcpu:2,ramGb:2,template:null,preparing:null,outcome:null,...extra});
readyFixture={freeBytes:5e11,qemu:{available:true},images:[
  readyImage('cloud-fixture',{name:'Cloud',publisher:'Cloud project',desktop:false,firstBoot:'cloud-init',defaultUser:null,verification:'Checksum',
    download:{state:'idle',bytes:0,totalBytes:439484416,canResume:false}}),
  readyImage('desktop-fixture',{name:'Desk',publisher:'Desk project',desktop:true,firstBoot:'default-login',defaultUser:'kali',verification:'Signed',
    download:{state:'verified',bytes:439484416,totalBytes:439484416},template:{id:'vm-template',name:'Desk template',machines:2}}),
  readyImage('cloud-ready',{name:'Lab',publisher:'Lab project',desktop:false,firstBoot:'cloud-init',defaultUser:null,verification:'Signed',
    download:{state:'verified',bytes:439484416,totalBytes:439484416},template:{id:'vm-lab',name:'Lab template',machines:0}}),
]};
machineApi.catalogDownload=async(id,method)=>{readyCalls.push(['download',id,method]);return {state:'downloading'};};
const readyMarket=screen('os-catalog');
// The Marketplace keeps its last section between visits; choose Ready to run explicitly.
await clickButton(readyMarket,'Ready to run');
for(let i=0;i<3;i++)await new Promise(resolve=>setImmediate(resolve));
assert.ok(reads.includes('/v1/ready'));
assert.ok(walk(readyMarket).includes('Ready to run'));
assert.ok(walk(readyMarket).includes('Publisher default: kali / kali'));
assert.ok(walk(readyMarket).includes('Pinned SHA-256, checked on download'));
assert.ok(walk(readyMarket).includes('Publisher signature and SHA-256, checked on download'));
await clickButton(readyMarket,'Get');
// Get is one request: the service downloads, verifies and then prepares the image.
assert.ok(guestRequests.some(([m,p,b])=>m==='POST'&&p==='/v1/ready/cloud-fixture/prepare'&&JSON.stringify(b)==='{}'));
assert.equal(readyCalls.length,0);
const launchTargets=walk(readyMarket).filter(item=>item?.tag==='button'&&item.children.includes('Launch'));
assert.equal(launchTargets.length,2);
app.dialog=async(title,body,confirm)=>{
  if(confirm==='Create machine'){
    assert.ok(!walk(body).some(node=>node?.tag==='input'&&node.attrs.type==='password'),'default-login images ask for no password');
    return true;
  }
  return true;
};
launchTargets[0].attrs.onclick({stopPropagation(){},preventDefault(){}});
await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
const desktopLaunch=guestRequests.find(([m,p])=>m==='POST'&&p==='/v1/ready/desktop-fixture/launch');
assert.ok(desktopLaunch);
assert.equal(JSON.stringify(Object.keys(desktopLaunch[2])),JSON.stringify(['name']));
assert.ok(guestRequests.some(([m,p])=>m==='POST'&&p==='/v1/machines/fixture-ready/start'));
let shownPassword=null;
app.dialog=async(title,body,confirm)=>{
  if(confirm==='Create machine'){
    const inputs=walk(body).filter(node=>node?.tag==='input');
    const userInput=inputs.find(node=>node.attrs.placeholder==='labuser');
    assert.ok(userInput,'cloud images ask for a user name');
    userInput.value='labuser';
    return true;
  }
  if(confirm==='I saved it'){shownPassword=walk(body).find(text=>text==='Generated-Fixture-23');return true;}
  return true;
};
launchTargets[1].attrs.onclick({stopPropagation(){},preventDefault(){}});
for(let i=0;i<4;i++)await new Promise(resolve=>setImmediate(resolve));
const cloudLaunch=guestRequests.find(([m,p])=>m==='POST'&&p==='/v1/ready/cloud-ready/launch');
assert.ok(cloudLaunch);
assert.equal(cloudLaunch[2].user,'labuser');
assert.equal(cloudLaunch[2].generatePassword,true);
assert.ok(!('password' in cloudLaunch[2]));
assert.equal(shownPassword,'Generated-Fixture-23');
const defaultLoginVm={...guest,id:'fixture-default',name:'Desk 3',ready:{image:'desktop-fixture',defaultLogin:'kali',seed:false}};
const notice=app.defaultLoginNotice(defaultLoginVm);
assert.ok(walk(notice).includes('Change the default password'));
assert.ok(button(notice,'I changed it myself'));
assert.equal(app.defaultLoginNotice({...defaultLoginVm,ready:{image:'desktop-fixture',seed:false}}),null);
const throwawayNotice=app.defaultLoginNotice({...defaultLoginVm,throwaway:true});
assert.ok(Object.hasOwn(button(throwawayNotice,'I changed it myself').attrs,'disabled'),'a throwaway machine cannot confirm a discarded password');
assert.ok(walk(throwawayNotice).includes('Throwaway mode discards a changed password at power-off. Turn it off first to keep a new password.'));
console.log('PASS · Ready to run: default section, honest verification labels, Get, Launch without a password for default-login images, generated password shown once for cloud images, and the default-login notice.');

console.log('PASS · encrypted backup settings, availability, list and restore controls, checkpoint consistency, Hyper-V guest commands and SSH enrollment, emulated Arm and legacy BIOS wizards, disk import, export and cancellation, UI source checks, service data shapes, opaque IDs, refusal, mutation refresh, event polling, focus and visibility, bridge eligibility, installed guest controls, installer key choices, QEMU setup and capability-driven Android profile, '+contrastPairs+' contrast pairs.');
