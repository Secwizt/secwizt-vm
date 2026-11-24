(function () {
  const S=window.SVB, h=S.h, api=S.api;
  const ns=(name,attrs,...children)=>h(name,{...attrs,xmlns:true},...children);
  let selectedId,networkId,networkDraft,adding=false;
  function focus(id){S.render();document.getElementById(id)?.focus();}
  function openAddForm() {
    networkDraft={name:'',mode:'Routed',subnet:'',adapterId:'',adapters:null,loading:false,saving:false,error:'',lookupError:''};
    adding=true;S.render();
    const name=document.getElementById('network-name');
    name.focus({preventScroll:true});
    name.form.scrollIntoView({block:'start',inline:'nearest'});
  }
  function map(v, select) {
    const lines = [], nodes = [], routerX = 56, hostX = 201, netX = 364, vmX = 554;
    const networks = S.data.networks.map(n => ({n, members:S.data.vms.filter(m => m.engine!=='QEMU'&&m.net===n.id)}));
    for(const vm of S.data.vms.filter(m=>m.engine==='QEMU'))networks.push({n:{name:'QEMU NAT',mode:'NAT',userMode:true},members:[vm]});
    let y = 14;
    for (const group of networks) {
      group.ys = group.members.map((_,i) => y + 18 + 44*i);
      group.y = (group.ys[0] ?? y+18) + Math.max(0, (group.members.length-1)*22);
      y += Math.max(1,group.members.length)*44+14;
    }
    const hostY = Math.round(y/2);
    function wire(x1,y1,x2,y2,highlight,traffic) {
      const bend = x1 === x2 ? x1-52 : (x1+x2)/2;
      const d = `M${x1} ${y1} C${bend} ${y1},${bend} ${y2},${x2} ${y2}`;
      lines.push(ns('path',{d,class:'net-wire' + (highlight ? ' chosen' : '') + (traffic ? ' traffic' : '')}));
      if (traffic) lines.push(ns('path',{d,class:'net-pulse'}), ns('circle',{r:3,class:'net-packet',style:`offset-path:path('${d}')`}));
      for (const [cx,cy] of [[x1,y1],[x2,y2]]) lines.push(ns('circle',{cx,cy,r:3.5,class:'net-port' + (highlight || traffic ? ' chosen' : '')}));
    }
    function landmark(x,cy,label,sub) {
      return ns('g',{}, ns('rect',{x:x-42,y:cy-22,width:84,height:44,rx:6,class:'net-box'}),
        ns('text',{x,y:cy-2,'text-anchor':'middle'},label), ns('text',{x,y:cy+13,'text-anchor':'middle',class:'net-tiny'},sub));
    }
    const chosenNet = networks.find(group=>group.members.some(m=>m.id===v?.id))?.n;
    const lanModes = ['Routed','NAT','Bridged'];
    if (S.data.host.router) wire(routerX+42,hostY,hostX-42,hostY,lanModes.includes(chosenNet?.mode),false);
    if (S.data.host.router) nodes.push(landmark(routerX,hostY,'Router',S.data.host.router));
    nodes.push(landmark(hostX,hostY,S.data.host.name || 'This PC',S.data.host.lan || ''));
    for (const {n,members,ys,y:ny} of networks) {
      const selected = n === chosenNet;
      wire(hostX+42,hostY,netX-69,ny,selected,false);
      nodes.push(ns('g',{},ns('rect',{x:netX-69,y:ny-21,width:138,height:42,rx:6,class:'net-box' + (selected ? ' chosen' : '')}),
        ns('title',{},n.name), ns('text',{x:netX,y:ny-1,'text-anchor':'middle'},abbrev(n.name,18)),ns('text',{x:netX,y:ny+14,'text-anchor':'middle',class:'net-tiny'},subnetLabel(n))));
      let previousLive = null;
      members.forEach((m,i) => {
        const my = ys[i], active = m.id === v?.id, live = m.state === 'running';
        wire(netX+69,ny,vmX-9,my,active,false);
        if (live && previousLive !== null) wire(vmX-7,my,vmX-7,previousLive,true,true);
        if (live) previousLive = my;
        nodes.push(ns('g',{id:'net-machine-'+m.id,role:'button',tabindex:0,'aria-pressed':String(active),'aria-label':m.name+', '+m.state,
          class:'net-machine' + (active ? ' selected' : ''),onclick:() => select(m), onkeydown:e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(m); }
          }}, ns('title',{},m.name+' · '+S.address(m)),ns('rect',{x:vmX-12,y:my-17,width:196,height:34,rx:6,class:'net-hit'}),
          ns('path',{d:`M${vmX} ${my-7}l2 5 5 2-5 2-2 5-2-5-5-2 5-2z`,class:'net-star'+(live?' live':'')}),
          ns('text',{x:vmX+14,y:my+4},abbrev(m.name,22))));
      });
    }
    // Keep peer traffic in the clear channel immediately to the left of the machine labels.
    return ns('svg',{class:'net-map',viewBox:`0 0 750 ${y}`,role:'group','aria-label':'Network topology. Select a machine to inspect its path.'},lines,nodes);
  }
  function abbrev(s,limit) { return s.length > limit ? s.slice(0,limit-1)+'…' : s; }
  function table(headers,rows) {
    return h('table',{class:'net-table'},h('thead',{},h('tr',{},headers.map(t=>h('th',{scope:'col'},t)))),
      h('tbody',{},rows.map(row=>h('tr',{},row.map(cell=>h('td',{},cell))))));
  }

  function subnetLabel(n) {
    if(n.userMode)return 'Assigned by QEMU';
    if(n.mode==='Bridged')return 'Router DHCP';
    return n.mode==='NAT'?'Assigned by Windows':n.subnet||'Unavailable';
  }
  function reasons(items) {
    return h('ul',{},items.map(reason=>h('li',{},reason)));
  }
  async function loadAdapters(draft) {
    if(draft.loading)return;
    draft.loading=true;draft.lookupError='';
    try {const result=await api.get('/v1/networks/bridge-adapters');draft.adapters=result.adapters;}
    catch(error){draft.lookupError=error.message;}
    finally {
      draft.loading=false;
      if(adding&&draft===networkDraft&&S.view==='networks')S.render(true);
    }
  }
  function addForm() {
    const draft=networkDraft;
    const name=h('input',{id:'network-name',required:true,maxlength:80,value:draft.name,oninput:e=>{draft.name=e.target.value;}});
    const modes=['Routed','Host-only','Isolated segment','Link-local','Bridged'];
    const mode=h('select',{id:'network-mode',onchange:e=>{
      draft.mode=e.target.value;draft.error='';focus('network-mode');
      if(draft.mode==='Bridged'&&!draft.adapters&&!draft.loading)void loadAdapters(draft);
    }},modes.map(v=>h('option',{value:v,selected:v===draft.mode},v)));
    const bridged=draft.mode==='Bridged';
    const fields=[h('label',{},'Name',name),h('label',{},'Mode',mode)];
    const eligible=(draft.adapters||[]).filter(a=>a.available);
    if(bridged) {
      if(!draft.adapters) {
        fields.push(h('p',{role:'status'},draft.lookupError||'Checking physical Ethernet adapters…'));
        if(draft.lookupError)fields.push(h('button',{class:'btn',type:'button',onclick:()=>loadAdapters(draft)},'Retry adapter discovery'));
      } else {
        fields.push(h('label',{},'Physical Ethernet adapter',h('select',{id:'bridge-adapter',required:true,onchange:e=>{draft.adapterId=e.target.value;focus('bridge-adapter');}},
          h('option',{value:'',selected:!draft.adapterId},'Select an Ethernet adapter'),eligible.map(a=>h('option',{value:a.id,selected:a.id===draft.adapterId},a.name)))));
        if(!eligible.length)fields.push(h('p',{},'No eligible wired Ethernet adapter was found.'));
        if(draft.adapters.length)fields.push(table(['Physical adapter','Bridge eligibility'],draft.adapters.map(item=>[
          item.name,item.available?(item.switchGuid?'Existing shared switch':'Ready for setup'):
            reasons(item.reasons?.length?item.reasons:[item.reason||'Windows could not verify this adapter.'])
        ])));
        const chosen=eligible.find(a=>a.id===draft.adapterId);
        if(chosen)fields.push(h('p',{class:'new-hint'},chosen.switchGuid?'The existing external switch '+chosen.switchName+' will be reused.':'A new external switch requires administrator setup. The host keeps access through the switch.'));
      }
    } else if(draft.mode==='Link-local') {
      fields.push(h('p',{class:'new-hint'},'Fixed addresses use 169.254.0.0/16. Host and guest traffic stays on this link. No internet or administrator setup.'));
    } else {
      fields.push(h('label',{},'Subnet (optional)',h('input',{id:'network-subnet',value:draft.subnet,placeholder:'Automatic',oninput:e=>{draft.subnet=e.target.value;}})));
      if(draft.mode==='Routed') fields.push(h('p',{class:'new-hint'},'Automatic routed networks use 10.77.0.0/16. Guest internet requires administrator setup. A subnet outside this range keeps local access only.'));
    }
    return h('form',{class:'net-form',onsubmit:async e=>{
      e.preventDefault();if(draft.saving)return;
      const data={name:draft.name.trim(),mode:draft.mode};
      draft.saving=true;draft.error='';
      try {
        if(bridged) {
          const adapter=eligible.find(a=>a.id===draft.adapterId);
          if(!adapter)throw Error('Select an available physical Ethernet adapter.');
          const action=adapter.switchGuid?'Reuse '+adapter.switchName+' on '+adapter.name+'?':'Prepare a bridged network on '+adapter.name+'?';
          const warning='Binding a new external switch can interrupt this PC’s network connection for a few seconds. The host keeps its connection through the switch.';
          if(!await S.dialog(action,h('p',{},warning),adapter.switchGuid?'Reuse switch':'Prepare bridge'))return;
          data.adapterId=adapter.id;data.confirmDisconnect=true;
        } else if(draft.mode!=='Link-local'&&draft.subnet.trim())data.subnet=draft.subnet.trim();
        const result=await api.action('POST','/v1/networks',data);
        if(networkDraft===draft) {
          networkId=result.id;adding=false;networkDraft=null;focus('net-edit-'+networkId);
          S.toast(bridged&&result.ready===false?'Bridge saved. Administrator setup is required.':'Network created.');
        }
      } catch(error){draft.error=error.message;}
      finally {draft.saving=false;if(adding&&networkDraft===draft&&S.view==='networks')S.render(true);}
    }},fields,h('button',{class:'btn',type:'submit',disabled:draft.saving||(bridged&&!eligible.some(a=>a.id===draft.adapterId))},'Create network'),
      h('button',{class:'btn',type:'button',disabled:draft.saving,onclick:()=>{adding=false;networkDraft=null;focus('net-add');}},'Cancel'),
      h('p',{class:'new-error',role:'status'},draft.error));
  }
  function details(n) {
    const path='/v1/networks/'+api.segment(n.id),leases=h('div',{role:'region','aria-label':'IPv4 leases'});
    const bridged=n.mode==='Bridged';
    const guestAddresses=bridged||n.mode==='NAT';
    if(guestAddresses) {
      const members=S.data.vms.filter(v=>v.engine!=='QEMU'&&v.net===n.id);
      leases.append(h('p',{},bridged?'The LAN router manages leases.':'Windows manages the Default Switch leases.'),
        members.length?table(['Machine','Guest IPv4'],members.map(v=>[v.name,S.address(v)])):h('p',{},'No machines on this network.'));
    }
    else S.fill(leases,()=>api.get(path+'/leases'),rows=>rows.length?
      table(['Machine','Fixed MAC','IPv4','State'],rows.map(row=>[S.data.vms.find(v=>v.net===n.id&&v.mac===row.mac)?.name || '—',row.mac,row.ip,row.state])):
      h('p',{},'No leases or reservations.'));
    const card=h('section',{class:'card'},h('h2',{},'DHCP · '+n.name),h('p',{class:'net-lead'},n.note),
      S.facts(bridged?[['DHCP authority','LAN router'],['Bridge status',n.ready?'Ready':n.bridgeCanSetup?'Setup required':'Unavailable']]:
        [['DHCP',n.dhcp],['Subnet',subnetLabel(n)],['Gateway',n.gateway],['Host address',n.hostAddress],['DNS service',n.dnsStatus||'Status unavailable'],['DNS address',n.dnsAddress],['Guest internet',n.mode==='Routed'?(n.natStatus||'Windows NAT has not been verified.'):null]]));
    if(n.mode==='Link-local')card.append(h('p',{class:'new-hint'},'This network uses fixed 169.254 addresses. It has no internet route and needs no administrator setup.'));
    else if(!bridged&&n.mode!=='NAT')card.append(h('p',{class:'new-hint'},'When the DHCP and DNS services are active, DHCP supplies the guest DNS settings. Looking up vm.lan from the host depends on its Windows resolver configuration.'));
    if(bridged) {
      if(n.bridgeReasons?.length)card.append(reasons(n.bridgeReasons));
      if((n.bridgeCanSetup&&n.setupCommand)||n.removeCommand) {
        card.append(h('p',{},'Run the administrator command yourself. Binding or removing an external switch can interrupt the host network for a few seconds.'));
        if(n.bridgeCanSetup&&n.setupCommand) {
          card.append(h('code',{class:'command-text'},n.setupCommand));
          const controls=h('div',{role:'status'},'Checking the physical adapter…');
          card.append(controls);
          S.fill(controls,()=>api.get('/v1/networks/bridge-adapters'),list=>{
            const adapter=list.adapters.find(a=>a.id.toLowerCase()===n.adapterId.toLowerCase());
            if(!adapter)return h('p',{},'The recorded physical adapter is unavailable.');
            if(!adapter.available)return reasons(adapter.reasons?.length?adapter.reasons:[adapter.reason||'The physical adapter could not be verified.']);
            if(adapter.switchGuid||adapter.bound)return h('p',{},'An external switch is present. Refresh the bridge status.');
            return h('button',{class:'btn',onclick:async()=>{
              const current=await api.action('POST',path+'/refresh',{});
              if(!current.bridgeCanSetup||!current.setupCommand) {S.toast('Setup is unavailable. Review the current adapter status.');return;}
              await api.native('copyText',{text:current.setupCommand});S.toast('Bridge setup command copied.');
            }},'Copy bridge setup command');
          });
        }
        if(n.removeCommand) {
          if(n.bridgeReasons?.length)card.append(h('p',{},'Recorded bridge removal command'),h('code',{},n.removeCommand));
          else card.append(h('code',{class:'command-text'},n.removeCommand),
            h('button',{class:'btn',onclick:async()=>{await api.native('copyText',{text:n.removeCommand});S.toast('Bridge removal command copied.');}},'Copy bridge removal command'));
        }
      }
      card.append(h('button',{class:'btn',onclick:async()=>{
        const updated=await api.action('POST',path+'/refresh',{});S.toast(updated.ready?'Bridge is ready.':updated.bridgeCanSetup?'Bridge is waiting for setup.':'Bridge is unavailable. Review the adapter details.');
      }},'Refresh bridge status'));
    } else if(n.mode!=='Link-local'&&(n.setupInstruction||n.setupCommand)) {
      card.append(h('p',{},n.setupInstruction));
      if(n.setupCommand)card.append(h('code',{class:'command-text'},n.setupCommand),
        h('button',{class:'btn',onclick:async()=>{await api.native('copyText',{text:n.setupCommand});S.toast('Setup command copied.');}},'Copy command'));
    }
    if(!bridged&&n.mode!=='NAT')card.append(h('button',{class:'btn',onclick:async()=>{
      await api.action('POST',path+'/refresh',{});S.toast('Network status refreshed.');
    }},'Refresh network status'));
    if(n.mode!=='NAT')card.append(h('button',{class:'btn',onclick:async()=>{
      const message=bridged?(n.bridgeOwned?'Remove '+n.name+' from the library after undoing its app-owned switch with the administrator removal command?':'Forget '+n.name+' from this library? The shared external switch stays in place.'):'Remove '+n.name+' and its internal switch?';
      if(await S.dialog(bridged?'Remove bridged network?':'Delete network?',h('p',{},message),bridged?'Remove from library':'Delete')) {
        await api.action('DELETE',path);networkId=null;S.render();S.toast('Network removed.');
      }
    }},bridged?'Remove from library':'Delete network'));
    return [card,h('section',{class:'card'},h('h2',{},guestAddresses?'Guest addresses':'IPv4 leases and reservations'),leases)];
  }
  function render(root) {
    const v=S.vm(selectedId)||S.data.vms[0], n=S.net(networkId)||S.data.networks[0];
    root.append(h('div',{class:'net-page'},h('header',{},h('h1',{},'Networks'),h('p',{class:'sub'},'Select a machine to follow its connection. Gold packets show running peers on the same network.')),
      h('section',{class:'card'},h('h2',{},'Network constellation'),map(v,m=>{selectedId=m.id;networkId=m.net;focus('net-machine-'+m.id);})),
      v && S.screens.get('vm').identityCard(v),
      h('section',{class:'card'},h('div',{class:'net-heading'},h('h2',{},'Networks'),
        !adding&&h('button',{id:'net-add',class:'btn',onclick:openAddForm},'Add network')),
        adding&&addForm(),table(['Network','Mode','Subnet','DHCP'],S.data.networks.map(item=>[
          h('button',{id:'net-edit-'+item.id,class:'btn small','aria-pressed':String(item===n),onclick:()=>{networkId=item.id;focus('net-edit-'+item.id);}},item.name),
          item.mode,subnetLabel(item),item.mode==='Bridged'?'LAN router':item.dhcp]))),
      n && details(n)));
  }
  function motion(){document.documentElement.toggleAttribute('data-net-hidden',document.hidden);}
  document.addEventListener('visibilitychange',motion);motion();
  S.register('networks',{title:'Networks',render});
})();
