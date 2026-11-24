(function () {
  const S=window.SVB, h=S.h, api=S.api, tabs=['Overview','Hardware','Network','Snapshots','Guest tools','Storage'];
  let currentId, tab='Overview', selected=null, checkpointView, appLogMachine;
  function ipv4Number(text) {
    const parts=String(text).split('.');
    if(parts.length!==4||parts.some(part=>!/^(?:0|[1-9]\d{0,2})$/.test(part)||Number(part)>255))return null;
    return parts.reduce((value,part)=>value*256+Number(part),0);
  }
  function reservationIssue(v,net,ip) {
    const value=ipv4Number(ip);
    if(value===null)return 'Enter an IPv4 address with four decimal octets.';
    const [base,prefix]=String(net.subnet).split('/'),start=ipv4Number(base),bits=Number(prefix);
    if(start===null||!Number.isInteger(bits)||bits<0||bits>30)return 'The service has not reported a usable subnet for this network.';
    const end=start+2**(32-bits)-1;
    if(value<=start||value>=end)return 'Choose a usable host address inside '+net.subnet+'.';
    if(net.mode==='Link-local'&&(value<ipv4Number('169.254.1.0')||value>ipv4Number('169.254.254.255')))return 'Use 169.254.1.0 through 169.254.254.255 for a Link-local reservation.';
    if(ip===net.gateway)return 'That address belongs to the gateway.';
    if(ip===net.hostAddress||ip===net.dnsAddress)return 'That address belongs to the host or DNS service.';
    if(S.data.vms.some(peer=>peer.id!==v.id&&peer.net===net.id&&peer.ip===ip))return 'Another machine already holds this reservation.';
    return '';
  }
  function reservationForm(v,net) {
    if(v.template)return h('p',{class:'new-hint'},'Template network settings are read-only.');
    if(v.state!=='off'||v.registration!=='registered')return h('p',{class:'new-hint'},v.registration==='registered'?'Shut down the machine to change its reservation.':'Editing requires a verified machine registration.');
    const field=h('input',{id:'machine-reservation','data-draft':true,type:'text',required:true,maxlength:15,spellcheck:'false',value:v.ip||''});
    return h('div',{},h('form',{class:'new-actions',onsubmit:e=>{
      e.preventDefault();
      const ip=field.value.trim();
      return change(v,'network',async()=>{
        const issue=reservationIssue(v,net,ip);
        if(issue)throw Error(issue);
        if(ip!==v.ip)await api.action('PATCH',api.machinePath(v.id),{ip});
      },'IPv4 reservation saved.');
    }},h('label',{class:'new-field'},'Fixed IPv4 address',field),
      h('button',{class:'btn',type:'submit',disabled:detailWrites.has(v.id+'/network')},'Save reservation')),status(v,'network'));
  }
  function portForwarding(v) {
    const rules=Array.isArray(v.portForwards)?v.portForwards:[];
    const limit=16, section='port-forwards';
    const editable=!v.template&&v.registration==='registered'&&v.state==='off';
    const busy=S.powerBusy(v.id)||detailWrites.has(v.id+'/'+section);
    const save=next=>api.action('PATCH',api.machinePath(v.id),{portForwards:next});
    const rows=rules.map((rule,index)=>{
      const protocol=rule.protocol.toUpperCase(), endpoint=v.portForwardAddress+':'+rule.hostPort;
      return h('li',{},protocol+' '+endpoint+' → guest port '+rule.guestPort,' ',
        editable&&h('button',{class:'btn',type:'button',disabled:busy,
          id:'remove-forward-'+rule.protocol+'-'+rule.hostPort,
          'aria-label':'Remove '+protocol+' forward on '+endpoint,
          onclick:()=>change(v,section,()=>save(rules.filter((_,i)=>i!==index)),'Port forward removed.')},'Remove'));
    });
    const panel=h('section',{'aria-labelledby':'port-forwarding-title'},h('h3',{id:'port-forwarding-title'},'Port forwarding'),
      h('p',{class:'new-hint'},'Rules apply at startup. Forwarded ports listen on this PC’s loopback address.'),
      rows.length?h('ul',{},rows):h('p',{},'No port forwards configured.'));
    if(!editable) {
      panel.append(h('p',{class:'new-hint'},v.template?'Template forwarding rules are read-only.':v.registration==='registered'?
        'Power off the machine to change port forwarding.':'Editing requires a verified machine registration.'));
    } else if(rules.length>=limit) {
      panel.append(h('p',{class:'new-hint'},'This machine has the maximum of 16 port forwards.'));
    } else {
      const protocol=h('select',{id:'forward-protocol','data-draft':true,disabled:busy},
        h('option',{value:'tcp'},'TCP'),h('option',{value:'udp'},'UDP'));
      const port=id=>h('input',{id,'data-draft':true,type:'number',min:1,max:65535,step:1,required:true,disabled:busy});
      const host=port('forward-host-port'),guest=port('forward-guest-port');
      panel.append(h('form',{class:'new-actions',onsubmit:e=>{
        e.preventDefault();
        const next={protocol:protocol.value,hostPort:host.valueAsNumber,guestPort:guest.valueAsNumber};
        return change(v,section,async()=>{
          if(!['tcp','udp'].includes(next.protocol)||
            [next.hostPort,next.guestPort].some(value=>!Number.isInteger(value)||value<1||value>65535)) {
            throw Error('Enter host and guest ports from 1 to 65535.');
          }
          if(rules.some(rule=>rule.protocol===next.protocol&&rule.hostPort===next.hostPort)) {
            throw Error('That host port is already forwarded for this protocol.');
          }
          await save([...rules,next]);
          if(S.view==='vm'&&currentId===v.id&&tab==='Network') {
            for(const [id,value] of [[host.id,next.hostPort],[guest.id,next.guestPort]]) {
              const field=document.getElementById(id);
              if(field?.valueAsNumber===value)field.value='';
            }
          }
        },'Port forward added.');
      }},h('label',{class:'new-field'},'Protocol',protocol),
      h('label',{class:'new-field'},'Host port',host),h('label',{class:'new-field'},'Guest port',guest),
      h('button',{id:'add-port-forward',class:'btn',type:'submit',disabled:busy},'Add port forward')));
    }
    panel.append(status(v,section));
    return panel;
  }
  let captureView;
  const captureSection='capture';
  const captureReasons={
    limit:'Size limit reached','low-disk-space':'Free disk space fell below 2 GiB',
    stopped:'Stopped','machine-stopped':'Machine stopped',
  };
  function readCaptures(view) {
    if(!view.read) {
      view.read=api.get(view.path).then(report=>{
        if(typeof report?.active!=='boolean'||!Array.isArray(report.captures))throw Error('The service returned an unreadable capture list.');
        view.report=report;
        view.error='';
      }).catch(error=>{view.error=error.message;}).finally(()=>{view.read=null;});
    }
    return view.read;
  }
  function changeCapture(v,view,method,path,body,message) {
    return change(v,captureSection,async()=>{
      await api.action(method,path,body);
      await view.read;
      await readCaptures(view);
    },message);
  }
  function captureContents(v,view) {
    const {report,error,wireshark,path}=view;
    const busy=S.powerBusy(v.id)||detailWrites.has(v.id+'/'+captureSection);
    const running=v.registration==='registered'&&v.state==='running';
    const capturing=report?.active===true;
    const summary=error||(!report?'Loading captures…':capturing?'Capture is running.':
      running?'Ready to capture.':'Start a registered machine to capture packets.');
    const results=report?.captures||[];
    const controls=h('div',{},h('p',{class:'new-hint',role:'status'},summary));
    if(capturing) {
      controls.append(h('button',{id:'stop-capture',class:'btn',type:'button',disabled:busy,
        onclick:()=>changeCapture(v,view,'POST',path+'/stop',{},'Capture stopped.')},'Stop capture'));
    } else if(running&&report&&!error) {
      const max=h('input',{id:'capture-limit','data-draft':true,type:'number',min:1,max:512,step:1,value:512,required:true,disabled:busy});
      controls.append(h('form',{class:'new-actions',onsubmit:event=>{
        event.preventDefault();
        const limitMiB=max.valueAsNumber;
        if(!Number.isInteger(limitMiB)||limitMiB<1||limitMiB>512) {
          return change(v,captureSection,()=>{throw Error('Enter a limit from 1 to 512 MiB.');});
        }
        return changeCapture(v,view,'POST',path,{limitMiB},'Capture started.');
      }},h('label',{class:'new-field'},'Maximum size (MiB)',max),
      h('button',{id:'start-capture',class:'btn',type:'submit',disabled:busy},'Start capture')));
    }
    if(results.length) {
      controls.append(h('ul',{'aria-label':'Saved captures'},results.map(file=>{
        const label=wireshark?'Open in Wireshark':'Show file';
        const action=wireshark?'openCaptureInWireshark':'showCaptureFile';
        return h('li',{},file.name+' · '+size(file.bytes)+' · '+(captureReasons[file.stoppedBecause]||'Finished'),
          h('div',{class:'vm-actions'},
            h('button',{class:'btn',type:'button',disabled:busy,'aria-label':label+' '+file.name,
              onclick:()=>change(v,captureSection,()=>api.native(action,{id:v.id,text:file.id}))},label),
            h('button',{class:'btn',type:'button',disabled:busy,'aria-label':'Delete '+file.name,onclick:async()=>{
              if(!await S.dialog('Delete capture?',h('p',{},file.name+' will be permanently deleted.'),'Delete capture'))return;
              return changeCapture(v,view,'DELETE',path+'/'+api.segment(file.id),undefined,'Capture deleted.');
            }},'Delete')));
      })));
    } else if(report) {
      controls.append(h('p',{},'No saved captures.'));
    }
    return controls;
  }
  function packetCapture(v) {
    const heading=h('h3',{id:'packet-capture-title'},'Packet capture');
    if(v.engine==='Hyper-V')return h('section',{'aria-labelledby':'packet-capture-title'},heading,
      h('p',{class:'new-hint'},'Hyper-V capture requires the Windows pktmon tool and administrator rights. Capture is unavailable in this app.'));
    if(captureView?.id!==v.id)captureView={id:v.id,path:api.machinePath(v.id)+'/captures'};
    const view=captureView;
    const contents=h('div',{},captureContents(v,view));
    const key=()=>JSON.stringify([view.report,view.error,view.wireshark]);
    let shown=key();
    const redraw=()=>{
      const latest=key();
      if(contents.isConnected&&latest!==shown) {
        shown=latest;
        const draft=contents.querySelector('#capture-limit')?.value;
        contents.replaceChildren(captureContents(v,view));
        const limit=contents.querySelector('#capture-limit');
        if(limit&&draft!==undefined)limit.value=draft;
      }
    };
    const poll=async()=>{
      if(!contents.isConnected)return;
      await readCaptures(view);
      if(!contents.isConnected)return;
      redraw();
      if(view.report?.captures.length&&view.wireshark===undefined) {
        view.viewerCheck??=api.native('captureViewerAvailable').then(result=>{view.wireshark=result===true;})
          .catch(()=>{view.wireshark=false;});
        view.viewerCheck.then(redraw);
      }
      if(v.state==='running'||view.report?.active)setTimeout(poll,1500);
    };
    setTimeout(poll,0);
    return h('section',{'aria-labelledby':'packet-capture-title'},heading,contents,status(v,captureSection));
  }
  function identityCard(v,edit=false) {
    if(v.engine==='QEMU')return h('section',{class:'card vm-identity'},h('h2',{},'Network identity'),h('p',{class:'vm-lead'},v.name),
      S.facts([['Fixed MAC',v.mac],['Network','QEMU user-mode NAT'],['Guest IPv4',S.address(v)],['Address source',v.addressSource==='guest agent'?'Guest agent':null],['DHCP service','QEMU']]),
      v.family==='android'&&h('p',{class:'new-hint'},'In Android-x86 9 setup, open See all Wi-Fi networks and select VirtWifi to connect.'),edit&&v.portForwardAddress&&networkIsolation(v),edit&&v.portForwardAddress&&portForwarding(v),edit&&packetCapture(v));
    const net=S.net(v.net), automatic=net?.mode==='Bridged'||net?.mode==='NAT';
    const managed=['Routed','Host-only','Isolated segment','Link-local'].includes(net?.mode);
    return h('section',{class:'card vm-identity'},h('h2',{},'Network identity'),h('p',{class:'vm-lead'},v.name),
      S.facts([['Fixed MAC',v.mac],[automatic?'Guest IPv4':'IPv4 reservation',S.address(v)],['Address source',automatic?null:managed?'Service reservation':v.addressSource||net?.dhcp],
        ['Library DNS name',v.dns],['DNS service',net?.dnsStatus||'Status unavailable'],['Network',net?.name],['Network mode',net?.mode],['DHCP service',net?.dhcp],['Internet NAT',net?.mode==='Routed'?net.natStatus:null],['Network status',net?.note]]),
      net?.mode==='Link-local'&&h('p',{class:'new-hint'},'This virtual link has no internet route.'),
      edit&&v.engine==='Hyper-V'&&v.net==='nat'&&h('p',{class:'new-hint'},'Port forwarding isn’t available on the Default Switch. Connect to the guest’s IP from this PC.'),
      v.family==='android'&&h('p',{class:'new-hint'},S.androidNetworkHint),edit&&managed&&reservationForm(v,net),edit&&v.engine==='Hyper-V'&&packetCapture(v));
  }
  function snapshotTree(nodes, id, select) {
    const children=new Map(), seen=new Set(), order=[], ids=new Set(nodes.map(n=>n.id));
    for(const n of nodes){const list=children.get(n.parent)||[];list.push(n);children.set(n.parent,list);}
    function walk(starts) {
      const stack=starts.toReversed().map(n=>[n,0]);
      while(stack.length){const [n,depth]=stack.pop();if(seen.has(n.id))continue;
        seen.add(n.id);order.push({n,depth});for(const child of (children.get(n.id)||[]).toReversed())stack.push([child,depth+1]);}
    }
    walk(nodes.filter(n=>n.parent==null||!ids.has(n.parent)));
    for(const n of nodes)if(!seen.has(n.id))walk([n]);
    const max=order.reduce((acc,x)=>Math.max(acc,x.depth),1);
    const coords=new Map(order.map(({n,depth},i)=>[n.id,{x:8+78*depth/max,y:i*44+22}]));
    const lines=[],rings=[];
    for(const {n} of order){const a=coords.get(n.parent),b=coords.get(n.id);
      if(a)lines.push(h('path',{xmlns:true,class:'vm-branch',d:`M${a.x} ${a.y} C${a.x} ${b.y}, ${a.x} ${b.y}, ${b.x} ${b.y}`}));
      rings.push(h('circle',{xmlns:true,cx:b.x,cy:b.y,r:4,class:'vm-ring'+(n.id===id?' current':'')}));}
    return h('div',{class:'vm-tree'},h('svg',{viewBox:'0 0 100 '+order.length*44,preserveAspectRatio:'none','aria-hidden':'true'},lines,rings),
      h('div',{},order.map(({n})=>h('button',{class:'vm-node','aria-pressed':String(id===n.id),onclick:()=>select(n.id)},n.name))));
  }
  function snapshots(v) {
    const path=api.machinePath(v.id)+'/snapshots', tree=h('div',{role:'region','aria-label':'Checkpoint history'});
    const name=h('input',{id:'snapshot-name','data-draft':true,maxlength:180,placeholder:'Snapshot name (optional)','aria-label':'Snapshot name'});
    const memory=h('input',{id:'snapshot-memory','data-draft':true,type:'checkbox'});
    const form=S.cap(v.id,'Snapshot') && h('form',{class:'vm-actions',onsubmit:e=>{
      e.preventDefault();return change(v,'checkpoint',async()=>{
        const body={withMemory:S.cap(v.id,'SnapshotWithMemory')&&memory.checked===true};
        if(name.value.trim())body.name=name.value.trim();
        const result=await api.action('POST',path,body);selected=result.id;
      },'Snapshot saved.');
    }},name,S.cap(v.id,'SnapshotWithMemory')&&h('label',{},memory,' Include memory'),h('button',{class:'btn',type:'submit',disabled:detailWrites.has(v.id+'/checkpoint')},'Take snapshot'));
    function draw(nodes){
      if(!nodes.length)return h('p',{},'No snapshots.');
      const chosen=nodes.find(n=>n.id===selected)||nodes[0], one=path+'/'+api.segment(chosen.id);
      const consistency={
        'guest-quiesced':'Guest filesystems quiesced',
        'crash-consistent':'Crash-consistent',
        'hyperv-production':'Hyper-V production',
        standard:'Hyper-V standard',
        unverified:'Consistency unverified',
      }[chosen.consistency];
      return h('div',{},snapshotTree(nodes,chosen.id,id=>{selected=id;tree.replaceChildren(draw(nodes));tree.querySelector('[aria-pressed="true"]')?.focus();}),
        S.facts([['Selected checkpoint',chosen.name],['Parent',nodes.find(n=>n.id===chosen.parent)?.name || 'Original disk'],['Saved memory',chosen.withMemory?'Included':'Disk only'],['Consistency',consistency]]),
        h('div',{class:'vm-actions'},S.cap(v.id,'RevertSnapshot')&&h('button',{class:'btn',onclick:async()=>{
          if(await S.dialog('Revert checkpoint?',h('p',{},'Restore '+v.name+' to '+chosen.name+'?'),'Revert')) {
            await api.action('POST',one+'/revert',{});S.toast('Checkpoint restored.');}
        }},'Revert to selected'),S.cap(v.id,'DeleteSnapshot')&&h('button',{class:'btn',onclick:async()=>{
          if(await S.dialog('Delete checkpoint?',h('p',{},'Remove '+chosen.name+' from '+v.name+'?'),'Delete')) {
            await api.action('DELETE',one);S.toast('Checkpoint deleted.');}
        }},'Delete selected')));
    }
    if (checkpointView?.path !== path) checkpointView = {path, rows:null};
    const view = checkpointView, shown = view.rows;
    tree.append(shown ? draw(shown) : h('p',{role:'status'},'Loading checkpoints…'));
    if (view.state !== S.data) {
      view.state = S.data;
      const read = api.get(path).then(rows => {
        if (view.read === read && JSON.stringify(rows) !== JSON.stringify(view.rows)) view.rows = rows;
      });
      view.read = read;
    }
    const read = view.read;
    read.then(() => {
      if (tree.isConnected && view.read === read && shown !== view.rows) tree.replaceChildren(draw(view.rows));
    }).catch(error => {
      if (view.read !== read) return;
      view.state = null; view.rows = null;
      if (tree.isConnected) tree.replaceChildren(h('p',{role:'status'},error.message));
    });
    return h('section',{class:'card'},h('h2',{},'Snapshot tree'),form,status(v,'checkpoint'),tree);
  }
  async function clone(v) {
    const field=h('label',{class:'new-field'},'Clone name',h('input',{required:true,maxlength:80}));
    const name=await S.dialog('Clone '+v.name,h('p',{},'Create an independent copy with its own network identity.'),'Clone',field);
    if(!name)return;const copy=await api.action('POST',api.machinePath(v.id)+'/clone',{name});S.go('vm',{id:copy.id});
  }
  async function remove(v) {
    if(!await S.dialog('Delete '+v.name+'?',h('p',{},'Move this machine to library trash? The service preserves a retained copy when its state requires one.'),'Move to trash'))return;
    const reply=await api.action('DELETE',api.machinePath(v.id));S.go('library');
    const kept=reply.removalPath==='retained-copy';
    await S.dialog('Machine moved to trash',h('div',{},
      h('p',{},kept?'A retained copy was kept.':'The bundle went directly to trash.'),
      S.facts([['Trash location',reply.trashPath],['Retained copy',kept?reply.retainedPath:null],
        ['Retained size',kept&&Number.isFinite(reply.retainedBytes)?reply.retainedBytes.toLocaleString()+' bytes':null]]),
      h('button',{type:'button',class:'btn',onclick:e=>{
        e.currentTarget.closest('dialog').close(); S.go('trash');
      }},'Open library trash')),
      'Close',null,false);
  }
  const tabId=name=>'vm-tab-'+name.toLowerCase().replaceAll(' ','-');
  function chooseTab(name){tab=name;S.render();document.getElementById(tabId(name))?.focus();}
  const detailErrors=new Map(), detailWrites=new Set();
  async function change(v,section,work,success) {
    const key=v.id+'/'+section;
    if(detailWrites.has(key))return;
    detailWrites.add(key);detailErrors.delete(key);
    try {await work();if(success)S.toast(success);}
    catch(error){detailErrors.set(key,error.message);}
    finally {
      detailWrites.delete(key);
      if(S.view==='vm'&&currentId===v.id)S.render(true);
    }
  }
  function status(v,section) {
    return h('p',{class:'new-error',role:'status'},detailErrors.get(v.id+'/'+section)||'');
  }
  const clipboardLimit=1024*1024;
  function clipboardTextError(text,toGuest=false) {
    if(typeof text!=='string'||!text||text.includes('\0'))return 'Choose plain text to share.';
    if(text.length>clipboardLimit)return 'Clipboard text exceeds 1 MiB.';
    const bytes=new TextEncoder().encode(toGuest?text.replace(/\r\n|\r|\n/g,'\r\n'):text).length;
    if(bytes>clipboardLimit)return 'Clipboard text exceeds 1 MiB.';
    if(toGuest) {
      // noVNC adds a length field and terminator before deflate. Leave space for its flush and flags.
      const payload=bytes+5;
      const maximum=payload+(payload>>>12)+(payload>>>14)+(payload>>>25)+23;
      if(maximum>clipboardLimit)return 'Clipboard text exceeds the guest’s 1 MiB limit after encoding.';
    }
    return '';
  }
  function consoleClipboard(mount) {
    const status=h('p',{class:'new-hint',role:'status',id:'qemu-clipboard-status'});
    const guest=h('textarea',{id:'qemu-guest-clipboard',rows:3,readonly:true,spellcheck:'false',autocomplete:'off',dir:'auto'});
    const paste=h('textarea',{id:'qemu-host-clipboard',rows:2,disabled:true,spellcheck:'false',autocomplete:'off',
      'aria-describedby':'qemu-clipboard-status',onbeforeinput:event=>event.preventDefault(),onpaste:event=>{
        event.preventDefault();
        if(!event.isTrusted||mount!==embeddedConsole||!mount.connected)return;
        const text=event.clipboardData?.getData('text/plain');
        const error=clipboardTextError(text,true);
        if(error){status.textContent=error;return;}
        mount.viewer.clipboardPasteFrom(text);
        status.textContent='Text sent to the guest console.';
      }});
    const copy=h('button',{class:'btn',id:'qemu-copy-clipboard',type:'button',disabled:true,onclick:async event=>{
      if(!event.isTrusted||mount!==embeddedConsole||!mount.connected||clipboardTextError(guest.value))return;
      try {
        await api.native('copyConsoleText',{id:mount.id,text:guest.value});
        if(mount.connected)status.textContent='Guest text copied.';
      } catch(error) {
        if(mount.connected)status.textContent=error.message;
      }
    }},'Copy guest text');
    const panel=h('details',{class:'qemu-clipboard'},h('summary',{},'Clipboard'),
      h('div',{class:'qemu-clipboard-fields'},h('label',{class:'new-field'},'Paste text to guest',paste),
        h('label',{class:'new-field'},'Text from guest',guest)),
      h('div',{class:'vm-actions'},copy,status));
    return {panel,paste,guest,copy,status};
  }
  function setConsoleClipboardConnection(mount,connected) {
    mount.connected=connected;
    const clipboard=mount.clipboard;
    if(!clipboard)return;
    clipboard.paste.disabled=!connected;
    clipboard.guest.value='';
    clipboard.copy.disabled=true;
    clipboard.status.textContent='';
  }
  let embeddedConsole;
  function closeEmbeddedConsole() {
    const mount=embeddedConsole;
    embeddedConsole=null;
    if(!mount)return;
    clearTimeout(mount.timeout);
    setConsoleClipboardConnection(mount,false);
    mount.viewer?.disconnect();
  }
  function reportConsole(mount,message,retry=false) {
    mount.status.textContent=message;
    mount.retry.hidden=!retry;
  }
  async function connectConsole(mount) {
    if(mount!==embeddedConsole||!mount.panel.isConnected||mount.connecting||mount.viewer)return;
    mount.connecting=true;
    reportConsole(mount,'Connecting to the guest display…');
    try {
      const {default:RFB}=await import('/console/assets/core/rfb.js');
      if(mount!==embeddedConsole)return;
      const {port,ticket}=await api.consoleTicket(mount.id);
      if(mount!==embeddedConsole)return;
      if(!Number.isInteger(port)||port<1||port>65535||typeof ticket!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
        throw Error('The service returned an unreadable console connection.');
      }
      // The service listens on 127.77.0.1, which a guest's user-mode network cannot reach.
      const url='ws://127.77.0.1:'+port+'/console/'+api.segment(mount.id);
      const socket=new WebSocket(url,['binary',ticket]);
      let viewer;
      try {viewer=new RFB(mount.target,socket);}
      catch(error){socket.close();throw error;}
      mount.viewer=viewer;
      viewer.scaleViewport=true;
      viewer.resizeSession=true;
      const canvas=mount.target.querySelector('canvas');
      if(canvas) {
        canvas.id='qemu-guest-display';
        canvas.tabIndex=0;
        canvas.setAttribute('aria-label','Guest display for '+mount.name);
        canvas.setAttribute('aria-describedby','qemu-console-status');
      }
      mount.timeout=setTimeout(()=>{
        if(mount!==embeddedConsole||mount.viewer!==viewer)return;
        mount.viewer=null;
        setConsoleClipboardConnection(mount,false);
        viewer.disconnect();
        reportConsole(mount,'The guest display took too long to respond.',true);
      },12000);
      viewer.addEventListener('connect',()=>{
        if(mount!==embeddedConsole||mount.viewer!==viewer)return;
        clearTimeout(mount.timeout);
        setConsoleClipboardConnection(mount,true);
        reportConsole(mount,'Console connected. Press F6 to return to machine controls.');
      },{once:true});
      viewer.addEventListener('disconnect',()=>{
        if(mount!==embeddedConsole||mount.viewer!==viewer)return;
        clearTimeout(mount.timeout);
        const connected=mount.connected;
        mount.viewer=null;
        setConsoleClipboardConnection(mount,false);
        reportConsole(mount,connected?'Console disconnected.':'The service could not open the guest display.',true);
      },{once:true});
      const clipboard=mount.clipboard;
      if(clipboard)viewer.addEventListener('clipboard',event=>{
        if(mount!==embeddedConsole||mount.viewer!==viewer||!mount.connected)return;
        const text=event.detail?.text;
        const error=clipboardTextError(text);
        clipboard.guest.value=error?'':text;
        clipboard.copy.disabled=Boolean(error);
        clipboard.status.textContent=error||'Guest text received.';
      });
    } catch(error) {
      if(mount===embeddedConsole)reportConsole(mount,error.message||'The guest display could not be opened.',true);
    } finally {
      mount.connecting=false;
    }
  }
  function embeddedConsolePanel(v) {
    const shareClipboard=v.shareClipboard===true;
    if(embeddedConsole?.id!==v.id||Boolean(embeddedConsole.clipboard)!==shareClipboard) {
      closeEmbeddedConsole();
      const mount={id:v.id,name:v.name,target:h('div',{id:'qemu-console-display',class:'qemu-console-display'}),
        status:h('p',{id:'qemu-console-status',class:'new-hint',role:'status'},'Connecting to the guest display…')};
      mount.retry=h('button',{id:'qemu-console-reconnect',class:'btn',type:'button',hidden:true,
        onclick:()=>connectConsole(mount)},'Reconnect console');
      if(shareClipboard)mount.clipboard=consoleClipboard(mount);
      mount.panel=h('div',{class:'qemu-console', 'data-guest-console':v.id},mount.clipboard?.panel,mount.target,
        h('div',{class:'vm-actions'},mount.status,mount.retry));
      // Use the host focus-navigation key so a keyboard user can leave the guest canvas.
      mount.target.addEventListener('keydown',event=>{
        if(event.code!=='F6'||event.shiftKey||event.ctrlKey||event.altKey||event.metaKey)return;
        event.preventDefault();
        event.stopPropagation();
        document.getElementById(tabId('Console'))?.focus({preventScroll:true});
      },true);
      embeddedConsole=mount;
    }
    return embeddedConsole.panel;
  }
  window.addEventListener('svb-render',()=>{
    const mount=embeddedConsole;
    if(!mount)return;
    if(!mount.panel.isConnected)closeEmbeddedConsole();
    else if(!mount.started) {mount.started=true;void connectConsole(mount);}
  });
  window.addEventListener('pagehide',closeEmbeddedConsole);
  function clipboardSettings(v) {
    if(v.engine==='Hyper-V') {
      const enhanced=S.data.caps?.[v.id]?.EnhancedSession;
      return h('div',{},h('p',{class:'new-hint'},enhanced?.available?'Enhanced Session available.':
        enhanced?.reason||'Enhanced Session availability could not be verified.'),
        h('p',{class:'new-hint'},'Clipboard sharing follows VMConnect’s Show Options → Local Resources settings.'));
    }
    if(v.engine!=='QEMU')return null;
    const enabled=v.shareClipboard===true;
    return h('div',{},h('label',{class:'boot-key-option'},h('input',{
      type:'checkbox',id:'qemu-share-clipboard',checked:enabled,'aria-describedby':'clipboard-setting-hint',
      disabled:v.state!=='off'||S.powerBusy(v.id)||detailWrites.has(v.id+'/clipboard'),onchange:event=>{
        const field=event.currentTarget;
        const shareClipboard=field.checked;
        field.disabled=true;
        return change(v,'clipboard',()=>api.action('PATCH',api.machinePath(v.id),{shareClipboard}));
      }
    }),'Share clipboard'),
      h('p',{id:'clipboard-setting-hint',class:'new-hint'},v.state==='off'?
        'Applies at startup. Keep it off to isolate the host clipboard.':'Power off the machine to change clipboard sharing.'),
      status(v,'clipboard'));
  }
  function consolePanel(v, embedded=false) {
    const qemu=v.engine==='QEMU';
    const combined=!qemu&&S.cap(v.id,'Start')&&S.cap(v.id,'Console');
    const off=v.state==='off'||v.state==='saved';
    const hint=qemu?(embedded?'Click the guest display to send it keyboard input.':'Open the Console tab for the live display.'):combined?'The viewer opens before startup.':
      off?'Start the machine to see its guest display.':'The console opens in Windows’ viewer.';
    const open=combined?h('button',{class:'btn primary',disabled:S.powerBusy(v.id)||detailWrites.has(v.id+'/console'),onclick:()=>change(v,'console',()=>S.startWithConsole(v))},'Start and open console'):null;
    const prefix=v.id+': ';
    const installerKey=S.data.caps?.[v.id]?.PressKeyAtBoot;
    const installerReason=v.state==='off'&&v.family==='windows'&&installerKey?.available===false&&installerKey.reason;
    const lastBootKey=S.data.events?.findLast(event=>event.kind==='installer boot key'&&event.message.startsWith(prefix));
    const live=embedded&&['running','paused'].includes(v.state);
    const display=live?embeddedConsolePanel(v):h('div',{class:'vm-preview'},S.preview(v));
    const controls=h('div',{},h('h2',{},'Console'),h('p',{class:'vm-lead'},live||!embedded?hint:'Start the machine to see its guest display.'),h('div',{class:'vm-actions'},open,S.powers(v,false,combined),
        !qemu&&!off&&S.cap(v.id,'Console')&&h('button',{class:'btn',onclick:()=>change(v,'console',()=>api.native('openConsole',{id:v.id}))},'Open console'),
        v.state==='running'&&S.cap(v.id,'SendKeys')&&h('button',{class:'btn',onclick:()=>change(v,'console',async()=>{
          const receipt=await api.action('POST',api.machinePath(v.id)+'/keys',{keys:['Ctrl+Alt+Del']});
          if(receipt?.sent!==1)throw Error('The service could not confirm sending Ctrl+Alt+Del.');
          S.toast('Ctrl+Alt+Del sent to the machine. Check the guest screen for its response.');
        })},'Send Ctrl+Alt+Del')),
        v.engine==='QEMU'&&h('p',{class:'new-hint'},S.data.caps?.[v.id]?.AudioOutput?.message||(v.family==='android'?'Guest sound uses the PC’s default output device when available.':v.architecture==='aarch64'?'Sound is off for Emulated Arm.':'Sound is off for the legacy BIOS guest profile.')),
        v.engine==='QEMU'&&v.family==='android'&&v.isoPath&&h('p',{class:'new-hint'},'For a lasting installation, choose Installation in the Android boot menu and install onto the virtual disk. After installation, power off and choose Remove installer disc in Storage.'),
        clipboardSettings(v),
        !qemu&&h('p',{class:'new-hint'},'Hyper-V Enhanced Session shares the host clipboard by default. Turn off Clipboard in the connection settings or use Basic Session for an untrusted guest.'),
        qemu&&v.shareClipboard&&S.data.qemu?.openSeparateWindow&&h('p',{class:'new-hint'},'Turn off clipboard sharing or the separate window before starting this machine.'),
        qemu&&S.data.qemu?.openSeparateWindow&&h('p',{class:'new-hint'},'A separate window opens on the next start. Press Ctrl+Alt+G to release its mouse and keyboard.'),
        installerReason&&h('p',{class:'new-hint'},installerReason),
        lastBootKey&&h('p',{class:'new-hint'},'Last installer boot attempt · '+lastBootKey.message.slice(prefix.length)),status(v,'console'));
    return h('section',{class:'card vm-console'+(live?' vm-console-embedded':'')},...(live?[controls,display]:[display,controls]));
  }
  function hardware(v) {
    const host=S.data.host,decision=S.data.caps?.[v.id]?.EditHardware;
    const editable=!v.template&&v.state==='off'&&v.registration==='registered'&&(decision?decision.available===true:v.engine!=='QEMU');
    const section=h('section',{class:'card'},h('h2',{},'Hardware'),S.facts([
      ['Processor threads',v.vcpu],['Assigned logical cores',v.cores?.length?v.cores.join(', '):'Allocated on start'],
      ['Memory',v.ramGb+' GiB'],['Execution',v.architecture==='aarch64'?S.armLabel:v.engine==='QEMU'?'WHPX required':v.accel?'Accelerated':'Emulated'],['Host processor',host.cpu],
      ['Virtual TPM',v.tpm==null?'Not reported':v.tpm?'Enabled':'Disabled'],['Secure Boot',v.secureBoot==null?'Engine default':v.secureBoot?'Enabled':'Disabled']]));
    if(v.tpm===true)section.append(h('p',{class:'new-hint'},S.tpmCertificateHint));
    if(!editable){section.append(h('p',{class:'new-hint'},v.template?'Template hardware is read-only.':decision?.reason||(v.registration==='registered'?'Shut down this machine to edit its processor and memory.':'Hardware changes require a verified registration.')));return section;}
    function number(id,value,max) {return h('input',{id,'data-draft':true,type:'number',required:true,min:1,max,step:1,value});}
    const cpu=number('hardware-cpu',v.vcpu,v.engine==='QEMU'?Math.min(v.architecture==='aarch64'?2:4,host.logical):host.enabled?host.logical:undefined);
    const ram=number('hardware-memory',v.ramGb,v.engine==='QEMU'?Math.min(v.architecture==='aarch64'?4:8,host.ramGb):host.enabled?host.ramGb:undefined);
    section.append(h('form',{class:'new-actions',onsubmit:e=>{
      e.preventDefault();return change(v,'hardware',()=>api.action('PATCH',api.machinePath(v.id),{vcpu:cpu.valueAsNumber,ramGb:ram.valueAsNumber}),'Hardware saved.');
    }},h('label',{class:'new-field'},'Virtual CPUs',cpu),h('label',{class:'new-field'},'Memory (GiB)',ram),
      h('button',{class:'btn',type:'submit',disabled:detailWrites.has(v.id+'/hardware')},'Save hardware')),
      h('p',{class:'new-hint'},host.enabled?'This host’s protection settings apply when the machine starts.':'The engine checks the requested resources at startup.'),status(v,'hardware'));
    return section;
  }
  function size(bytes) {
    if(!Number.isFinite(bytes)||bytes<0)return 'Unavailable';
    if(bytes<1024)return bytes.toLocaleString()+(bytes===1?' byte':' bytes');
    const [factor,unit]=bytes>=1024**3?[1024**3,'GiB']:bytes>=1024**2?[1024**2,'MiB']:[1024,'KiB'];
    return (bytes/factor).toLocaleString(undefined,{maximumFractionDigits:2})+' '+unit+' ('+bytes.toLocaleString()+' bytes)';
  }
  function networkIsolation(v) {
    const section='isolated';
    const editable=!v.template&&v.registration==='registered'&&v.state==='off';
    const busy=S.powerBusy(v.id)||detailWrites.has(v.id+'/'+section);
    const control=h('input',{id:'isolated-switch',type:'checkbox',role:'switch',checked:v.isolated===true,
      disabled:!editable||busy,onchange:e=>{
        const enabled=e.currentTarget.checked;
        e.currentTarget.checked=v.isolated===true;
        return change(v,section,()=>api.action('PATCH',api.machinePath(v.id),{isolated:enabled}),
          enabled?'Network isolation enabled.':'Network isolation disabled.');
      }});
    return h('section',{'aria-labelledby':'isolated-title'},
      h('h3',{id:'isolated-title'},'Network isolation'),h('label',{},control,' Isolated network'),
      h('p',{class:'new-hint',role:'status'},v.isolated===true?
        'The guest cannot reach this PC or the internet. TCP port forwards still work; UDP forwards do not get replies.':
        'The guest can reach the internet and programs on this PC that only listen locally. Turn on Isolated network for untrusted software.'),
      !editable&&h('p',{class:'new-hint'},'Power off the machine to change network isolation.'),status(v,section));
  }
  function throwawayStorage(v) {
    const section='throwaway', decision=S.data.caps?.[v.id]?.EditThrowaway;
    const busy=S.powerBusy(v.id)||detailWrites.has(v.id+'/'+section);
    const canEdit=decision?.available===true&&!busy;
    const control=h('input',{id:'throwaway-switch',type:'checkbox',role:'switch',checked:v.throwaway===true,
      disabled:!canEdit,onchange:e=>{
        const enabled=e.currentTarget.checked;
        e.currentTarget.checked=v.throwaway===true;
        return change(v,section,()=>api.action('PATCH',api.machinePath(v.id),{throwaway:enabled}),
          enabled?'Throwaway mode enabled.':'Throwaway mode disabled.');
      }});
    return h('section',{'aria-labelledby':'throwaway-title'},
      h('h3',{id:'throwaway-title'},'Throwaway mode'),h('label',{},control,' Throwaway'),
      v.throwaway&&h('p',{class:'new-hint',role:'status'},'Changes are discarded at power-off while Secwiz VM is open. Start it only from Secwiz VM.'),
      decision?.reason&&h('p',{class:'new-hint'},decision.reason),status(v,section));
  }
  function templateStorage(v) {
    const section='template', base=api.machinePath(v.id);
    const panel=h('section',{'aria-labelledby':'template-storage-title'},h('h3',{id:'template-storage-title'},'Templates and linked clones'));
    if(v.linkedFrom) {
      const parent=S.vm(v.linkedFrom);
      panel.append(S.facts([['Parent template',parent?.name||v.linkedFrom],['Parent ID',parent?.name!==v.linkedFrom&&parent?v.linkedFrom:null]]),
        h('p',{class:'new-hint'},'This linked clone stores its disk changes separately from the template.'));
      return panel;
    }
    const eligible=v.registration==='registered'&&v.state==='off'&&['QEMU','Hyper-V'].includes(v.engine);
    const busy=S.powerBusy(v.id)||detailWrites.has(v.id+'/'+section);
    const caps=S.data.caps?.[v.id];
    const machineReason=v.registration!=='registered'?'A verified machine registration is required.':
      v.state!=='off'?'Power off the machine to change its template settings.':'This action is unavailable for this machine.';
    if(v.template) {
      const link=caps?.CreateLinkedClone, remove=caps?.RemoveTemplate;
      const canLink=eligible&&link?.available===true, canRemove=eligible&&remove?.available===true;
      panel.append(h('p',{id:'template-read-only',class:'new-hint'},'Read-only template. Its disk is the base for linked clones.'),
        h('div',{class:'vm-actions'},
          h('button',{id:'new-linked-clone',class:'btn',type:'button',disabled:busy||!canLink,onclick:async()=>{
            const field=h('label',{class:'new-field'},'Clone name',h('input',{id:'linked-clone-name',required:true,maxlength:180}));
            const name=await S.dialog('New linked clone',h('p',{},'The clone will use the template disk and store its own changes.'),'Create linked clone',field);
            if(!name)return;
            return change(v,section,async()=>{
              const clone=await api.action('POST',base+'/linked-clones',{name});
              if(S.view==='vm'&&currentId===v.id)S.go('vm',{id:clone.id});
            },'Linked clone created.');
          }},'New linked clone'),
          h('button',{id:'remove-template',class:'btn',type:'button',disabled:busy||!canRemove,onclick:async()=>{
            if(!await S.dialog('Remove template?',h('p',{},v.name+' will become a normal machine. Its disk will return to its earlier read-only setting.'),'Remove template'))return;
            return change(v,section,()=>api.action('DELETE',base+'/template'),'Template status removed.');
          }},'Remove template')));
      const reasons=new Set();
      if(!canLink)reasons.add(link?.reason||machineReason);
      if(!canRemove)reasons.add(remove?.reason||machineReason);
      for(const reason of reasons)panel.append(h('p',{class:'new-hint'},reason));
    } else {
      const make=caps?.CreateTemplate, canMake=eligible&&make?.available===true;
      panel.append(h('button',{id:'make-template',class:'btn',type:'button',disabled:busy||!canMake,
        onclick:()=>change(v,section,()=>api.action('POST',base+'/template',{}),'Read-only template created.')},'Make template'),
        h('p',{class:'new-hint'},canMake?'A template stays powered off and provides the base disk for linked clones.':make?.reason||machineReason));
    }
    panel.append(status(v,section));
    return panel;
  }
  function storage(v) {
    const section=h('section',{class:'card'},h('h2',{},'Storage'),templateStorage(v),!v.template&&throwawayStorage(v));
    const area=h('div',{'aria-live':'polite'},h('p',{},'Reading storage…'));
    const path=api.machinePath(v.id)+'/storage';
    const save=(data,success)=>change(v,'storage',()=>api.action('PUT',path,data),success);
    function draw(info) {
      const decision=S.data.caps?.[v.id]?.EditStorage;
      const editable=!v.template&&(decision?decision.available===true:v.engine!=='QEMU');
      const current=info.bootFirst==='system'?(info.bootDescription?'Installed system ('+info.bootDescription+')':'Installed system'):
        info.bootFirst==='disk'?'Disk first':info.bootFirst==='image'?'Installer image first':'Other firmware device first';
      const items=[h('h3',{},'Virtual disks')];
      if(!info.disks.length)items.push(h('p',{},'No virtual disk attached.'));
      for(const disk of info.disks)items.push(S.facts([['Path',disk.path],['Maximum size',size(disk.maximumBytes)],['Size on host now',size(disk.hostBytes)]]));
      items.push(h('h3',{},'DVD drive'),h('p',{class:'new-hint'},info.isoPath||'No installer image attached.'));
      if(v.engine==='QEMU'&&editable&&info.canEditMedia) {
        const attached=Boolean(info.isoPath);
        if(!attached&&!info.originalInstaller)items.push(S.imagePicker(isoPath=>save({isoPath},'Installer disc attached.')));
        else items.push(h('button',{class:'btn',disabled:detailWrites.has(v.id+'/storage'),onclick:()=>save({isoPath:attached?null:info.originalInstaller},
          attached?'Installer disc removed. The next start uses the virtual disk.':'Installer disc reattached.')},attached?'Remove installer disc':'Reattach installer disc'));
      } else if(v.engine==='QEMU')items.push(h('p',{},decision?.reason||info.mediaReason));
      else if(editable&&info.canEditMedia)items.push(h('div',{class:'vm-actions'},S.imagePicker(isoPath=>save({isoPath},'Installer image attached.')),
        info.isoPath&&h('button',{class:'btn',onclick:()=>save({isoPath:null},'Installer image ejected.')},'Eject image')));
      else if(editable)items.push(h('p',{},info.mediaReason||'Media changes are unavailable in the current state.'));
      items.push(h('h3',{},'Boot order'),h('p',{},current));
      if(editable&&info.canEditBoot) {
        const choices=[];
        if(info.disks.length&&info.bootFirst!=='disk')choices.push(h('button',{class:'btn',onclick:()=>save({bootFirst:'disk'},'Disk is first in the boot order.')},'Boot from disk first'));
        if(info.isoPath&&info.bootFirst!=='image')choices.push(h('button',{class:'btn',onclick:()=>save({bootFirst:'image'},'Installer image is first in the boot order.')},'Boot from image first'));
        if(choices.length)items.push(h('div',{class:'vm-actions'},choices));
      } else items.push(h('p',{},info.bootReason||decision?.reason||'Boot order changes are unavailable in the current state.'));
      area.replaceChildren(...items);
    }
    let read=0;
    async function load() {
      const request=++read;
      try {const info=await api.get(path);if(area.isConnected&&request===read)draw(info);}
      catch(error){if(area.isConnected&&request===read)area.replaceChildren(h('p',{class:'new-error',role:'alert'},error.message),
        h('button',{class:'btn',onclick:load},'Retry storage'));}
    }
    section.append(area,h('button',{class:'btn',onclick:load},'Refresh storage'),status(v,'storage'));
    const exportReason=v.throwaway&&v.state!=='off'?'Disk export is unavailable during a throwaway run.':
      v.template?'Disk export is unavailable for templates.':v.linkedFrom?'Disk export is unavailable for linked clones.':null;
    section.append(exportReason?h('section',{},h('h3',{},'Export disk'),
      h('p',{class:'new-hint'},exportReason)):S.exportDiskPanel(v));
    section.append(S.backupSection(v));
    void load();return section;
  }
  let guestPublicKey=null, guestCommandResult=null;
  function guestAccessFields(windows,prefix) {
    const username=h('input',{id:prefix+'-user',type:'text',autocomplete:'off',required:true,maxlength:512});
    const password=windows?h('input',{id:prefix+'-password',type:'password',autocomplete:'new-password',required:true,maxlength:8192}):null;
    const hostKey=windows?null:h('textarea',{id:prefix+'-host-key',rows:2,spellcheck:'false',required:true,maxlength:1024});
    const fields=[h('label',{class:'new-field'},'Guest username',username),
      password&&h('label',{class:'new-field'},'Guest password',password),
      hostKey&&h('label',{class:'new-field'},'SSH host public key',hostKey),
      hostKey&&h('p',{class:'new-hint'},'Copy the ssh-ed25519 public host key from the guest’s console.')];
    return {username,password,hostKey,fields};
  }
  function readGuestAccess(access,confirmed) {
    const {username,password,hostKey}=access;
    const guestPassword=confirmed?password?.value:undefined;
    if(password)password.value='';
    if(!confirmed)return null;
    if(password) {
      if(!username.value||!guestPassword)throw Error('Enter the Windows guest username and password for this run.');
      return {credentials:{username:username.value,password:guestPassword}};
    }
    if(!username.value||!hostKey.value.trim())throw Error('Enter the Linux guest username and host public key.');
    return {ssh:{username:username.value,hostKey:hostKey.value.trim()}};
  }
  async function guestFileAccess(v,direction) {
    const access=guestAccessFields(v.family==='windows','guest-file');
    return readGuestAccess(access,await S.dialog('Connect to the guest',h('div',{},access.fields),
      direction==='send'?'Send file':'Get file'));
  }
  async function runHypervGuestCommand(v) {
    const windows=v.family==='windows';
    const access=guestAccessFields(windows,'guest-command');
    const argumentsField=h('textarea',{id:'guest-command-arguments',rows:2,spellcheck:'false',required:true,
      placeholder:windows?'["hostname.exe"]':'["uname","-a"]'});
    const timeout=h('input',{id:'guest-command-timeout',type:'number',min:1,max:120,value:30});
    const stdin=h('textarea',{id:'guest-command-stdin',rows:2,spellcheck:'false'});
    const prompt=h('div',{},access.fields,
      h('label',{class:'new-field'},'Command arguments as a JSON array',argumentsField),
      h('label',{class:'new-field'},'Timeout in seconds',timeout),
      h('label',{class:'new-field'},'Standard input (optional)',stdin));
    const authorization=readGuestAccess(access,await S.dialog('Run guest command',prompt,'Run command'));
    if(!authorization)return;
    try {
      let argv;
      try {argv=JSON.parse(argumentsField.value);}
      catch {throw Error('Enter the executable and arguments as a JSON string array.');}
      if(!Array.isArray(argv)||argv.length===0||!argv.every(item=>typeof item==='string')){
        throw Error('Enter the executable and arguments as a JSON string array.');
      }
      const request={argv,timeoutSec:Number(timeout.value),...authorization};
      if(stdin.value)request.stdin=stdin.value;
      guestCommandResult=null;
      const result=await api.guestRequest(v.id,'exec',request);
      if(currentId===v.id)guestCommandResult=result;
    } finally {
      if(authorization.credentials)authorization.credentials.password='';
    }
  }
  function hypervGuestTools(v) {
    const linux=v.family==='linux';
    const command=guestCommandResult;
    return h('section',{class:'card'},h('h2',{},'Guest tools'),
      linux&&h('div',{},
        h('button',{class:'btn',disabled:detailWrites.has(v.id+'/agent'),onclick:()=>change(v,'agent',async()=>{
          const result=await api.guestRequest(v.id,'ssh-key',{});
          if(currentId===v.id)guestPublicKey=result.publicKey;
        })},'Show SSH enrollment key'),
        guestPublicKey&&h('div',{},h('p',{},'Add this line to authorized_keys for the guest account.'),
          h('textarea',{'aria-label':'SSH enrollment key',readonly:true,rows:2},guestPublicKey))),
      v.state==='running'?h('button',{class:'btn',disabled:detailWrites.has(v.id+'/agent'),
        onclick:()=>change(v,'agent',()=>runHypervGuestCommand(v))},'Run guest command'):
        h('p',{},'Start the machine before running a guest command.'),
      status(v,'agent'),
      command&&h('div',{},
        S.facts([['Channel',command.channel==='ssh'?'SSH':'PowerShell Direct'],['Exit code',command.exitCode]]),
        command.stdout&&h('pre',{'aria-label':'Standard output'},command.stdout),
        command.stdoutTruncated&&h('p',{},'Standard output was truncated.'),
        command.stderr&&h('pre',{'aria-label':'Standard error'},command.stderr),
        command.stderrTruncated&&h('p',{},'Standard error was truncated.')),S.guestFilePanel(v,guestFileAccess));
  }
  function panel(v) {
    if(tab==='Console')return consolePanel(v,true);
    if(tab==='Hardware')return hardware(v);
    if(tab==='Storage')return storage(v);
    if(tab==='Network')return identityCard(v,true);
    if(tab==='App log')return S.appJobPanel(v.id);
    if(tab==='Guest tools'){
      if(v.template)return h('section',{class:'card'},h('h2',{},'Guest tools'),h('p',{},'Create a linked clone to use guest tools.'));
      if(v.engine==='Hyper-V'&&['windows','linux'].includes(v.family))return hypervGuestTools(v);
      const reason=v.family==='android'?'Android guests have no guest agent.':
        v.engine!=='QEMU'?'Guest agent information is unavailable from this engine.':
        v.state!=='running'?'Start or resume the machine before using its guest agent.':null;
      return h('section',{class:'card'},h('h2',{},'Guest tools'),reason?h('p',{},reason):
        h('button',{class:'btn',disabled:detailWrites.has(v.id+'/agent'),onclick:()=>change(v,'agent',async()=>{
          const report=await api.get(api.machinePath(v.id)+'/agent');
          await api.load();
          if(!report.present)throw Error(report.reason||'The guest agent is not running in this machine.');
          S.toast(report.version?'Guest agent '+report.version+' is running.':'The guest agent is running.');
        })},'Check guest agent'),status(v,'agent'),S.guestFilePanel(v,guestFileAccess));
    }
    if(tab==='Snapshots'){
      if(v.template||v.linkedFrom)return h('section',{class:'card'},h('h2',{},'Snapshots'),
        h('p',{},v.template?'Checkpoints are unavailable for templates.':'Checkpoints are unavailable for linked clones.'));
      const decision=S.data.caps?.[v.id]?.ListSnapshots;
      if(decision?decision.available!==true:v.engine==='QEMU')return h('section',{class:'card'},h('h2',{},'Snapshots'),h('p',{},decision?.reason||'This engine cannot list snapshots.'));
      return snapshots(v);
    }
    const rows={
      Overview:[['Guest system',v.os],['Engine',v.engine],['Configuration',v.vcpu+' vCPU · '+v.ramGb+' GB RAM'],['Network',v.engine==='QEMU'?'QEMU user-mode NAT':S.net(v.net)?.name],['IPv4',S.address(v)],['Snapshots',v.snaps],['Registration',v.registration]],
    };
    return h('section',{class:'card'},h('h2',{},tab),S.facts(rows[tab]),
      tab==='Overview'&&h('div',{class:'vm-actions'},!v.template&&!v.linkedFrom&&S.cap(v.id,'Clone')&&h('button',{class:'btn',onclick:()=>clone(v)},'Clone machine'),
        S.cap(v.id,'Delete')&&h('button',{class:'btn',onclick:()=>remove(v)},'Delete machine')));
  }
  function render(root, params) {
    const v=S.vm(params.id);
    if(!v){root.append(h('section',{class:'card'},h('h1',{},'Machine unavailable'),
      h('p',{},'This machine is absent from the library.'),h('button',{class:'btn',onclick:()=>S.go('library')},'Open Library')));return;}
    const appTools=!v.template&&((v.family==='linux'&&['QEMU','Hyper-V'].includes(v.engine))||
      (v.family==='windows'&&v.engine==='Hyper-V'));
    const details=[...(v.engine==='QEMU'&&!v.template?['Console']:[]),...tabs,...(appTools?['App log']:[])];
    if(currentId!==v.id){currentId=v.id;tab=details[0];selected=null;checkpointView=null;guestPublicKey=null;guestCommandResult=null;}
    if(appLogMachine===v.id){appLogMachine=null;tab='App log';}
    if(!details.includes(tab))tab=details[0];
    root.append(h('div',{class:'vm-page'},h('header',{},h('h1',{},v.name),h('p',{class:'sub'},v.os+' · '+(v.architecture==='aarch64'?S.armLabel:v.engine)),v.architecture==='aarch64'&&h('p',{class:'new-hint'},S.armHint)),
      S.defaultLoginNotice?.(v),
      tab!=='Console'&&!v.template&&consolePanel(v),
      h('div',{class:'vm-tabs',role:'tablist','aria-label':'Machine details'},details.map((name,i)=>h('button',{
        id:tabId(name),class:'btn',role:'tab','aria-selected':String(name===tab),'aria-controls':'vm-panel',tabindex:name===tab?0:-1,
        onclick:()=>chooseTab(name),onkeydown:e=>{const next={ArrowRight:(i+1)%details.length,ArrowLeft:(i+details.length-1)%details.length,Home:0,End:details.length-1}[e.key];
          if(next!==undefined){e.preventDefault();chooseTab(details[next]);}}
      },name))),h('div',{id:'vm-panel',role:'tabpanel',tabindex:0,'aria-labelledby':tabId(tab)},panel(v))));
  }
  S.guestAccessFields=guestAccessFields;
  S.readGuestAccess=readGuestAccess;
  S.showAppLog=machine=>{appLogMachine=machine;S.go('vm',{id:machine});};
  S.register('vm',{title:'Machine',nav:false,render,identityCard});
})();
