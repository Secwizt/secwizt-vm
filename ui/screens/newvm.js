(function () {
  const S=window.SVB,h=S.h;
  const catalog=[
    {os:'Debian 13',arch:'amd64',family:'linux',source:'Debian installation images',licence:'Package licences are included with Debian.',profile:[2,2,20]},
    {os:'Ubuntu Server 26.04 LTS',arch:'amd64',family:'linux',source:'Ubuntu Server downloads',licence:'Package licences are listed in the image notices.',profile:[2,2,25]},
    {os:'Windows 10',arch:'x64',family:'windows',source:'Download Windows 10',licence:'A suitable Windows licence is required.',profile:[4,8,64]},
    {os:'Windows 11 Pro',arch:'x64',family:'windows',source:'Download Windows 11',licence:'A suitable Windows licence is required.',profile:[4,8,64],tpm:true,secureBoot:true,minVcpu:2,minRamGb:4,minDiskGb:64},
    {os:'Android-x86 9.0-r2',arch:'x86_64',family:'android',source:'Android-x86 Project · Release 9.0-r2',licence:'See the image notices.',profile:[2,4,16],secureBoot:false},
    {os:'Debian 13',arch:'arm64',family:'linux',source:'Debian arm64 installation images',licence:'Package licences are included with Debian.',profile:[1,2,12]}
  ];
  const stages=['System','Installer image','Resources','Network identity','Review'];
  const catalogRoute='catalog/';
  let draft, selectedInstaller;
  function diskLimit(host) {return Number.isSafeInteger(host.maxDiskGb)&&host.maxDiskGb>=0?host.maxDiskGb:null;}
  function ramLimit(host) {
    const room=Number.isFinite(host.freeRamGb)?Math.max(0,Math.floor(host.freeRamGb)):host.ramGb;
    if(!host.enabled)return room;
    return Math.min(room,Math.max(0,host.ramGb-host.reserveGb-host.usedRamGb));
  }
  function isArm() {return draft.catalog?.arch==='aarch64'||draft.system===-2||catalog[draft.system]?.arch==='arm64';}
  function applyProfile(entry) {
    const host=S.data.host,[cpu,ram,disk]=entry?.profile || (isArm()?[1,2,12]:[2,2,20]);
    const threads=host.enabled?host.threadBudget-host.usedThreads:host.logical;
    draft.cpu=Math.max(1,Math.min(cpu,threads));
    draft.ram=Math.max(1,Math.min(ram,ramLimit(host)));
    draft.disk=Math.min(disk,diskLimit(host) ?? 0);
    if(draft.engine==='QEMU'){
      const android=(entry?.family||draft.family)==='android';
      draft.cpu=android?1:Math.min(isArm()?2:4,draft.cpu);draft.ram=android?2:Math.min(isArm()?4:8,draft.ram);draft.net='nat';
    }
  }
  function reset(installer){
    draft={step:0,system:0,name:installer?installer.os+' '+installer.arch:'',family:'linux',custom:'',iso:'',net:null,
      saving:false,error:'',pressKeyAtBoot:true,engine:installer?.engine||'Hyper-V',catalog:installer};
    applyProfile(installer||catalog[0]);
  }
  async function loadInstaller(selection) {
    try {
      const data=await S.api.catalog();
      if(selectedInstaller!==selection)return;
      const managed=data.entries.find(entry=>entry.id===selection.id);
      const row=managed||(data.references||[]).find(entry=>entry.id===selection.id&&entry.localIso===true);
      if(!row)throw new Error('This catalog entry has no installer available in the wizard.');
      if(managed&&!data.transfers.some(transfer=>transfer.id===selection.id&&transfer.state==='verified'))
        throw new Error('The catalog installer needs to be verified before it can be used.');
      reset({id:row.id,os:[row.name,row.version].filter(Boolean).join(' '),arch:row.architecture,
        edition:row.edition,fileName:row.fileName,source:row.sourceUrl||row.sourceHost,engine:row.engine,
        engines:row.allowedEngines||[row.engine],family:row.family,secureBoot:row.secureBoot,tpm:row.tpm,
        minVcpu:row.minVcpu,minRamGb:row.minRamGb,minDiskGb:row.minDiskGb,
        localIso:!managed,checksumRequired:row.checksumRequired,profile:[row.vcpu,row.ramGb,row.diskGb]});
    } catch(error) {
      if(selectedInstaller===selection)selection.error=error.message;
    }
    if(selectedInstaller===selection&&S.view==='newvm')S.render(true);
  }
  function jump(step,focus='new-step'){draft.step=step;draft.error='';S.render();document.getElementById(focus)?.focus();}
  function noImage() {return draft.disk?'This machine will have an empty disk and nothing to start from.':'This machine has no disk or installer image to start from.';}
  function render(root,{id}={}) {
    const catalogId=id?.startsWith(catalogRoute)?id.slice(catalogRoute.length):null;
    if(catalogId===null) {
      selectedInstaller=null;
      if(!draft||draft.catalog)reset();
    } else {
      if(selectedInstaller?.id!==catalogId) {
        draft=null;
        selectedInstaller={id:catalogId};
        void loadInstaller(selectedInstaller);
      }
      if(!draft) {
        const error=selectedInstaller.error;
        root.append(h('div',{class:'new-page'},h('h1',{},'New machine'),h('section',{class:'card'},
          h('p',{role:'status'},error||'Checking the catalog installer…'),
          h('button',{type:'button',class:'btn',onclick:()=>S.go('os-catalog')},'Back to OS catalog'))));
        return;
      }
    }
    const step=draft.step,installer=draft.catalog,entry=installer||catalog[draft.system],host=S.data.host;
    const qemu=draft.engine==='QEMU',setup=S.data.qemu;
    const networks=S.data.networks.filter(n=>qemu?n.id==='nat':n.mode!=='Bridged'||n.ready===true);
    if(draft.net==null)draft.net=(networks.find(n=>n.mode==='Routed'&&n.dhcp==='serving')||networks.find(n=>n.mode==='NAT')||networks[0])?.id;
    const net=networks.find(n=>n.id===draft.net);
    const title=entry?.os || draft.custom.trim(),family=entry?.family || draft.family,maxDisk=diskLimit(host);
    const localIso=installer?.localIso===true,managed=installer&&!localIso;
    const hasImage=Boolean(managed||draft.iso);
    const minimumCpu=entry?.minVcpu??1,minimumRam=entry?.minRamGb??1,minimumDisk=entry?.minDiskGb??(qemu||installer?1:0);
    const image=managed?(installer.fileName||[title,installer.edition].filter(Boolean).join(' · ')):draft.iso;
    const arm=isArm(),android=qemu&&family==='android';
    const armReason=setup?.armReason||'Select the matching Arm executable and firmware by verifying the QEMU folder in Settings.';
    const content=h('div',{class:'new-content'}),reason=h('p',{class:'new-error',role:'status'});
    const next=h('button',{class:'btn new-next',type:'submit'},step===4?'Create stopped machine':'Continue');
    function update() {
      let msg='';
      if(step===0||step===4) {
        if(!draft.name.trim())msg='Enter a name for this machine.';
        else if(draft.system<0&&!draft.custom.trim())msg='Enter the guest operating system.';
        else if(S.data.vms.some(v=>v.name.toLowerCase()===draft.name.trim().toLowerCase()))msg='This machine name is in use.';
        else if(entry?.tpm&&host.tpm?.available===false)msg=installer?'The virtual TPM needed for this installer is unavailable.':'The virtual TPM is unavailable. Select Windows 10 or another guest.';
        else if(qemu&&setup?.available!==true)msg=S.qemuReason(setup);
        else if(arm&&setup.armAvailable!==true)msg=armReason;
      }
      if(!msg&&(step===1||step===4)&&!hasImage) {
        if(localIso)msg='Choose a local ISO for this catalog entry.';
        else if(android)msg='Choose a local Android x86-64 installer image.';
      }
      if(!msg&&(step===2||step===4)) {
        msg=S.screens.get('guard').issue(draft.cpu,draft.ram);
        if(!msg&&host.enabled&&draft.ram>ramLimit(host))msg='Only '+ramLimit(host)+' GiB of memory is available for this guest.';
        if(!msg&&maxDisk===null&&installer)msg='Free space on the library drive could not be measured.';
        if(!msg&&installer&&maxDisk===0)msg='The library drive has no room for this machine’s virtual disk.';
        if(!msg&&maxDisk===null&&draft.disk!==0)msg='Free space is unavailable. Choose zero for a diskless machine or retry when the library drive is available.';
        if(!msg&&(!Number.isSafeInteger(draft.disk)||draft.disk<0||draft.disk>(maxDisk ?? 0)))msg='Choose a whole disk size from 0 to '+(maxDisk ?? 0).toLocaleString()+' GiB.';
        if(!msg&&arm&&(draft.cpu<1||draft.cpu>2||draft.ram<1||draft.ram>4))msg='Choose 1 to 2 CPUs and 1 to 4 GiB for Emulated Arm.';
        if(!msg&&qemu&&!arm&&(draft.cpu<1||draft.cpu>4||draft.ram<1||draft.ram>8))msg='Choose 1 to 4 CPUs and 1 to 8 GiB for a legacy BIOS guest.';
        if(!msg&&minimumDisk===1&&draft.disk<1)
          msg=qemu&&!installer?'Choose at least 1 GiB for the QEMU disk.':'Choose at least 1 GiB for the virtual disk.';
        if(!msg&&(draft.cpu<minimumCpu||draft.ram<minimumRam||draft.disk<minimumDisk))
          msg=title+' needs at least '+minimumCpu+' vCPU, '+minimumRam+' GiB of memory and '+minimumDisk+' GiB of disk space.';
      }
      if(!msg&&(step===3||step===4)&&!net)msg='Select an available network.';
      reason.textContent=msg||draft.error;next.disabled=Boolean(msg)||draft.saving;
    }
    if(step===0) {
      const name=h('label',{class:'new-field'},'Machine name',h('input',{id:'new-name',required:true,maxlength:80,value:draft.name,oninput:e=>{draft.name=e.target.value;update();}}));
      if(installer) {
        content.append(name,S.facts([['Guest system',title],['Edition',installer.edition],['Architecture',installer.arch],
          ['Recommended engine',installer.engine],['Recommended resources',installer.profile[0]+' vCPU · '+installer.profile[1]+' GiB RAM · '+installer.profile[2]+' GiB disk']],'new-facts'));
      } else {
        content.append(h('button',{class:'btn',type:'button',disabled:setup?.available!==true,onclick:()=>S.go('diskimport')},'Import an existing virtual disk'),
          h('p',{class:'new-hint'},setup?.available===true?'Import a local disk to create a machine that boots its installed system.':'Select QEMU in Settings to import a virtual disk.'));
        const choices=catalog.map((p,i)=>{
          const blocked=p.tpm&&host.tpm?.available===false;
          const armEntry=p.arch==='arm64';
          return h('label',{class:'new-choice'},h('input',{type:'radio',name:'guest-system',disabled:blocked||(armEntry&&setup?.armAvailable!==true),checked:draft.system===i,onchange:()=>{
            draft.system=i;draft.engine=armEntry?'QEMU':'Hyper-V';applyProfile(p);jump(0);
          }}),h('span',{},h('strong',{},p.os+' · '+p.arch),h('small',{},'Official source · '+p.source),h('small',{},p.licence),
            armEntry&&h('small',{},setup?.armAvailable===true?S.armLabel:armReason),p.tpm&&h('small',{},host.tpm?.reason||'Windows 11 requires Secure Boot and a virtual TPM. This account’s TPM access is checked during creation.'),
            blocked&&h('small',{},'Choose Windows 10 on this host.')));
        });
        choices.push(h('label',{class:'new-choice'},h('input',{type:'radio',name:'guest-system',checked:draft.system===-1,
          onchange:()=>{draft.system=-1;draft.engine='Hyper-V';applyProfile(null);jump(0,'new-custom');}}),h('span',{},'Other x86 guest')));
        choices.push(h('label',{class:'new-choice'},h('input',{type:'radio',name:'guest-system',checked:draft.system===-2,disabled:setup?.armAvailable!==true,
          onchange:()=>{draft.system=-2;draft.family='other';draft.engine='QEMU';applyProfile(null);jump(0,'new-custom');}}),h('span',{},'Other Arm guest')));
        content.append(name,h('fieldset',{},h('legend',{},'Guest system'),h('div',{class:'new-catalog'},choices)));
      }
      if(arm)content.append(h('p',{},h('strong',{},S.armLabel)),h('p',{class:'new-hint'},S.armHint));
      else if(installer?installer.engines.length>1:['android','linux','bsd','other'].includes(family)) {
        content.append(h('fieldset',{},h('legend',{},'Virtualization engine'),
          (installer?.engines||['Hyper-V','QEMU']).map(engine=>h('label',{class:'new-choice'},
            h('input',{type:'radio',name:'guest-engine',value:engine,checked:draft.engine===engine,
              disabled:engine==='QEMU'&&setup?.available!==true,'aria-describedby':engine==='QEMU'?'qemu-setup-state':null,
              onchange:()=>{draft.engine=engine;if(installer&&engine==='Hyper-V')draft.net=null;applyProfile(entry);jump(0);}}),
            h('span',{},h('strong',{},family==='android'?engine:engine==='QEMU'?'Legacy BIOS · QEMU':'UEFI · Hyper-V'),engine==='QEMU'&&h('small',{id:'qemu-setup-state'},
              setup?.available===true?(family==='android'?'Requires Windows Hypervisor Platform acceleration.':'This guest uses legacy BIOS, so it runs on QEMU with WHPX acceleration.'):S.qemuReason(setup)))))));
      }
      if(entry?.tpm)content.append(h('p',{class:'new-hint'},S.tpmCertificateHint));
      if(!entry) content.append(h('div',{class:'new-fields'},h('label',{class:'new-field'},'Guest system',
        h('input',{id:'new-custom',required:true,maxlength:160,value:draft.custom,oninput:e=>{draft.custom=e.target.value;update();}})),
        h('label',{class:'new-field'},'System family',h('select',{onchange:e=>{draft.family=e.target.value;if(!['linux','bsd','other','android'].includes(draft.family))draft.engine='Hyper-V';applyProfile(null);jump(0);}},
          (arm?['linux','other']:['linux','windows','bsd','android','other']).map(f=>h('option',{value:f,selected:f===draft.family},f))))));
    } else if(step===1&&localIso) {
      const pending=draft;
      content.append(S.facts([['Guest system',title],['Edition',installer.edition],['Architecture',installer.arch],
        ['Official page',installer.source]],'new-facts'),
        h('p',{class:'new-hint'},installer.checksumRequired?'Choose the exact release listed here. The service checks the ISO checksum when you create the machine.':'Choose an installer ISO you already have.'),
        S.imagePicker(path=>{if(draft===pending){draft.iso=path;jump(1);}}),
        h('p',{class:'new-hint'},draft.iso||'No local ISO selected.'));
      if(draft.iso)content.append(h('button',{class:'btn',type:'button',onclick:()=>{draft.iso='';jump(1);}},'Clear image'));
    } else if(step===1&&managed) {
      content.append(S.facts([['Verified installer',image],['Guest system',title],['Edition',installer.edition],
        ['Architecture',installer.arch],['Official source',installer.source]],'new-facts'));
    } else if(step===1) {
      content.append(h('p',{},arm?'Choose a local arm64 UEFI installer ISO, or attach one later in Storage.':android?'Choose the read-only Android x86-64 ISO for this machine.':qemu?'Choose a local x86 BIOS installer ISO, or attach the first installer later in Storage.':'Choose the ISO image to boot in the console. You can eject it from Storage after installation.'),
        S.imagePicker(path=>{draft.iso=path;jump(1);}),h('p',{class:'new-hint'},draft.iso||'No installer image selected.'));
      if(draft.iso)content.append(h('button',{class:'btn',type:'button',onclick:()=>{draft.iso='';jump(1);}},'Clear image'));
    } else if(step===2) {
      function field(label,key,min,max) {return h('label',{class:'new-field'},label,
        h('input',{id:'new-'+key,type:'number',min,max,step:1,required:true,value:Number.isFinite(draft[key])?draft[key]:'',
          oninput:e=>{draft[key]=e.target.valueAsNumber;update();}}));}
      content.append(h('p',{},host.enabled?'Available under host protection · '+Math.max(0,host.threadBudget-host.usedThreads)+' vCPU · '+ramLimit(host)+' GiB memory':
        'Host capacity · '+host.logical+' logical processors · '+host.ramGb+' GiB memory'+(Number.isFinite(host.freeRamGb)?' · '+host.freeRamGb+' GiB currently available':'')),
        h('p',{class:'new-hint'},maxDisk===null?'The service could not measure free space on the library drive.':'Maximum new disk on this library drive · '+maxDisk.toLocaleString()+' GiB'),
        android&&S.facts([['Virtual CPUs',1],['Memory','2 GiB'],['Disk format','qcow2']]),
        h('div',{class:'new-fields'},!android&&field('Virtual CPUs','cpu',minimumCpu,qemu?Math.min(arm?2:4,host.logical):host.enabled?host.logical:null),!android&&field('Memory (GiB)','ram',minimumRam,qemu?Math.min(arm?4:8,ramLimit(host)):host.enabled?host.ramGb:null),
          field(minimumDisk?'Disk size (GiB)':'Disk size (GiB, 0 for no disk)','disk',minimumDisk,maxDisk ?? 0)));
    } else if(step===3) {
      if(qemu)content.append(S.facts([['Network','QEMU user-mode NAT'],['Address','Assigned by QEMU']],'new-facts'));
      else {
        if(family==='android')content.append(h('p',{class:'new-hint'},S.androidNetworkHint));
        content.append(h('label',{class:'new-field'},'Network',h('select',{id:'new-net',onchange:e=>{draft.net=e.target.value;jump(3);}},
        !net&&h('option',{value:'',selected:true,disabled:true},'Select a ready network'),
        networks.map(n=>h('option',{value:n.id,selected:n.id===net?.id},n.name+' · '+n.mode)))),
        networks.length<S.data.networks.length&&h('p',{class:'new-hint'},'Finish bridge setup in Networks before selecting that network.'),
        h('p',{class:'new-hint'},net?.note),S.facts([['Address',net?.mode==='Bridged'?'Assigned by the LAN router':net?.mode==='NAT'?'Assigned by Windows':'Reserved by the service on creation'],
          ['MAC and library name','Assigned by the service on creation'],['DHCP service',net?.dhcp],['DNS service',net?.dnsStatus||'Status unavailable'],['Internet NAT',net?.mode==='Routed'?net.natStatus:null]],'new-facts'));
        if(net?.mode==='Link-local')content.append(h('p',{class:'new-hint'},'Fixed 169.254 addresses on this link. No internet or administrator setup.'));
      }
    } else {
      content.append(S.facts([['Machine',draft.name.trim()],['Guest system',title],['Engine',arm?S.armLabel:qemu?(android?'QEMU · WHPX required':'QEMU · legacy BIOS · WHPX required'):'Hyper-V · generation 2'],
        ['Resources',draft.cpu+' vCPU · '+draft.ram+' GiB RAM'],['Disk',draft.disk?draft.disk+' GiB':'No disk'],
        [localIso?'Local installer ISO':'Installer image',image||'None'],['Architecture',installer?.arch],
        ['Official page',localIso?installer.source:null],
        ['Secure Boot',entry?.secureBoot===true?'On':entry?.secureBoot===false?'Off':null],
        ['Virtual TPM',entry?.tpm?'Required':null],['Network',qemu?'QEMU user-mode NAT':net?.name],['Initial state','Stopped']],'new-facts'));
      if(entry?.tpm)content.append(h('p',{class:'new-hint'},S.tpmCertificateHint));
      if(!hasImage)content.append(h('p',{class:'new-error',role:'status'},noImage()),
        h('button',{class:'btn',type:'button',onclick:()=>jump(1)},'Choose installer image'));
      else if(!draft.disk)content.append(h('p',{class:'new-error'},'This machine can boot the image, but has no virtual disk to install onto.'));
      else if(family==='windows')content.append(S.bootKeyOption(draft.pressKeyAtBoot,enabled=>{draft.pressKeyAtBoot=enabled;}));
    }
    function continueFromHeading(e) {
      if(e.key!=='Enter'||e.altKey||e.ctrlKey||e.metaKey||e.shiftKey||e.isComposing)return;
      e.preventDefault();
      if(!e.repeat&&!next.disabled)e.currentTarget.closest('form').requestSubmit(next);
    }
    const progress=h('ol',{class:'new-stages','aria-label':'Wizard progress'},stages.map((s,i)=>h('li',{'aria-current':i===step?'step':null},(i+1)+' · '+s)));
    root.append(h('div',{class:'new-page'},h('h1',{},'New machine'),progress,h('form',{class:'card',onsubmit:async e=>{
      e.preventDefault();draft.error='';update();if(next.disabled)return;if(step<4){jump(step+1);return;}
      const pending=draft;
      const body={name:pending.name.trim(),vcpu:pending.cpu,ramGb:pending.ram,net:pending.net};
      if(installer) {
        Object.assign(body,{catalogId:installer.id,engine:pending.engine,diskGb:pending.disk});
        if(localIso)body.isoPath=pending.iso;
      } else {
        Object.assign(body,{os:title,family});
        if(arm)body.architecture='aarch64';
        if(qemu){body.engine='QEMU';body.secureBoot=false;body.tpm=false;}
        if(pending.disk)body.diskGb=pending.disk;if(pending.iso)body.isoPath=pending.iso;
        if(entry?.secureBoot===false)body.secureBoot=false;
        if(entry?.tpm){body.secureBoot=true;body.tpm=true;}
      }
      pending.saving=true;update();
      e.currentTarget.querySelectorAll('button').forEach(button=>{button.disabled=true;});
      try {
        const machine=await S.api.action('POST','/v1/machines',body);
        if(family==='windows'&&hasImage&&pending.disk)S.setBootKey(machine.id,pending.pressKeyAtBoot);
        if(draft===pending){draft=null;S.go('vm',{id:machine.id});}
      } catch(error) {
        if(draft===pending){pending.error=error.message;pending.saving=false;S.render();}
      }
    }},h('h2',{id:'new-step',tabindex:-1,onkeydown:continueFromHeading},stages[step]),content,reason,h('div',{class:'new-actions'},
        step>0&&h('button',{class:'btn',type:'button',disabled:draft.saving,onclick:()=>jump(step-1)},'Back'),next,
        h('button',{class:'btn',type:'button',disabled:draft.saving,onclick:()=>{draft=null;S.go(installer?'os-catalog':'library');}},'Cancel')))));
    update();
  }
  addEventListener('svb-render',()=>{if(S.view!=='newvm'){draft=null;selectedInstaller=null;}});
  S.register('newvm',{title:'New machine',render});
})();
