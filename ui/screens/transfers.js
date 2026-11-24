(function () {
  const S=window.SVB, h=S.h, api=S.api;
  const base='/v1/transfers';
  const running=job=>job && (job.state==='running'||job.state==='cancelling');
  const button=(text,fn)=>h('button',{class:'btn',type:'button',onclick:fn},text);
  const field=(name,input)=>h('label',{class:'new-field'},name,input);
  let draft=null;
  const exportDrafts=new Map();

  function watch(kind,vmId) {
    const box=h('div',{'aria-live':'polite'}), detail=h('p',{}), bar=h('progress',{max:100,'aria-label':'Disk conversion progress'});
    let job=null, timer, request=0;
    const cancel=button('Cancel conversion',async()=>{
      if(job)show(await api.diskRequest('DELETE',base+'/'+api.segment(job.id)));
    });
    function show(next){
      job=next;
      clearTimeout(timer);
      if(!job){box.replaceChildren();return;}
      const active=running(job);
      bar.value=job.percent||0;
      const text=active?(job.state==='cancelling'?'Cancelling conversion…':(kind==='import'?'Importing disk · ':'Exporting disk · ')+bar.value+'%'):
        job.state==='completed'?(kind==='import'?'Import complete. The machine is stopped.':'Export complete · '+job.result.path):
        (job.message||'Disk conversion ended.');
      detail.textContent=text+(job.cleanupMessage?' '+job.cleanupMessage:'');
      cancel.disabled=job.state==='cancelling';
      box.replaceChildren(detail);
      if(active){
        box.append(bar,cancel);
        timer=setTimeout(()=>{if(box.isConnected)void read(job.id);},650);
      }else if(job.state==='completed'&&kind==='import'){
        box.append(button('Open imported machine',async()=>{await api.load();S.go('vm',{id:job.machineId});}));
      }
    }
    async function read(id){
      const version=++request;
      try {
        const data=await api.get(id?base+'/'+api.segment(id):base);
        if(version!==request||!box.isConnected)return;
        if(id)show(data);
        else {
          const match=item=>item?.kind===kind&&(!vmId||item.machineId===vmId);
          show(match(data.current)?data.current:(data.recent||[]).slice().reverse().find(match));
        }
      }catch(error){
        if(version===request&&box.isConnected){detail.textContent=error.message;box.replaceChildren(detail,button('Retry status',()=>read(id)));}
      }
    }
    void read();
    return {box,started:next=>{++request;show(next);}};
  }

  function importScreen(root) {
    if(!draft)draft={path:'',name:'',family:'linux',firmware:'',info:null,busy:false,error:''};
    const form=draft, watcher=watch('import');
    const status=h('p',{role:'status',class:'new-error'},form.error);
    const choose=button(form.path?'Choose another disk':'Choose disk',async()=>{
      const selected=await api.native('pickDisk');
      if(!selected)return;
      form.path=selected;form.info=null;form.firmware='';form.error='';form.busy=true;S.render();
      try {
        const info=await api.diskRequest('POST',base+'/inspect',{path:selected});
        form.info=info;form.firmware=info.firmware||'';
      }catch(error){form.error=error.message;}
      finally{form.busy=false;if(draft===form)S.render();}
    });
    choose.disabled=form.busy;
    const name=h('input',{id:'import-name',required:true,maxlength:80,value:form.name,oninput:e=>{form.name=e.target.value;}});
    const families=[['linux','Linux'],['windows','Windows'],['android','Android'],['bsd','BSD'],['dos','DOS'],['other','Other']];
    const family=h('select',{onchange:e=>{form.family=e.target.value;}},families.map(([key,label])=>h('option',{value:key,selected:key===form.family},label)));
    const firmware=h('select',{required:true,onchange:e=>{form.firmware=e.target.value;}},
      h('option',{value:'',selected:!form.firmware,disabled:true},'Select the firmware used by this disk'),
      h('option',{value:'uefi',selected:form.firmware==='uefi'},'UEFI · Hyper-V generation 2'),
      h('option',{value:'bios',selected:form.firmware==='bios'},'Legacy BIOS · QEMU'));
    const start=h('button',{class:'btn primary',type:'submit',disabled:form.busy||!form.info},'Import disk');
    const submit=async e=>{
      e.preventDefault();
      if(!form.info||form.busy)return;
      form.busy=true;start.disabled=true;status.textContent='';
      try {
        const os=families.find(([key])=>key===form.family)[1];
        const job=await api.diskRequest('POST',base+'/import',{path:form.path,name:form.name.trim(),family:form.family,os,firmware:form.firmware});
        watcher.started(job);
      }catch(error){status.textContent=error.message;}
      finally{form.busy=false;start.disabled=false;}
    };
    root.append(h('div',{class:'new-page'},h('h1',{},'Import a virtual disk'),
      h('p',{},'Create a stopped x86 machine from a local VMDK, VDI, VHD, VHDX, qcow2 or raw .img file. The service reads the source and writes a separate system disk in the library.'),
      h('form',{class:'card',onsubmit:submit},choose,h('p',{},form.path||'No disk selected.'),
        form.info&&S.facts([['Detected format',form.info.format],['Virtual size',form.info.bytes.toLocaleString()+' bytes']]),
        field('Machine name',name),field('Installed guest system',family),field('Boot firmware',firmware),
        form.info&&h('p',{class:'new-hint'},form.info.firmware?'The partition table suggests the selected firmware. You can change it.':'Choose the firmware the original system used.'),
        h('p',{class:'new-hint'},'The machine starts with one CPU, 2 GiB memory and NAT networking.'),
        start,button('Back to new machine',()=>S.go('newvm')),status),watcher.box));
  }

  function exportPanel(vm) {
    const area=h('section',{},h('h3',{},'Export disk')),watcher=watch('export',vm.id);
    const reason=vm.state!=='off'||vm.registration!=='registered'?'Power off the machine and verify its registration before exporting.':
      vm.snaps?'Merge all checkpoints before exporting.':S.data.qemu?.available!==true?S.qemuReason(S.data.qemu):'';
    if(reason){area.append(h('p',{},reason),watcher.box);return area;}
    const form=exportDrafts.get(vm.id)||{format:'vmdk',folder:'',name:vm.id+'.vmdk'};
    exportDrafts.set(vm.id,form);
    const file=h('input',{required:true,value:form.name,oninput:e=>{form.name=e.target.value;}});
    const select=h('select',{onchange:e=>{
      const stem=form.name.replace(/\.(vmdk|vdi|vhdx|qcow2)$/i,'');
      form.format=e.target.value;form.name=stem+'.'+form.format;file.value=form.name;
    }},['vmdk','vdi','vhdx','qcow2'].map(f=>h('option',{value:f,selected:f===form.format},f.toUpperCase())));
    const folder=h('p',{},form.folder||'No export folder selected.'), status=h('p',{role:'status',class:'new-error'});
    const choose=button('Choose export folder',async()=>{
      const selected=await api.native('pickExportFolder');
      if(selected){form.folder=selected;folder.textContent=selected;status.textContent='';}
    });
    const submit=async e=>{
      e.preventDefault();
      if(!form.folder){status.textContent='Choose the destination folder.';return;}
      try {
        const job=await api.diskRequest('POST',base+'/export',{machineId:vm.id,folder:form.folder,format:form.format,fileName:form.name.trim()});
        status.textContent='';watcher.started(job);
      }catch(error){status.textContent=error.message;}
    };
    area.append(h('form',{onsubmit:submit},field('Export format',select),field('Filename',file),choose,folder,
      h('button',{type:'submit',class:'btn'},'Export disk'),status),watcher.box);
    return area;
  }
  const guestFiles=new Map();
  const activeFileStates=['running','cancelling','finalizing'];
  const pendingFile=job=>Boolean(job&&activeFileStates.includes(job.state));
  const byteCount=value=>Number.isSafeInteger(value)&&value>=0;
  const bytesText=value=>value.toLocaleString()+(value===1?' byte':' bytes');

  function fileReceipt(job,direction,id) {
    if(!job||typeof job.id!=='string'||!['send','get'].includes(job.direction)||
        (direction&&job.direction!==direction)||(id&&job.id!==id)||
        ![...activeFileStates,'completed','cancelled','failed'].includes(job.state)||!byteCount(job.bytes)||
        (job.totalBytes!=null&&(!byteCount(job.totalBytes)||job.bytes>job.totalBytes))) {
      throw Error('The service returned unreadable file transfer status.');
    }
    api.segment(job.id);
    return job;
  }

  function watchGuestFile(vmId,entry) {
    clearTimeout(entry.timer);
    if(pendingFile(entry.job)&&!entry.error) {
      entry.timer=setTimeout(()=>void readGuestFile(vmId,entry,'GET'),650);
    }
  }

  async function attachGuestFile(vmId,entry,notice='') {
    if(entry.attaching||entry.starting||entry.cancelling)return;
    clearTimeout(entry.timer);
    const previous=entry.job?.id;
    const request=++entry.request;
    entry.discovered=true;
    entry.attaching=true;
    entry.error='';
    entry.draw();
    try {
      const reply=await api.guestFileRequest(vmId,'GET',null);
      if(request!==entry.request)return;
      entry.job=reply?.job===null?null:fileReceipt(reply?.job);
      if(notice&&(!entry.job||entry.job.id===previous))entry.error=notice;
    } catch(error) {
      if(request===entry.request)entry.error=notice||error.message;
    } finally {
      if(request===entry.request) {
        entry.attaching=false;
        entry.draw();
        watchGuestFile(vmId,entry);
      }
    }
  }

  async function readGuestFile(vmId,entry,method) {
    if(!pendingFile(entry.job)||entry.attaching||entry.cancelling||(method==='DELETE'&&entry.job.state!=='running'))return;
    clearTimeout(entry.timer);
    const {id,direction}=entry.job;
    const request=++entry.request;
    entry.cancelling=method==='DELETE';
    entry.error='';
    entry.draw();
    try {
      const reply=await api.guestFileRequest(vmId,method,id).catch(error=>{
        if(method==='DELETE'&&error.code==='refused')return api.guestFileRequest(vmId,'GET',id);
        throw error;
      });
      if(request===entry.request)entry.job=fileReceipt(reply,direction,id);
    } catch(error) {
      if(request===entry.request) {
        if(method==='GET'&&error.code==='not_found') {
          void attachGuestFile(vmId,entry);
          return;
        }
        entry.error=error.message;
      }
    } finally {
      if(request===entry.request) {
        entry.cancelling=false;
        entry.draw();
        watchGuestFile(vmId,entry);
      }
    }
  }

  async function updateGuestFileService(vmId,entry,enabled) {
    if(enabled!==undefined&&(entry.serviceBusy||S.vm(vmId)?.state!=='off'))return;
    const request=(entry.serviceRequest||0)+1;
    entry.serviceRequest=request;
    entry.serviceBusy=true;
    entry.serviceError='';
    entry.draw();
    try {
      const status=await api.guestFileService(vmId,enabled);
      if(request!==entry.serviceRequest)return;
      if(typeof status?.available!=='boolean'||typeof status.enabled!=='boolean'||typeof status.canChange!=='boolean') {
        throw Error('The service returned unreadable Guest Service Interface status.');
      }
      entry.guestService=status;
    } catch(error) {
      if(request===entry.serviceRequest)entry.serviceError=error.message;
    } finally {
      if(request===entry.serviceRequest) {
        entry.serviceBusy=false;
        entry.draw();
      }
    }
  }

  const canSendToHyperV=entry=>entry.guestService?.available===true&&entry.guestService.enabled&&
    entry.guestService.sendSupported===true&&!entry.serviceBusy&&!entry.serviceError;

  async function startGuestFile(vm,entry,direction,access) {
    if(entry.starting||entry.attaching||pendingFile(entry.job)||
        (vm.engine==='Hyper-V'&&direction==='send'&&!canSendToHyperV(entry)))return;
    entry.starting=true;
    entry.error='';
    entry.draw();
    let request, submitted=false;
    try {
      const sending=direction==='send';
      let hostPath=sending?await api.native('pickGuestUpload'):null;
      if(sending&&!hostPath)return;
      const path=h('input',{id:'guest-file-path',type:'text',required:true,maxlength:4096,autocomplete:'off',spellcheck:'false',
        placeholder:vm.family==='windows'?'C:\\Temp\\file.txt':'/tmp/file.txt'});
      const confirmed=await S.dialog(sending?'Send file to machine':'Get file from machine',
        sending?h('p',{},hostPath):h('p',{},'Enter the full path to the file in the guest.'),
        sending?'Send file':'Choose destination',field(sending?'Guest destination path':'Guest source path',path));
      if(!confirmed)return;
      const guestPath=path.value;
      if(!sending) {
        hostPath=await api.native('pickGuestDownload',{text:guestPath.split(/[\\/]/).at(-1)||''});
        if(!hostPath)return;
      }
      request={direction,hostPath,guestPath};
      if(vm.engine==='Hyper-V') {
        const authorization=await access(vm,direction);
        if(!authorization)return;
        Object.assign(request,authorization);
      }
      if(!S.data.online||S.vm(vm.id)?.state!=='running')throw Error('Start or resume the machine before transferring a file.');
      submitted=true;
      const response=api.guestFileRequest(vm.id,'POST',null,request);
      if(request.credentials)request.credentials.password='';
      entry.job=fileReceipt(await response,direction);
    } catch(error) {
      entry.error=error.message;
    } finally {
      if(request?.credentials)request.credentials.password='';
      entry.starting=false;
      entry.draw();
      if(submitted&&entry.error)void attachGuestFile(vm.id,entry,entry.error);
      else watchGuestFile(vm.id,entry);
    }
  }

  function filePhase(entry) {
    if(entry.starting)return 'Preparing the file transfer…';
    if(entry.attaching)return 'Checking for a file transfer…';
    if(entry.cancelling)return 'Cancelling transfer…';
    switch(entry.job?.state) {
      case 'running': return entry.job.direction==='send'?'Sending file…':'Getting file…';
      case 'finalizing': return 'Verifying and saving…';
      case 'cancelling': return 'Cancelling transfer…';
      case 'completed': return 'Transfer complete.';
      case 'cancelled': return 'Transfer cancelled.';
      case 'failed': return 'Transfer failed.';
      default: return '';
    }
  }

  function guestFilePanel(vm,access) {
    const entry=guestFiles.get(vm.id)||{request:0,error:''};
    guestFiles.set(vm.id,entry);
    const hyperv=vm.engine==='Hyper-V'&&['windows','linux'].includes(vm.family);
    const supported=hyperv||(vm.engine==='QEMU'&&['linux','windows'].includes(vm.family));
    const unavailable=vm.family==='android'?'Android guests have no guest agent.':
      !supported?'File transfer is unavailable for this guest.':
      vm.state!=='running'?'Start or resume the machine to transfer files.':'';
    const send=h('button',{id:'guest-file-send',class:'btn',type:'button',
      onclick:()=>startGuestFile(vm,entry,'send',access)},'Send file to machine');
    const get=h('button',{id:'guest-file-get',class:'btn',type:'button',
      onclick:()=>startGuestFile(vm,entry,'get',access)},'Get file from machine');
    const phase=h('p',{role:'status'});
    const count=h('p',{});
    const progress=h('progress',{id:'guest-file-progress','aria-label':'File transfer progress'});
    const cancel=h('button',{class:'btn',id:'guest-file-cancel',type:'button',
      onclick:()=>readGuestFile(vm.id,entry,'DELETE')},'Cancel transfer');
    const checksum=h('p',{id:'guest-file-checksum',class:'guest-file-checksum'});
    const message=h('p',{}), failure=h('p',{role:'alert',class:'new-error'});
    const check=button('Check transfer status',()=>pendingFile(entry.job)?
      readGuestFile(vm.id,entry,'GET'):attachGuestFile(vm.id,entry));
    const status=h('div',{id:'guest-file-status'},phase,count,h('div',{class:'vm-actions'},progress,cancel),
      checksum,message,failure,check);
    const serviceToggle=hyperv?h('input',{id:'guest-file-interface',type:'checkbox',
      'aria-describedby':'guest-file-interface-status',onchange:event=>
        updateGuestFileService(vm.id,entry,event.currentTarget.checked)}):null;
    const serviceStatus=hyperv?h('p',{id:'guest-file-interface-status',role:'status',class:'new-hint'}):null;
    const refreshService=hyperv?button('Check Guest Service Interface',()=>updateGuestFileService(vm.id,entry)):null;
    const serviceControls=hyperv?h('div',{},
      h('label',{class:'boot-key-option'},serviceToggle,'Enable Guest Service Interface'),
      h('p',{class:'new-hint'},'Allows sending files when the Hyper-V file copy service is running inside this machine. Send uses '+
        (vm.family==='windows'?'PowerShell Direct':'pinned SSH')+' to verify the file.'),
      serviceStatus,refreshService):null;
    entry.draw=()=>{
      const job=entry.starting?null:entry.job;
      const active=pendingFile(job);
      const error=entry.error;
      get.disabled=Boolean(unavailable||active||entry.starting||entry.attaching);
      send.disabled=get.disabled||(hyperv&&!canSendToHyperV(entry));
      if(hyperv) {
        const service=entry.guestService;
        serviceToggle.checked=service?.enabled===true;
        serviceToggle.disabled=entry.serviceBusy||vm.state!=='off'||service?.canChange!==true||
          service?.available!==true||service?.sendSupported!==true||active||entry.starting||Boolean(entry.serviceError);
        const reason=entry.serviceError||(entry.serviceBusy?'Checking Guest Service Interface…':service?.reason
          ||(service?.available===false?'Guest Service Interface is unavailable for this machine.':
            service&&service.sendSupported!==true?'Sending files to Hyper-V is unavailable.':
            vm.state!=='off'?'Power off the machine to change this setting.':''));
        serviceStatus.textContent=reason;
        serviceStatus.hidden=!reason;
        refreshService.hidden=!entry.serviceError||entry.serviceBusy;
      }
      const title=filePhase(entry);
      if(phase.textContent!==title)phase.textContent=title;
      phase.hidden=!title;
      count.hidden=!job;
      count.textContent=job?bytesText(job.bytes)+(job.totalBytes==null?'':' of '+bytesText(job.totalBytes)):'';
      progress.hidden=cancel.hidden=!active;
      cancel.disabled=entry.cancelling||job?.state!=='running';
      if(active&&job.totalBytes>0) {
        progress.max=job.totalBytes;
        progress.value=job.bytes;
      } else progress.removeAttribute?.('value');
      const hash=job?.state==='completed'&&typeof job.sha256==='string'&&/^[0-9a-f]{64}$/i.test(job.sha256)?job.sha256:'';
      checksum.hidden=!hash;
      checksum.textContent=hash?'SHA-256 '+hash:'';
      message.hidden=!job?.message;
      message.textContent=job?.message||'';
      failure.hidden=!error;
      if(failure.textContent!==error)failure.textContent=error;
      check.hidden=!error;
    };
    entry.draw();
    if(supported&&S.data.online&&!entry.discovered)void attachGuestFile(vm.id,entry);
    if(hyperv&&S.data.online&&entry.serviceObservedState!==vm.state) {
      entry.serviceObservedState=vm.state;
      void updateGuestFileService(vm.id,entry);
    }
    return h('div',{class:'guest-files'},h('h3',{},'File transfer'),serviceControls,
      unavailable&&h('p',{class:'new-hint'},unavailable),h('div',{class:'vm-actions'},send,get),status);
  }

  S.guestFilePanel=guestFilePanel;
  S.exportDiskPanel=exportPanel;
  S.register('diskimport',{title:'Import a virtual disk',nav:false,render:importScreen});
  addEventListener('svb-render',()=>{if(S.view!=='diskimport')draft=null;});
})();
