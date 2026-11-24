(function () {
  const S=window.SVB,h=S.h;
  let qemuBusy=false,qemuError='';
  function qemuSettings() {
    const setup=S.data.qemu;
    async function choose() {
      if(qemuBusy)return;
      qemuBusy=true;qemuError='';S.render(true);
      try {
        const path=await S.api.native('pickQemu');
        if(path)await S.api.action('PUT','/v1/settings/qemu',{path});
      } catch(error){qemuError=error.message;}
      finally{qemuBusy=false;if(S.view==='settings')S.render(true);}
    }
    return h('section',{class:'card pref-form'},h('h2',{},'QEMU engine'),
      h('p',{},'Choose an installed qemu-system-x86_64.exe to verify its matching disk tool, Arm executable and UEFI firmware.'),
      S.facts([['Executable',setup?.path],['Verified version',setup?.version],['Emulated Arm',setup?.available?(setup.armAvailable?'Ready':setup.armReason):null]]),
      setup?.available!==true&&h('p',{class:'new-hint'},S.qemuReason(setup)),
      h('div',{class:'vm-actions'},h('button',{class:'btn',id:'choose-qemu',disabled:qemuBusy,onclick:choose},'Choose and verify executable')),
      h('label',{class:'boot-key-option'},h('input',{id:'qemu-separate-window',type:'checkbox',
        checked:setup?.openSeparateWindow===true,disabled:qemuBusy,onchange:async event=>{
          if(qemuBusy)return;
          qemuBusy=true;qemuError='';S.render(true);
          try {await S.api.action('PUT','/v1/settings/qemu',{openSeparateWindow:event.target.checked});}
          catch(error){qemuError=error.message;}
          finally{qemuBusy=false;if(S.view==='settings')S.render(true);}
        }}),'Open a separate window'),
      h('p',{class:'new-hint'},'Applies the next time a QEMU machine starts.'),
      qemuError&&h('p',{class:'new-error',role:'alert'},qemuError));
  }
  function render(root) {
    const on=document.documentElement.dataset.fx==='on', folder=S.info.dataFolder, notices=h('pre',{class:'notices'});
    S.fill(notices,()=>S.api.notices(),text=>document.createTextNode(text));
    root.append(h('div',{class:'pref-page'},h('h1',{},'Settings and About'),
      S.info.interfaceSize != null && h('section',{class:'card pref-form'},h('h2',{},'Interface size'),
        h('label',{class:'new-field'},'Size relative to Windows',h('select',{id:'interface-size',onchange:async e=>{
          const select=e.currentTarget; select.disabled=true;
          try { await S.setInterfaceSize(select.value); }
          finally { select.value=String(S.info.interfaceSize); select.disabled=false; }
        }},[85,100,115,130].map(value=>h('option',{value,selected:S.info.interfaceSize===value},
          value===100?'100% (Windows default)':value+'%'))))),
      h('section',{class:'card'},h('h2',{},'Effects'),h('button',{class:'switch',id:'settings-fx','aria-pressed':String(on),
        onclick:()=>S.setFx(document.documentElement.dataset.fx==='on'?'off':'on')},on?'Pause effects':'Resume effects')),
      S.data.online&&qemuSettings(),
      S.data.online&&S.backupSettings(),
      h('section',{class:'card pref-form'},h('h2',{},'Service'),
        S.facts([['Status',S.data.online?'Running':'Service is not running'],['Service version',S.data.health?.version],['Data folder',folder]]),
        h('div',{class:'vm-actions'},folder&&h('button',{class:'btn',onclick:()=>S.api.native('openFolder')},'Open folder'),
          S.data.online&&h('button',{class:'btn',onclick:()=>S.go('trash')},'Open library trash'),
          h('button',{class:'btn',onclick:()=>S.api.native('appMenu')},'App menu')),
        S.data.online&&h('button',{class:'btn',onclick:()=>S.go('guard')},'Host protection settings')),
      h('section',{class:'card'},h('h2',{},'About Secwizt Virtual Machine'),h('p',{},'Secwizt Private Limited'),
        h('p',{},'Secwizt Virtual Machine is open-source software from Secwizt Private Limited, licensed under the Apache License, Version 2.0.'),
        S.info.version&&h('p',{},'App version '+S.info.version),h('h3',{},'Third-party notices'),notices)));
  }
  addEventListener('svb-fx',()=>{
    const el=document.getElementById('settings-fx');if(!el)return;const on=document.documentElement.dataset.fx==='on';
    el.textContent=on?'Pause effects':'Resume effects';el.setAttribute('aria-pressed',String(on));
  });
  function trash(root) {
    const rows=h('div',{class:'pref-page','aria-live':'polite'},h('p',{},'Loading trash…'));
    root.append(h('div',{class:'pref-page'},h('h1',{},'Library trash'),
      S.info.dataFolder&&h('button',{class:'btn',onclick:()=>S.api.native('openTrash')},'Open trash folder'),rows));
    S.fill(rows,()=>S.api.get('/v1/trash'),entries=>{
      if (!entries.length) return h('p',{},'Trash is empty.');
      return h('div',{class:'pref-page'},entries.map(entry=>{
        const path='/v1/trash/'+S.api.segment(entry.key);
        const restore=async()=>{
          const result=await S.api.action('POST',path+'/restore');
          S.toast(entry.name+' was restored.'); S.go('vm',{id:result.id});
        };
        const purge=async()=>{
          const message='The disks, checkpoints, saved state and retained copies inside this machine’s trashed folder will be permanently lost.';
          if (!await S.dialog('Permanently delete “'+entry.name+'”?',h('p',{},message),'Delete permanently')) return;
          await S.api.action('DELETE',path,{confirmName:entry.name});
          S.toast(entry.name+' was permanently deleted.'); if (S.view==='trash') S.render();
        };
        const preserved=entry.retainedBytes==null?'':new Intl.NumberFormat().format(entry.retainedBytes)+' bytes in retained export';
        return h('article',{class:'card'},h('h2',{},entry.name),h('p',{},entry.os),preserved&&h('p',{},preserved),
          entry.restoreReason&&h('p',{},entry.restoreReason),
          entry.restoring&&h('p',{},'Restore is pending. Retry to verify the registration.'),
          h('div',{class:'vm-actions'},!entry.restoreReason&&h('button',{class:'btn primary',onclick:restore},entry.restoring?'Retry restore':'Restore'),
            h('button',{class:'btn',onclick:purge},entry.purging?'Finish permanent deletion':'Delete permanently')));
      }));
    });
  }
  S.register('trash',{title:'Library trash',nav:false,render:trash});
  S.register('settings',{title:'Settings and About',render});
})();
