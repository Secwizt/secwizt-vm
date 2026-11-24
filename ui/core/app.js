(function () {
  'use strict';
  const api = window.SvmApi, root = document.documentElement;
  const svgSpace = document.getElementById('vector').content.firstElementChild.namespaceURI;
  const screens = new Map(), busy = new WeakSet();
  let toastTimer, info = {}, connectedOnce = false, initializing = true, screenId = 'library', currentId = null;
  function h(tag, attrs = {}, ...children) {
    const el = tag === 'svg' || attrs.xmlns ? document.createElementNS(svgSpace, tag) : document.createElement(tag);
    for (const [key, val] of Object.entries(attrs)) {
      if (val == null || val === false || key === 'xmlns') continue;
      if (key.startsWith('on') && typeof val === 'function') {
        el.addEventListener(key.slice(2), event => {
          if (busy.has(el)) { event.preventDefault(); return; }
          try {
            const result = val(event);
            if (result && typeof result.then === 'function') {
              busy.add(el);
              result.catch(error => toast(error.message)).finally(() => busy.delete(el));
            }
          } catch (error) { toast(error.message); }
        });
      } else el.setAttribute(key, val === true ? '' : String(val));
    }
    for (const child of children.flat(Infinity)) if (child != null && child !== false)
      el.append(child.nodeType ? child : document.createTextNode(String(child)));
    return el;
  }
  function toast(message) {
    const box = document.getElementById('toast');
    box.textContent = message; box.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => box.classList.remove('show'), 6500);
  }
  function facts(rows, cls = 'vm-facts') {
    return h('dl', {class:cls}, rows.filter(row => row[1] != null).map(([key,value]) => [h('dt',{},key), h('dd',{},value)]));
  }
  function dialog(title, content, submit = 'OK', field = null, cancel = true, locked = false) {
    return new Promise(resolve => {
      const input = field?.querySelector('input');
      const cancelButton = cancel && h('button',{type:'button',class:'btn',autofocus:!input,onclick:() => box.close()},'Cancel');
      const form = h('form', {method:'dialog'}, h('h2',{id:'dialog-title'}, title), content, field,
        h('div',{class:'vm-actions'}, h('button',{type:'submit',class:'btn primary',value:'accept'},submit),
          cancelButton));
      const box = h('dialog', {'aria-labelledby':'dialog-title'}, form);
      // A locked dialog closes only through its own button; Escape would lose what it shows.
      if (locked) box.addEventListener('cancel', event => event.preventDefault());
      box.addEventListener('close', () => {
        const value = box.returnValue === 'accept' ? (field ? field.querySelector('input').value.trim() : true) : null;
        box.remove(); resolve(value);
      }, {once:true});
      document.body.append(box); box.showModal();
      (input || cancelButton || box.querySelector('button')).focus();
    });
  }
  function go(view, options = {}) {
    const hash = view + (options.id != null ? '/' + encodeURIComponent(options.id) : '');
    if (location.hash.slice(1) !== hash) location.hash = hash;
    else navigate();
  }
  function navigate() {
    const raw = location.hash.slice(1), at = raw.indexOf('/');
    const view = at < 0 ? raw : raw.slice(0, at);
    screenId = screens.has(view) ? view : 'library';
    try { currentId = at < 0 ? null : decodeURIComponent(raw.slice(at + 1)); } catch { currentId = null; }
    render(false); document.getElementById('main').focus({preventScroll:true});
  }
  function fx(mode) {
    root.dataset.fx = mode;
    try { localStorage.setItem('svm-effects',mode); } catch {}
    bar(); window.dispatchEvent(new Event('svb-fx'));
  }
  let thumbTimer = 0, observer;
  const visible = new Set(), thumbs = new Map();
  function clearViews() {
    observer?.disconnect(); visible.clear(); clearTimeout(thumbTimer); thumbTimer = 0;
  }
  function syncThumbs() {
    clearTimeout(thumbTimer);
    if (document.hidden || !document.hasFocus() || !api.state.online || !visible.size) return;
    const now = Date.now();
    let fetching = [...thumbs.values()].filter(slot => slot.job).length;
    const ordered = [...visible].sort((a,b) => (thumbs.get(a.dataset.thumb)?.time || 0) - (thumbs.get(b.dataset.thumb)?.time || 0));
    for (const canvas of ordered) {
      if (!canvas.isConnected) {visible.delete(canvas);continue;}
      const id = canvas.dataset.thumb;
      if (!api.canThumbnail(id)) continue;
      const slot = thumbs.get(id) || {time:0, frame:null, job:null};
      thumbs.set(id,slot);
      if (slot.frame && canvas._frame !== slot.frame) {
        canvas.width = slot.frame.width; canvas.height = slot.frame.height;
        canvas.getContext('2d').drawImage(slot.frame,0,0); canvas._frame = slot.frame;
      }
      if (fetching < 2 && !slot.job && now - slot.time >= 5000) {
        fetching++;
        slot.time = now;
        const stage = document.createElement('canvas');
        slot.job = api.thumbnail(id,stage).then(rendered => {
          if (rendered && api.canThumbnail(id)) slot.frame = stage;
        }).catch(error => {
          canvas.title = error.message;
        }).finally(() => { slot.job = null; syncThumbs(); });
      }
    }
    if (visible.size) thumbTimer = setTimeout(syncThumbs, 5000);
  }
  function observeThumbs() {
    if (!observer) observer = new IntersectionObserver(entries => {
      for (const e of entries) {
        if (e.isIntersecting && e.target.isConnected) visible.add(e.target);
        else visible.delete(e.target);
      }
      syncThumbs();
    }, {root:document.getElementById('main')});
    document.querySelectorAll('canvas[data-thumb]').forEach(el => observer.observe(el));
    for (const id of thumbs.keys()) if (!api.state.vms.some(vm => vm.id === id && ['running','paused'].includes(vm.state))) thumbs.delete(id);
  }
  function cap(id, name) { return api.state.caps?.[id]?.[name]?.available === true; }
  function preview(vm) {
    if (['running','paused'].includes(vm.state) && cap(vm.id,'Thumbnail'))
      return h('canvas',{class:'gscreen live-frame',width:320,height:240,'data-thumb':vm.id,role:'img','aria-label':'Guest display for '+vm.name});
    const label = vm.state === 'off' ? 'Powered off' : vm.state === 'saved' ? 'Saved' : vm.engine==='QEMU'?'Preview unavailable':'Display unavailable';
    return h('svg',{class:'gscreen',viewBox:'0 0 160 90',role:'img','aria-label':vm.name+' · '+label},
      h('rect',{xmlns:true,width:160,height:90,fill:'var(--panel-2)'}),
      h('text',{xmlns:true,x:80,y:50,'text-anchor':'middle','font-size':11,fill:'var(--muted)'},label));
  }
  const powerLabels={Start:'Start',Pause:'Pause',Resume:'Resume',Shutdown:'Shut down',Restart:'Restart',Stop:'Power off'};
  const powerPending=new Map();
  const skipBootKey=new Set();
  function setBootKey(id,enabled) {
    if(enabled)skipBootKey.delete(id);else skipBootKey.add(id);
    try {
      if(enabled)localStorage.removeItem('svm-skip-boot-key-'+id);
      else localStorage.setItem('svm-skip-boot-key-'+id,'1');
    } catch {}
  }
  function bootKeyEnabled(id) {
    if(skipBootKey.has(id))return false;
    try {return localStorage.getItem('svm-skip-boot-key-'+id)!=='1';} catch {return true;}
  }
  function bootKeyOption(checked,choose,disabled=false) {
    return h('label',{class:'boot-key-option'},h('input',{type:'checkbox',checked,disabled,onchange:e=>choose(e.target.checked)}),
      'Automatically press Enter to boot from the installer image');
  }
  function confirmPowerOff(vm,error) {
    const warning=vm.state==='saved'?'Powering off discards the saved memory.':
      vm.state==='paused'?'Hyper-V briefly resumes this paused machine before cutting power. Unsaved guest work may be lost.':
      'This cuts power immediately. Unsaved guest work may be lost.';
    return S.dialog('Power off '+vm.name+'?',h('div',{},error&&h('p',{},error),h('p',{},warning)),'Power off');
  }
  async function power(vm,name,openConsole=false) {
    if(powerPending.has(vm.id))return;
    if(name==='Stop'&&!await confirmPowerOff(vm))return;
    const path=api.machinePath(vm.id);
    powerPending.set(vm.id,name);
    S.render(true);
    try {
      const body={};
      if(name==='Start'&&api.state.caps?.[vm.id]?.PressKeyAtBoot) {
        body.pressKeyAtBoot=cap(vm.id,'PressKeyAtBoot')&&bootKeyEnabled(vm.id);
      }
      if(openConsole)await api.native('openConsole',{id:vm.id,text:'beforeStart'});
      const result=await api.action('POST',path+'/'+name.toLowerCase(),body);
      if(name==='Start') {
        setBootKey(vm.id,true);
        if(result?.bootKey?.message)S.toast(result.bootKey.message);
      }
      if(name==='Restart'&&result?.guestPowerStatus==='restart_requested')S.toast(vm.name+' accepted the restart request.');
    } catch(error) {
      if(!['Shutdown','Restart'].includes(name)||error.code!=='guest_power_timeout')throw error;
      await api.load();
      const latest=S.vm(vm.id);
      if(!latest||latest.state!=='running'||!cap(vm.id,'Stop'))throw error;
      if(await confirmPowerOff(latest,error.message))await api.action('POST',path+'/stop',{});
    } finally {
      powerPending.delete(vm.id);
      S.render(true);
    }
  }
  function powers(vm, compact = false, omitStart = false) {
    const pending=powerPending.get(vm.id);
    const controls=Object.entries(powerLabels).filter(([name])=>!(omitStart&&name==='Start')&&cap(vm.id,name)).map(([name,label])=>
      h('button',{class:'btn'+(compact?' small':'')+(['Start','Resume'].includes(name)?' primary':''),disabled:!!pending,onclick:e=>{
        e.stopPropagation();return power(vm,name);
      }},label));
    if(cap(vm.id,'Start')&&cap(vm.id,'PressKeyAtBoot')) {
      controls.push(bootKeyOption(bootKeyEnabled(vm.id),enabled=>setBootKey(vm.id,enabled),!!pending));
    }
    if(pending==='Start') {
      const installer=cap(vm.id,'PressKeyAtBoot')&&bootKeyEnabled(vm.id);
      controls.push(h('small',{class:'power-hint',role:'status'},installer?'Starting the machine with the 12-second installer key window…':'Starting the machine…'));
    } else if(pending==='Shutdown'||pending==='Restart') {
      controls.push(h('small',{class:'power-hint',role:'status'},'Waiting for '+vm.name+' to '+(pending==='Shutdown'?'shut down':'restart')+'. The guest has 25 seconds to respond.'));
    } else if(vm.state==='running') {
      const missing=new Map();
      for(const name of ['Shutdown','Restart']) {
        if(cap(vm.id,name))continue;
        const why=api.state.caps?.[vm.id]?.[name]?.reason||'The guest shutdown integration service could not be verified.';
        missing.set(why,[...(missing.get(why)||[]),powerLabels[name]]);
      }
      for(const [why,labels] of missing)controls.push(h('small',{class:'power-hint'},labels.join(' / ')+' unavailable. '+why));
    }
    return controls;
  }
  function recentImages() {
    try {
      const list = JSON.parse(localStorage.getItem('svm-installer-images') || '[]');
      return Array.isArray(list) ? list.filter(path => typeof path === 'string' && /\.iso$/i.test(path)).slice(0,6) : [];
    } catch { return []; }
  }
  function rememberImage(path) {
    if (typeof path !== 'string' || !/\.iso$/i.test(path)) return;
    const rest = recentImages().filter(item => item.toLowerCase() !== path.toLowerCase());
    try { localStorage.setItem('svm-installer-images',JSON.stringify([path,...rest].slice(0,6))); } catch {}
  }
  function imagePicker(onSelect) {
    const images = recentImages();
    const browse = h('button',{class:'btn',type:'button',onclick:async () => {
      const previous = recentImages()[0] || '';
      const folder = previous.slice(0,Math.max(previous.lastIndexOf('\\'),previous.lastIndexOf('/'))+1);
      const selected = await api.native('pickIso',{text:folder});
      if (!selected) return;
      rememberImage(selected);
      await onSelect(selected);
    }},'Choose installer image');
    if (!images.length) return browse;
    return h('div',{class:'vm-actions'},browse,h('label',{class:'new-field'},'Recent images',
      h('select',{'aria-label':'Recent installer images',onchange:async e => {
        const selected = e.target.value;
        if (!selected) return;
        e.target.value = '';
        await onSelect(selected);
        rememberImage(selected);
      }},h('option',{value:''},'Select an image'),images.map(path => h('option',{value:path},path)))));
  }
  function address(vm) {
    if(vm.addressSource==='guest agent'&&vm.ip)return vm.ip;
    const net=api.state.networks.find(n=>n.id===vm.net);
    if(net?.mode==='Bridged'||net?.mode==='NAT') {
      return vm.addressSource==='reported by the guest'&&vm.ip?vm.ip+' (reported by the guest)':'not reported by the guest';
    }
    return vm.ip||'Unavailable';
  }
  function bar() {
    const d = api.state, host = d.host || {};
    const used = host.usedThreads || 0, memory = host.usedRamGb || 0;
    document.getElementById('bar').replaceChildren(
      h('div',{class:'brand'},h('span',{class:'mark','aria-hidden':'true'},'✦'),'Secwizt Virtual Machine'), h('div',{class:'grow'}),
      host.logical && h('button',{class:'guard-pill',title:'Open Host · guest processor and memory allocations',onclick:()=>go('guard')},
        h('span',{},'Host'),h('span',{class:'meter'},h('i',{style:'width:'+Math.min(100,100*used/host.logical)+'%'})),
        h('span',{class:'mono'},used+' vCPU · '+memory+' GiB')),
      h('button',{class:'switch','aria-pressed':String(root.dataset.fx === 'on'),onclick:()=>fx(root.dataset.fx === 'on'?'off':'on')},
        root.dataset.fx === 'on'?'Pause effects':'Resume effects'));
    document.getElementById('service-status').textContent = d.online
      ? 'Service running · '+d.vms.filter(v=>v.state==='running').length+' running · '+used+' vCPU allocated'
      : initializing ? 'Connecting…' : 'Service is not running';
  }
  function render(refresh = false) {
    const main = document.getElementById('main'), active = document.activeElement;
    const focusId = refresh && active?.id, focusMain = main.contains(active);
    const focusShell = refresh && active?.closest('#nav,#bar');
    const controls = 'button,input,select,[tabindex="0"]';
    const ordinal = refresh && focusMain ? [...main.querySelectorAll(controls)].indexOf(active) : -1;
    const cursor = refresh && active?.matches('input[type=search],input[type=text],input:not([type])') ? [active.selectionStart,active.selectionEnd] : null;
    const fields = refresh ? Array.from(main.querySelectorAll('[data-draft][id]')).map(el => [el.id, el.value, el.checked]) : [];
    const scroll = refresh ? main.scrollTop : 0;
    clearViews(); bar();
    // The buttons must be SPREAD: replaceChildren turns an array argument into the text "[object HTMLButtonElement],..."
    // (found in the real window on the build host; the Node checker cannot see it because it never paints).
    document.getElementById('nav').replaceChildren(h('div',{class:'sep'},'Workspace'),
      ...[...screens].filter(([,s])=>s.nav !== false).map(([id,s])=>h('button',{id:'nav-'+id,'aria-current':id===screenId?'page':null,onclick:()=>go(id)},s.title)));
    main.replaceChildren();
    if (!api.state.online && !initializing) {
      const reason = info.startupError || api.state.error || 'The app could not reach the local service.';
      main.append(h('section',{class:'card service-bar',role:'alert'}, h('h2',{},'Service is not running'),h('p',{},reason),
        h('button',{class:'btn primary',onclick:async()=>{await api.native('startService'); info={...info,startupError:null}; await api.load();}},'Start it')));
    }
    if (api.state.online || (connectedOnce && screenId === 'settings')) screens.get(screenId)?.render(main,{id:currentId});
    else if (initializing) main.append(h('h1',{},'Connecting to the service'));
    for (const [id, value, checked] of fields) {
      const el = document.getElementById(id);
      if (el?.matches('[data-draft]')) {el.value=value;if (typeof checked === 'boolean') el.checked=checked;}
    }
    if (refresh && (focusMain || focusShell)) {
      const alternative = main.querySelectorAll(controls)[ordinal];
      const next = (focusId && document.getElementById(focusId)) ||
        (alternative?.tagName === active?.tagName && alternative?.textContent === active?.textContent ? alternative : null);
      next?.focus({preventScroll:true});
      if (cursor && next?.setSelectionRange) next.setSelectionRange(...cursor);
    }
    main.scrollTop = scroll;
    observeThumbs(); window.dispatchEvent(new Event('svb-render'));
  }
  const S = window.SVB = {h,facts,toast,dialog,go,render,setFx:fx,preview,powers,address,cap,api,
    startWithConsole:vm=>power(vm,'Start',true),powerBusy:id=>powerPending.has(id),bootKeyOption,setBootKey,
    async setInterfaceSize(percent) {
      const value = await api.native('setInterfaceSize',{text:String(percent)});
      info = {...info,interfaceSize:value}; render(true);
    },
    tpmCertificateHint:'A local virtual TPM uses guardian certificates in Windows’ Local Machine certificate store (Shielded VM Local Certificates). Moving this machine or reinstalling Windows can prevent it from reopening unless you also preserve and restore its guardian certificates and private keys.',
    androidNetworkHint:'In Android, open Wi-Fi settings and select VirtWifi to connect the guest’s virtual Ethernet adapter.',
    armLabel:'Emulated Arm (slow)',
    armHint:'Arm guests run by software emulation on this PC. Expect them to be much slower than x86 guests.',
    qemuReason(setup) {
      const label='QEMU is not set up on this PC.';
      return setup?.reason?.startsWith(label)?setup.reason:[label,setup?.reason].filter(Boolean).join(' ');
    },
    imagePicker, get data(){return api.state;}, get info(){return info;}, get view(){return screenId;},
    vm(id){return api.state.vms.find(v=>v.id===id);}, net(id){return api.state.networks.find(n=>n.id===id);},
    register(id,def){screens.set(id,def);}, get screens(){return screens;},
    async fill(element,read,draw) {
      try { const data = await read(); if (element.isConnected) element.replaceChildren(draw(data)); }
      catch (error) { if (element.isConnected) element.replaceChildren(h('p',{role:'status'},error.message)); }
    }
  };
  window.addEventListener('svm-read-error', event => toast(event.detail));
  document.addEventListener('DOMContentLoaded', () => {
    try { root.dataset.fx = localStorage.getItem('svm-effects')==='off'?'off':'on'; } catch {}
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) root.dataset.fx='off';
    navigate(); window.addEventListener('hashchange',navigate);
    document.addEventListener('visibilitychange',syncThumbs);
    window.addEventListener('focus',syncThumbs);
    window.addEventListener('blur',syncThumbs);
    document.addEventListener('keydown',e => {
      if(e.key==='Escape' && !e.target?.closest?.('#qemu-console-display') &&
          !document.querySelector('dialog[open]') && screenId!=='library') go('library');
    });
    api.native('appInfo',{text:String(window.innerWidth)}).then(data => { info=data || {}; if(!api.state.online || screenId==='settings') render(true); }).catch(error => {
      info={startupError:error.message}; if(!api.state.online) render(true);
    });
    api.start(() => { initializing=false; if(api.state.online) {connectedOnce=true; info={...info,startupError:null};} render(true); });
  });
})();
