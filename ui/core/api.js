(function () {
  'use strict';
  function immutable(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      for (const child of Object.values(value)) immutable(child);
      Object.freeze(value);
    }
    return value;
  }
  let current = immutable({online: false, host: {}, guard: {}, health: {}, vms: [], networks: [], events: [], caps: Object.create(null)});
  let listener, timer = null, epoch = 0, tail = Promise.resolve(), requestNumber = 0;
  const pending = new Map();
  const previewJobs = new Map(), machineWrites = new Map(), unconfirmed = new Set();
  let lastReadError = null;
  function readError(error) {
    if (!current.online) { offline(error.message); return; }
    if (lastReadError !== error.message) {
      lastReadError = error.message;
      window.dispatchEvent(new CustomEvent('svm-read-error', {detail:error.message}));
    }
  }

  function segment(id) {
    if (typeof id !== 'string' || !id || /[/\\%?#\s]/u.test(id) || id.includes('..') || id === '.') {
      throw new Error('The service returned an invalid identifier.');
    }
    return encodeURIComponent(id);
  }
  const machinePath = id => '/v1/machines/' + segment(id);
  function publish(next) {
    current = immutable(next);
    if (listener) listener(current);
  }
  function offline(message) {
    if (current.online || current.error !== message) publish({...current, online: false, error: message});
  }
  function serial(work) {
    const result = tail.then(work);
    tail = result.catch(() => {});
    return result;
  }

  async function request(path, method = 'GET', data) {
    if (!path.startsWith('/v1/')) throw new Error('This request is not supported.');
    const options = {method, cache: 'no-store', credentials: 'omit', redirect: 'error'};
    if (data !== undefined) {
      options.headers = {'Content-Type': 'application/json'};
      options.body = JSON.stringify(data);
    }
    let response;
    try { response = await fetch('/api' + path, options); }
    catch { const message = 'The service is not running. Start it to continue.'; offline(message); throw new Error(message); }
    if (!response.ok) {
      let detail;
      try { detail = (await response.json()).error; } catch { /* No readable service message. */ }
      const message = detail?.message || 'The service did not complete the request.';
      if (detail?.code === 'service_offline' || detail?.code === 'service_unavailable') offline(message);
      const error = new Error(message);
      error.code = detail?.code;
      throw error;
    }
    return response;
  }
  const get = async path => (await request(path)).json();
  function newest(events) { return events.length ? events[events.length - 1].id : 0; }

  async function refresh(changes) {
    // Read the journal first. Changes that arrive during the snapshot are picked up by the next poll.
    const events = changes === undefined ? await get('/v1/events?since=0') : current.events.concat(changes);
    const [health, host, guard, vms, networks, qemu] = await Promise.all([
      get('/v1/health'), get('/v1/host'), get('/v1/guard'), get('/v1/machines'), get('/v1/networks'),
      get('/v1/settings/qemu').catch(error=>({available:false,reason:error.message}))
    ]);
    const caps = Object.create(null);
    // Bound preview-control lookups. The service serializes hypervisor access.
    for (let i = 0; i < vms.length; i += 2) {
      await Promise.all(vms.slice(i, i + 2).map(async vm => {
        caps[vm.id] = await get(machinePath(vm.id) + '/capabilities');
      }));
    }
    lastReadError = null;
    unconfirmed.clear();
    publish({online: true, error: '', health, host, guard, vms, networks, events, caps, qemu});
    return current;
  }
  const load = () => serial(() => refresh());

  function action(method, path, data) {
    const key = path.match(/^\/v1\/machines\/[^/?]+(?=\/|$)/)?.[0];
    if (key) machineWrites.set(key, (machineWrites.get(key) || 0) + 1);
    return serial(async () => {
      // Finish any outstanding frame before changing this guest's state.
      await previewJobs.get(key)?.catch(() => {});
      const response = await request(path, method, data);
      if (key) unconfirmed.add(key);
      const result = await response.json();
      // Once a mutation succeeds it must not be retried just because a refresh failed.
      try { await refresh(); }
      catch (error) { readError(error); }
      return result;
    }).finally(() => {
      if (!key) return;
      const remaining = machineWrites.get(key) - 1;
      if (remaining) machineWrites.set(key, remaining);
      else machineWrites.delete(key);
    });
  }
  async function poll() {
    if (document.hidden) return;
    if (!current.online) { await refresh(); return; }
    const changes = await get('/v1/events?since=' + newest(current.events));
    if (changes.length) await refresh(changes);
  }
  function schedule(immediate = false) {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    const generation = ++epoch;
    if (!listener || document.hidden) return;
    timer = setTimeout(async () => {
      if (generation !== epoch || document.hidden) return;
      timer = null;
      try { await serial(() => generation === epoch ? poll() : undefined); }
      catch (error) { readError(error); }
      if (generation === epoch) schedule();
    }, immediate ? 0 : (document.hasFocus() ? 2000 : 10000));
  }
  function visibility() { schedule(!document.hidden); }
  function focusChanged() { schedule(); }
  async function start(onChange) {
    if (listener) stop();
    listener = onChange;
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('focus', focusChanged);
    window.addEventListener('blur', focusChanged);
    if (!document.hidden) {
      try { await load(); } catch (error) { offline(error.message); }
    }
    schedule();
  }
  function stop() {
    listener = null;
    schedule();
    document.removeEventListener('visibilitychange', visibility);
    window.removeEventListener('focus', focusChanged);
    window.removeEventListener('blur', focusChanged);
  }

  function canThumbnail(id) {
    if (!current.online || current.caps[id]?.Thumbnail?.available !== true) return false;
    const vm = current.vms.find(machine => machine.id === id);
    if (!vm || (vm.state !== 'running' && vm.state !== 'paused')) return false;
    const key = machinePath(id);
    return !machineWrites.has(key) && !unconfirmed.has(key);
  }
  async function thumbnail(id, canvas) {
    if (!canThumbnail(id)) return false;
    const key = machinePath(id);
    if (previewJobs.has(key)) return false;
    const job = drawThumbnail(key, id, canvas);
    previewJobs.set(key, job);
    try { return await job; }
    finally { previewJobs.delete(key); }
  }
  async function drawThumbnail(key, id, canvas) {
    const response = await request(key + '/thumbnail');
    const width = Number(response.headers.get('x-width')), height = Number(response.headers.get('x-height'));
    const pixels = new Uint8ClampedArray(await response.arrayBuffer());
    if (!Number.isInteger(width) || width < 1 || !Number.isInteger(height) || height < 1 ||
        width * height * 4 !== pixels.length || response.headers.get('x-pixel-format') !== 'RGBA8') {
      throw new Error('The service returned an unreadable preview.');
    }
    if (!canThumbnail(id)) return false;
    const context = canvas.getContext('2d');
    if (!context) return false;
    canvas.width = width; canvas.height = height;
    context.putImageData(new ImageData(pixels, width, height), 0, 0);
    return true;
  }

  const commands = new Set(['startService','appInfo','openConsole','pickIso','pickQemu','pickDisk','pickExportFolder','pickGuestUpload','pickGuestDownload','openFolder','openTrash','setInterfaceSize','copyText','copyConsoleText','appMenu']);
  function native(action, args = {}) {
    if (!commands.has(action) || !window.ipc?.postMessage) return Promise.reject(new Error('This action requires the desktop app.'));
    const requestId = ++requestNumber;
    return new Promise((resolve, reject) => {
      pending.set(requestId, {resolve, reject});
      try { window.ipc.postMessage(JSON.stringify({...args, action, requestId})); }
      catch { pending.delete(requestId); reject(new Error('The desktop app could not receive the request.')); }
    });
  }
  window.addEventListener('svm-native-result', event => {
    const value = event.detail;
    const call = pending.get(value?.requestId);
    if (!call) return;
    pending.delete(value.requestId);
    if (value.ok) call.resolve(value.value);
    else call.reject(new Error(value.error || 'The desktop action could not be completed.'));
  });
  async function notices() {
    const response = await fetch('/notices.txt', {credentials:'omit'});
    if (!response.ok) throw new Error('The component notices could not be loaded.');
    return response.text();
  }
  window.SvmApi = Object.freeze({get state() { return current; }, segment, machinePath,
    async diskRequest(method,path,data){
      if(!path.startsWith('/v1/transfers/'))throw new Error('Choose a disk operation.');
      return (await request(path,method,data)).json();
    },
    async guestRequest(id,operation,data){
      if(!['exec','ssh-key'].includes(operation))throw new Error('Choose a guest command operation.');
      return (await request(machinePath(id)+'/'+operation,'POST',data)).json();
    },
    async guestFileRequest(vmId,method,jobId,data){
      const path=machinePath(vmId)+'/files';
      if((method==='GET'||method==='POST')&&jobId==null)return (await request(path,method,data)).json();
      if((method==='GET'||method==='DELETE')&&jobId!=null)return (await request(path+'/'+segment(jobId),method)).json();
      throw new Error('Choose a guest file transfer operation.');
    },
    async guestFileService(vmId,enabled){
      const path=machinePath(vmId)+'/file-guest-service';
      if(enabled===undefined)return (await request(path)).json();
      if(typeof enabled==='boolean')return (await request(path,'POST',{enabled})).json();
      throw new Error('Choose whether to enable Guest Service Interface.');
    },
    catalog:()=>get('/v1/catalog'),
    appCatalog:()=>get('/v1/catalog/apps'),
    appMachines:id=>get('/v1/catalog/apps/'+segment(id)+'/machines'),
    async appPreview(machine, app, action, access){
      const path=machinePath(machine)+'/apps/'+segment(app)+'/preview';
      return (await request(path,'POST',{action,access})).json();
    },
    async appRun(machine, app, previewId, access){
      const path=machinePath(machine)+'/apps/'+segment(app)+'/run';
      return (await request(path,'POST',{previewId,access})).json();
    },
    appJob:id=>get(machinePath(id)+'/apps'),
    async catalogLatest(id){
      return (await request('/v1/catalog/'+segment(id)+'/latest','POST',{})).json();
    },
    async catalogDownload(id,method='GET'){
      if(!['GET','POST','DELETE'].includes(method))throw new Error('Choose an installer download operation.');
      const path='/v1/catalog/'+segment(id)+'/download';
      return (await request(path,method,method==='POST'?{}:undefined)).json();
    },
    async consoleTicket(id){
      return (await request(machinePath(id)+'/console-ticket','POST',{})).json();
    },
    get, load, action, canThumbnail, thumbnail, start, stop, native, notices});
})();
