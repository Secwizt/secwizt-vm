(function () {
  const S=window.SVB,h=S.h;
  const palette=['--gold','--blue-deep','--ok','--warn','--bad','--control','--ink','--blue'];
  let limit=60,draft=null,saving=false,saveError='';
  function colour(v){return 'var('+palette[S.data.vms.indexOf(v)%palette.length]+')';}
  function issue(cpu,ram) {
    if(!Number.isSafeInteger(cpu)||cpu<1||!Number.isSafeInteger(ram)||ram<1)return 'Enter positive whole numbers for vCPUs and memory.';
    const host=S.data.host;
    if(host.enabled!==true)return '';
    if(cpu+host.usedThreads>host.threadBudget)return 'Host protection allows '+host.threadBudget+' allocated vCPUs. '+host.usedThreads+' are in use.';
    const room=Math.max(0,host.ramGb-host.reserveGb-host.usedRamGb);
    if(ram>room)return 'Host protection leaves '+room+' GiB available after the memory reserve.';
    if(host.maxRunning!=null&&S.data.vms.filter(v=>v.state==='running').length>=host.maxRunning)return 'The host has reached its configured running-machine limit.';
    return '';
  }
  function group(label,range) {
    const nodes=Array.from({length:range[1]-range[0]+1},(_,index)=>{
      const id=range[0]+index,machines=S.data.vms.filter(v=>v.cores?.includes(id)),desc='Logical core '+id+' · '+(machines.map(v=>v.name).join(', ')||'Unassigned');
      return h('div',{class:'guard-cell',role:'img',title:desc,'aria-label':desc,
        style:'--cell-colour:'+(machines.length?colour(machines[0]):'var(--line)')+';--cell-load:'+(machines.length?'100%':'0%')},
        h('span',{'aria-hidden':'true'},id),h('small',{'aria-hidden':'true'},machines.length?'Assigned':'Free'));
    });
    return h('section',{class:'guard-group'},h('h3',{},label+' · '+range.join('–')),h('div',{class:'guard-cells'},nodes));
  }
  function coreOrder(text,logical) {
    if(!text.trim())return [];
    const ordered=[],seen=new Set();
    for(const part of text.split(',')) {
      const match=/^\s*(\d+)(?:\s*[-–]\s*(\d+))?\s*$/.exec(part);
      if(!match)throw Error('Enter core IDs or ranges separated by commas.');
      const first=Number(match[1]),last=Number(match[2]??match[1]);
      if(first>last||last>=logical)throw Error('Choose ascending core ranges from 0 to '+(logical-1)+'.');
      for(let id=first;id<=last;id++){
        if(seen.has(id))throw Error('Each preferred core can appear once.');
        seen.add(id);ordered.push(id);
      }
    }
    return ordered;
  }
  function hostForm(host) {
    const policy=S.data.guard;
    if(typeof policy?.enabled!=='boolean')return h('p',{class:'guard-note'},'The service has not reported editable protection settings.');
    const state=draft||{enabled:policy.enabled,budgetPct:policy.budgetPct,reserveGb:policy.reserveGb,
      maxRunning:policy.maxRunning??'',preferred:(policy.preferredCores||[]).join(', ')};
    const notice=h('p',{class:'new-error',role:'status'},saveError);
    const save=h('button',{class:'btn',type:'submit',disabled:saving||!draft},saving?'Saving…':'Save host settings');
    function edit(key,value){draft=state;state[key]=value;save.disabled=saving;saveError='';notice.textContent='Changes are ready to save.';}
    function number(label,key,min,max,required) {
      return h('label',{class:'new-field'},label,h('input',{id:'host-'+key,type:'number',min,max,step:1,required,value:state[key],
        oninput:e=>edit(key,e.target.value)}));
    }
    const fields=h('fieldset',{class:'host-fields',disabled:!state.enabled||saving},
      h('legend',{},'Protection settings'),h('div',{class:'new-fields'},
        number('CPU share (%)','budgetPct',1,100,true),number('Memory kept free (GiB)','reserveGb',0,host.ramGb,true),
        number('Machines running at once (empty for unlimited)','maxRunning',1,null,false),
        h('label',{class:'new-field'},'Preferred logical cores',h('input',{id:'host-core-order',type:'text',value:state.preferred,
          oninput:e=>edit('preferred',e.target.value)}))),
      h('p',{class:'guard-note'},'Enter core IDs or ranges in preferred order, separated by commas. Leave empty for automatic placement.'));
    const toggle=h('input',{id:'host-protect',type:'checkbox',role:'switch',checked:state.enabled,disabled:saving,onchange:e=>{
      edit('enabled',e.target.checked);fields.disabled=!state.enabled;
    }});
    return h('form',{onsubmit:async e=>{
      e.preventDefault();if(saving||!draft)return;
      const body={enabled:state.enabled};
      try {
        if(state.enabled) {
          body.budgetPct=Number(state.budgetPct);body.reserveGb=Number(state.reserveGb);
          body.maxRunning=String(state.maxRunning).trim()===''?null:Number(state.maxRunning);
          body.preferredCores=coreOrder(state.preferred,host.logical);
        }
        saving=true;save.disabled=true;toggle.disabled=true;fields.disabled=true;
        await S.api.action('PUT','/v1/guard',body);
        draft=null;saveError='';S.toast('Host settings saved.');
      } catch(error){saveError=error.message;}
      finally {saving=false;if(S.view==='guard')S.render(true);}
    }},h('label',{for:'host-protect'},toggle,' Protect this host'),fields,save,notice);
  }
  function render(root) {
    const host=S.data.host, events=S.data.events.slice(-limit).reverse();
    const validRange=r=>Array.isArray(r)&&r.length===2&&r[0]>=0&&r[0]<=r[1]&&r[1]<host.logical;
    const separate=validRange(host.pCores)&&validRange(host.eCores)&&
      (host.pCores[1]<host.eCores[0]||host.eCores[1]<host.pCores[0]);
    root.append(h('div',{class:'guard-page'},h('header',{},h('h1',{},'Host'),h('p',{class:'sub'},host.cpu+' · '+host.logical+' logical processors · '+host.ramGb+' GiB')),
      h('section',{class:'card'},h('h2',{},'Guest allocations'),S.facts([
        ['Processor',host.usedThreads+' vCPU allocated to running guests'],['Guest memory',host.usedRamGb+' GiB allocated'],
        ['Host memory available',Number.isFinite(host.freeRamGb)?host.freeRamGb+' GiB':null],['Host protection',typeof host.enabled==='boolean'?(host.enabled?'On':'Off'):'Status unavailable']])),
      h('section',{class:'card'},h('h2',{},'Core map'),h('p',{class:'guard-note'},'Core placement is advisory. Colour identifies a machine assigned to a core.'),
        separate?[group('Performance',host.pCores),group('Efficiency',host.eCores)]:host.logical>0&&group('Logical processors',[0,host.logical-1])),
      h('section',{class:'card'},h('h2',{},'Host protection'),hostForm(host)),
      h('section',{class:'card'},h('h2',{},'Machine assignments'),h('table',{},h('thead',{},h('tr',{},
        ['Machine','State','vCPU','Logical cores','Details'].map(t=>h('th',{scope:'col'},t)))),
        h('tbody',{},S.data.vms.map(v=>h('tr',{},h('td',{},h('span',{class:'guard-key',style:'--key:'+colour(v)}),v.name),
          h('td',{},v.state||'Unavailable'),h('td',{},v.vcpu),h('td',{},v.cores?.join(', ')||'Automatic'),
          h('td',{},h('button',{class:'btn small',onclick:()=>S.go('vm',{id:v.id})},'Open '+v.name))))))),
      h('section',{class:'card'},h('h2',{},'Events'),
        events.length?h('ol',{class:'guard-log'},events.map(e=>h('li',{},h('time',{},new Date(e.timestamp*1000).toLocaleTimeString()),h('b',{},e.kind),h('span',{},e.message)))):
          h('p',{class:'guard-note'},'No events recorded.'),
        events.length<S.data.events.length&&h('button',{class:'btn',onclick:()=>{limit+=60;S.render();}},'Show earlier events'))));
  }
  addEventListener('svb-render',()=>{if(S.view!=='guard'&&!saving){draft=null;saveError='';}});
  S.register('guard',{title:'Host',render,issue});
})();
