(function () {
  const S=window.SVB, h=S.h;
  let view='boxes', query='', observer;
  function badge(vm) {
    if(vm.registration==='restore incomplete')return h('span',{class:'badge'},'Restore incomplete');
    const style={running:'run',paused:'pause'}[vm.state] || 'off';
    return h('span',{class:'badge '+style},vm.state==='off'?'Powered off':vm.state?vm.state[0].toUpperCase()+vm.state.slice(1):'Unavailable');
  }
  function open(vm){S.go('vm',{id:vm.id});}
  function box(vm) {
    const title=h('button',{class:'machine-link',onclick:()=>open(vm)},vm.name);
    return h('article',{class:'vmbox card'+(vm.state==='running'?' live':vm.state==='off'?' off':''),'data-net':vm.engine==='QEMU'?'qemu/'+vm.id:vm.net,
        onclick:e=>{if(!e.target.closest('button,label,input'))open(vm);}},
      S.preview(vm),h('div',{class:'vmhead'},title,badge(vm)),h('div',{class:'vmos'},vm.os),
      h('div',{class:'vmbadges'},h('span',{class:'badge'},vm.engine),
        h('span',{class:'badge'+(vm.accel?'':' emul')},vm.architecture==='aarch64'?S.armLabel:vm.engine==='QEMU'?'WHPX required':vm.accel?'Accelerated':'Emulated'),
        h('span',{class:'badge'},vm.engine==='QEMU'?'User-mode NAT':S.net(vm.net)?.mode || 'Unknown network'),
        vm.throwaway&&h('span',{class:'badge emul',title:'Changes are discarded at power-off while Secwiz VM is open'},'Throwaway')),
      h('div',{class:'vmip mono'},S.address(vm),h('span',{class:'vmres'},vm.vcpu+' vCPU · '+vm.ramGb+' GB')),
      h('div',{class:'vmact'},S.powers(vm,true)));
  }
  function links(grid) {
    if (!grid.isConnected) return;
    grid.querySelectorAll('.links,.pkt').forEach(el=>el.remove());
    const groups=new Map(), paths=[];
    for(const el of grid.querySelectorAll('.vmbox')) {
      const list=groups.get(el.dataset.net) || []; list.push(el);groups.set(el.dataset.net,list);
    }
    for (const members of groups.values()) for(let i=1;i<members.length;i++) {
      const A=members[i-1], B=members[i], live=A.classList.contains('live') && B.classList.contains('live');
      const row=Math.abs(A.offsetTop-B.offsetTop)<20;
      const x1=A.offsetLeft+A.offsetWidth*(row?1:.5), y1=A.offsetTop+A.offsetHeight*(row?.38:1);
      const x2=B.offsetLeft+B.offsetWidth*(row?0:.5), y2=B.offsetTop+B.offsetHeight*(row?.38:0);
      const mx=(x1+x2)/2, my=(y1+y2)/2;
      const d=row?`M${x1},${y1} Q${mx},${my-18} ${x2},${y2}`:`M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`;
      paths.push(h('path',{xmlns:true,d,class:'wire'+(live?' live':'')}));
      if(live) paths.push(h('path',{xmlns:true,d,class:'pulse'}));
      for(const [cx,cy] of [[x1,y1],[x2,y2]]) paths.push(h('circle',{xmlns:true,cx,cy,r:5,class:'port'+(live?' live':'')}));
      if(live && document.documentElement.dataset.fx==='on') for(const delay of [0,-.8,-1.6])
        grid.append(h('i',{class:'pkt',style:`offset-path:path('${d}');animation-delay:${delay}s`}));
    }
    if(paths.length) grid.prepend(h('svg',{class:'links',width:grid.scrollWidth,height:grid.scrollHeight,'aria-hidden':'true'},paths));
  }
  function render(root) {
    const vms=S.data.vms.filter(v=>[v.name,v.os,S.address(v),v.engine].join(' ').toLowerCase().includes(query.toLowerCase()));
    root.append(h('h1',{},'Your machines'),h('p',{class:'sub'},`${S.data.vms.length} ${S.data.vms.length===1?'machine':'machines'}, ${S.data.vms.filter(v=>v.state==='running').length} running. A line joins machines on the same network.`),
      h('div',{class:'libbar'},h('input',{id:'library-search',type:'search',placeholder:'Search by name, system or address','aria-label':'Search machines',value:query,
        oninput:e=>{query=e.target.value;const pos=e.target.selectionStart;S.render();const field=document.getElementById('library-search');field.focus();field.setSelectionRange(pos,pos);}}),
        h('button',{class:'switch','aria-pressed':String(view==='boxes'),onclick:()=>{view=view==='boxes'?'list':'boxes';S.render();}},view==='boxes'?'Show as list':'Show as boxes'),
        h('button',{class:'btn primary',onclick:()=>S.go('newvm')},'New machine')));
    if(!vms.length){root.append(h('div',{class:'card'},query?'No machines match this search.':'Your library is empty. Create a machine to get started.'));return;}
    if(view==='list') {
      root.append(h('div',{class:'card'},h('table',{},h('thead',{},h('tr',{},['Machine','System','State','Engine','Address','Network','Resources',''].map(t=>h('th',{scope:'col'},t)))),
        h('tbody',{},vms.map(v=>h('tr',{},h('td',{},h('button',{class:'btn small',onclick:()=>open(v)},v.name)),h('td',{},v.os),h('td',{},badge(v),v.throwaway&&h('span',{class:'badge emul',title:'Changes are discarded at power-off while Secwiz VM is open'},'Throwaway')),h('td',{},v.engine),
          h('td',{class:'mono'},S.address(v)),h('td',{},S.net(v.net)?.name),h('td',{class:'mono'},v.vcpu+' vCPU · '+v.ramGb+' GB'),h('td',{},h('div',{class:'vmact'},S.powers(v,true)))))))));
    } else {
      const grid=h('div',{class:'boxgrid'},vms.map(box));root.append(grid);
      observer?.disconnect(); observer=new ResizeObserver(()=>links(grid));observer.observe(grid);
      requestAnimationFrame(()=>links(grid));
    }
  }
  addEventListener('svb-fx',()=>{const grid=document.querySelector('.boxgrid');if(grid)links(grid);});
  addEventListener('svb-render',()=>{if(!document.querySelector('.boxgrid'))observer?.disconnect();});
  S.register('library',{title:'Library',render});
})();
