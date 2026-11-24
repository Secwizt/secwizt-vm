(function () {
  const S=window.SVB,h=S.h;
  const hostLimits=[
    ['macOS guest','macOS guests need a compatible Apple virtualization engine.'],
    ['DirectX 11 in Windows guests','No engine on this PC provides it. Windows guests get a fast 2D desktop.'],
    ['Bridging over Wi-Fi','Bridged networks require an active physical Ethernet adapter. Wi-Fi adapters can restrict frames from guest MAC addresses.'],
    ['A public IPv4 address per VM','One home connection has one public IPv4 address. IPv6 can give each machine an address when the provider supplies a prefix.']
  ];
  const labels={Start:'Start',Stop:'Power off',Shutdown:'Shut down',Restart:'Restart',SendKeys:'Send keys to the guest',Pause:'Pause',Resume:'Resume',Snapshot:'Take snapshot',SnapshotWithMemory:'Snapshot with memory',
    Clone:'Clone machine',Delete:'Delete machine',DeleteSnapshot:'Delete checkpoint',RevertSnapshot:'Revert checkpoint',UsbPassthrough:'USB passthrough',
    OwnLanAddress:'Own LAN address',Accelerated:'Hardware acceleration',Console:'Open console',Thumbnail:'Display preview',EditHardware:'Edit hardware',
    EditStorage:'Edit storage',ListSnapshots:'List snapshots',PressKeyAtBoot:'Installer boot key'};
  let machineId=null;
  function render(root) {
    const machines=S.data.vms,v=S.vm(machineId)||machines[0];
    const missing=v?Object.entries(S.data.caps[v.id]||{}).filter(([,d])=>!d.available):[];
    root.append(h('div',{class:'why-page'},h('h1',{},'Why not available'),
      v&&h('section',{class:'card'},h('label',{class:'new-field'},'Machine',
        h('select',{id:'why-machine',onchange:e=>{machineId=e.target.value;S.render();document.getElementById('why-machine')?.focus();}},
          machines.map(m=>h('option',{value:m.id,selected:m.id===v.id},m.name))))),
      v&&h('div',{class:'why-grid'},missing.length?missing.map(([name,d])=>h('article',{class:'card'},h('h2',{},labels[name]||name),h('p',{},d.reason))):
        h('p',{},'The service reports no unavailable controls for this machine.')),
      h('section',{class:'card'},h('h2',{},'Engine and network limits'),h('dl',{},
        hostLimits.map(([name,reason])=>[h('dt',{},name),h('dd',{},reason)])))));
  }
  S.register('whynot',{title:'Why not available',render});
})();
