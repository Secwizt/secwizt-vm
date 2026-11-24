(function () {
  const nodes = [[60, 150], [150, 70], [150, 230], [260, 150], [370, 70], [370, 230], [460, 150]];
  const edges = [[0, 1], [0, 2], [1, 3], [2, 3], [3, 4], [3, 5], [4, 6], [5, 6], [1, 4], [2, 5]];
  const css = `
  #intro{position:fixed;inset:0;z-index:20;display:grid;place-items:center;background:linear-gradient(180deg,var(--sky-1),var(--sky-2) 46%,var(--sky-3));transition:opacity .5s}
  #intro.out{opacity:0;pointer-events:none}
  #intro .in{display:grid;justify-items:center;gap:6px}
  #intro svg{width:min(520px,70vw);height:auto;overflow:visible}
  #intro .e{fill:none;stroke:var(--blue);stroke-width:2;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1;animation:idraw .7s ease-out forwards}
  #intro .n{fill:var(--panel);stroke:var(--blue);stroke-width:2.5;transform-box:fill-box;transform-origin:center;transform:scale(0);animation:ipop .35s ease-out forwards}
  #intro .n.hub{fill:var(--gold);stroke:var(--gold-ink)}
  #intro .p{fill:var(--gold);opacity:0;animation:irun 1s linear .9s 2}
  #intro h1{font:600 34px var(--display);color:var(--blue-deep);margin:10px 0 0;opacity:0;animation:iup .5s ease-out 1s forwards}
  #intro p{color:var(--muted);margin:0;opacity:0;animation:iup .5s ease-out 1.25s forwards}
  @keyframes idraw{to{stroke-dashoffset:0}}
  @keyframes ipop{to{transform:scale(1)}}
  @keyframes irun{0%{offset-distance:0%;opacity:1}100%{offset-distance:100%;opacity:1}}
  @keyframes iup{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}`;
  document.addEventListener('DOMContentLoaded', () => {
    if (document.documentElement.dataset.fx === 'off' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const style = document.createElement('style'); style.textContent = css; document.head.append(style);
    const el = document.createElement('div'); el.id = 'intro'; el.setAttribute('role', 'img'); el.setAttribute('aria-label', 'Secwizt Virtual Machine is starting');
    const lines = edges.map(([a, b], i) => `<path class="e" pathLength="1" style="animation-delay:${(i * .06).toFixed(2)}s" d="M${nodes[a]} L${nodes[b]}"/>`).join('');
    const dots = nodes.map((n, i) => `<circle class="n${i === 3 ? ' hub' : ''}" cx="${n[0]}" cy="${n[1]}" r="${i === 3 ? 13 : 8}" style="animation-delay:${(.45 + i * .06).toFixed(2)}s"/>`).join('');
    const run = [[0, 1, 3, 4, 6], [0, 2, 3, 5, 6]].map((p, i) => `<circle class="p" r="5" style="offset-path:path('M${p.map(k => nodes[k]).join(' L')}');animation-delay:${.9 + i * .25}s"/>`).join('');
    el.innerHTML = `<div class="in"><svg viewBox="0 0 520 300" aria-hidden="true">${lines}${dots}${run}</svg><h1>✦ Secwizt Virtual Machine</h1><p>Every machine its own address</p></div>`;
    document.body.append(el);
    let done = false; const close = () => { if (done) return; done = true; el.classList.add('out'); setTimeout(() => el.remove(), 550); removeEventListener('keydown', close); };
    el.addEventListener('click', close); addEventListener('keydown', close); setTimeout(close, 2600);
  });
})();
