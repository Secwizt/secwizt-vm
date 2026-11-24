(function () {
  const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d');
  let W = 0, H = 0, drops = [], raf = 0, frameTimer = 0, due = 0, last = 0, col = {};
  const frameInterval = 1000 / 24;
  const atlas = document.createElement('canvas'), ink = atlas.getContext('2d');
  const columns = 10, headX = 4, headY = 132;
  let scale = 1, cellW = 0, cellH = 0, atlasKey;
  function css(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
  function readColors() { col = { drop: css('--blue'), line: css('--star-line'), spark: css('--gold') }; }
  function resize() {
    const r = Math.min(2, devicePixelRatio || 1);
    if (scale === r && W === innerWidth && H === innerHeight) return;
    if (W && H) for (const d of drops) { d.x *= innerWidth / W; d.y *= innerHeight / H; }
    W = innerWidth; H = innerHeight; scale = r;
    canvas.width = W * r; canvas.height = H * r; ctx.setTransform(r, 0, 0, r, 0, 0);
  }
  let s = 11; const rnd = () => (s = (s * 16807) % 2147483647) / 2147483647;
  function newDrop(top) { const z = .35 + rnd() * .65; return { x: rnd() * W, y: top ? -rnd() * 200 : rnd() * H, z, v: (.05 + rnd() * .09) * z, len: (40 + rnd() * 90) * z, spark: rnd() < .08 }; }
  function seed() { s = 11; drops = Array.from({ length: 90 }, () => newDrop(false)); }
  // Each drop keeps its shape while falling. Share one texture for their trails and heads.
  function paintDrop(i) {
    const d = drops[i], color = d.spark ? col.spark : col.drop;
    ink.setTransform(scale, 0, 0, scale, (i % columns) * cellW, Math.floor(i / columns) * cellH);
    ink.clearRect(0, 0, cellW / scale, cellH / scale);
    const gradient = ink.createLinearGradient(headX, headY - d.len, headX, headY);
    gradient.addColorStop(0, 'transparent'); gradient.addColorStop(1, color);
    ink.globalAlpha = .3 + d.z * .5; ink.strokeStyle = gradient; ink.lineWidth = 1 + d.z;
    ink.beginPath(); ink.moveTo(headX, headY - d.len); ink.lineTo(headX, headY); ink.stroke();
    ink.globalAlpha = .45 + d.z * .5; ink.fillStyle = color;
    ink.beginPath(); ink.arc(headX, headY, 1.2 + d.z * 1.6, 0, Math.PI * 2); ink.fill();
  }
  function draw(dt) {
    const key = [scale, col.drop, col.spark].join('|');
    if (key !== atlasKey) {
      atlasKey = key; cellW = Math.ceil(8 * scale); cellH = Math.ceil(136 * scale);
      atlas.width = columns * cellW; atlas.height = Math.ceil(drops.length / columns) * cellH;
      drops.forEach((_,i) => paintDrop(i));
    }
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i < drops.length; i++) {
      const d = drops[i]; d.y += d.v * dt;
      if (d.y - d.len > H) { Object.assign(d, newDrop(true)); paintDrop(i); }
    }
    // links between drops that are close: the "network" in the rain
    ctx.lineWidth = 1; ctx.strokeStyle = col.line;
    for (let i = 0; i < drops.length; i++) for (let j = i + 1; j < drops.length; j++) {
      const a = drops[i], b = drops[j], dx = a.x - b.x, dy = a.y - b.y;
      const squared = dx * dx + dy * dy;
      if (squared >= 120 * 120) continue;
      ctx.globalAlpha = (1 - Math.sqrt(squared) / 120) * .5 * Math.min(a.z, b.z);
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
    ctx.globalAlpha = 1;
    for (let i = 0; i < drops.length; i++) {
      const d = drops[i];
      ctx.drawImage(atlas, (i % columns) * cellW, Math.floor(i / columns) * cellH, cellW, cellH,
        d.x - headX, d.y - headY, cellW / scale, cellH / scale);
    }
  }
  // cost meter: how long our drawing takes, so the CPU cost can be read instead of guessed (window.SVB_SKY_STATS)
  const stats = window.SVB_SKY_STATS = { frames: 0, drawMs: 0, since: performance.now() };
  function running() {
    return document.documentElement.dataset.fx !== 'off' && !document.hidden && document.hasFocus();
  }
  function tick(t) {
    raf = 0;
    if (!running()) return;
    const start = performance.now();
    draw(last ? Math.min(66, t - last) : 0);
    stats.drawMs += performance.now() - start; stats.frames++;
    last = t;
    due = Math.max(due + frameInterval, t);
    frameTimer = setTimeout(() => {
      frameTimer = 0;
      if (running()) raf = requestAnimationFrame(tick);
    }, Math.max(0, due - performance.now()));
  }
  function sync() {
    cancelAnimationFrame(raf); clearTimeout(frameTimer);
    raf = 0; last = 0; due = performance.now();
    const idle = document.hidden || !document.hasFocus();
    document.documentElement.toggleAttribute('data-motion-idle', idle);
    if (idle) return;
    resize(); readColors();
    if (running()) raf = requestAnimationFrame(tick);
    else draw(0);
  }
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('sky').append(canvas); resize(); seed(); sync();
    addEventListener('resize', () => {
      if (document.hidden || !document.hasFocus()) return;
      resize(); if (!running()) draw(0);
    });
    addEventListener('focus', sync);
    addEventListener('blur', sync);
    addEventListener('svb-fx', sync);
    document.addEventListener('visibilitychange', sync);
  });
})();
