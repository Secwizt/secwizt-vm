window.addEventListener('DOMContentLoaded', () => {
  const id = __FIXTURE_ID__;
  const send = (consoleFixture, values = {}) => window.ipc.postMessage(JSON.stringify({consoleFixture, ...values}));
  const wait = async (fn, ms) => {
    const limit = performance.now() + ms;
    while (performance.now() < limit) {
      const value = fn();
      if (value) return value;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw Error('The expected console observation did not arrive.');
  };
  const observedDimensions = (canvas) => {
    const rect = canvas.getBoundingClientRect();
    const css = [Math.round(rect.width), Math.round(rect.height)];
    return {frame: [canvas.width, canvas.height], css, viewport: [innerWidth, innerHeight]};
  };
  const getPixels = (canvas) => {
    const rgba = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
    let count = 0;
    for (let i = 0; i < rgba.length; i += 4) {
      if (rgba[i] || rgba[i + 1] || rgba[i + 2]) count++;
    }
    return count;
  };
  let assetStatus, mime, policy;
  let step = 'load viewer module';
  document.addEventListener('securitypolicyviolation', event => { policy = event.effectiveDirective; });
  (async () => {
    const asset = await fetch('/console/assets/core/rfb.js');
    assetStatus = asset.status;
    mime = asset.headers.get('content-type');
    if (!asset.ok) throw Error('The viewer module request failed.');
    let viewer;
    const {default: RFB} = await import('/console/assets/core/rfb.js');
    step = 'open embedded console';
    const scale = Object.getOwnPropertyDescriptor(RFB.prototype, 'scaleViewport');
    Object.defineProperty(RFB.prototype, 'scaleViewport', {...scale, set(value) {
      viewer = this;
      return scale.set.call(this, value);
    }});
    location.hash = 'vm/' + id;
    const canvas = await wait(() => {
      const current = document.getElementById('qemu-guest-display');
      const status = document.getElementById('qemu-console-status');
      if (current && status?.textContent.startsWith('Console connected.') && current.width > 200 && getPixels(current) > 100) {
        return current;
      }
    }, 21000);

    const before = observedDimensions(canvas);
    const litPixels = getPixels(canvas);
    const desktopResizeAdvertised = viewer._supportsSetDesktopSize === true;
    let resizeRequests = 0;
    const setDesktopSize = RFB.messages.setDesktopSize;
    RFB.messages.setDesktopSize = function (...args) {
      resizeRequests++;
      return setDesktopSize.apply(this, args);
    };
    viewer.sendKey(0xffc6, 'F9');
    viewer._sendMouse(77, 64, 1);
    viewer._sendMouse(81, 67, 0);

    step = 'observe desktop resize';
    send('resize');
    await wait(() => {
      const current = observedDimensions(canvas);
      return before.viewport[0] !== current.viewport[0] && before.css[0] !== current.css[0];
    }, 7000);
    await new Promise(resolve => setTimeout(resolve, 900));
    const after = observedDimensions(canvas);
    send('done', {origin: location.origin, secure: isSecureContext, before, after, litPixels,
      desktopResizeAdvertised, resizeRequests, sameCanvas: canvas === document.getElementById('qemu-guest-display'), keyboardSent: true, pointerSent: true});
  })().catch(error => {
    send('failed', {origin: location.origin, step, assetStatus, mime, policy, visibility: document.visibilityState, secure: isSecureContext, reason: error.message,
      status: document.getElementById('qemu-console-status')?.textContent || ''});
  });
}, {once: true});
