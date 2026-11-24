window.addEventListener('DOMContentLoaded', () => {
  const id = __FIXTURE_ID__;
  const sharing = __CLIPBOARD_ENABLED__;
  const send = (consoleFixture, fields = {}) => window.ipc.postMessage(JSON.stringify({consoleFixture, ...fields}));
  const wait = async (predicate, ms) => {
    const deadline = performance.now() + ms;
    do {
      if (predicate()) return true;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (performance.now() < deadline);
    return false;
  };
  (async () => {
    let viewer;
    const {default:RFB} = await import('/console/assets/core/rfb.js');
    const scale = Object.getOwnPropertyDescriptor(RFB.prototype, 'scaleViewport');
    Object.defineProperty(RFB.prototype, 'scaleViewport', {...scale, set(value) {
      viewer = this;
      return scale.set.call(this, value);
    }});
    location.hash = 'vm/' + id;
    if (!await wait(() => viewer && document.getElementById('qemu-console-status')?.textContent.startsWith('Console connected.'), 18000)) {
      throw Error('The fixture console did not connect.');
    }
    const guestText = 'guest clipboard ' + id;
    let matches = 0;
    let events = 0;
    viewer.addEventListener('clipboard', event => {
      events++;
      if (event.detail?.text === guestText) matches++;
    });
    const pasteVisible = Boolean(document.getElementById('qemu-host-clipboard'));
    const copyVisible = Boolean(document.getElementById('qemu-copy-clipboard'));

    // Try the wire operation even in the off run to exercise the real missing guest device.
    // The synthetic fixture does not read or write the actual Windows clipboard.
    viewer.clipboardPasteFrom('host clipboard ' + id);
    send('clipboard-ready', {sharing, pasteVisible, copyVisible});
    if (sharing) {
      const received = await wait(() => matches > 0 && document.getElementById('qemu-guest-clipboard')?.value === guestText, 12000);
      send(received && pasteVisible && copyVisible ? 'done' : 'failed', {sharing, pasteVisible, copyVisible, received, events, matches});
      return;
    }
    const crossed = await wait(() => matches > 0, 11500);
    send(!crossed && events === 0 && !pasteVisible && !copyVisible ? 'done' : 'failed',
      {sharing, pasteVisible, copyVisible, received:crossed, events, matches});
  })().catch(() => send('failed', {sharing, failure:'console unavailable'}));
}, {once:true});
