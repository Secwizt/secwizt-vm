(function () {
  'use strict';
  const S = window.SVB, h = S.h, api = S.api;
  const GB = 1e9;
  const POLL_MS = 2000;
  const gb = bytes => Number.isSafeInteger(bytes) ? (bytes / GB).toLocaleString(undefined, {maximumFractionDigits: 1}) + ' GB' : 'Unavailable';
  const stageLabels = {checking: 'Checking the download', unpacking: 'Unpacking the archive', converting: 'Preparing the disk', hashing: 'Checking the prepared disk'};
  const downloadLabels = {
    downloading: 'Downloading', cancelling: 'Cancelling', verifying: 'Verifying the download', publishing: 'Saving the verified download',
    paused: 'Download paused', failed: 'Download failed', verified: 'Downloaded and verified'
  };
  const userPattern = /^[a-z_][a-z0-9_-]{0,30}$/;
  const title = image => image.name + ' ' + image.version;
  const path = id => '/v1/ready/' + api.segment(id);
  let view;

  function busy(image) {
    return Boolean(image.preparing) || image.queued === true
      || ['downloading', 'cancelling', 'verifying', 'publishing'].includes(image.download?.state);
  }

  function statusOf(image) {
    if (image.template) {
      const count = image.template.machines;
      return {text: 'Ready. ' + (count === 1 ? '1 machine uses it.' : count + ' machines use it.')};
    }
    if (image.preparing) {
      const label = stageLabels[image.preparing.stage] || 'Preparing';
      return {text: image.preparing.state === 'cancelling' ? 'Cancelling…' : label, percent: image.preparing.stage === 'checking' ? null : image.preparing.percent};
    }
    const download = image.download || {state: 'idle'};
    const text = (downloadLabels[download.state] || 'Not downloaded yet') + (image.queued && download.state !== 'verified' ? '. It is prepared when the download is verified.' : '');
    const percent = ['downloading', 'verifying', 'publishing'].includes(download.state) && download.totalBytes > 0
      ? Math.floor(100 * Math.min(download.bytes, download.totalBytes) / download.totalBytes) : null;
    return {text, percent};
  }

  function message(image) {
    if (view.errors.has(image.id)) return view.errors.get(image.id);
    if (image.unsealed) return 'An unfinished copy of this image exists (' + image.unsealed.name + '). Make it a template from its machine page, or delete it, then choose Get again.';
    if (image.preparing || image.queued) return '';
    if (image.outcome) return (image.outcome.state === 'cancelled' ? 'Preparation cancelled. ' : 'Preparation failed. ') + image.outcome.message;
    return image.download?.message || '';
  }

  async function guarded(image, work) {
    view.errors.delete(image.id);
    view.pending.add(image.id);
    draw();
    try { await work(); }
    catch (error) { view.errors.set(image.id, error.message); }
    finally { view.pending.delete(image.id); await load(); }
  }

  // Get starts or continues the download; the service prepares the image once it is verified.
  const get = image => guarded(image, () => api.action('POST', path(image.id) + '/prepare', {}));

  function cancel(image) {
    return guarded(image, async () => {
      if (image.preparing || image.queued) await api.action('DELETE', path(image.id) + '/prepare');
      if (!image.preparing && ['downloading', 'verifying'].includes(image.download?.state)) await api.catalogDownload(image.id, 'DELETE');
    });
  }

  function field(label, input, hint) {
    return h('label', {class: 'new-field'}, label, input, hint && h('span', {class: 'new-hint'}, hint));
  }

  function launchProblem(cloud, values) {
    if (!values.name) return 'Enter a machine name.';
    if (!cloud) return '';
    if (!userPattern.test(values.user)) return 'Use a user name of lowercase letters, digits, - or _ that starts with a letter or _.';
    if (!values.generate) {
      const length = [...values.password].length;
      if (length < 8 || length > 128 || /[\r\n]/.test(values.password) || values.password.trim() !== values.password) {
        return 'Use a password of 8 to 128 characters without line breaks or outer spaces.';
      }
    }
    if (values.key && !/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*( .*)?$/.test(values.key)) {
      return 'Paste one OpenSSH public key line, or leave the key empty.';
    }
    return '';
  }

  async function launch(image) {
    const cloud = image.firstBoot === 'cloud-init';
    const name = h('input', {type: 'text', required: true, maxlength: 64});
    name.value = image.name + ' ' + ((image.template?.machines || 0) + 1);
    const user = h('input', {type: 'text', autocomplete: 'off', spellcheck: 'false', maxlength: 31, pattern: '[a-z_][a-z0-9_-]{0,30}', placeholder: 'labuser'});
    const generate = h('input', {type: 'checkbox'});
    generate.checked = true;
    const password = h('input', {type: 'password', autocomplete: 'new-password', maxlength: 128});
    password.disabled = true;
    generate.addEventListener('change', () => { password.disabled = generate.checked; if (generate.checked) password.value = ''; });
    const key = h('input', {type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'ssh-ed25519 AAAA…'});
    const throwaway = h('input', {type: 'checkbox'});
    const start = h('input', {type: 'checkbox'});
    start.checked = true;
    const problem = h('p', {class: 'new-error', role: 'status'});
    const content = h('div', {},
      h('p', {}, cloud
        ? 'The machine is a linked copy of the prepared image. Its first-boot settings are written for it alone.'
        : 'The machine is a linked copy of the prepared image. It starts with the publisher’s default login: ' + image.defaultUser + ' / ' + image.defaultUser + '. Change the password at the first sign-in.'),
      field('Machine name', name),
      cloud && field('User name', user, 'Lowercase letters, digits, - or _. System account names are refused.'),
      cloud && h('label', {class: 'new-check'}, generate, ' Generate a strong password and show it once'),
      cloud && field('Password', password, '8 to 128 characters. Only its hash is saved, never the password itself.'),
      cloud && field('SSH public key (optional)', key, 'One line. Password sign-in over SSH stays off.'),
      h('label', {class: 'new-check'}, throwaway, ' Throwaway: discard every change when the machine powers off'),
      !cloud && h('p', {class: 'new-hint'}, 'A throwaway machine also discards a changed password, so it keeps the publisher’s default login.'),
      h('label', {class: 'new-check'}, start, ' Start the machine now'), problem);
    let values;
    for (;;) {
      const accepted = await S.dialog('Launch ' + title(image), content, 'Create machine');
      values = {name: name.value.trim(), user: user.value.trim(), generate: generate.checked, password: password.value, key: key.value.trim()};
      if (!accepted) { password.value = ''; return; }
      problem.textContent = launchProblem(cloud, values);
      if (!problem.textContent) break;
    }
    password.value = '';
    const body = {name: values.name};
    if (cloud) {
      body.user = values.user;
      if (values.generate) body.generatePassword = true; else body.password = values.password;
      if (values.key) body.sshKey = values.key;
    }
    await guarded(image, async () => {
      const result = await api.action('POST', path(image.id) + '/launch', body);
      const machine = result.machine;
      if (result.password) await showPassword(machine, body.user, result.password);
      if (throwaway.checked) await api.action('PATCH', api.machinePath(machine.id), {throwaway: true});
      if (start.checked) await api.action('POST', api.machinePath(machine.id) + '/start', {});
      S.toast(machine.name + (start.checked ? ' is starting.' : ' is ready.'));
      S.go('vm', {id: machine.id});
    });
  }

  async function showPassword(machine, user, password) {
    const copy = h('button', {type: 'button', class: 'btn', onclick: async () => {
      await api.native('copyText', {text: password});
      S.toast('Password copied. Clear the clipboard after you sign in.');
    }}, 'Copy password');
    // No Cancel and no Escape: the password exists only in this dialog.
    await S.dialog('Save this password now', h('div', {},
      h('p', {}, 'Sign in to ' + machine.name + ' as ' + user + ' with this password. It is not stored and cannot be shown again.'),
      h('p', {class: 'catalog-checksum'}, password), copy), 'I saved it', null, false, true);
  }

  function card(image) {
    const entry = {image, primaryAction: () => {}, secondaryAction: () => {}};
    const status = h('p', {class: 'catalog-transfer-state', role: 'status'});
    const progress = h('progress', {max: 100, 'aria-label': 'Progress for ' + title(image)});
    const note = h('p', {class: 'new-error', role: 'status'});
    const primary = h('button', {type: 'button', class: 'btn primary', onclick: () => entry.primaryAction()});
    const secondary = h('button', {type: 'button', class: 'btn', onclick: () => entry.secondaryAction()});
    const facts = [
      ['Publisher', image.publisher], ['Official source', image.sourceHost],
      ['Verification', image.verification === 'Signed' ? 'Publisher signature and SHA-256, checked on download' : 'Pinned SHA-256, checked on download'],
      ['Interface', image.desktop ? 'Desktop' : 'Text console'],
      ['First sign-in', image.firstBoot === 'cloud-init' ? 'You choose the user and password' : 'Publisher default: ' + image.defaultUser + ' / ' + image.defaultUser],
      ['Download', gb(image.bytes)], ['Disk', image.diskGb + ' GiB'],
      ['Space to prepare', gb(image.spaceNeeded)],
    ];
    const element = h('article', {class: 'card catalog-installer'},
      h('h3', {}, title(image)), h('p', {}, image.note), S.facts(facts, 'new-facts'),
      status, progress, note, h('div', {class: 'vm-actions'}, primary, secondary));
    return Object.assign(entry, {element, status, progress, note, primary, secondary});
  }

  function label(button, text) {
    if (button.textContent !== text) button.replaceChildren(text);
  }

  function drawCard(entry) {
    const image = entry.image;
    const state = statusOf(image);
    const waiting = view.pending.has(image.id);
    entry.status.textContent = state.text;
    entry.progress.hidden = state.percent == null;
    if (state.percent != null) entry.progress.value = state.percent;
    entry.note.textContent = message(image);
    const qemuReady = view.qemu?.available === true;
    entry.secondary.hidden = !busy(image);
    label(entry.secondary, image.preparing ? 'Cancel preparation' : 'Cancel download');
    entry.secondary.disabled = waiting || image.preparing?.state === 'cancelling' || image.download?.state === 'cancelling';
    entry.secondaryAction = () => cancel(image);
    if (image.template) {
      label(entry.primary, 'Launch');
      entry.primaryAction = () => launch(image);
    } else {
      label(entry.primary, image.download?.state === 'paused' && image.download.canResume ? 'Resume and prepare' : 'Get');
      entry.primaryAction = () => get(image);
    }
    entry.primary.hidden = busy(image);
    entry.primary.disabled = waiting || !qemuReady || Boolean(image.unsealed);
  }

  function draw() {
    if (!view?.panel.isConnected) return;
    view.cards.forEach(drawCard);
    view.status.textContent = view.qemu && view.qemu.available !== true
      ? (view.qemu.reason || 'Select QEMU in Settings to use ready-made machines.')
      : view.loadError || '';
  }

  async function load() {
    if (!view) return;
    clearTimeout(view.timer);
    try {
      const data = await api.get('/v1/ready');
      if (!view?.panel.isConnected) return;
      view.loadError = '';
      view.qemu = data.qemu;
      for (const image of data.images) {
        let entry = view.cards.get(image.id);
        if (!entry) {
          entry = card(image);
          view.cards.set(image.id, entry);
          view.list.append(entry.element);
        }
        const wasWorking = busy(entry.image);
        entry.image = image;
        if (wasWorking && !busy(image) && image.template) S.toast(title(image) + ' is ready to launch.');
      }
      draw();
      if (data.images.some(busy)) view.timer = setTimeout(load, POLL_MS);
    } catch (error) {
      if (!view?.panel.isConnected) return;
      view.loadError = error.message;
      draw();
    }
  }

  S.readyImages = function () {
    if (view?.panel.isConnected) { void load(); return view.panel; }
    const status = h('p', {class: 'new-error', role: 'status'});
    const list = h('div', {class: 'catalog-grid'});
    const panel = h('section', {}, h('h2', {}, 'Ready to run'),
      h('p', {class: 'sub'}, 'Official ready-made machines. The first Get downloads and prepares an image once; after that each new machine is a linked copy that is created in seconds, without an installer.'),
      status, list);
    view = {panel, status, list, cards: new Map(), errors: new Map(), pending: new Set(), timer: null, qemu: null, loadError: ''};
    void load();
    return panel;
  };

  // The machine page shows this while a publisher's public default login is still in use.
  S.defaultLoginNotice = function (vm) {
    const user = vm.ready?.defaultLogin;
    if (!user || vm.template) return null;
    const throwaway = vm.throwaway === true;
    const notice = h('p', {class: 'new-error', role: 'status'});
    const change = h('button', {type: 'button', class: 'btn primary', disabled: throwaway || vm.state !== 'running', onclick: async () => {
      const first = h('input', {type: 'password', autocomplete: 'new-password', maxlength: 128});
      const again = h('input', {type: 'password', autocomplete: 'new-password', maxlength: 128});
      const accepted = await S.dialog('Set a new password for ' + user, h('div', {},
        h('p', {}, 'The guest agent sets it inside the machine. It is not saved by this app.'),
        field('New password', first, '8 to 128 characters, no line breaks.'), field('Repeat it', again)), 'Set password');
      const value = first.value, repeat = again.value;
      first.value = ''; again.value = '';
      if (!accepted) return;
      if (value !== repeat) { notice.textContent = 'The two passwords differ.'; return; }
      if (value.length < 8 || value.length > 128 || /[\r\n]/.test(value)) { notice.textContent = 'Use 8 to 128 characters without line breaks.'; return; }
      try {
        const result = await api.guestRequest(vm.id, 'exec', {argv: ['/usr/sbin/chpasswd'], timeoutSec: 30, stdin: user + ':' + value + '\n'});
        if (result.exitCode !== 0) throw new Error('The guest refused the new password.');
        await api.action('POST', api.machinePath(vm.id) + '/default-login', {changed: true});
        S.toast('Password changed. Port forwarding is available again.');
      } catch (error) {
        notice.textContent = error.message + ' Sign in, run passwd, then choose “I changed it myself”.';
      }
    }}, 'Set a new password');
    const confirm = h('button', {type: 'button', class: 'btn', disabled: throwaway, onclick: async () => {
      if (!await S.dialog('Confirm the new password', h('p', {}, 'Confirm only after you changed the password for ' + user + ' inside the machine.'), 'I changed it')) return;
      try { await api.action('POST', api.machinePath(vm.id) + '/default-login', {changed: true}); }
      catch (error) { notice.textContent = error.message; }
    }}, 'I changed it myself');
    return h('section', {class: 'card'}, h('h2', {}, 'Change the default password'),
      h('p', {}, 'This machine still uses the publisher’s public default login for the user ' + user + '. Anyone who knows it can sign in, so port forwarding stays off until you change it.'),
      throwaway ? h('p', {class: 'new-hint'}, 'Throwaway mode discards a changed password at power-off. Turn it off first to keep a new password.')
        : vm.state !== 'running' && h('p', {class: 'new-hint'}, 'Start the machine to set the password through the guest agent.'),
      notice, h('div', {class: 'vm-actions'}, change, confirm));
  };

  window.addEventListener('svb-render', () => {
    if (view && !view.panel.isConnected) {
      clearTimeout(view.timer);
      view = null;
    }
  });
})();
