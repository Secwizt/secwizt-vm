(function () {
  'use strict';
  const S = window.SVB, h = S.h;
  const fields = [
    ['tools', 'Folder containing restic, age and age-plugin-yubikey', 'pickExportFolder'],
    ['repository', 'Initialized restic repository', 'pickExportFolder'],
    ['identity', 'YubiKey identity file', 'pickGuestUpload'],
    ['encryptedPassword', 'Encrypted repository password file', 'pickGuestUpload'],
  ];

  function date(value) {
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? value : time.toLocaleString();
  }

  function reason(vm, throwawayPending) {
    if (!vm) return '';
    if (vm.registration !== 'registered') return 'A verified machine registration is required to back up.';
    if (vm.state !== 'off') return 'Power off the machine to back it up.';
    if (throwawayPending) return 'Wait for recovery of the previous throwaway run.';
    if (vm.linkedFrom) return 'Linked clones depend on their template. Back up the template or make a full clone first.';
    if (vm.tpm) return 'This machine uses a host-bound virtual TPM. Its keys cannot move to a new machine.';
    if (vm.snaps) return 'Merge the checkpoints into a standalone disk first.';
    if (!['QEMU','Hyper-V'].includes(vm.engine)) return 'This engine does not support encrypted backups.';
    return '';
  }

  S.backupSection = function (machine) {
    const area = h('div', {'aria-live':'polite'});
    const panel = h('section', {class:'card pref-form'}, h('h3', {}, 'Encrypted backups'), area);
    const endpoint = '/v1/backups' + (machine ? '?machineId=' + S.api.segment(machine.id) : '');
    let timer;
    async function start(path, body) {
      await S.api.action('POST', path, body);
      await load();
    }
    async function restore(row) {
      const name = await S.dialog('Restore as a new machine', h('p', {},
        'The restored machine starts powered off with a new network identity. Hyper-V keeps its original network. QEMU keeps its isolation setting.'),
        'Restore', h('label', {class:'new-field'}, 'New machine name', h('input', {required:true,maxlength:80})));
      if (name) await start('/v1/backups/restore', {snapshotId:row.id, name});
    }
    async function load() {
      clearTimeout(timer);
      await S.fill(area, () => S.api.get(endpoint), data => {
        if (!data.configured) return h('p', {}, 'Choose your backup tools and repository in Settings.');
        const busy = !!(data.current || data.cooldownSeconds || data.unreadableReceipt || data.last?.state === 'pending'), last = data.last, rows = data.snapshots;
        const unavailable = reason(machine, data.throwawayPending);
        const disabled = busy || !!unavailable;
        if (data.current || data.cooldownSeconds || last?.state === 'pending') timer = setTimeout(() => { if (area.isConnected) void load(); }, 1500);
        return h('div', {}, h('p', {}, 'Your YubiKey unlocks the encrypted repository password. Have the key ready for the console prompt. Close the backup console to cancel.'),
          machine && h('p', {}, rows.length ? 'Last backup: ' + date(rows[0].time) : 'No backup is listed for this machine.'),
          unavailable && h('p', {}, unavailable),
          machine && h('button', {class:'btn', disabled, onclick:() => start('/v1/backups', {machineId:machine.id})}, 'Back up now'),
          h('button', {class:'btn', disabled:busy, onclick:() => start('/v1/backups/refresh', {})}, 'Refresh backup list'),
          data.unreadableReceipt && h('p', {role:'status'}, 'Close the backup console, then inspect and remove the unreadable ' + data.unreadableReceipt + ' from the service data folder.'),
          data.cooldownSeconds > 0 && h('p', {role:'status'}, 'The key prompt can reopen in ' + data.cooldownSeconds + ' seconds.'),
          data.current && h('p', {role:'status'}, 'In progress: ' + data.current.kind + (data.current.seconds == null ? '' : ' (' + data.current.seconds + ' s)')),
          !data.current && last && (!machine || last.machineId === machine.id || last.kind === 'list') &&
            h('p', {role:'status'}, last.state === 'completed' ? 'Completed: ' + last.kind + (last.seconds == null ? '' : ' (' + last.seconds + ' s)') : last.message),
          !machine && !rows.length && h('p', {}, 'No snapshots are listed. Refresh to read the repository.'),
          rows.map(row => h('article', {}, h('p', {}, (machine ? '' : row.machineId + ' · ') + date(row.time) + ' · ' + row.id.slice(0,12)),
            h('button', {class:'btn', disabled:busy, onclick:() => restore(row)}, 'Restore as a new machine'))));
      });
    }
    void load();
    return panel;
  };

  let draft = {};
  S.backupSettings = function () {
    const form = h('div', {});
    S.fill(form, () => S.api.get('/v1/settings/backup'), data => {
      const selected = {...data.paths, ...draft};
      const controls = fields.map(([key, label, picker]) => {
        const value = h('span', {}, selected[key] || 'Choose a path');
        return h('div', {class:'new-field'}, h('span', {}, label), value,
          h('button', {class:'btn', 'aria-label':'Choose ' + label, onclick:async () => {
            const path = await S.api.native(picker, {text:'backup'});
            if (path) { draft[key] = selected[key] = path; value.textContent = path; if (!value.isConnected && S.view === 'settings') S.render(true); }
          }}, 'Choose'));
      });
      const hashes = Object.entries(data.hashes || {});
      return h('div', {}, controls,
        hashes.length > 0 && h('section', {}, h('h3', {}, 'Pinned SHA-256 values'),
          S.facts(hashes.map(([name, digest]) => [name, h('code', {}, digest)]))),
        h('button', {class:'btn', onclick:async () => {
        if (fields.some(([key]) => !selected[key])) { S.toast('Choose all four paths first.'); return; }
        await S.api.action('PUT', '/v1/settings/backup', selected);
        draft = {};
        S.toast('Backup tools pinned and settings saved.');
        if (S.view === 'settings') S.render(true);
      }}, 'Pin tools and save backup settings'));
    });
    return h('section', {class:'card pref-form'}, h('h2', {}, 'Backup settings'),
      h('p', {}, 'Choose the files from your YubiKey setup and an existing local restic repository.'), form, S.backupSection());
  };
})();
