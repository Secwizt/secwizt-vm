(function () {
  'use strict';
  const S = window.SVB, h = S.h, api = S.api;
  const categories = ['Security', 'Developer', 'AI tools', 'Everyday'];
  const families = {debian:'Debian family', fedora:'Fedora family', windows:'Windows'};
  const distros = {debian:'Debian', ubuntu:'Ubuntu', kali:'Kali', parrot:'Parrot', linuxmint:'Mint',
    fedora:'Fedora', rocky:'Rocky', almalinux:'AlmaLinux'};
  const previewText = steps => steps.map((step, i) =>
    (i + 1) + '. ' + step.title + ' (' + step.timeoutSec + ' s limit)\n' + JSON.stringify(step.argv, null, 2)).join('\n\n');

  async function chooseMachine(app, action) {
    const candidates = await api.appMachines(app.id);
    const ready = candidates.filter(vm => !vm.reason);
    const blocked = candidates.filter(vm => vm.reason);
    if (!ready.length) {
      await S.dialog(app.name, h('div', {}, blocked.length
        ? blocked.map(vm => h('p', {}, vm.name + ' — ' + vm.reason))
        : h('p', {}, 'Start a compatible machine and make its guest command channel available.')), 'Close', null, false);
      return null;
    }
    const select = h('select', {id:'app-machine', required:true}, h('option', {value:''}, 'Choose a machine'),
      ready.map(vm => h('option', {value:vm.id}, vm.name + ' · ' + vm.engine)));
    const confirmed = await S.dialog((action === 'install' ? 'Install ' : 'Uninstall ') + app.name,
      h('div', {}, h('label', {class:'new-field'}, 'Running machine', select),
        blocked.map(vm => h('p', {class:'new-hint'}, vm.name + ' — ' + vm.reason))), 'Continue');
    return confirmed ? ready.find(vm => vm.id === select.value) : null;
  }

  async function configure(app, action) {
    const machine = await chooseMachine(app, action);
    if (!machine) return;
    let access = {};
    if (machine.engine === 'Hyper-V') {
      const fields = S.guestAccessFields(machine.family === 'windows', 'app-access');
      access = S.readGuestAccess(fields, await S.dialog('Check ' + machine.name, h('div', {}, fields.fields), 'Check guest access'));
      if (!access) return;
    }
    try {
      const preview = await api.appPreview(machine.id, app.id, action, access);
      const install = action === 'install';
      const confirm = (install ? 'Install in ' : 'Uninstall from ') + machine.name;
      const release = app.recipes?.windows?.packageId;
      const accepted = await S.dialog('Review guest commands', h('div', {},
        h('p', {}, app.name + ' · ' + machine.name),
        machine.family === 'windows' && release && h('p', {}, 'WinGet package ID: ' + release),
        h('label', {class:'new-field'}, 'Commands and time limits',
          h('textarea', {class:'app-preview', readonly:true, rows:14, spellcheck:'false'}, previewText(preview.steps)))), confirm);
      if (!accepted) return;
      await api.appRun(machine.id, app.id, preview.previewId, access);
      S.showAppLog(machine.id);
    } finally {
      if (access.credentials) access.credentials.password = '';
    }
  }

  function card(app) {
    const source = Object.entries(app.recipes).map(([family, recipe]) => {
      const names = recipe.distros?.length ? recipe.distros.map(id => distros[id]).join(', ') : families[family];
      const detail = recipe.packageId || (recipe.needsDocker ? 'Docker required' : '');
      return [names, recipe.label + (detail ? ' · ' + detail : '')];
    });
    const copy = async () => {
      await api.native('copyText', {text:app.homepage});
      S.toast('Publisher link copied.');
    };
    return h('article', {class:'card catalog-installer'},
      h('h3', {}, app.name), h('p', {}, app.description),
      S.facts([['Publisher', app.publisher], ['Licence', app.licence],
        ...source, ['Availability', app.label]], 'new-facts'),
      app.note && h('p', {class:'new-hint'}, app.note),
      h('div', {class:'vm-actions'},
        !app.label && h('button', {type:'button', class:'btn', 'aria-label':'Install ' + app.name,
          onclick:() => configure(app, 'install')}, 'Install'),
        !app.label && h('button', {type:'button', class:'btn', 'aria-label':'Uninstall ' + app.name,
          onclick:() => configure(app, 'uninstall')}, 'Uninstall'),
        h('button', {type:'button', class:'btn', 'aria-label':'Copy publisher link for ' + app.name, onclick:copy}, 'Copy publisher link')));
  }

  S.appsCatalog = function () {
    let apps = [];
    const status = h('p', {class:'sub', role:'status'});
    const list = h('div', {class:'catalog-grid'});
    const search = h('input', {id:'app-catalog-search', type:'search', placeholder:'Search apps and AI tools',
      'aria-label':'Search apps and AI tools', oninput:draw});
    const category = h('select', {id:'app-catalog-category', 'aria-label':'App category', onchange:draw},
      h('option', {value:''}, 'All categories'), categories.map(value => h('option', {value}, value)));
    const retry = h('button', {type:'button', class:'btn', hidden:true, onclick:load}, 'Retry app catalog');
    function draw() {
      const query = search.value.trim().toLowerCase();
      const matches = apps.filter(app => (!category.value || app.category === category.value) &&
        [app.name, app.description, app.publisher].join(' ').toLowerCase().includes(query));
      list.replaceChildren(...matches.map(card));
      status.textContent = matches.length ? '' : 'No apps match these filters.';
    }
    async function load() {
      retry.hidden = true;
      status.textContent = 'Loading apps…';
      try { apps = await api.appCatalog(); draw(); }
      catch (error) { status.textContent = error.message; retry.hidden = false; }
    }
    const panel = h('section', {}, h('h2', {}, 'Apps & AI tools'),
      h('div', {class:'libbar catalog-filters'}, search, h('div', {class:'new-field'}, category)),
      status, retry, list);
    void load();
    return panel;
  };

  let logView;
  S.appJobPanel = function (machine) {
    if (logView?.machine === machine) return logView.panel;
    const status = h('p', {role:'status'});
    const output = h('div', {});
    const view = {machine, status, timer:null, running:false};
    let rendered;
    async function poll() {
      clearTimeout(view.timer);
      try {
        const job = await api.appJob(machine);
        if (view !== logView || !view.panel.isConnected) return;
        view.running = job?.state === 'running';
        status.textContent = job ? job.app + ' — ' + job.message : 'No app operation recorded for this machine.';
        const revision = job ? JSON.stringify(job.log) + job.id : '';
        if (rendered !== revision) {
          rendered = revision;
          output.replaceChildren(...(job?.log || []).map(step => h('section', {},
            h('h3', {}, 'Step ' + step.step + ' · ' + step.title + ' · ' + step.state),
            step.output?.stdout && h('pre', {class:'app-log-output'}, step.output.stdout),
            step.output?.stderr && h('pre', {class:'app-log-output'}, step.output.stderr))));
        }
      } catch (error) {
        if (view === logView) status.textContent = error.message;
      }
      if (view === logView && view.panel.isConnected && view.running) view.timer = setTimeout(poll, 1000);
    }
    view.panel = h('section', {class:'card'}, h('h2', {}, 'App log'), status, output,
      h('button', {type:'button', class:'btn', onclick:poll}, 'Refresh app log'));
    logView = view;
    void poll();
    return view.panel;
  };

  window.addEventListener('svb-render', () => {
    if (!logView?.panel.isConnected) {
      clearTimeout(logView?.timer);
      logView = null;
    }
  });
})();
