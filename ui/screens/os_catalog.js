(function () {
  'use strict';
  const S = window.SVB, h = S.h;
  const screen = 'os-catalog';
  const collections = ['Open source', 'Security', 'Windows'];
  const activeStates = new Set(['downloading', 'cancelling', 'verifying', 'publishing']);
  const stateLabels = {
    idle: 'Ready to download', downloading: 'Downloading', cancelling: 'Cancelling',
    verifying: 'Verifying the installer', publishing: 'Saving the verified installer', paused: 'Download paused',
    verified: 'Installer verified', failed: 'Download failed'
  };
  let page, marketplace;

  const knownBytes = value => Number.isSafeInteger(value) && value >= 0;
  const bytes = value => value.toLocaleString() + ' bytes';
  const availableBytes = value => knownBytes(value) ? bytes(value) : 'Unavailable';
  const title = entry => [entry.name, entry.version, entry.versionVerified === false && '(version unverified)', entry.edition]
    .filter(Boolean).join(' ');
  const isCurrent = view => page === view && view.el.isConnected;
  const setText = (element, value) => {
    if (element.textContent !== value) element.textContent = value;
  };

  function resumable(transfer) {
    return transfer.canResume === true && ['paused', 'failed'].includes(transfer.state);
  }

  function requiredBytes(entry, transfer) {
    const staged = ['paused', 'failed'].includes(transfer.state) && knownBytes(transfer.bytes);
    return staged ? Math.max(0, entry.bytes - transfer.bytes) : entry.bytes;
  }

  function operation(transfer) {
    if (transfer.state === 'verified') return 'create';
    if (resumable(transfer)) return 'resume';
    if (['idle', 'paused', 'failed'].includes(transfer.state)) return 'download';
    if (['downloading', 'cancelling', 'verifying'].includes(transfer.state)) return 'cancel';
    return '';
  }

  async function keepFocus(view, button, work, fallback) {
    const focused = document.activeElement === button;
    try {
      await work();
    } finally {
      const active = document.activeElement;
      if (focused && isCurrent(view) && (!active || active === document.body || active === button)) {
        const control = document.getElementById(button.id);
        const target = control && !control.disabled && !control.hidden ? control : fallback?.() || view.search;
        target.focus({preventScroll:true});
      }
    }
  }

  function drawTransfer(view, id) {
    const card = view.cards.get(id);
    if (!card) return;
    const transfer = view.transfers.get(id) || {state:'idle'};
    const action = operation(transfer);
    const checkFailed = view.checkErrors.has(id);
    const waiting = view.actions.has(id) || (checkFailed && view.checking.has(id));
    const enoughSpace = knownBytes(card.entry.bytes) && knownBytes(view.freeBytes) &&
      view.freeBytes >= requiredBytes(card.entry, transfer);
    const full = knownBytes(transfer.totalBytes) && transfer.totalBytes > 0;
    const shownProgress = activeStates.has(transfer.state) && knownBytes(transfer.bytes);
    const description = view.checkErrors.get(id) || view.actionErrors.get(id) || transfer.message || '';
    const verified = transfer.state === 'verified';

    setText(card.status, stateLabels[transfer.state] || 'Status unavailable');
    setText(card.description, description);
    card.description.hidden = !description;
    card.progress.hidden = !shownProgress || !full;
    if (shownProgress && full) {
      card.progress.max = transfer.totalBytes;
      card.progress.value = Math.min(transfer.bytes, transfer.totalBytes);
    }
    setText(card.count, shownProgress || verified ? availableBytes(transfer.bytes) +
      (full ? ' of ' + bytes(transfer.totalBytes) : '') : '');
    card.count.hidden = !card.count.textContent;
    const checksum = verified && transfer.sha256 ? 'SHA-256 ' + transfer.sha256 : '';
    setText(card.checksum, checksum);
    card.checksum.hidden = !checksum;
    const signature = verified && transfer.signatureVerified === true
      ? (card.entry.versionVerified === false ? 'Publisher signature verified for installer bytes' : 'Publisher signature verified')
      : '';
    setText(card.signature, signature);
    card.signature.hidden = !signature;

    const hideAction = !checkFailed && !action;
    if (hideAction && document.activeElement === card.action) card.status.focus({preventScroll:true});
    card.action.hidden = hideAction;
    const needsSpace = ['download', 'resume'].includes(action);
    card.action.disabled = waiting || (!checkFailed && (transfer.state === 'cancelling' || (needsSpace && !enoughSpace)));
    setText(card.action, checkFailed ? 'Check status' : action === 'cancel'
      ? (transfer.state === 'cancelling' ? 'Cancelling…' : 'Cancel download')
      : action === 'create' ? 'Create VM' : action === 'resume' ? 'Resume download' : transfer.state === 'idle' ? 'Download' : 'Download again');

    const spaceHint = !waiting && !checkFailed && needsSpace && !enoughSpace
      ? (!knownBytes(view.freeBytes) ? 'Refresh the catalog to check available space.' : 'More free disk space is needed.')
      : '';
    setText(card.spaceHint, spaceHint);
    card.spaceHint.hidden = !spaceHint;
  }

  function drawPublisher(view, publisher) {
    const controls = view.publisherControls.get(publisher.id);
    if (!controls) return;
    const checking = publisher.state === 'checking' || view.latestActions.has(publisher.id);
    const message = view.latestErrors.get(publisher.id) || (checking ? 'Checking the publisher’s latest release…'
      : publisher.message || (publisher.state === 'failed' ? 'The latest release could not be checked.' : ''));
    setText(controls.status, message);
    controls.status.hidden = !message;
    controls.button.disabled = checking;
  }

  function publisherActions(view, publisher) {
    const status = h('p', {class:'new-hint', role:'status', tabindex:-1});
    const button = h('button', {type:'button', class:'btn', id:'catalog-latest-' + publisher.id,
      'aria-label':'Check latest release for ' + publisher.name,
      onclick:e => keepFocus(view, e.currentTarget, () => checkLatest(view, publisher.id),
        () => view.publisherControls.get(publisher.id)?.status)}, 'Check latest');
    view.publisherControls.set(publisher.id, {status, button});
    drawPublisher(view, publisher);
    return h('div', {class:'catalog-transfer'}, status, button);
  }

  function publisherCard(view, publisher) {
    return h('article', {class:'card catalog-installer'},
      h('h2', {}, title(publisher)),
      S.facts([['Official source', publisher.sourceHost], ['Verification', publisher.verification]], 'new-facts'),
      publisherActions(view, publisher));
  }

  function installerCard(view, entry, publisher) {
    const status = h('p', {class:'catalog-transfer-state', role:'status', tabindex:-1});
    const progress = h('progress', {'aria-label':'Download progress for ' + title(entry)});
    const count = h('p', {class:'new-hint'});
    const description = h('p', {class:'new-hint', role:'status'});
    const checksum = h('p', {class:'catalog-checksum'});
    const signature = h('p', {class:'new-hint'});
    const spaceHint = h('p', {class:'new-hint'});
    const action = h('button', {type:'button', class:'btn', id:'catalog-action-' + entry.id,
      onclick:e => keepFocus(view, e.currentTarget, () => perform(view, entry), () => view.cards.get(entry.id)?.status)});
    const card = h('article', {class:'card catalog-installer'},
      h('h2', {}, title(entry)),
      S.facts([
        ['Architecture', entry.architecture],
        ['Installer size', availableBytes(entry.bytes)],
        ['Official source', entry.sourceHost],
        ['Recommended VM', entry.engine + ' · ' + entry.vcpu + ' vCPU · ' + entry.ramGb + ' GiB RAM · ' + entry.diskGb + ' GiB disk'],
        ['Verification', entry.verification || (entry.signatureRequired ? 'Signed' : 'Checksum')]
      ], 'new-facts'),
      h('div', {class:'catalog-transfer'},
        status, progress, count, description, checksum, signature, spaceHint, action),
      publisher && publisherActions(view, publisher));
    view.cards.set(entry.id, {entry, status, description, progress, count, checksum, signature, spaceHint, action});
    drawTransfer(view, entry.id);
    return card;
  }

  function officialPage(value) {
    try {
      const page = new URL(value);
      if (page.protocol === 'https:' && !page.username && !page.password && !page.port) return page;
    } catch { /* This reference has no valid page. */ }
    return null;
  }

  function referenceCard(entry) {
    const source = entry.sourceUrl ? officialPage(entry.sourceUrl) : null;
    const hasIso = entry.localIso === true;
    return h('article', {class:'card catalog-installer'},
      h('h2', {}, title(entry)),
      S.facts([['Availability', 'Reference'], ['Architecture', entry.architecture],
        ['Installation media', hasIso ? 'Choose a local ISO' : null],
        ['Official page', source?.hostname]], 'new-facts'),
      entry.note && h('p', {class:'new-hint'}, entry.note),
      (source || hasIso) && h('div', {class:'vm-actions'},
        source && h('button', {type:'button', class:'btn', id:'catalog-copy-' + entry.id,
          'aria-label':'Copy official page link for ' + title(entry), onclick:async () => {
            await S.api.native('copyText', {text:entry.sourceUrl});
            S.toast('Official page link copied.');
          }}, 'Copy official page link'),
        hasIso && h('button', {type:'button', class:'btn', id:'catalog-iso-' + entry.id,
          'aria-label':'Use your ISO for ' + title(entry),
          onclick:() => S.go('newvm', {id:'catalog/' + entry.id})}, 'Use your ISO')));
  }

  function drawCatalog(view) {
    const focused = document.activeElement?.id;
    view.cards.clear();
    view.publisherControls.clear();
    const query = view.search.value.trim().toLowerCase();
    const collection = view.collection.value;
    const matches = entry => (!collection || (entry.collection || 'Open source') === collection) &&
      [title(entry), entry.architecture].join(' ').toLowerCase().includes(query);
    const entryIds = new Set(view.entries.map(entry => entry.id));
    const publishersByEntry = new Map(), pendingPublishers = [];
    for (const publisher of view.publishers) {
      const entryId = entryIds.has(publisher.activeEntryId) ? publisher.activeEntryId
        : view.entries.find(entry => entry.publisherId === publisher.id)?.id;
      if (entryId) publishersByEntry.set(entryId, publisher);
      else if (matches(publisher)) pendingPublishers.push(publisherCard(view, publisher));
    }
    const cards = [...view.entries.filter(entry => matches(entry) ||
      (publishersByEntry.has(entry.id) && matches(publishersByEntry.get(entry.id))))
      .map(entry => installerCard(view, entry, publishersByEntry.get(entry.id))), ...pendingPublishers,
      ...view.references.filter(matches).map(referenceCard)];
    view.list.replaceChildren(...cards);
    view.empty.hidden = cards.length > 0 || view.loading || Boolean(view.error);
    setText(view.empty, query || collection ? 'No catalog entries match these filters.' : 'No catalog entries are available.');
    if (focused && /^catalog-(action|copy|iso|latest)-/.test(focused)) document.getElementById(focused)?.focus({preventScroll:true});
  }

  function drawSpace(view) {
    setText(view.space, 'Free space in the download library: ' + availableBytes(view.freeBytes));
    for (const id of view.cards.keys()) drawTransfer(view, id);
  }

  function schedulePoll(view) {
    clearTimeout(view.timer);
    if (!isCurrent(view) || ![...view.transfers.values()].some(transfer =>
      activeStates.has(transfer.state) && !view.checkErrors.has(transfer.id) &&
      !view.actions.has(transfer.id) && !view.checking.has(transfer.id))) return;
    view.timer = setTimeout(async () => {
      await Promise.all([...view.transfers.values()]
        .filter(transfer => activeStates.has(transfer.state) && !view.checkErrors.has(transfer.id))
        .map(transfer => checkTransfer(view, transfer.id)));
      schedulePoll(view);
    }, 1500);
  }

  async function checkTransfer(view, id) {
    if (!isCurrent(view) || view.actions.has(id) || view.checking.has(id)) return;
    const before = view.transfers.get(id);
    view.checking.add(id);
    drawTransfer(view, id);
    try {
      const transfer = await S.api.catalogDownload(id);
      if (isCurrent(view) && !view.actions.has(id) && view.transfers.get(id) === before) {
        view.transfers.set(id, transfer);
        view.checkErrors.delete(id);
      }
    } catch (error) {
      if (isCurrent(view) && !view.actions.has(id) && view.transfers.get(id) === before)
        view.checkErrors.set(id, error.message);
    } finally {
      view.checking.delete(id);
      if (isCurrent(view)) drawTransfer(view, id);
      schedulePoll(view);
    }
  }

  function scheduleLatestPoll(view) {
    clearTimeout(view.latestTimer);
    if (isCurrent(view) && !view.error && view.publishers.some(publisher => publisher.state === 'checking'))
      view.latestTimer = setTimeout(() => loadCatalog(view, true), 1500);
  }

  async function checkLatest(view, id) {
    const publisher = view.publishers.find(item => item.id === id);
    if (!isCurrent(view) || !publisher || publisher.state === 'checking' || view.latestActions.has(id)) return;
    view.latestActions.add(id);
    view.latestErrors.delete(id);
    drawPublisher(view, publisher);
    try {
      const accepted = await S.api.catalogLatest(id);
      if (!isCurrent(view)) return;
      view.latestRevision++;
      const current = view.publishers.find(item => item.id === id);
      if (current) Object.assign(current, accepted, {state:'checking'});
      await loadCatalog(view, true);
    } catch (error) {
      if (isCurrent(view)) view.latestErrors.set(id, error.message);
    } finally {
      view.latestActions.delete(id);
      if (isCurrent(view)) {
        const current = view.publishers.find(item => item.id === id);
        if (current) drawPublisher(view, current);
        scheduleLatestPoll(view);
      }
    }
  }

  async function loadCatalog(view, quiet = false) {
    if (view.loading) return;
    const before = new Map(view.transfers), latestRevision = view.latestRevision;
    view.loading = true;
    if (!quiet) {
      view.refresh.disabled = true;
      view.empty.hidden = true;
      setText(view.notice, 'Loading catalog…');
    }
    try {
      const catalog = await S.api.catalog();
      if (!isCurrent(view)) return;
      view.error = '';
      view.entries = catalog.entries;
      view.references = catalog.references || [];
      if (latestRevision === view.latestRevision) {
        view.publishers = catalog.publishers || [];
        for (const publisher of view.publishers) {
          if (publisher.state !== 'idle') view.latestErrors.delete(publisher.id);
        }
      }
      view.freeBytes = catalog.freeBytes;
      for (const transfer of catalog.transfers) {
        if (!view.actions.has(transfer.id) && before.get(transfer.id) === view.transfers.get(transfer.id)) {
          view.transfers.set(transfer.id, transfer);
          view.checkErrors.delete(transfer.id);
        }
      }
    } catch (error) {
      if (isCurrent(view)) view.error = quiet ? 'Refresh the catalog to check the latest release status. ' + error.message : error.message;
    } finally {
      view.loading = false;
      if (isCurrent(view)) {
        view.refresh.disabled = false;
        setText(view.notice, view.error);
        drawSpace(view);
        drawCatalog(view);
        schedulePoll(view);
        scheduleLatestPoll(view);
      }
    }
  }

  async function confirmDownload(view, entry, transfer, action) {
    const catalog = await S.api.catalog();
    if (!isCurrent(view)) return false;
    view.freeBytes = catalog.freeBytes;
    drawSpace(view);
    const current = catalog.entries.find(item => item.id === entry.id);
    if (!current || current.bytes !== entry.bytes)
      throw new Error('The installer listing changed. Refresh the catalog before downloading.');
    const needed = requiredBytes(entry, transfer);
    if (!knownBytes(view.freeBytes)) throw new Error('Available disk space could not be checked.');
    if (!knownBytes(needed) || view.freeBytes < needed) throw new Error('More free disk space is needed.');
    const verb = action === 'resume' ? 'Resume download' : 'Download';
    return S.dialog(verb + ' for ' + title(entry) + '?', S.facts([
      ['Installer size', bytes(entry.bytes)],
      ['Remaining download', action === 'resume' ? bytes(needed) : null],
      ['Additional space needed', action === 'download' && needed < entry.bytes ? bytes(needed) : null],
      ['Free disk space', bytes(view.freeBytes)],
      ['Official source', entry.sourceHost]
    ]), verb);
  }

  async function perform(view, entry) {
    const id = entry.id;
    if (!isCurrent(view) || view.actions.has(id)) return;
    if (view.checkErrors.has(id)) {
      await checkTransfer(view, id);
      return;
    }

    const transfer = view.transfers.get(id) || {state:'idle'};
    const action = operation(transfer);
    if (!action || transfer.state === 'cancelling') return;
    if (action === 'create') {
      S.go('newvm', {id:'catalog/' + id});
      return;
    }
    view.actions.add(id);
    view.actionErrors.delete(id);
    drawTransfer(view, id);
    let attempted = false, recover = false;
    try {
      if (action !== 'cancel' && !await confirmDownload(view, entry, transfer, action)) return;
      if (!isCurrent(view)) return;
      attempted = true;
      const result = await S.api.catalogDownload(id, action === 'cancel' ? 'DELETE' : 'POST');
      if (isCurrent(view)) view.transfers.set(id, result);
    } catch (error) {
      if (isCurrent(view)) view.actionErrors.set(id, error.message);
      recover = attempted;
    } finally {
      view.actions.delete(id);
      if (isCurrent(view)) {
        drawTransfer(view, id);
        if (recover) await checkTransfer(view, id);
        schedulePoll(view);
      }
    }
  }

  function render(root) {
    if (page) {
      root.append(page.el);
      return;
    }

    const view = {
      entries:[], references:[], publishers:[], transfers:new Map(), cards:new Map(), actions:new Set(), checking:new Set(),
      actionErrors:new Map(), checkErrors:new Map(), publisherControls:new Map(), latestActions:new Set(),
      latestErrors:new Map(), latestRevision:0, error:''
    };
    view.search = h('input', {type:'search', id:'catalog-search', placeholder:'Search the catalog',
      'aria-label':'Search the catalog', oninput:() => drawCatalog(view)});
    view.collection = h('select', {id:'catalog-collection', 'aria-label':'Collection', onchange:() => drawCatalog(view)},
      h('option', {value:''}, 'All collections'), collections.map(name => h('option', {value:name}, name)));
    view.refresh = h('button', {type:'button', class:'btn', id:'catalog-refresh',
      onclick:e => keepFocus(view, e.currentTarget, () => loadCatalog(view))}, 'Refresh catalog');
    view.space = h('p', {class:'sub'}, 'Free space in the download library: Checking…');
    view.notice = h('p', {class:'new-error', role:'status'});
    view.empty = h('p', {class:'sub', hidden:true});
    view.list = h('div', {class:'catalog-grid'});
    view.el = h('section', {},
      h('h2', {}, 'OS catalog'), view.space, h('div', {class:'libbar catalog-filters'},
        view.search, h('div', {class:'new-field'}, view.collection), view.refresh),
      view.notice, view.empty, view.list);
    page = view;
    root.append(view.el);
    void loadCatalog(view);
  }

  window.addEventListener('svb-render', () => {
    if (page && !page.el.isConnected) {
      clearTimeout(page.timer);
      clearTimeout(page.latestTimer);
      page = null;
    }
    if (marketplace && !marketplace.isConnected) marketplace = null;
  });

  function renderMarketplace(root) {
    if (marketplace) { root.append(marketplace); return; }
    const body = h('div', {});
    const ready = h('button', {type:'button', class:'btn', onclick:() => show('ready')}, 'Ready to run');
    const os = h('button', {type:'button', class:'btn', onclick:() => show('os')}, 'Installers');
    const apps = h('button', {type:'button', class:'btn', onclick:() => show('apps')}, 'Apps & AI tools');
    function show(section) {
      const buttons = {ready, os, apps};
      if (buttons[section].getAttribute('aria-pressed') === 'true') return;
      for (const [key, button] of Object.entries(buttons)) button.setAttribute('aria-pressed', key === section);
      if (page && section !== 'os') {
        clearTimeout(page.timer);
        clearTimeout(page.latestTimer);
        page = null;
      }
      body.replaceChildren();
      if (section === 'apps') body.append(S.appsCatalog());
      else if (section === 'ready') body.append(S.readyImages());
      else render(body);
    }
    marketplace = h('section', {class:'new-page'}, h('h1', {}, 'Marketplace'),
      h('div', {class:'vm-actions', role:'group', 'aria-label':'Marketplace sections'}, ready, os, apps), body);
    root.append(marketplace);
    show('ready');
  }

  S.register(screen, {title:'Marketplace', render:renderMarketplace});
})();
