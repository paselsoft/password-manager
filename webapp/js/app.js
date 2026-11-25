// Cassaforte - interfaccia della web app.
// Tutti i dati vengono cifrati e decifrati nel browser: Dropbox e il sito che
// ospita l'app vedono solo il file .kdbx cifrato.

import * as V from './vault.js';
import { totp, buildOtpUri } from './totp.js';
import { generatePassword } from './generator.js';
import { Dropbox } from './dropbox.js';
import * as store from './store.js';

const APP_VERSION = '0.1.0';
const MAX_LIST = 500;
const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------ impostazioni

const LS = { appKey: 'pm.appKey', path: 'pm.path', settings: 'pm.settings' };

function lsGet(k) {
  try { return localStorage.getItem(k); } catch (e) { return null; }
}
function lsSet(k, v) {
  try {
    if (v == null) localStorage.removeItem(k);
    else localStorage.setItem(k, v);
  } catch (e) { /* archiviazione non disponibile */ }
}

const settings = { autoLockMin: 5, clipboardSec: 30, lockWhenHidden: false };
try { Object.assign(settings, JSON.parse(lsGet(LS.settings) || '{}')); } catch (e) { /* default */ }
const saveSettings = () => lsSet(LS.settings, JSON.stringify(settings));

const state = {
  dbx: null,
  path: lsGet(LS.path),
  db: null,
  rev: null,
  pending: false,
  online: true,
  pushing: false,
  pushAgain: false,
  query: '',
  groupId: null,
  recycle: false,
  selectedId: null,
  editingId: null,
  editingOtpRaw: '',
  keyFile: null, // { name, bytes, remembered }
  lastActivity: Date.now(),
  otpTimer: null,
  clipTimer: null,
};

// Agganci per i test automatici (lo stesso codice della pagina vi accede comunque)
window.__pm = { state, settings, pushPending: () => pushPending(), syncNow: (m) => syncNow(m), lock: () => lock() };

function redirectUri() {
  return location.origin + location.pathname.replace(/index\.html$/, '');
}

// ------------------------------------------------------------ utilità UI

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of [].concat(children == null ? [] : children)) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : String(c));
  }
  return e;
}

function show(id) {
  for (const s of document.querySelectorAll('.screen')) s.hidden = s.id !== id;
}

let toastTimer = null;
function toast(text, isError) {
  const t = $('toast');
  t.textContent = text;
  t.className = 'toast' + (isError ? ' err' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 6000 : 3500);
}

function busy(text) {
  $('busy').hidden = !text;
  if (text) $('busy-msg').textContent = text;
}

function setMsg(id, text, ok) {
  const m = $(id);
  m.textContent = text || '';
  m.className = 'msg' + (ok ? ' ok' : '');
}

function errorText(e) {
  return V.describeError(e);
}

const dateFmt = new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeStyle: 'short' });
const fmtDate = (ms) => (ms ? dateFmt.format(new Date(ms)) : '—');

function hashHue(s) {
  let h = 0;
  for (const c of s) h = (h * 31 + c.codePointAt(0)) % 360;
  return h;
}

function avatar(title) {
  const a = el('span', { class: 'avatar', 'aria-hidden': 'true' }, [...(title || '?').trim()][0] || '?');
  a.style.setProperty('--avatar', `hsl(${hashHue(title || '')}, 45%, 42%)`);
  return a;
}

function baseName(path) {
  return (path || '').split('/').pop().replace(/\.kdbx$/i, '');
}

function safeUrl(url) {
  const u = /^[a-z][a-z0-9+.-]*:/i.test(url) ? url : 'https://' + url;
  return /^https?:\/\//i.test(u) ? u : null;
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = el('textarea', { readonly: true, class: 'visually-hidden' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand('copy');
    ta.remove();
    if (!ok) {
      toast('Copia non consentita dal browser', true);
      return;
    }
  }
  toast(`${what} copiato` + (settings.clipboardSec ? ` (appunti svuotati tra ${settings.clipboardSec} s)` : ''));
  clearTimeout(state.clipTimer);
  if (settings.clipboardSec > 0) {
    state.clipTimer = setTimeout(() => {
      if (navigator.clipboard) navigator.clipboard.writeText('').catch(() => {});
    }, settings.clipboardSec * 1000);
  }
}

function downloadBytes(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

async function readFile(file) {
  return new Uint8Array(await file.arrayBuffer());
}

// ------------------------------------------------------------ avvio e navigazione

async function init() {
  V.initArgon2(globalThis.hashwasm);
  $('s-version').textContent = `Cassaforte ${APP_VERSION} · formato KeePass KDBX`;
  bindEvents();
  registerServiceWorker();

  const appKey = (window.PM_CONFIG && window.PM_CONFIG.dropboxAppKey) || lsGet(LS.appKey);
  if (appKey) state.dbx = new Dropbox(appKey, redirectUri());

  if (state.dbx && /[?&](code|error)=/.test(location.search)) {
    busy('Collegamento a Dropbox…');
    try {
      await state.dbx.handleRedirect(location.search);
      toast('Dropbox collegato');
    } catch (e) {
      toast(e.message, true);
    } finally {
      busy(false);
      history.replaceState(null, '', redirectUri());
    }
  }
  route();
}

function route() {
  if (!state.dbx) return showSetup('appkey');
  if (!state.dbx.connected) return showSetup('connect');
  if (!state.path) return showFiles();
  return showUnlock();
}

function showSetup(step) {
  show('screen-setup');
  $('form-appkey').hidden = step !== 'appkey';
  $('connect-box').hidden = step !== 'connect';
  if (step === 'appkey') $('appkey').value = lsGet(LS.appKey) || '';
}

async function showFiles() {
  show('screen-files');
  const ul = $('file-list');
  ul.textContent = '';
  ul.append(el('li', { class: 'muted' }, 'Caricamento…'));
  try {
    const files = await state.dbx.listKdbx();
    ul.textContent = '';
    if (!files.length) {
      ul.append(el('li', { class: 'muted' }, 'Nessun file .kdbx. Caricane uno dal dispositivo, copialo nella cartella dell\'app su Dropbox, oppure creane uno nuovo.'));
    }
    for (const f of files) {
      ul.append(el('li', {}, [el('button', {
        type: 'button',
        onclick: () => {
          state.path = f.path;
          lsSet(LS.path, f.path);
          showUnlock();
        },
      }, [el('span', {}, f.path.replace(/^\//, '')), el('span', { class: 'muted' }, fmtDate(Date.parse(f.modified)))])]));
    }
  } catch (e) {
    ul.textContent = '';
    ul.append(el('li', { class: 'msg' }, e.offline ? 'Sei offline: impossibile leggere l\'elenco dei file.' : e.message));
  }
}

async function showUnlock(message) {
  show('screen-unlock');
  $('unlock-name').textContent = baseName(state.path) || 'Database';
  $('unlock-path').textContent = 'Dropbox: ' + state.path;
  $('master').value = '';
  $('master').type = 'password';
  setMsg('unlock-msg', message || '', !!message);
  const kf = await store.get(store.keyFileKey(state.path));
  state.keyFile = kf ? { name: kf.name, bytes: kf.bytes, remembered: true } : null;
  renderKeyFile();
  if (!matchMedia('(pointer: coarse)').matches) $('master').focus();
}

function renderKeyFile() {
  const kf = state.keyFile;
  $('keyfile-name').textContent = kf ? kf.name + (kf.remembered ? ' (ricordato)' : '') : 'nessuno';
  $('btn-keyfile-clear').hidden = !kf;
}

// ------------------------------------------------------------ sblocco e sincronizzazione

async function doUnlock(ev) {
  ev.preventDefault();
  setMsg('unlock-msg', '');
  const password = $('master').value;
  if (!password && !state.keyFile) {
    setMsg('unlock-msg', 'Inserisci la password principale.');
    return;
  }
  busy('Sblocco in corso…');
  try {
    const creds = await V.makeCredentials(password, state.keyFile && state.keyFile.bytes);
    await openFromSources(creds);
    if (state.keyFile && !state.keyFile.remembered && $('keyfile-remember').checked) {
      await store.set(store.keyFileKey(state.path), { name: state.keyFile.name, bytes: state.keyFile.bytes });
      state.keyFile.remembered = true;
    }
    $('master').value = '';
    enterMain();
    if (state.pending && state.online) pushPending();
  } catch (e) {
    state.db = null;
    setMsg('unlock-msg', errorText(e));
  } finally {
    busy(false);
  }
}

async function openFromSources(creds) {
  const path = state.path;
  const pending = await store.get(store.pendingKey(path));
  const cached = await store.get(store.cacheKey(path));
  let remote = null;
  let online = true;
  try {
    remote = await state.dbx.download(path);
  } catch (e) {
    if (e.notFound && !pending && !cached) throw new Error('Il file non esiste più su Dropbox. Scegli un altro database.');
    if (!pending && !cached) throw e;
    online = !e.offline;
  }

  if (pending) {
    state.db = await V.openDatabase(pending.bytes, creds);
    state.rev = pending.baseRev || null;
    state.pending = true;
    if (remote && remote.rev !== state.rev) {
      await V.mergeRemote(state.db, remote.bytes);
      state.rev = remote.rev;
    }
  } else if (remote) {
    state.db = await V.openDatabase(remote.bytes, creds);
    state.rev = remote.rev;
    state.pending = false;
    await store.set(store.cacheKey(path), { bytes: remote.bytes, rev: remote.rev, at: Date.now() });
  } else {
    state.db = await V.openDatabase(cached.bytes, creds);
    state.rev = cached.rev;
    state.pending = false;
    online = false;
  }
  state.online = online && !!remote;
}

/** Salva il database cifrato in locale e prova a caricarlo su Dropbox. */
async function persist() {
  state.pending = true;
  updateStatus();
  const bytes = await V.saveDatabase(state.db);
  await store.set(store.pendingKey(state.path), { bytes, baseRev: state.rev, at: Date.now() });
  state.pending = true;
  updateStatus();
  return pushPending();
}

async function pushPending() {
  if (!state.pending || !state.db) return false;
  if (state.pushing) {
    state.pushAgain = true;
    return false;
  }
  state.pushing = true;
  updateStatus();
  const db = state.db;
  const path = state.path;
  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      const bytes = await V.saveDatabase(db);
      try {
        const meta = await state.dbx.upload(path, bytes, state.rev);
        if (db !== state.db) return false; // bloccato nel frattempo: resta la copia in attesa
        state.rev = meta.rev;
        state.online = true;
        await store.set(store.cacheKey(path), { bytes, rev: meta.rev, at: Date.now() });
        if (!state.pushAgain) {
          await store.del(store.pendingKey(path));
          state.pending = false;
          db.removeLocalEditState();
        }
        return true;
      } catch (e) {
        if (e.conflict) {
          // Qualcun altro (un altro dispositivo, KeePassXC...) ha modificato il file: unisco
          const remote = await state.dbx.download(path);
          if (db !== state.db) return false;
          await V.mergeRemote(db, remote.bytes);
          state.rev = remote.rev;
          refreshViews();
          continue;
        }
        if (e.notFound) {
          state.rev = null;
          continue;
        }
        if (e.offline) {
          state.online = false;
          await store.set(store.pendingKey(path), { bytes, baseRev: state.rev, at: Date.now() });
          return false;
        }
        throw e;
      }
    }
    throw new Error('troppi conflitti consecutivi, riprova.');
  } catch (e) {
    toast('Sincronizzazione non riuscita: ' + errorText(e), true);
    return false;
  } finally {
    state.pushing = false;
    if (state.pushAgain && state.db) {
      state.pushAgain = false;
      state.pending = true;
      pushPending();
    }
    updateStatus();
  }
}

/** Scarica le modifiche fatte da altri dispositivi. */
async function syncNow(manual) {
  if (!state.db) return;
  if (state.pending) {
    const ok = await pushPending();
    if (manual) toast(ok ? 'Modifiche caricate su Dropbox' : 'Modifiche ancora in attesa', !ok);
    return;
  }
  const db = state.db;
  try {
    const meta = await state.dbx.metadata(state.path);
    state.online = true;
    if (meta.rev !== state.rev) {
      const remote = await state.dbx.download(state.path);
      if (db !== state.db) return;
      if (state.pending || state.pushing) {
        await V.mergeRemote(db, remote.bytes);
        state.rev = remote.rev;
      } else {
        const fresh = await V.openDatabase(remote.bytes, db.credentials);
        if (db !== state.db || state.pending) {
          if (db === state.db) await V.mergeRemote(db, remote.bytes);
        } else {
          state.db = fresh;
        }
        state.rev = remote.rev;
        await store.set(store.cacheKey(state.path), { bytes: remote.bytes, rev: remote.rev, at: Date.now() });
      }
      refreshViews();
      if (manual) toast('Aggiornato con le modifiche da Dropbox');
    } else if (manual) {
      toast('Già aggiornato');
    }
  } catch (e) {
    if (e.offline) {
      state.online = false;
      if (manual) toast('Sei offline: uso la copia salvata sul dispositivo', true);
    } else if (manual) {
      toast(errorText(e), true);
    }
  }
  updateStatus();
}

function updateStatus() {
  const s = $('sync-status');
  let text = 'Sincronizzato';
  let cls = 'ok';
  if (state.pushing) { text = 'Salvataggio…'; cls = ''; }
  else if (state.pending) { text = state.online ? 'Da sincronizzare' : 'Offline · modifiche in attesa'; cls = 'warn'; }
  else if (!state.online) { text = 'Offline · copia locale'; cls = 'warn'; }
  s.textContent = text;
  s.className = 'pill ' + cls;
}

/** Esegue una modifica, salva e aggiorna l'interfaccia. */
async function mutate(fn, okText) {
  if (!state.db) return;
  try {
    await fn();
    refreshViews();
    const pushed = persist();
    if (okText) toast(okText);
    await pushed;
  } catch (e) {
    toast(errorText(e), true);
  }
}

// ------------------------------------------------------------ blocco

function touch() {
  state.lastActivity = Date.now();
}

function checkAutoLock() {
  if (state.db && Date.now() - state.lastActivity > settings.autoLockMin * 60000) {
    lock('Bloccato per inattività.');
  }
}

function lock(message) {
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  stopOtp();
  state.db = null;
  state.selectedId = null;
  state.editingId = null;
  $('entry-list').textContent = '';
  $('detail').textContent = '';
  $('search').value = '';
  state.query = '';
  document.body.classList.remove('show-detail');
  if (state.path && state.dbx) showUnlock(message);
  else route();
}

// ------------------------------------------------------------ schermata principale

function enterMain() {
  show('screen-main');
  touch();
  $('db-name').textContent = state.db.meta.name || baseName(state.path);
  state.groupId = null;
  state.recycle = false;
  state.selectedId = null;
  refreshViews();
  updateStatus();
  const info = V.securityInfo(state.db);
  const banner = $('banner');
  banner.textContent = '';
  banner.hidden = !info.outdated;
  if (info.outdated) {
    banner.append(
      el('span', {}, `Il file usa una protezione datata (KDBX ${info.version}, ${info.kdf}). Aggiornarla rende l'apertura più veloce sul telefono e più robusta contro gli attacchi.`),
      el('button', { type: 'button', class: 'small', onclick: upgradeSecurity }, 'Aggiorna ora'),
    );
  }
}

async function upgradeSecurity() {
  if (!confirm('Aggiornare il file a KDBX 4 con Argon2id?\n\nKeePassXC 2.7+, KeePassium e Strongbox lo aprono senza problemi. Le versioni molto vecchie di KeePass (1.x) no.')) return;
  busy('Aggiornamento della protezione…');
  try {
    await mutate(() => V.upgradeSecurity(state.db), 'Protezione aggiornata');
    $('banner').hidden = true;
    fillSettings();
  } finally {
    busy(false);
  }
}

function refreshViews() {
  if (!state.db) return;
  renderGroups();
  renderList();
  if (state.selectedId && !V.findEntry(state.db, state.selectedId)) state.selectedId = null;
  renderDetail();
}

function renderGroups() {
  const sel = $('group-filter');
  sel.textContent = '';
  sel.append(new Option('Tutte le voci', ''));
  for (const g of V.listGroups(state.db).slice(1)) {
    sel.append(new Option('  '.repeat(g.depth - 1) + g.name, g.id));
  }
  if (V.hasRecycleBin(state.db)) sel.append(new Option('🗑 Cestino', '__bin__'));
  const want = state.recycle ? '__bin__' : state.groupId || '';
  sel.value = want;
  if (sel.value !== want) {
    state.groupId = null;
    state.recycle = false;
    sel.value = '';
  }
}

function renderList() {
  const items = V.listEntries(state.db, { query: state.query, groupId: state.groupId, recycleBin: state.recycle });
  const ul = $('entry-list');
  ul.textContent = '';
  const frag = document.createDocumentFragment();
  for (const it of items.slice(0, MAX_LIST)) {
    frag.append(el('li', {}, [el('button', { type: 'button', 'data-id': it.id, 'aria-current': String(it.id === state.selectedId) }, [
      avatar(it.title),
      el('span', { class: 'entry-text' }, [el('strong', {}, it.title), el('span', {}, it.username || it.host || it.group || ' ')]),
      it.hasOtp ? el('span', { class: 'badge' }, '2FA') : null,
    ])]));
  }
  ul.append(frag);
  let text = items.length === 1 ? '1 voce' : `${items.length} voci`;
  if (items.length > MAX_LIST) text += ` (mostrate le prime ${MAX_LIST}: affina la ricerca)`;
  $('list-count').textContent = text;
}

function markSelected() {
  for (const b of $('entry-list').querySelectorAll('button[data-id]')) {
    b.setAttribute('aria-current', String(b.dataset.id === state.selectedId));
  }
}

const isNarrow = () => matchMedia('(max-width: 859px)').matches;

function select(id) {
  state.selectedId = id;
  markSelected();
  renderDetail();
  if (isNarrow()) {
    history.pushState({ detail: true }, '');
    $('detail').scrollTop = 0;
  }
}

function closeDetail() {
  if (history.state && history.state.detail) {
    history.back();
    return;
  }
  state.selectedId = null;
  markSelected();
  renderDetail();
}

function stopOtp() {
  clearInterval(state.otpTimer);
  state.otpTimer = null;
}

function fieldBox(label, valueNode, buttons) {
  return el('div', { class: 'field' }, [
    el('div', { class: 'k' }, label),
    el('div', { class: 'v-row' }, [valueNode, ...buttons]),
  ]);
}

function plainRow(label, value) {
  return fieldBox(label, el('span', { class: 'v plain' }, value), [
    el('button', { type: 'button', onclick: () => copy(value, label) }, 'Copia'),
  ]);
}

function secretRow(label, getter) {
  const v = el('span', { class: 'v' }, '••••••••••');
  let shown = false;
  const toggle = el('button', { type: 'button' }, 'Mostra');
  toggle.addEventListener('click', () => {
    shown = !shown;
    v.textContent = shown ? getter() : '••••••••••';
    toggle.textContent = shown ? 'Nascondi' : 'Mostra';
  });
  return fieldBox(label, v, [toggle, el('button', { type: 'button', onclick: () => copy(getter(), label) }, 'Copia')]);
}

function urlRow(label, url) {
  const href = safeUrl(url);
  const link = href
    ? el('a', { class: 'v plain', href, target: '_blank', rel: 'noopener noreferrer' }, url)
    : el('span', { class: 'v plain' }, url);
  return fieldBox(label, link, [el('button', { type: 'button', onclick: () => copy(url, label) }, 'Copia')]);
}

function otpRow(cfg) {
  if (cfg.error) return fieldBox('Codice 2FA', el('span', { class: 'v plain msg' }, cfg.error), []);
  const code = el('span', { class: 'v otp-code' }, '··· ···');
  const inner = el('div');
  const bar = el('div', { class: 'otp-bar' }, inner);
  let current = '';
  const tick = async () => {
    try {
      const r = await totp(cfg);
      current = r.code;
      code.textContent = r.code.length === 6 ? r.code.slice(0, 3) + ' ' + r.code.slice(3) : r.code;
      inner.style.setProperty('--w', `${(r.remaining / r.period) * 100}%`);
      bar.classList.toggle('low', r.remaining <= 5);
    } catch (e) {
      code.textContent = 'errore';
    }
  };
  tick();
  state.otpTimer = setInterval(tick, 1000);
  const box = fieldBox('Codice 2FA', code, [el('button', { type: 'button', onclick: () => current && copy(current, 'Codice') }, 'Copia')]);
  box.append(bar);
  return box;
}

function attachmentsBlock(entry, d) {
  const input = el('input', { type: 'file', class: 'visually-hidden', id: 'attach-input' });
  input.addEventListener('change', async () => {
    const file = input.files[0];
    input.value = '';
    if (!file) return;
    if (file.size > 10 * 1024 * 1024 && !confirm('Il file supera 10 MB e rallenterà la sincronizzazione. Continuare?')) return;
    const bytes = await readFile(file);
    await mutate(() => V.addAttachment(state.db, entry, file.name, bytes), 'Allegato aggiunto');
  });
  const list = el('ul', { class: 'attach-list' }, d.attachments.map((a) => el('li', {}, [
    el('span', {}, `${a.name} (${Math.max(1, Math.round(a.size / 1024))} KB)`),
    el('button', { type: 'button', class: 'small', onclick: () => downloadBytes(V.attachmentBytes(entry, a.name), a.name) }, 'Scarica'),
    el('button', {
      type: 'button',
      class: 'small danger',
      onclick: () => confirm(`Eliminare l'allegato "${a.name}"?`) && mutate(() => V.removeAttachment(entry, a.name), 'Allegato eliminato'),
    }, 'Elimina'),
  ])));
  const box = el('div', { class: 'field' }, [
    el('div', { class: 'k' }, `Allegati (${d.attachments.length})`),
    list,
    input,
    el('label', { class: 'button small mt', for: 'attach-input' }, '+ Aggiungi allegato'),
  ]);
  return box;
}

function renderDetail() {
  stopOtp();
  const pane = $('detail');
  pane.textContent = '';
  const entry = state.selectedId && state.db ? V.findEntry(state.db, state.selectedId) : null;
  if (!entry) {
    document.body.classList.remove('show-detail');
    pane.append(el('p', { class: 'muted empty' }, 'Seleziona una voce.'));
    return;
  }
  const d = V.entryDetail(state.db, entry);
  document.body.classList.add('show-detail');
  pane.append(el('button', { type: 'button', class: 'back small', onclick: closeDetail }, '‹ Elenco'));
  pane.append(el('div', { class: 'detail-head' }, [
    avatar(d.title),
    el('div', {}, [el('h2', {}, d.title), el('div', { class: 'hint' }, d.inRecycleBin ? 'Nel cestino' : d.group || 'Gruppo principale')]),
  ]));
  if (d.tags.length) pane.append(el('div', { class: 'tags' }, d.tags.map((t) => el('span', { class: 'tag' }, t))));
  if (d.username) pane.append(plainRow('Utente', d.username));
  if (d.hasPassword) pane.append(secretRow('Password', () => V.fieldText(entry, 'Password')));
  if (d.otp) pane.append(otpRow(d.otp));
  if (d.url) pane.append(urlRow('Sito', d.url));
  for (const f of d.fields) {
    if (/^KP2A_URL/i.test(f.key) && !f.protected) pane.append(urlRow('Altro sito', f.value));
    else if (f.protected) pane.append(secretRow(f.key, () => V.fieldText(entry, f.key)));
    else pane.append(plainRow(f.key, f.value));
  }
  if (d.notes) {
    pane.append(fieldBox('Note', el('span', { class: 'v notes' }, d.notes), [
      el('button', { type: 'button', onclick: () => copy(d.notes, 'Note') }, 'Copia'),
    ]));
  }
  pane.append(attachmentsBlock(entry, d));
  pane.append(el('p', { class: 'meta' }, `Creata ${fmtDate(d.created)} · Modificata ${fmtDate(d.modified)}` +
    (d.historyCount ? ` · ${d.historyCount} versioni precedenti` : '')));

  const actions = el('div', { class: 'actions' });
  if (d.inRecycleBin) {
    actions.append(
      el('button', { type: 'button', onclick: () => mutate(() => V.restoreEntry(state.db, entry, null), 'Voce ripristinata nel gruppo principale') }, 'Ripristina'),
      el('button', {
        type: 'button',
        class: 'danger',
        onclick: () => confirm(`Eliminare definitivamente "${d.title}"? L'operazione non si può annullare.`) &&
          mutate(() => { V.deleteEntry(state.db, entry); state.selectedId = null; }, 'Voce eliminata'),
      }, 'Elimina definitivamente'),
    );
  } else {
    actions.append(
      el('button', { type: 'button', class: 'primary', onclick: () => openEditor(entry) }, 'Modifica'),
      el('button', {
        type: 'button',
        class: 'danger',
        onclick: () => confirm(`Spostare "${d.title}" nel cestino?`) &&
          mutate(() => { V.deleteEntry(state.db, entry); state.selectedId = null; }, 'Spostata nel cestino'),
      }, 'Elimina'),
    );
  }
  pane.append(actions);
}

// ------------------------------------------------------------ editor voce

function fillGroupSelect(sel, selectedId) {
  sel.textContent = '';
  for (const g of V.listGroups(state.db)) {
    sel.append(new Option(g.depth ? '  '.repeat(g.depth - 1) + g.name : `${g.name} (principale)`, g.id));
  }
  sel.append(new Option('+ Nuovo gruppo…', '__new__'));
  sel.value = selectedId || V.listGroups(state.db)[0].id;
}

function customFieldRow(f) {
  const key = el('input', { class: 'cf-key', placeholder: 'Nome', 'aria-label': 'Nome del campo' });
  key.value = f ? f.key : '';
  const val = el('input', { class: 'cf-value', placeholder: 'Valore', 'aria-label': 'Valore del campo', autocapitalize: 'off', spellcheck: 'false' });
  val.value = f ? f.value : '';
  const prot = el('input', { type: 'checkbox', class: 'cf-protected' });
  prot.checked = !!(f && f.protected);
  if (prot.checked) val.type = 'password';
  prot.addEventListener('change', () => { val.type = prot.checked ? 'password' : 'text'; });
  const row = el('div', { class: 'cf-row' }, [
    key, val,
    el('label', { class: 'check', title: 'Valore protetto (nascosto)' }, [prot, 'protetto']),
    el('button', { type: 'button', class: 'small', 'aria-label': 'Rimuovi campo', onclick: () => row.remove() }, '✕'),
  ]);
  return row;
}

function openEditor(entry) {
  const db = state.db;
  state.editingId = entry ? entry.uuid.id : null;
  const d = entry ? V.entryDetail(db, entry) : null;
  const f = (k) => (entry ? V.fieldText(entry, k) : '');
  $('entry-dlg-title').textContent = entry ? 'Modifica voce' : 'Nuova voce';
  $('f-title').value = f('Title');
  $('f-username').value = f('UserName');
  $('f-password').value = f('Password');
  $('f-password').type = 'password';
  $('f-url').value = f('URL');
  state.editingOtpRaw = d ? d.otpRaw : '';
  $('f-otp').value = state.editingOtpRaw;
  fillGroupSelect($('f-group'), d ? d.groupId : (!state.recycle && state.groupId) || null);
  $('f-tags').value = d ? d.tags.join(', ') : '';
  $('f-notes').value = f('Notes');
  const box = $('f-fields');
  box.textContent = '';
  if (d) {
    for (const cf of d.fields) {
      box.append(customFieldRow({ key: cf.key, value: cf.protected ? V.fieldText(entry, cf.key) : cf.value, protected: cf.protected }));
    }
  }
  $('gen-box').hidden = true;
  setMsg('entry-msg', '');
  $('dlg-entry').showModal();
  if (!entry && !matchMedia('(pointer: coarse)').matches) $('f-title').focus();
}

function regenerate() {
  $('f-password').value = generatePassword({
    length: +$('gen-len').value,
    upper: $('gen-upper').checked,
    lower: $('gen-lower').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
  });
  $('f-password').type = 'text';
}

async function saveEditor(ev) {
  ev.preventDefault();
  if (!state.db) return;
  setMsg('entry-msg', '');
  const title = $('f-title').value.trim();
  const username = $('f-username').value.trim();
  const otpIn = $('f-otp').value.trim();
  let otp = '';
  try {
    otp = otpIn === state.editingOtpRaw ? otpIn : buildOtpUri(otpIn, title, username);
  } catch (e) {
    setMsg('entry-msg', 'Codice 2FA non valido: ' + e.message);
    return;
  }
  const fields = [];
  const seen = new Set();
  for (const row of $('f-fields').querySelectorAll('.cf-row')) {
    const key = row.querySelector('.cf-key').value.trim();
    const value = row.querySelector('.cf-value').value;
    if (!key && !value) continue;
    if (!key) { setMsg('entry-msg', 'Ogni campo personalizzato deve avere un nome.'); return; }
    const low = key.toLowerCase();
    if (seen.has(low) || ['title', 'username', 'password', 'url', 'notes', 'otp'].includes(low)) {
      setMsg('entry-msg', `Nome di campo non valido o ripetuto: "${key}".`);
      return;
    }
    seen.add(low);
    fields.push({ key, value, protected: row.querySelector('.cf-protected').checked });
  }
  let groupId = $('f-group').value;
  if (groupId === '__new__') groupId = null;
  const data = {
    title,
    username,
    password: $('f-password').value,
    url: $('f-url').value.trim(),
    notes: $('f-notes').value,
    otp,
    tags: $('f-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
    groupId,
    fields,
  };
  const editingId = state.editingId;
  $('dlg-entry').close();
  await mutate(() => {
    const entry = editingId ? V.findEntry(state.db, editingId) : null;
    if (editingId && !entry) throw new Error('La voce non esiste più (eliminata su un altro dispositivo?).');
    const saved = V.saveEntry(state.db, entry, data);
    state.selectedId = saved.uuid.id;
  }, editingId ? 'Voce salvata' : 'Voce creata');
}

// ------------------------------------------------------------ database: creazione e caricamento

async function createDatabase(ev) {
  ev.preventDefault();
  const name = $('n-name').value.trim().replace(/\.kdbx$/i, '');
  const p1 = $('n-pass').value;
  if (!name || /[\\/:*?"<>|]/.test(name)) return setMsg('newdb-msg', 'Nome file non valido.');
  if (p1.length < 12) return setMsg('newdb-msg', 'La password deve avere almeno 12 caratteri.');
  if (p1 !== $('n-pass2').value) return setMsg('newdb-msg', 'Le due password non coincidono.');
  busy('Creazione del database…');
  try {
    const creds = await V.makeCredentials(p1, null);
    const db = V.createDatabase(creds, name);
    const bytes = await V.saveDatabase(db);
    const path = `/${name}.kdbx`;
    const meta = await state.dbx.upload(path, bytes, null);
    state.path = path;
    lsSet(LS.path, path);
    state.db = db;
    state.rev = meta.rev;
    state.pending = false;
    state.online = true;
    await store.set(store.cacheKey(path), { bytes, rev: meta.rev, at: Date.now() });
    $('n-pass').value = '';
    $('n-pass2').value = '';
    $('dlg-newdb').close();
    enterMain();
    toast('Database creato');
  } catch (e) {
    setMsg('newdb-msg', e.conflict ? 'Esiste già un file con questo nome.' : errorText(e));
  } finally {
    busy(false);
  }
}

async function uploadKdbx() {
  const input = $('upload-kdbx');
  const file = input.files[0];
  input.value = '';
  if (!file) return;
  busy('Caricamento su Dropbox…');
  try {
    const bytes = await readFile(file);
    if (bytes.length < 12 || bytes[0] !== 0x03 || bytes[1] !== 0xd9 || bytes[2] !== 0xa2 || bytes[3] !== 0x9a) {
      throw new Error('Il file scelto non è un database KeePass (.kdbx).');
    }
    await state.dbx.upload('/' + file.name, bytes, null);
    toast('File caricato');
    await showFiles();
  } catch (e) {
    toast(e.conflict ? 'Esiste già un file con questo nome su Dropbox.' : errorText(e), true);
  } finally {
    busy(false);
  }
}

// ------------------------------------------------------------ impostazioni

function fillSettings() {
  $('s-autolock').value = String(settings.autoLockMin);
  $('s-clip').value = String(settings.clipboardSec);
  $('s-lockhidden').checked = !!settings.lockWhenHidden;
  if (state.db) {
    const info = V.securityInfo(state.db);
    $('s-fileinfo').textContent = `${state.path} · KDBX ${info.version} · ${info.kdf}${info.detail ? ' (' + info.detail + ')' : ''}`;
    $('btn-upgrade').hidden = !info.outdated;
  } else {
    $('s-fileinfo').textContent = state.path || '';
    $('btn-upgrade').hidden = true;
  }
}

async function forgetLocal() {
  const warn = state.pending ? '\n\nATTENZIONE: ci sono modifiche non ancora caricate su Dropbox, andrebbero perse.' : '';
  if (!confirm('Cancellare da questo dispositivo la copia offline, le modifiche in attesa e i key file ricordati?' + warn)) return;
  await store.clear();
  state.pending = false;
  toast('Dati locali cancellati');
  lock();
}

async function disconnect() {
  const warn = state.pending ? '\n\nATTENZIONE: ci sono modifiche non ancora caricate su Dropbox, andrebbero perse.' : '';
  if (!confirm('Scollegare Dropbox e cancellare i dati locali da questo dispositivo?' + warn)) return;
  $('dlg-settings').close();
  await state.dbx.disconnect();
  await store.clear();
  state.pending = false;
  state.path = null;
  lsSet(LS.path, null);
  lock();
  route();
}

// ------------------------------------------------------------ eventi

function bindEvents() {
  $('form-appkey').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const key = $('appkey').value.trim();
    if (!key) return;
    lsSet(LS.appKey, key);
    state.dbx = new Dropbox(key, redirectUri());
    route();
  });
  $('link-change-appkey').addEventListener('click', (ev) => {
    ev.preventDefault();
    showSetup('appkey');
  });
  $('btn-connect').addEventListener('click', async () => {
    location.href = await state.dbx.authorizeUrl(true);
  });
  $('btn-connect-code').addEventListener('click', async () => {
    const url = await state.dbx.authorizeUrl(false);
    window.open(url, '_blank', 'noopener');
    $('form-code').hidden = false;
  });
  $('form-code').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    busy('Collegamento a Dropbox…');
    try {
      await state.dbx.exchangeManualCode($('auth-code').value);
      $('auth-code').value = '';
      toast('Dropbox collegato');
      route();
    } catch (e) {
      toast(e.message, true);
    } finally {
      busy(false);
    }
  });

  $('btn-refresh-files').addEventListener('click', showFiles);
  $('upload-kdbx').addEventListener('change', uploadKdbx);
  $('btn-new-db').addEventListener('click', () => {
    setMsg('newdb-msg', '');
    $('dlg-newdb').showModal();
  });
  $('form-newdb').addEventListener('submit', createDatabase);
  $('btn-newdb-cancel').addEventListener('click', () => $('dlg-newdb').close());
  $('link-disconnect-files').addEventListener('click', (ev) => {
    ev.preventDefault();
    disconnect();
  });

  $('form-unlock').addEventListener('submit', doUnlock);
  $('keyfile-input').addEventListener('change', async () => {
    const file = $('keyfile-input').files[0];
    $('keyfile-input').value = '';
    if (!file) return;
    state.keyFile = { name: file.name, bytes: await readFile(file), remembered: false };
    renderKeyFile();
  });
  $('btn-keyfile-clear').addEventListener('click', async () => {
    if (state.keyFile && state.keyFile.remembered) await store.del(store.keyFileKey(state.path));
    state.keyFile = null;
    renderKeyFile();
  });
  $('link-change-db').addEventListener('click', (ev) => {
    ev.preventDefault();
    state.path = null;
    lsSet(LS.path, null);
    showFiles();
  });

  for (const b of document.querySelectorAll('[data-toggle-visibility]')) {
    b.addEventListener('click', () => {
      const input = $(b.dataset.toggleVisibility);
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

  $('btn-lock').addEventListener('click', () => lock());
  $('btn-sync').addEventListener('click', () => syncNow(true));
  $('btn-settings').addEventListener('click', () => {
    fillSettings();
    $('dlg-settings').showModal();
  });
  let searchTimer = null;
  $('search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = $('search').value;
      renderList();
    }, 120);
  });
  $('search').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      const first = $('entry-list').querySelector('button[data-id]');
      if (first) select(first.dataset.id);
    }
  });
  $('group-filter').addEventListener('change', () => {
    const v = $('group-filter').value;
    state.recycle = v === '__bin__';
    state.groupId = state.recycle || !v ? null : v;
    renderList();
  });
  $('entry-list').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-id]');
    if (b) select(b.dataset.id);
  });
  $('btn-new-entry').addEventListener('click', () => openEditor(null));

  $('form-entry').addEventListener('submit', saveEditor);
  $('btn-entry-cancel').addEventListener('click', () => $('dlg-entry').close());
  $('btn-add-field').addEventListener('click', () => $('f-fields').append(customFieldRow(null)));
  $('f-group').addEventListener('change', () => {
    if ($('f-group').value !== '__new__') return;
    const name = (prompt('Nome del nuovo gruppo:') || '').trim();
    if (!name) {
      fillGroupSelect($('f-group'), null);
      return;
    }
    const g = V.createGroup(state.db, null, name);
    fillGroupSelect($('f-group'), g.uuid.id);
  });
  $('btn-gen').addEventListener('click', () => {
    $('gen-box').hidden = false;
    regenerate();
  });
  $('btn-gen-again').addEventListener('click', regenerate);
  $('gen-len').addEventListener('input', () => {
    $('gen-len-out').textContent = $('gen-len').value;
    regenerate();
  });
  for (const id of ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols']) {
    $(id).addEventListener('change', () => {
      try { regenerate(); } catch (e) { setMsg('entry-msg', e.message); }
    });
  }

  $('s-autolock').addEventListener('change', () => { settings.autoLockMin = +$('s-autolock').value; saveSettings(); });
  $('s-clip').addEventListener('change', () => { settings.clipboardSec = +$('s-clip').value; saveSettings(); });
  $('s-lockhidden').addEventListener('change', () => { settings.lockWhenHidden = $('s-lockhidden').checked; saveSettings(); });
  $('btn-upgrade').addEventListener('click', () => {
    $('dlg-settings').close();
    upgradeSecurity();
  });
  $('btn-change-db').addEventListener('click', () => {
    if (state.pending && !confirm('Ci sono modifiche in attesa di sincronizzazione: verranno caricate alla prossima apertura di questo database. Continuare?')) return;
    $('dlg-settings').close();
    lock();
    state.path = null;
    lsSet(LS.path, null);
    showFiles();
  });
  $('btn-forget-local').addEventListener('click', forgetLocal);
  $('btn-disconnect').addEventListener('click', disconnect);

  for (const evName of ['pointerdown', 'keydown', 'touchstart', 'wheel']) {
    document.addEventListener(evName, touch, { passive: true });
  }
  setInterval(checkAutoLock, 10000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (state.db && settings.lockWhenHidden) lock();
    } else {
      checkAutoLock();
      if (state.db) syncNow(false);
    }
  });
  window.addEventListener('online', () => {
    state.online = true;
    if (state.db) syncNow(false);
  });
  window.addEventListener('offline', () => {
    state.online = false;
    if (state.db) updateStatus();
  });
  window.addEventListener('popstate', () => {
    if (state.selectedId && isNarrow()) {
      state.selectedId = null;
      markSelected();
      renderDetail();
    }
  });
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') return;
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

init().catch((e) => {
  document.body.prepend(el('p', { class: 'msg pad' }, 'Errore di avvio: ' + e.message));
});
