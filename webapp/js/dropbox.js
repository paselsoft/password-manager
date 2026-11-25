// Client Dropbox minimale per app pubbliche (OAuth 2 + PKCE, nessun segreto).
// L'app Dropbox va creata con accesso "App folder": il token può leggere e
// scrivere solo nella cartella Dropbox/App/<nome app>/.

const AUTH_URL = 'https://www.dropbox.com/oauth2/authorize';
const TOKEN_URL = 'https://api.dropboxapi.com/oauth2/token';
const API = 'https://api.dropboxapi.com/2';
const CONTENT = 'https://content.dropboxapi.com/2';

const LS_REFRESH = 'pm.dropbox.refresh';
const LS_PKCE = 'pm.dropbox.pkce';

export class DropboxError extends Error {
  constructor(message, { status = 0, summary = '', offline = false } = {}) {
    super(message);
    this.status = status;
    this.summary = summary;
    this.offline = offline;
  }
  get conflict() { return this.status === 409 && /conflict/.test(this.summary); }
  get notFound() { return this.status === 409 && /not_found/.test(this.summary); }
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(n = 48) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a);
}

// Dropbox richiede che i caratteri non ASCII nell'header siano in forma \uXXXX
function apiArg(obj) {
  return JSON.stringify(obj).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safeStorage(kind) {
  try {
    return kind === 'session' ? window.sessionStorage : window.localStorage;
  } catch (e) {
    return null;
  }
}

export class Dropbox {
  constructor(appKey, redirectUri) {
    this.appKey = appKey;
    this.redirectUri = redirectUri;
    this.access = null;
    this.accessExpires = 0;
  }

  get connected() {
    const ls = safeStorage('local');
    return !!(ls && ls.getItem(LS_REFRESH));
  }

  /**
   * URL della pagina di consenso Dropbox.
   * withRedirect = true: Dropbox torna all'app con ?code=...
   * withRedirect = false: Dropbox mostra un codice da copiare e incollare nell'app
   * (utile nella web app aggiunta alla schermata Home di iPhone/iPad).
   */
  async authorizeUrl(withRedirect = true) {
    const verifier = randomString(64);
    const state = randomString(16);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    // localStorage e non sessionStorage: su iOS il ritorno può avvenire in un'altra finestra
    const ls = safeStorage('local');
    ls.setItem(LS_PKCE, JSON.stringify({ verifier, state, withRedirect, at: Date.now() }));
    const p = new URLSearchParams({
      client_id: this.appKey,
      response_type: 'code',
      code_challenge: b64url(digest),
      code_challenge_method: 'S256',
      token_access_type: 'offline',
    });
    if (withRedirect) {
      p.set('redirect_uri', this.redirectUri);
      p.set('state', state);
    }
    return `${AUTH_URL}?${p}`;
  }

  _takePkce() {
    const ls = safeStorage('local');
    let pkce = null;
    try {
      pkce = JSON.parse(ls.getItem(LS_PKCE) || 'null');
    } catch (e) { /* ignorato */ }
    ls.removeItem(LS_PKCE);
    if (!pkce || Date.now() - pkce.at > 30 * 60 * 1000) {
      throw new DropboxError('Richiesta di collegamento scaduta o non trovata. Riprova il collegamento.');
    }
    return pkce;
  }

  /** Completa l'accesso se l'URL contiene ?code=. Restituisce true se ha gestito il ritorno. */
  async handleRedirect(search) {
    const p = new URLSearchParams(search);
    if (p.get('error')) throw new DropboxError('Accesso a Dropbox annullato: ' + (p.get('error_description') || p.get('error')));
    const code = p.get('code');
    if (!code) return false;
    const pkce = this._takePkce();
    if (p.get('state') !== pkce.state) {
      throw new DropboxError('Risposta di Dropbox non valida (stato non corrispondente). Riprova il collegamento.');
    }
    await this._exchange(code, pkce.verifier, this.redirectUri);
    return true;
  }

  /** Completa l'accesso con il codice copiato dalla pagina di Dropbox. */
  async exchangeManualCode(code) {
    const pkce = this._takePkce();
    await this._exchange(String(code).trim(), pkce.verifier, null);
  }

  async _exchange(code, verifier, redirectUri) {
    const params = { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: this.appKey };
    if (redirectUri) params.redirect_uri = redirectUri;
    const data = await this._token(params);
    if (!data.refresh_token) throw new DropboxError('Dropbox non ha restituito un refresh token.');
    safeStorage('local').setItem(LS_REFRESH, data.refresh_token);
  }

  async _token(params) {
    let res;
    try {
      res = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(params),
      });
    } catch (e) {
      throw new DropboxError('Dropbox non raggiungibile (sei offline?)', { offline: true });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (data.error === 'invalid_grant') safeStorage('local').removeItem(LS_REFRESH);
      throw new DropboxError('Autorizzazione Dropbox non valida: ' + (data.error_description || data.error || res.status), { status: res.status });
    }
    this.access = data.access_token;
    this.accessExpires = Date.now() + ((data.expires_in || 14400) - 60) * 1000;
    return data;
  }

  async _accessToken() {
    if (this.access && Date.now() < this.accessExpires) return this.access;
    const refresh = safeStorage('local').getItem(LS_REFRESH);
    if (!refresh) throw new DropboxError('Dropbox non collegato.', { status: 401 });
    await this._token({ grant_type: 'refresh_token', refresh_token: refresh, client_id: this.appKey });
    return this.access;
  }

  async _fetch(url, init, retry = true) {
    const token = await this._accessToken();
    init.headers = Object.assign({ Authorization: 'Bearer ' + token }, init.headers || {});
    let res;
    try {
      res = await fetch(url, init);
    } catch (e) {
      throw new DropboxError('Dropbox non raggiungibile (sei offline?)', { offline: true });
    }
    if (res.status === 401 && retry) {
      this.access = null;
      return this._fetch(url, init, false);
    }
    if (!res.ok) {
      let summary = '';
      try {
        const body = await res.json();
        summary = body.error_summary || '';
      } catch (e) { /* risposta non JSON */ }
      throw new DropboxError(`Errore Dropbox ${res.status}${summary ? ': ' + summary : ''}`, { status: res.status, summary });
    }
    return res;
  }

  async _rpc(endpoint, body) {
    const res = await this._fetch(API + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  }

  /** Elenca i file .kdbx nella cartella dell'app (ricorsivo). */
  async listKdbx() {
    let page = await this._rpc('/files/list_folder', { path: '', recursive: true, limit: 2000 });
    const files = [];
    for (;;) {
      for (const e of page.entries) {
        if (e['.tag'] === 'file' && /\.kdbx$/i.test(e.name)) {
          files.push({ path: e.path_display, name: e.name, rev: e.rev, size: e.size, modified: e.server_modified });
        }
      }
      if (!page.has_more) break;
      page = await this._rpc('/files/list_folder/continue', { cursor: page.cursor });
    }
    return files.sort((a, b) => a.path.localeCompare(b.path));
  }

  async metadata(path) {
    return this._rpc('/files/get_metadata', { path });
  }

  async download(path) {
    const res = await this._fetch(CONTENT + '/files/download', {
      method: 'POST',
      headers: { 'Dropbox-API-Arg': apiArg({ path }) },
    });
    let meta = JSON.parse(res.headers.get('Dropbox-API-Result') || '{}');
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (!meta.rev) meta = await this.metadata(path); // header non esposto dal browser
    return { bytes, rev: meta.rev, meta };
  }

  /**
   * Carica il file. Con rev: sovrascrive solo se su Dropbox c'è ancora quella
   * revisione (altrimenti DropboxError con .conflict). Senza rev: crea un file
   * nuovo e fallisce se esiste già.
   */
  async upload(path, bytes, rev) {
    const mode = rev ? { '.tag': 'update', update: rev } : { '.tag': 'add' };
    const res = await this._fetch(CONTENT + '/files/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Dropbox-API-Arg': apiArg({ path, mode, autorename: false, mute: true, strict_conflict: true }),
      },
      body: bytes,
    });
    return res.json();
  }

  async disconnect() {
    try {
      if (this.connected) await this._fetch(API + '/auth/token/revoke', { method: 'POST' });
    } catch (e) { /* si scollega comunque in locale */ }
    const ls = safeStorage('local');
    if (ls) ls.removeItem(LS_REFRESH);
    this.access = null;
  }
}
