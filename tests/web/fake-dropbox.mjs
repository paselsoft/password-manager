// Dropbox simulato per i test nel browser (intercetta le chiamate con Playwright).

/** Dropbox finto: file in memoria con revisioni. */
export class FakeDropbox {
  constructor() {
    this.files = new Map();
    this.n = 0;
    this.offline = false;
    this.uploads = 0;
  }
  put(path, bytes) {
    const rev = 'rev' + (++this.n).toString(16).padStart(9, '0');
    this.files.set(path.toLowerCase(), { path, bytes: Buffer.from(bytes), rev });
    return rev;
  }
  get(path) {
    return this.files.get(path.toLowerCase());
  }
  meta(f) {
    return { '.tag': 'file', name: f.path.slice(1), path_display: f.path, path_lower: f.path.toLowerCase(), rev: f.rev, size: f.bytes.length, server_modified: '2026-11-25T10:00:00Z' };
  }
  async handle(route) {
    const req = route.request();
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Dropbox-API-Arg',
      'Access-Control-Expose-Headers': 'Dropbox-API-Result',
    };
    if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
    if (this.offline) return route.abort('internetdisconnected');
    const url = new URL(req.url());
    const json = (status, body, extra = {}) => route.fulfill({ status, headers: { ...cors, 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(body) });
    const arg = () => JSON.parse(req.headers()['dropbox-api-arg'] || '{}');
    switch (url.pathname) {
      case '/oauth2/token':
        return json(200, { access_token: 'tok', token_type: 'bearer', expires_in: 14400 });
      case '/2/files/list_folder':
        return json(200, { entries: [...this.files.values()].map((f) => this.meta(f)), has_more: false, cursor: 'c' });
      case '/2/files/get_metadata': {
        const f = this.get(JSON.parse(req.postData()).path);
        return f ? json(200, this.meta(f)) : json(409, { error_summary: 'path/not_found/..' });
      }
      case '/2/files/download': {
        const f = this.get(arg().path);
        if (!f) return json(409, { error_summary: 'path/not_found/..' });
        return route.fulfill({ status: 200, headers: { ...cors, 'Content-Type': 'application/octet-stream', 'Dropbox-API-Result': JSON.stringify(this.meta(f)) }, body: f.bytes });
      }
      case '/2/files/upload': {
        const a = arg();
        const f = this.get(a.path);
        if (a.mode['.tag'] === 'add' && f) return json(409, { error_summary: 'path/conflict/file/..' });
        if (a.mode['.tag'] === 'update' && (!f || f.rev !== a.mode.update)) return json(409, { error_summary: 'path/conflict/file/..' });
        this.uploads++;
        this.put(a.path, req.postDataBuffer());
        return json(200, this.meta(this.get(a.path)));
      }
      case '/2/auth/token/revoke':
        return json(200, null);
      default:
        return json(400, { error_summary: 'endpoint non simulato: ' + url.pathname });
    }
  }
}
