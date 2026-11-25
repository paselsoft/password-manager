// Accesso al database KeePass (.kdbx) tramite kdbxweb.
// Funziona sia nel browser (kdbxweb globale) sia in Node per i test.

import { otpFromFields } from './totp.js';

function K() {
  const k = globalThis.kdbxweb;
  if (!k) throw new Error('Libreria kdbxweb non caricata');
  return k;
}

export const STANDARD_FIELDS = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
export const OTP_FIELDS = ['otp', 'TimeOtp-Secret-Base32', 'TimeOtp-Secret', 'TimeOtp-Secret-Hex',
  'TimeOtp-Secret-Base64', 'TimeOtp-Period', 'TimeOtp-Length', 'TimeOtp-Algorithm',
  'TOTP Seed', 'TOTP Settings'];
const RESERVED = new Set([...STANDARD_FIELDS, ...OTP_FIELDS].map((k) => k.toLowerCase()));

// Parametri Argon2id per i database nuovi (circa 1 s su un telefono recente)
export const NEW_DB_KDF = { memoryMiB: 64, iterations: 3, parallelism: 2 };

function toArrayBuffer(data) {
  if (data instanceof ArrayBuffer) return data;
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}

/** Collega l'implementazione Argon2 di hash-wasm a kdbxweb. */
export function initArgon2(hashwasm) {
  K().CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
    if (version !== 0x13) throw new Error('Versione Argon2 non supportata: ' + version);
    const fn = type === 2 ? hashwasm.argon2id : hashwasm.argon2d;
    const out = await fn({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      parallelism,
      iterations,
      memorySize: memory, // KiB
      hashLength: length,
      outputType: 'binary',
    });
    return toArrayBuffer(out);
  });
}

export async function makeCredentials(password, keyFile) {
  const k = K();
  const pv = password ? k.ProtectedValue.fromString(password) : null;
  const c = new k.Credentials(pv, keyFile ? toArrayBuffer(keyFile) : null);
  await c.ready;
  return c;
}

export function describeError(err) {
  const codes = K().Consts.ErrorCodes;
  switch (err && err.code) {
    case codes.InvalidKey: return 'Password o key file errati.';
    case codes.BadSignature: return 'Il file non è un database KeePass (.kdbx).';
    case codes.InvalidVersion: return 'Versione del file KeePass non supportata.';
    case codes.FileCorrupt: return 'Il file sembra danneggiato.';
    default: return (err && err.message) || String(err);
  }
}

export async function openDatabase(bytes, credentials) {
  return K().Kdbx.load(toArrayBuffer(bytes), credentials);
}

export function createDatabase(credentials, name) {
  const db = K().Kdbx.create(credentials, name || 'Password');
  upgradeSecurity(db);
  return db;
}

/** Descrive formato e protezione del file. */
export function securityInfo(db) {
  const k = K();
  const h = db.header;
  let kdf = 'AES-KDF';
  let detail = '';
  if (h.versionMajor >= 4 && h.kdfParameters) {
    const id = k.ByteUtils.bytesToBase64(h.kdfParameters.get('$UUID'));
    const num = (key) => {
      const v = h.kdfParameters.get(key);
      return v && typeof v === 'object' && 'value' in v ? v.value : v;
    };
    if (id === k.Consts.KdfId.Argon2id || id === k.Consts.KdfId.Argon2d) {
      kdf = id === k.Consts.KdfId.Argon2id ? 'Argon2id' : 'Argon2d';
      detail = `${Math.round(num('M') / 1048576)} MiB, ${num('I')} iterazioni, parallelismo ${num('P')}`;
    } else {
      detail = `${num('R')} cicli`;
    }
  } else if (h.keyEncryptionRounds) {
    detail = `${h.keyEncryptionRounds} cicli`;
  }
  const version = `${h.versionMajor}.${h.versionMinor}`;
  return { version, kdf, detail, outdated: h.versionMajor < 4 || kdf === 'AES-KDF' };
}

/** Porta il file a KDBX 4 con Argon2id (compatibile con KeePassXC 2.7+, KeePassium, Strongbox). */
export function upgradeSecurity(db) {
  const k = K();
  db.upgrade();
  db.setKdf(k.Consts.KdfId.Argon2id);
  const p = db.header.kdfParameters;
  const T = k.VarDictionary.ValueType;
  p.set('M', T.UInt64, new k.Int64(NEW_DB_KDF.memoryMiB * 1024 * 1024));
  p.set('I', T.UInt64, new k.Int64(NEW_DB_KDF.iterations));
  p.set('P', T.UInt32, NEW_DB_KDF.parallelism);
}

export async function saveDatabase(db) {
  db.cleanup({ historyRules: true, binaries: true });
  return new Uint8Array(await db.save());
}

/** Unisce nel database locale le modifiche presenti nella copia remota. */
export async function mergeRemote(db, remoteBytes) {
  const remote = await K().Kdbx.load(toArrayBuffer(remoteBytes), db.credentials);
  db.merge(remote);
}

// ---------------------------------------------------------------- lettura

export function fieldText(entry, key) {
  const v = entry.fields.get(key);
  if (v == null) return '';
  return typeof v === 'string' ? v : v.getText();
}

function isProtected(entry, key) {
  const v = entry.fields.get(key);
  return v != null && typeof v !== 'string';
}

function binId(db) {
  return db.meta.recycleBinEnabled && db.meta.recycleBinUuid && !db.meta.recycleBinUuid.empty
    ? db.meta.recycleBinUuid.id : null;
}

function inRecycleBin(db, item) {
  const bin = binId(db);
  if (!bin) return false;
  for (let g = item.parentGroup; g; g = g.parentGroup) {
    if (g.uuid.id === bin) return true;
  }
  return false;
}

export function groupPath(db, group) {
  const names = [];
  const root = db.getDefaultGroup();
  for (let g = group; g && g !== root; g = g.parentGroup) names.unshift(g.name || '');
  return names.join(' / ');
}

/** Gruppi navigabili (escluso il cestino), in ordine ad albero. */
export function listGroups(db) {
  const root = db.getDefaultGroup();
  const out = [{ id: root.uuid.id, path: '', depth: 0, name: root.name || 'Database' }];
  const bin = binId(db);
  const walk = (g, depth) => {
    const kids = [...g.groups].sort((a, b) => (a.name || '').localeCompare(b.name || '', 'it'));
    for (const c of kids) {
      if (c.uuid.id === bin) continue;
      out.push({ id: c.uuid.id, path: groupPath(db, c), depth, name: c.name || '' });
      walk(c, depth + 1);
    }
  };
  walk(root, 1);
  return out;
}

export function findGroup(db, id) {
  const root = db.getDefaultGroup();
  if (!id || root.uuid.id === id) return root;
  for (const g of root.allGroups()) if (g.uuid.id === id) return g;
  return null;
}

export function findEntry(db, id) {
  for (const e of db.getDefaultGroup().allEntries()) if (e.uuid.id === id) return e;
  return null;
}

function hostOf(url) {
  if (!url) return '';
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : 'https://' + url);
    return u.hostname.replace(/^www\./, '');
  } catch (e) {
    return '';
  }
}

export function normalize(s) {
  return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

function otpConfigOf(entry) {
  try {
    return otpFromFields((k) => fieldText(entry, k));
  } catch (e) {
    return { error: e.message };
  }
}

function summary(db, e) {
  const url = fieldText(e, 'URL');
  return {
    id: e.uuid.id,
    title: fieldText(e, 'Title') || '(senza titolo)',
    username: fieldText(e, 'UserName'),
    url,
    host: hostOf(url),
    group: groupPath(db, e.parentGroup),
    groupId: e.parentGroup ? e.parentGroup.uuid.id : null,
    tags: [...(e.tags || [])],
    hasOtp: OTP_FIELDS.some((k) => e.fields.has(k)),
    modified: e.times.lastModTime ? e.times.lastModTime.getTime() : 0,
  };
}

/**
 * Elenco voci filtrato.
 * opts: { query, groupId (include sottogruppi), recycleBin (true = solo cestino) }
 */
export function listEntries(db, opts = {}) {
  const words = normalize(opts.query).split(/\s+/).filter(Boolean);
  const scope = opts.recycleBin ? findGroup(db, binId(db)) : findGroup(db, opts.groupId);
  if (!scope) return [];
  const out = [];
  for (const e of scope.allEntries()) {
    if (!opts.recycleBin && inRecycleBin(db, e)) continue;
    if (words.length) {
      const hay = normalize([
        fieldText(e, 'Title'), fieldText(e, 'UserName'), fieldText(e, 'URL'), fieldText(e, 'Notes'),
        (e.tags || []).join(' '), groupPath(db, e.parentGroup),
        ...[...e.fields.entries()]
          .filter(([k, v]) => typeof v === 'string' && !RESERVED.has(k.toLowerCase()))
          .map(([k, v]) => k + ' ' + v),
      ].join('\n'));
      if (!words.every((w) => hay.includes(w))) continue;
    }
    out.push(summary(db, e));
  }
  out.sort((a, b) => a.title.localeCompare(b.title, 'it', { sensitivity: 'base' }));
  return out;
}

export function hasRecycleBin(db) {
  const g = findGroup(db, binId(db));
  return !!(binId(db) && g && g.uuid.id === binId(db));
}

/** Dettaglio completo di una voce (i valori protetti si leggono con fieldText). */
export function entryDetail(db, entry) {
  const fields = [];
  for (const [key, v] of entry.fields.entries()) {
    if (RESERVED.has(key.toLowerCase())) continue;
    fields.push({ key, protected: typeof v !== 'string', value: typeof v === 'string' ? v : null });
  }
  fields.sort((a, b) => a.key.localeCompare(b.key, 'it'));
  const attachments = [...entry.binaries.entries()].map(([name, b]) => {
    const val = b && b.value !== undefined ? b.value : b;
    const size = val instanceof ArrayBuffer ? val.byteLength : (val && val.byteLength) || 0;
    return { name, size };
  });
  return Object.assign(summary(db, entry), {
    notes: fieldText(entry, 'Notes'),
    hasPassword: !!fieldText(entry, 'Password'),
    otp: otpConfigOf(entry),
    otpRaw: fieldText(entry, 'otp') || fieldText(entry, 'TimeOtp-Secret-Base32') || fieldText(entry, 'TOTP Seed'),
    fields,
    attachments,
    historyCount: entry.history.length,
    created: entry.times.creationTime ? entry.times.creationTime.getTime() : 0,
    inRecycleBin: inRecycleBin(db, entry),
  });
}

export function attachmentBytes(entry, name) {
  const b = entry.binaries.get(name);
  if (!b) return null;
  const val = b.value !== undefined ? b.value : b;
  if (val instanceof ArrayBuffer) return new Uint8Array(val);
  if (val && typeof val.getBinary === 'function') return val.getBinary();
  return null;
}

// ---------------------------------------------------------------- modifica

/**
 * Crea (entry = null) o modifica una voce.
 * data: { title, username, password, url, notes, otp, tags: [], groupId,
 *         fields: [{ key, value, protected }] }
 * Il campo otp accetta un URI otpauth:// già validato oppure '' per rimuoverlo.
 * Restituisce la voce.
 */
export function saveEntry(db, entry, data) {
  const k = K();
  const target = findGroup(db, data.groupId) || db.getDefaultGroup();
  if (entry) {
    entry.pushHistory();
  } else {
    entry = db.createEntry(target);
  }
  const PV = k.ProtectedValue;
  entry.fields.set('Title', data.title || '');
  entry.fields.set('UserName', data.username || '');
  entry.fields.set('Password', PV.fromString(data.password || ''));
  entry.fields.set('URL', data.url || '');
  entry.fields.set('Notes', data.notes || '');

  const currentOtp = fieldText(entry, 'otp') || fieldText(entry, 'TimeOtp-Secret-Base32') || fieldText(entry, 'TOTP Seed');
  if ((data.otp || '') !== currentOtp) {
    for (const key of OTP_FIELDS) entry.fields.delete(key);
    if (data.otp) entry.fields.set('otp', PV.fromString(data.otp));
  }

  if (Array.isArray(data.fields)) {
    for (const key of [...entry.fields.keys()]) {
      if (!RESERVED.has(key.toLowerCase())) entry.fields.delete(key);
    }
    for (const f of data.fields) {
      const key = String(f.key || '').trim();
      if (!key || RESERVED.has(key.toLowerCase())) continue;
      entry.fields.set(key, f.protected ? PV.fromString(f.value || '') : String(f.value || ''));
    }
  }
  if (Array.isArray(data.tags)) {
    entry.tags = data.tags.map((t) => String(t).trim()).filter(Boolean);
  }
  entry.times.update();
  if (entry.parentGroup !== target) db.move(entry, target);
  return entry;
}

export async function addAttachment(db, entry, name, bytes) {
  entry.pushHistory();
  const bin = await db.createBinary(K().ProtectedValue.fromBinary(toArrayBuffer(bytes)));
  let n = name;
  for (let i = 2; entry.binaries.has(n); i++) n = name.replace(/(\.[^.]*)?$/, ` (${i})$1`);
  entry.binaries.set(n, bin);
  entry.times.update();
  return n;
}

export function removeAttachment(entry, name) {
  entry.pushHistory();
  entry.binaries.delete(name);
  entry.times.update();
}

/** Sposta nel cestino (o elimina definitivamente se è già nel cestino). */
export function deleteEntry(db, entry) {
  db.remove(entry);
}

export function restoreEntry(db, entry, groupId) {
  db.move(entry, findGroup(db, groupId) || db.getDefaultGroup());
}

export function createGroup(db, parentId, name) {
  return db.createGroup(findGroup(db, parentId) || db.getDefaultGroup(), name);
}
