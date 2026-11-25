// Piccolo archivio IndexedDB per:
//  - copia locale del file .kdbx (sempre cifrata) per l'uso offline
//  - modifiche in attesa di essere caricate su Dropbox (file cifrato)
//  - key file ricordato su questo dispositivo (se l'utente lo chiede)
// Nessun dato in chiaro viene mai salvato.

const DB_NAME = 'password-manager';
const STORE = 'kv';

let dbPromise = null;

function open() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }).catch((e) => {
      dbPromise = null;
      throw e;
    });
  }
  return dbPromise;
}

async function tx(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(req ? req.result : undefined);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export async function get(key) {
  try {
    return await tx('readonly', (s) => s.get(key));
  } catch (e) {
    return undefined;
  }
}

export function set(key, value) {
  return tx('readwrite', (s) => s.put(value, key));
}

export function del(key) {
  return tx('readwrite', (s) => s.delete(key));
}

export function clear() {
  return tx('readwrite', (s) => s.clear());
}

// Chiavi usate dall'app
export const cacheKey = (path) => 'cache:' + path.toLowerCase();
export const pendingKey = (path) => 'pending:' + path.toLowerCase();
export const keyFileKey = (path) => 'keyfile:' + path.toLowerCase();
