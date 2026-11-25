// Utilità comuni ai test della web app.
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const require = createRequire(import.meta.url);
globalThis.kdbxweb = require('kdbxweb');
const hashwasm = require('hash-wasm');

export const V = await import('../../webapp/js/vault.js');
export const T = await import('../../webapp/js/totp.js');
export const G = await import('../../webapp/js/generator.js');
V.initArgon2(hashwasm);

export function hasKeepassxc() {
  try {
    execFileSync('keepassxc-cli', ['--version'], { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

/** Esegue keepassxc-cli passando la password su stdin. */
export function kx(args, password = 'prova123', extraInput = '') {
  return execFileSync('keepassxc-cli', args, { input: password + '\n' + extraInput, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

/** Crea un database di prova con voci, gruppi e TOTP. */
export async function sampleDb(password = 'prova123') {
  const db = V.createDatabase(await V.makeCredentials(password), 'Prova');
  // parametri leggeri per i test
  const k = globalThis.kdbxweb;
  db.header.kdfParameters.set('M', k.VarDictionary.ValueType.UInt64, new k.Int64(1024 * 1024));
  db.header.kdfParameters.set('I', k.VarDictionary.ValueType.UInt64, new k.Int64(2));
  const lavoro = V.createGroup(db, null, 'Lavoro');
  V.saveEntry(db, null, {
    title: 'Posta', username: 'mario@example.com', password: 'Segreta-1', url: 'https://mail.example.com',
    notes: 'nota', otp: 'otpauth://totp/Example:mario?secret=JBSWY3DPEHPK3PXP&issuer=Example',
    tags: ['email'], groupId: lavoro.uuid.id, fields: [{ key: 'PIN', value: '4321', protected: true }],
  });
  V.saveEntry(db, null, { title: 'Banca', username: 'mrossi', password: 'Banca-2', url: 'banca.example.it', groupId: null, fields: [] });
  V.saveEntry(db, null, { title: 'Àrea riservata', username: 'utente', password: 'x', url: '', groupId: lavoro.uuid.id, fields: [] });
  return db;
}
