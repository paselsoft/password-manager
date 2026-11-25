// Test end-to-end nel browser (Chromium via Playwright) con un Dropbox simulato.
// Verifica: scelta file, sblocco, ricerca, TOTP, modifica e salvataggio,
// conflitto con un altro dispositivo (unione), lavoro offline e blocco.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { V, T, sampleDb } from './helpers.mjs';
import { startServer } from '../../scripts/serve.mjs';
import { FakeDropbox } from './fake-dropbox.mjs';

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (e) {
  chromium = null;
}

const PATH = '/Prova.kdbx';

let server;
let base;
let browser;

before(async () => {
  if (!chromium) return;
  server = await startServer(new URL('../../webapp', import.meta.url).pathname, 0);
  base = `http://127.0.0.1:${server.address().port}/`;
  browser = await chromium.launch();
});

after(async () => {
  if (browser) await browser.close();
  if (server) server.close();
});

async function newPage(fake, viewport = { width: 1200, height: 800 }) {
  const context = await browser.newContext({ viewport, serviceWorkers: 'block' });
  await context.addInitScript(() => {
    localStorage.setItem('pm.appKey', 'chiave-test');
    localStorage.setItem('pm.dropbox.refresh', 'refresh-test');
  });
  await context.route(/https:\/\/(api|content)\.dropboxapi\.com\/.*/, (r) => fake.handle(r));
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/Failed to load resource|ERR_INTERNET_DISCONNECTED/.test(m.text())) errors.push(m.text());
  });
  await page.goto(base);
  return { page, context, errors };
}

async function remoteDb(fake) {
  return V.openDatabase(fake.get(PATH).bytes, await V.makeCredentials('prova123'));
}

const status = (page) => page.locator('#sync-status').textContent();

/** Attende che la pagina abbia caricato su Dropbox almeno un nuovo file e sia tornata in pari. */
async function synced(page, fake, uploadsBefore) {
  for (let i = 0; i < 200 && fake.uploads <= uploadsBefore; i++) await new Promise((r) => setTimeout(r, 50));
  assert.ok(fake.uploads > uploadsBefore, 'nessun caricamento su Dropbox');
  await page.waitForFunction(() => document.querySelector('#sync-status').textContent === 'Sincronizzato');
}

/** Cerca e attende che il primo risultato sia la voce indicata. */
async function search(page, query, title) {
  await page.fill('#search', query);
  await page.waitForFunction((t) => {
    const first = document.querySelector('#entry-list button strong');
    return first && first.textContent === t;
  }, title);
}

test('flusso completo con Dropbox simulato', { skip: !chromium && 'playwright non disponibile', timeout: 120000 }, async () => {
  const fake = new FakeDropbox();
  fake.put(PATH, await V.saveDatabase(await sampleDb()));
  const { page, context, errors } = await newPage(fake);

  // Scelta del file e sblocco
  await page.getByRole('button', { name: /Prova\.kdbx/ }).click();
  await page.fill('#master', 'sbagliata');
  await page.click('#btn-unlock');
  await page.waitForFunction(() => document.querySelector('#unlock-msg').textContent.includes('errati'));
  await page.fill('#master', 'prova123');
  await page.click('#btn-unlock');
  await page.waitForSelector('#screen-main:not([hidden])');
  assert.equal(await page.locator('#list-count').textContent(), '3 voci');
  assert.equal(await status(page), 'Sincronizzato');

  // Ricerca, dettaglio e codice TOTP
  await search(page, 'mail', 'Posta');
  assert.equal(await page.locator('#list-count').textContent(), '1 voce');
  await page.locator('#entry-list button').first().click();
  await page.waitForSelector('.otp-code');
  await page.waitForFunction(() => /^\d{3} \d{3}$/.test(document.querySelector('.otp-code').textContent));
  const shown = (await page.locator('.otp-code').textContent()).replace(' ', '');
  const expected = [(await T.totp(T.parseOtp('JBSWY3DPEHPK3PXP'))).code, (await T.totp(T.parseOtp('JBSWY3DPEHPK3PXP'), Date.now() - 30000)).code];
  assert.ok(expected.includes(shown), `TOTP ${shown} atteso ${expected}`);
  const detail = await page.locator('#detail').textContent();
  assert.match(detail, /mario@example\.com/);
  assert.doesNotMatch(detail, /Segreta-1/, 'la password resta nascosta finché non si preme Mostra');

  // Modifica e salvataggio su Dropbox
  await page.getByRole('button', { name: 'Modifica' }).click();
  await page.fill('#f-password', 'Cambiata-dal-web');
  let up = fake.uploads;
  await page.click('#btn-entry-save');
  await synced(page, fake, up);
  let db = await remoteDb(fake);
  let posta = V.findEntry(db, V.listEntries(db, { query: 'posta' })[0].id);
  assert.equal(V.fieldText(posta, 'Password'), 'Cambiata-dal-web');

  // Un altro dispositivo modifica "Banca" su Dropbox; poi il web crea una voce: deve unire
  await new Promise((r) => setTimeout(r, 1100));
  db = await remoteDb(fake);
  const banca = V.findEntry(db, V.listEntries(db, { query: 'banca' })[0].id);
  V.saveEntry(db, banca, { ...V.entryDetail(db, banca), password: 'Da-altro-dispositivo' });
  fake.put(PATH, await V.saveDatabase(db));
  await page.click('#btn-new-entry');
  await page.fill('#f-title', 'Creata sul web');
  await page.fill('#f-username', 'web');
  await page.click('#btn-gen');
  await page.fill('#f-otp', 'JBSWY3DPEHPK3PXP');
  up = fake.uploads;
  await page.click('#btn-entry-save');
  await synced(page, fake, up);
  db = await remoteDb(fake);
  const pw = (q) => V.fieldText(V.findEntry(db, V.listEntries(db, { query: q })[0].id), 'Password');
  assert.equal(pw('banca'), 'Da-altro-dispositivo');
  assert.equal(pw('posta'), 'Cambiata-dal-web');
  const creata = V.findEntry(db, V.listEntries(db, { query: 'creata sul web' })[0].id);
  assert.ok(V.fieldText(creata, 'Password').length >= 20, 'password generata');
  assert.match(V.fieldText(creata, 'otp'), /^otpauth:\/\/totp\//);

  // Offline: le modifiche restano in attesa (cifrate) e partono al ritorno della rete
  fake.offline = true;
  await search(page, 'banca', 'Banca');
  await page.locator('#entry-list button').first().click();
  await page.getByRole('button', { name: 'Modifica' }).click();
  await page.fill('#f-notes', 'scritta offline');
  await page.click('#btn-entry-save');
  await page.waitForFunction(() => document.querySelector('#sync-status').textContent.includes('in attesa'));
  // blocco e nuovo sblocco ancora offline: la modifica non va persa
  await page.click('#btn-lock');
  assert.equal(await page.locator('#entry-list li').count(), 0, 'dopo il blocco l\'elenco è vuoto');
  await page.fill('#master', 'prova123');
  await page.click('#btn-unlock');
  await page.waitForSelector('#screen-main:not([hidden])');
  await search(page, 'scritta offline', 'Banca');
  fake.offline = false;
  up = fake.uploads;
  await page.click('#btn-sync');
  await synced(page, fake, up);
  db = await remoteDb(fake);
  assert.equal(V.fieldText(V.findEntry(db, V.listEntries(db, { query: 'banca' })[0].id), 'Notes'), 'scritta offline');

  // Cestino
  await page.locator('#entry-list button').first().click();
  page.once('dialog', (d) => d.accept());
  up = fake.uploads;
  await page.getByRole('button', { name: 'Elimina' }).click();
  await synced(page, fake, up);
  db = await remoteDb(fake);
  assert.equal(V.listEntries(db, { recycleBin: true }).length, 1);

  assert.deepEqual(errors, [], 'nessun errore nella console (CSP compresa)');
  await context.close();
});

test('file vecchio formato: avviso e aggiornamento della protezione', { skip: !chromium && 'playwright non disponibile', timeout: 120000 }, async () => {
  const fake = new FakeDropbox();
  const db = await sampleDb();
  db.setVersion(3);
  db.setKdf(globalThis.kdbxweb.Consts.KdfId.Aes);
  fake.put(PATH, await V.saveDatabase(db));
  const { page, context, errors } = await newPage(fake, { width: 390, height: 844 });
  await page.getByRole('button', { name: /Prova\.kdbx/ }).click();
  await page.fill('#master', 'prova123');
  await page.click('#btn-unlock');
  await page.waitForSelector('#banner:not([hidden])');
  page.once('dialog', (d) => d.accept());
  const up = fake.uploads;
  await page.getByRole('button', { name: 'Aggiorna ora' }).click();
  await page.waitForFunction(() => document.querySelector('#banner').hidden);
  await synced(page, fake, up);
  const info = V.securityInfo(await remoteDb(fake));
  assert.equal(info.kdf, 'Argon2id');
  assert.equal(info.version, '4.0');
  assert.deepEqual(errors, []);
  await context.close();
});
