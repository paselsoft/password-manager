// Genera screenshot dell'app con dati di prova: node tests/web/screens.mjs CARTELLA
import { createRequire } from 'node:module';
import { V, sampleDb } from './helpers.mjs';
import { FakeDropbox } from './fake-dropbox.mjs';
import { startServer } from '../../scripts/serve.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const out = process.argv[2] || '.';
const fake = new FakeDropbox();
const db = await sampleDb();
for (const [t, u, url] of [['Amazon', 'mario.rossi@example.com', 'https://www.amazon.it'], ['GitHub', 'mrossi', 'https://github.com'], ['Poste Italiane', 'MRSMRA80A01L219X', 'https://www.poste.it'], ['Wi-Fi di casa', '', ''], ['Comune di Torino', 'mario.rossi', 'https://servizi.comune.torino.it']]) {
  V.saveEntry(db, null, { title: t, username: u, password: 'x-' + t, url, groupId: null, fields: [] });
}
fake.put('/Password.kdbx', await V.saveDatabase(db));
const server = await startServer(new URL('../../webapp', import.meta.url).pathname, 0);
const base = `http://127.0.0.1:${server.address().port}/`;
const browser = await chromium.launch();
for (const [name, vp, scale] of [['desktop', { width: 1280, height: 760 }, 2], ['iphone', { width: 375, height: 812 }, 2]]) {
  const ctx = await browser.newContext({ viewport: vp, deviceScaleFactor: scale, serviceWorkers: 'block', colorScheme: name === 'iphone' ? 'dark' : 'light' });
  await ctx.addInitScript(() => { localStorage.setItem('pm.appKey', 'k'); localStorage.setItem('pm.dropbox.refresh', 'r'); localStorage.setItem('pm.path', '/Password.kdbx'); });
  await ctx.route(/https:\/\/(api|content)\.dropboxapi\.com\/.*/, (r) => fake.handle(r));
  const page = await ctx.newPage();
  await page.goto(base);
  await page.waitForSelector('#screen-unlock:not([hidden])');
  await page.screenshot({ path: `${out}/${name}-1-sblocco.png` });
  await page.fill('#master', 'prova123');
  await page.click('#btn-unlock');
  await page.waitForSelector('#screen-main:not([hidden])');
  await page.screenshot({ path: `${out}/${name}-2-elenco.png` });
  await page.fill('#search', 'posta');
  await page.waitForFunction(() => document.querySelector('#entry-list strong')?.textContent === 'Posta');
  await page.locator('#entry-list button').first().click();
  await page.waitForFunction(() => /\d{3} \d{3}/.test(document.querySelector('.otp-code')?.textContent || ''));
  await page.screenshot({ path: `${out}/${name}-3-dettaglio.png` });
  await page.getByRole('button', { name: 'Modifica' }).click();
  await page.click('#btn-gen');
  await page.screenshot({ path: `${out}/${name}-4-modifica.png` });
  await ctx.close();
}
await browser.close();
server.close();
