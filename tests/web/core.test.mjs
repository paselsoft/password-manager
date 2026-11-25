// Test di vault.js, totp.js e generator.js (Node, senza browser).
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { V, T, G, hasKeepassxc, kx, sampleDb } from './helpers.mjs';

const enc = (s) => new TextEncoder().encode(s);

test('TOTP: vettori ufficiali RFC 6238', async () => {
  const s1 = enc('12345678901234567890');
  const s256 = enc('12345678901234567890123456789012');
  const s512 = enc('1234567890123456789012345678901234567890123456789012345678901234');
  const cases = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, c1, c256, c512] of cases) {
    const counter = Math.floor(t / 30);
    assert.equal(await T.hotp(s1, counter, 8, 'SHA1'), c1);
    assert.equal(await T.hotp(s256, counter, 8, 'SHA256'), c256);
    assert.equal(await T.hotp(s512, counter, 8, 'SHA512'), c512);
  }
});

test('TOTP: parsing di otpauth e segreti nudi', async () => {
  const cfg = T.parseOtp('otpauth://totp/ACME:mario@x.it?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60&algorithm=SHA256');
  assert.equal(cfg.digits, 8);
  assert.equal(cfg.period, 60);
  assert.equal(cfg.algorithm, 'SHA256');
  assert.equal(cfg.account, 'mario@x.it');
  assert.equal(T.parseOtp('jbsw y3dp ehpk 3pxp').secretText, 'JBSWY3DPEHPK3PXP');
  assert.throws(() => T.parseOtp('NON-VALIDO-0189'));
  assert.match(T.buildOtpUri('JBSWY3DPEHPK3PXP', 'Sito', 'io'), /^otpauth:\/\/totp\/Sito:io\?secret=JBSWY3DPEHPK3PXP/);
  const legacy = T.otpFromFields((k) => ({ 'TOTP Seed': 'JBSWY3DPEHPK3PXP', 'TOTP Settings': '30;8' })[k] || '');
  assert.equal(legacy.digits, 8);
  const kp = T.otpFromFields((k) => ({ 'TimeOtp-Secret-Base32': 'JBSWY3DPEHPK3PXP', 'TimeOtp-Algorithm': 'HMAC-SHA-256' })[k] || '');
  assert.equal(kp.algorithm, 'SHA256');
});

test('Generatore: lunghezza e insiemi di caratteri', () => {
  for (let i = 0; i < 200; i++) {
    const p = G.generatePassword({ length: 16 });
    assert.equal(p.length, 16);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[0-9]/);
    assert.match(p, /[^a-zA-Z0-9]/);
  }
  assert.match(G.generatePassword({ length: 30, upper: false, symbols: false, digits: false }), /^[a-z]{30}$/);
  assert.throws(() => G.generatePassword({ lower: false, upper: false, digits: false, symbols: false }));
});

test('Vault: crea, cerca, modifica, salva e riapre', async () => {
  const db = await sampleDb();
  const info = V.securityInfo(db);
  assert.equal(info.kdf, 'Argon2id');
  assert.equal(info.outdated, false);
  assert.deepEqual(V.listGroups(db).map((g) => g.path), ['', 'Lavoro']);
  assert.equal(V.listEntries(db).length, 3);
  assert.equal(V.listEntries(db, { query: 'area' }).length, 1, 'ricerca senza accenti');
  assert.equal(V.listEntries(db, { query: 'mail mario' }).length, 1, 'ricerca a più parole');
  const lavoro = V.listGroups(db)[1].id;
  assert.equal(V.listEntries(db, { groupId: lavoro }).length, 2);

  const posta = V.findEntry(db, V.listEntries(db, { query: 'posta' })[0].id);
  const d = V.entryDetail(db, posta);
  assert.equal(d.fields.length, 1);
  assert.equal(d.fields[0].protected, true);
  assert.ok(d.otp && !d.otp.error);

  V.saveEntry(db, posta, { ...d, password: 'Nuova-3', otp: d.otpRaw, fields: [{ key: 'PIN', value: '9999', protected: true }] });
  assert.equal(posta.history.length, 1, 'storico delle versioni');
  await V.addAttachment(db, posta, 'doc.txt', enc('contenuto'));

  const bytes = await V.saveDatabase(db);
  const again = await V.openDatabase(bytes, await V.makeCredentials('prova123'));
  const p2 = V.findEntry(again, posta.uuid.id);
  assert.equal(V.fieldText(p2, 'Password'), 'Nuova-3');
  assert.equal(V.fieldText(p2, 'PIN'), '9999');
  assert.equal(new TextDecoder().decode(V.attachmentBytes(p2, 'doc.txt')), 'contenuto');

  await assert.rejects(V.openDatabase(bytes, await V.makeCredentials('sbagliata')), (e) => V.describeError(e) === 'Password o key file errati.');
});

test('Vault: cestino e ripristino', async () => {
  const db = await sampleDb();
  const banca = V.findEntry(db, V.listEntries(db, { query: 'banca' })[0].id);
  V.deleteEntry(db, banca);
  assert.equal(V.listEntries(db).length, 2);
  assert.ok(V.hasRecycleBin(db));
  assert.equal(V.listEntries(db, { recycleBin: true }).length, 1);
  assert.ok(V.entryDetail(db, banca).inRecycleBin);
  V.restoreEntry(db, banca, null);
  assert.equal(V.listEntries(db).length, 3);
});

test('Vault: unione di modifiche concorrenti su due dispositivi', async () => {
  const base = await V.saveDatabase(await sampleDb());
  // KeePass registra le date al secondo: le modifiche reali avvengono dopo la base
  await new Promise((r) => setTimeout(r, 1100));
  const creds = () => V.makeCredentials('prova123');
  const a = await V.openDatabase(base, await creds());
  const b = await V.openDatabase(base, await creds());
  const id = (db, q) => V.listEntries(db, { query: q })[0].id;

  // A modifica Posta e crea una voce; B modifica Banca ed elimina "Àrea riservata"
  const pa = V.findEntry(a, id(a, 'posta'));
  V.saveEntry(a, pa, { ...V.entryDetail(a, pa), password: 'da-A', otp: V.entryDetail(a, pa).otpRaw });
  V.saveEntry(a, null, { title: 'Nuova da A', username: 'a', password: 'a', groupId: null, fields: [] });
  const bb = V.findEntry(b, id(b, 'banca'));
  V.saveEntry(b, bb, { ...V.entryDetail(b, bb), password: 'da-B' });
  V.deleteEntry(b, V.findEntry(b, id(b, 'riservata')));
  const bBytes = await V.saveDatabase(b);

  await V.mergeRemote(a, bBytes);
  const merged = await V.openDatabase(await V.saveDatabase(a), await creds());
  const pw = (q) => V.fieldText(V.findEntry(merged, id(merged, q)), 'Password');
  assert.equal(pw('posta'), 'da-A');
  assert.equal(pw('banca'), 'da-B');
  assert.equal(pw('nuova'), 'a');
  assert.equal(V.listEntries(merged, { query: 'riservata' }).length, 0);
});

test('Compatibilità con KeePassXC (keepassxc-cli)', { skip: !hasKeepassxc() && 'keepassxc-cli non installato' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pm-'));
  try {
    // 1. file creato da keepassxc-cli (che di default usa AES-KDF) aperto e modificato dall'app
    const kdbx = join(dir, 'kx.kdbx');
    kx(['db-create', '-p', '-t', '200', kdbx], 'prova123', 'prova123\n');
    kx(['add', '-u', 'mario', '-p', '--url', 'https://es.it', kdbx, 'Sito'], 'prova123', 'Pw-KeePassXC\n');
    kx(['mkdir', kdbx, 'Lavoro']);
    const db = await V.openDatabase(readFileSync(kdbx), await V.makeCredentials('prova123'));
    const sito = V.findEntry(db, V.listEntries(db, { query: 'sito' })[0].id);
    assert.equal(V.fieldText(sito, 'Password'), 'Pw-KeePassXC');
    const lavoro = V.listGroups(db).find((g) => g.path === 'Lavoro').id;
    V.saveEntry(db, sito, { ...V.entryDetail(db, sito), password: 'Pw-Web', otp: 'otpauth://totp/Es:mario?secret=JBSWY3DPEHPK3PXP&issuer=Es', groupId: lavoro });
    await V.addAttachment(db, sito, 'nota.txt', enc('allegato web'));
    writeFileSync(kdbx, await V.saveDatabase(db));

    const shown = kx(['show', '-s', '-a', 'Password', kdbx, 'Lavoro/Sito']);
    assert.match(shown, /Pw-Web/);
    const code = kx(['show', '-t', kdbx, 'Lavoro/Sito']).trim().split('\n').pop();
    const mine = (await T.totp(T.parseOtp('JBSWY3DPEHPK3PXP'))).code;
    assert.equal(code, mine);
    assert.match(kx(['attachment-export', '--stdout', kdbx, 'Lavoro/Sito', 'nota.txt']), /allegato web/);

    // 2. file vecchio formato (KDBX 3.1 / AES-KDF): aggiornamento della protezione
    const xml = join(dir, 'in.xml');
    writeFileSync(xml, kx(['export', '-f', 'xml', kdbx]).replace(/^.*?(<\?xml)/s, '$1'));
    const old = join(dir, 'old.kdbx');
    kx(['import', '-p', '-t', '100', xml, old], 'prova123', 'prova123\n');
    const odb = await V.openDatabase(readFileSync(old), await V.makeCredentials('prova123'));
    assert.equal(V.securityInfo(odb).outdated, true);
    V.upgradeSecurity(odb);
    writeFileSync(old, await V.saveDatabase(odb));
    assert.match(kx(['db-info', old]), /Argon2id/);
    assert.match(kx(['show', '-s', '-a', 'Password', old, 'Lavoro/Sito']), /Pw-Web/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
