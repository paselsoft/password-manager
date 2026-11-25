// Codici TOTP (RFC 6238) con WebCrypto. Nessuna dipendenza.
//
// Formati riconosciuti nelle voci KeePass:
//  - attributo "otp" con URI otpauth://totp/... (KeePassXC, KeePassium, Strongbox)
//  - attributi "TimeOtp-Secret-Base32" / "TimeOtp-Period" / "TimeOtp-Length" /
//    "TimeOtp-Algorithm" (KeePass 2.47+)
//  - attributi "TOTP Seed" / "TOTP Settings" (vecchio formato KeePassXC)

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error('Segreto TOTP non in Base32');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

const ALGOS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

function normAlgo(a) {
  const k = String(a || 'SHA1').toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^HMAC/, '');
  if (!ALGOS[k]) throw new Error('Algoritmo TOTP non supportato: ' + a);
  return k;
}

/** Interpreta un valore otpauth:// o un segreto Base32 nudo. */
export function parseOtp(value) {
  const v = String(value || '').trim();
  if (!v) return null;
  if (/^otpauth:\/\//i.test(v)) {
    const url = new URL(v);
    if (url.host.toLowerCase() !== 'totp') throw new Error('Solo TOTP è supportato (non HOTP)');
    const p = url.searchParams;
    const secret = p.get('secret');
    if (!secret) throw new Error('URI otpauth senza secret');
    const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
    return {
      secret: base32Decode(secret),
      secretText: secret.toUpperCase().replace(/\s/g, ''),
      period: parseInt(p.get('period') || '30', 10) || 30,
      digits: parseInt(p.get('digits') || '6', 10) || 6,
      algorithm: normAlgo(p.get('algorithm')),
      issuer: p.get('issuer') || (label.includes(':') ? label.split(':')[0] : ''),
      account: label.includes(':') ? label.split(':').slice(1).join(':') : label,
    };
  }
  return {
    secret: base32Decode(v),
    secretText: v.toUpperCase().replace(/\s/g, ''),
    period: 30,
    digits: 6,
    algorithm: 'SHA1',
    issuer: '',
    account: '',
  };
}

/** Cerca la configurazione TOTP fra i campi di una voce (Map nome -> stringa). */
export function otpFromFields(get) {
  const otp = get('otp');
  if (otp) return parseOtp(otp);
  const kp = get('TimeOtp-Secret-Base32');
  if (kp) {
    const cfg = parseOtp(kp);
    cfg.period = parseInt(get('TimeOtp-Period') || '30', 10) || 30;
    cfg.digits = parseInt(get('TimeOtp-Length') || '6', 10) || 6;
    cfg.algorithm = normAlgo((get('TimeOtp-Algorithm') || 'SHA1').replace('HMAC-', ''));
    return cfg;
  }
  const seed = get('TOTP Seed');
  if (seed) {
    const cfg = parseOtp(seed);
    const s = (get('TOTP Settings') || '').split(';');
    if (s[0]) cfg.period = parseInt(s[0], 10) || 30;
    if (s[1] && /^\d+$/.test(s[1])) cfg.digits = parseInt(s[1], 10);
    return cfg;
  }
  return null;
}

/** Costruisce l'URI otpauth da salvare nell'attributo "otp". */
export function buildOtpUri(value, issuer, account) {
  const v = String(value || '').trim();
  if (!v) return '';
  if (/^otpauth:\/\//i.test(v)) {
    parseOtp(v); // valida
    return v;
  }
  const secret = v.toUpperCase().replace(/\s/g, '');
  base32Decode(secret); // valida
  const iss = issuer || 'Password';
  const label = encodeURIComponent(iss) + (account ? ':' + encodeURIComponent(account) : '');
  return `otpauth://totp/${label}?secret=${secret}&period=30&digits=6&issuer=${encodeURIComponent(iss)}`;
}

export async function hotp(secret, counter, digits = 6, algorithm = 'SHA1') {
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey('raw', secret, { name: 'HMAC', hash: ALGOS[normAlgo(algorithm)] }, false, ['sign']);
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await subtle.sign('HMAC', key, msg));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Restituisce { code, remaining } per l'istante dato (ms). */
export async function totp(cfg, nowMs = Date.now()) {
  const t = Math.floor(nowMs / 1000);
  const counter = Math.floor(t / cfg.period);
  const code = await hotp(cfg.secret, counter, cfg.digits, cfg.algorithm);
  return { code, remaining: cfg.period - (t % cfg.period), period: cfg.period };
}
