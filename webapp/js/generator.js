// Generatore di password con crypto.getRandomValues (senza bias da modulo).

export const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!#$%&*+-=?@_~.,;:',
};
// Versioni complete (senza esclusione dei caratteri ambigui)
const FULL = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: SETS.symbols,
};

function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

/**
 * opts: { length, lower, upper, digits, symbols, avoidAmbiguous }
 * Garantisce almeno un carattere per ogni insieme scelto.
 */
export function generatePassword(opts = {}) {
  const o = Object.assign({ length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true }, opts);
  const src = o.avoidAmbiguous ? SETS : FULL;
  const chosen = ['lower', 'upper', 'digits', 'symbols'].filter((k) => o[k]).map((k) => src[k]);
  if (!chosen.length) throw new Error('Scegli almeno un tipo di carattere');
  const length = Math.max(Math.min(parseInt(o.length, 10) || 20, 128), chosen.length);
  const all = chosen.join('');
  const chars = chosen.map((set) => set[randomInt(set.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}
