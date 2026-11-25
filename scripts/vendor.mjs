// Copia le librerie di terze parti nella web app (nessun passaggio di build).
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'webapp', 'vendor');
mkdirSync(out, { recursive: true });
const files = [
  ['node_modules/kdbxweb/dist/kdbxweb.min.js', 'kdbxweb.min.js'],
  ['node_modules/hash-wasm/dist/argon2.umd.min.js', 'argon2.umd.min.js'],
];
for (const [src, dst] of files) {
  copyFileSync(join(root, src), join(out, dst));
  console.log('copiato', dst);
}
