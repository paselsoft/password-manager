// Server statico minimale per provare la web app in locale:
//   node scripts/serve.mjs webapp 8080   ->   http://localhost:8080/
// (http://localhost è un "contesto sicuro": WebCrypto e service worker funzionano)
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

export function startServer(dir, port = 8080) {
  const root = resolve(dir);
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      let path = normalize(join(root, decodeURIComponent(url.pathname)));
      if (!path.startsWith(root)) throw new Error('fuori dalla cartella');
      if ((await stat(path).catch(() => null))?.isDirectory()) path = join(path, 'index.html');
      const body = await readFile(path);
      res.writeHead(200, { 'Content-Type': TYPES[extname(path)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(body);
    } catch (e) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Non trovato');
    }
  });
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok(server)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [dir = 'webapp', port = '8080'] = process.argv.slice(2);
  startServer(dir, +port).then(() => console.log(`Cassaforte su http://localhost:${port}/`));
}
