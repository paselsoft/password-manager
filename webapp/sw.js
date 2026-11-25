// Service worker: rende l'app disponibile offline.
// Strategia "prima la rete": online si usa sempre la versione più recente,
// offline la copia in cache. Le chiamate a Dropbox non passano di qui.

const CACHE = 'cassaforte-v1';
const SHELL = [
  './',
  'index.html',
  'config.js',
  'manifest.webmanifest',
  'css/app.css',
  'js/app.js',
  'js/vault.js',
  'js/totp.js',
  'js/generator.js',
  'js/dropbox.js',
  'js/store.js',
  'vendor/kdbxweb.min.js',
  'vendor/argon2.umd.min.js',
  'icons/icon.svg',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  // Il ritorno da Dropbox (?code=...) non va mai messo in cache
  const cacheable = !url.search;
  event.respondWith((async () => {
    try {
      const res = await fetch(req, { cache: 'no-cache' });
      if (res.ok && cacheable) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
      }
      return res;
    } catch (e) {
      const hit = await caches.match(req, { ignoreSearch: true });
      if (hit) return hit;
      if (req.mode === 'navigate') {
        const shell = await caches.match('index.html');
        if (shell) return shell;
      }
      throw e;
    }
  })());
});
