// Iskan Portal PWA — offline shell + cache-first for static, network-first for APIs
const CACHE = 'iskan-portal-v2';
const SHELL = [
  '/',
  '/login.html',
  '/offline.html',
  '/manifest.json',
  '/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

function isApi(url) { return url.pathname.startsWith('/api/'); }
function isCdn(url) { return url.hostname.includes('cdn.tailwindcss.com') || url.hostname.includes('cdn.jsdelivr.net'); }

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // only handle same-origin + cdn
  const sameOrigin = url.origin === self.location.origin;
  if (!sameOrigin && !isCdn(url)) return;

  // API: network-first, no cache
  if (isApi(url)) {
    e.respondWith(
      fetch(req, { cache: 'no-store' }).catch(() => caches.match(req))
    );
    return;
  }

  // CDN: stale-while-revalidate
  if (isCdn(url)) {
    e.respondWith(
      caches.open(CACHE).then((cache) =>
        cache.match(req).then((cached) => {
          const fetched = fetch(req).then((res) => {
            if (res.ok) cache.put(req, res.clone());
            return res;
          }).catch(() => cached);
          return cached || fetched;
        })
      )
    );
    return;
  }

  // navigate: network-first fallback to cache then offline
  if (req.mode === 'navigate' || req.headers.get('accept')?.includes('text/html')) {
    e.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      }).catch(async () => {
        const cached = await caches.match(req);
        if (cached) return cached;
        const shell = await caches.match('/offline.html');
        if (shell) return shell;
        return new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' }});
      })
    );
    return;
  }

  // static same-origin: cache-first
  e.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => cached);
    })
  );
});
