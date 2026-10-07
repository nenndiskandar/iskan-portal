// Iskan Portal PWA : robust offline v10
// CACHE v9 + SHELL pre-cache + API network-first (offline queue, no stale) + CDN SWR + navigate NF -> cache -> offline + static CF + background update + SKIP_WAITING + periodic cleanup
const CACHE = 'iskan-portal-v48';
const OFFLINE_URL = '/offline.html';
const SHELL = [
  '/',
  '/login.html',
  '/offline.html',
  '/manifest.json',
  '/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/xl.svg',
  '/icons/telkomsel.svg',
  '/icons/tri.svg',
  '/apple-touch-icon.png'
];

// --- helpers ---
function isApi(url) { return url.pathname.startsWith('/api/'); }
function isCdn(url) { return url.hostname.includes('cdn.tailwindcss.com') || url.hostname.includes('cdn.jsdelivr.net'); }
function isNavigationRequest(req) {
  return req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html');
}

// --- offline queue (IndexedDB) for API mutating requests ---
const QUEUE_DB_NAME = 'iskan-portal-queue';
const QUEUE_STORE = 'offline-queue';
const QUEUE_DB_VERSION = 1;

function openQueueDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(QUEUE_DB_NAME, QUEUE_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(QUEUE_STORE)) db.createObjectStore(QUEUE_STORE, { autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function enqueueRequest(request) {
  try {
    const body = request.method !== 'GET' && request.method !== 'HEAD' ? await request.clone().text() : null;
    const headers = {};
    request.headers.forEach((v, k) => { headers[k] = v; });
    const entry = {
      url: request.url,
      method: request.method,
      headers,
      body,
      ts: Date.now()
    };
    const db = await openQueueDB();
    await new Promise((res, rej) => {
      const tx = db.transaction(QUEUE_STORE, 'readwrite');
      tx.objectStore(QUEUE_STORE).add(entry);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
    db.close();
    // try background sync registration
    try { if ('sync' in self.registration) await self.registration.sync.register('iskan-sync-queue'); } catch (_) {}
  } catch (e) {
    // fallback: silent fail
  }
}

async function replayQueue() {
  const db = await openQueueDB();
  const entries = await new Promise((res, rej) => {
    const tx = db.transaction(QUEUE_STORE, 'readonly');
    const store = tx.objectStore(QUEUE_STORE);
    const req = store.getAll();
    req.onsuccess = () => res(req.result || []);
    req.onerror = () => rej(req.error);
  });
  // need keys to delete per success
  const keys = await new Promise((res, rej) => {
    const tx = db.transaction(QUEUE_STORE, 'readonly');
    const req = tx.objectStore(QUEUE_STORE).getAllKeys();
    req.onsuccess = () => res(req.result || []);
    req.onerror = () => rej(req.error);
  });
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const key = keys[i];
    try {
      const res = await fetch(e.url, {
        method: e.method,
        headers: e.headers,
        body: e.body || undefined
      });
      if (res.ok || (res.status >= 200 && res.status < 300) || res.status === 409) {
        // success -> remove from queue
        await new Promise((res2, rej2) => {
          const tx2 = db.transaction(QUEUE_STORE, 'readwrite');
          tx2.objectStore(QUEUE_STORE).delete(key);
          tx2.oncomplete = () => res2();
          tx2.onerror = () => rej2(tx2.error);
        });
      }
    } catch (_) {
      // keep in queue, stop replay to preserve order
      break;
    }
  }
  db.close();
}

function offlineApiResponse() {
  return new Response(JSON.stringify({ ok: false, offline: true, queued: true, message: 'Offline - request queued' }), {
    status: 503,
    headers: { 'Content-Type': 'application/json' }
  });
}

// --- install: pre-cache SHELL (must include /login.html /offline.html /manifest.json /favicon.svg /icons/*) ---
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch((err) => {
        // even if one asset fails, still activate
        console.warn('[SW] install addAll failed', err);
        return self.skipWaiting();
      })
  );
});

// --- activate: cleanup old caches (periode cleanup) ---
async function cleanupOldCaches() {
  const keys = await caches.keys();
  await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
}

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      await cleanupOldCaches();
      await self.clients.claim();
      // periode cleanup: also schedule next cleanup check (if periodicSync not available, cleanup on every activate is enough)
    })()
  );
});

// --- message handler: SKIP_WAITING + periode cleanup old caches ---
self.addEventListener('message', (event) => {
  const data = event.data;
  const type = typeof data === 'string' ? data : (data && data.type);
  if (type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (type === 'CLEANUP_OLD_CACHES' || type === 'CLEAN_OLD_CACHES' || type === 'CLEAR_OLD_CACHES') {
    event.waitUntil(cleanupOldCaches());
  }
  if (type === 'GET_QUEUE_SIZE') {
    event.waitUntil(
      (async () => {
        try {
          const db = await openQueueDB();
          const tx = db.transaction(QUEUE_STORE, 'readonly');
          const req = tx.objectStore(QUEUE_STORE).count();
          const count = await new Promise((res) => { req.onsuccess = () => res(req.result); req.onerror = () => res(0); });
          db.close();
          if (event.ports && event.ports[0]) event.ports[0].postMessage({ type: 'QUEUE_SIZE', count });
        } catch (_) {}
      })()
    );
  }
});

// --- sync: replay offline queue when back online ---
self.addEventListener('sync', (event) => {
  if (event.tag === 'iskan-sync-queue' || event.tag === 'offline-queue' || event.tag === 'sync-queue') {
    event.waitUntil(replayQueue());
  }
});

// also try replay on online via message or fetch success
self.addEventListener('online', () => {
  // event not standard in SW, but keep hook via sync
});

// --- periodicsync (periode cleanup) if supported ---
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'cleanup-old-caches') {
    event.waitUntil(cleanupOldCaches());
  }
});

// --- fetch handler ---
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  const sameOrigin = url.origin === self.location.origin;

  // 1) API: network-first with offline queue (no cache stale)
  if (isApi(url)) {
    // handle both GET and mutating methods
    if (!sameOrigin) return; // only same-origin API
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req.clone(), { cache: 'no-store' });
          // also trigger queue replay on successful API call (back online)
          try { replayQueue().catch(() => {}); } catch (_) {}
          return res;
        } catch (err) {
          // network failed -> offline queue path, NO stale cache
          if (req.method !== 'GET' && req.method !== 'HEAD') {
            await enqueueRequest(req.clone());
            return offlineApiResponse();
          }
          // GET API offline -> return 503 JSON, no cache stale
          return new Response(JSON.stringify({ ok: false, offline: true, message: 'Offline - API unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', 'X-Offline': '1' }
          });
        }
      })()
    );
    return;
  }

  // for non-API, only GET is cacheable
  if (req.method !== 'GET') return;

  // only handle same-origin + CDN (ignore other cross-origin)
  if (!sameOrigin && !isCdn(url)) return;

  // 2) CDN: stale-while-revalidate
  if (isCdn(url)) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE);
        const cached = await cache.match(req);
        const fetchPromise = fetch(req)
          .then((res) => {
            if (res && res.ok) cache.put(req, res.clone());
            return res;
          })
          .catch(() => cached || null);
        // stale-while-revalidate: return cached immediately if exists, else wait for network
        return cached || fetchPromise;
      })()
    );
    return;
  }

  // 3) navigate: network-first -> cache -> offline.html
  if (isNavigationRequest(req)) {
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(req);
          // cache successful navigations for offline fallback
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        } catch (_) {
          const cached = await caches.match(req);
          if (cached) return cached;
          const offline = await caches.match(OFFLINE_URL);
          if (offline) return offline;
          // last resort
          return new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } });
        }
      })()
    );
    return;
  }

  // 4) static same-origin: cache-first dengan background update
  event.respondWith(
    (async () => {
      const cached = await caches.match(req);
      if (cached) {
        // background update: fetch and refresh cache without blocking
        event.waitUntil(
          (async () => {
            try {
              const res = await fetch(req);
              if (res && res.ok) {
                const cache = await caches.open(CACHE);
                await cache.put(req, res.clone());
              }
            } catch (_) {}
          })()
        );
        return cached;
      }
      // no cache -> network, then cache
      try {
        const res = await fetch(req);
        if (res && res.ok) {
          const cache = await caches.open(CACHE);
          await cache.put(req, res.clone());
        }
        return res;
      } catch (_) {
        // if fetch fails and no cache, try offline fallback for html-like?
        const offline = await caches.match(OFFLINE_URL);
        if (offline && req.headers.get('accept')?.includes('text/html')) return offline;
        throw _;
      }
    })()
  );
});
