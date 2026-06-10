// Filament service worker — offline app shell + runtime asset cache.
// Deliberately hands off anything dynamic: signaling (/socket.io), the API
// (/api), and cross-origin requests are never intercepted, so the P2P/WebRTC
// path is untouched. Bump CACHE to invalidate.
const CACHE = 'filament-v1'
const SHELL = ['/', '/index.html']

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (e) => {
  const req = e.request
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return // signaling/TURN/cross-origin
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/socket.io')) return

  // Navigations: network-first so updates land, fall back to the cached shell.
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).catch(() => caches.match('/index.html')))
    return
  }
  // Same-origin assets: cache-first, then network (and cache the result).
  e.respondWith(
    caches.match(req).then((hit) =>
      hit ||
      fetch(req).then((res) => {
        if (res && res.ok && res.type === 'basic') {
          const copy = res.clone()
          caches.open(CACHE).then((c) => c.put(req, copy))
        }
        return res
      }),
    ),
  )
})
