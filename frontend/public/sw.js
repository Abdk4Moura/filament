// Filament service worker — offline app shell + runtime asset cache.
// Deliberately hands off anything dynamic: signaling (/socket.io), the API
// (/api), and cross-origin requests are never intercepted, so the P2P/WebRTC
// path is untouched.
//
// Cache strategy (deploy-safe, never pins a stale bundle):
//   - VERSIONED cache name (BUILD_ID is stamped in at build time by the
//     sw-version Vite plugin). On `activate` we delete every cache that isn't
//     the current build, so a new deploy can't keep serving old entries forever.
//   - skipWaiting() on install + clients.claim() on activate, so a freshly
//     deployed SW takes control immediately instead of waiting for every tab to
//     close.
//   - Navigations + the entry HTML (/, /index.html): NETWORK-FIRST, so the
//     freshest index.html — which references the new content-hashed bundles —
//     is always fetched when online (cached shell is only the offline fallback).
//   - Content-hashed assets (/assets/*-<hash>.js|css, fonts, icons, images):
//     CACHE-FIRST. They're immutable (the hash changes on every change), so
//     caching them long is safe and fast.
//   - /api + /socket.io (+ cross-origin: TURN/signaling): NEVER intercepted.
const BUILD_ID = '__BUILD_ID__'
const CACHE = 'filament-' + BUILD_ID
const SHELL = ['/', '/index.html']

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => c.addAll(SHELL))
      .catch(() => {})
      .then(() => self.skipWaiting()),
  )
})

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  )
})

// Let the page ask a waiting SW to activate now (the "update ready — reload"
// nudge posts {type:'SKIP_WAITING'} so the user's refresh lands on the new SW).
self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting()
})

function isHashedAsset(url) {
  // Vite emits content-hashed files under /assets/ — immutable, safe to cache
  // first. Fonts/icons/images are effectively immutable too.
  if (url.pathname.startsWith('/assets/')) return true
  return /\.(?:js|css|woff2?|ttf|otf|png|jpg|jpeg|gif|svg|webp|ico|wasm)$/.test(url.pathname)
}

self.addEventListener('fetch', (e) => {
  const req = e.request
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return // signaling/TURN/cross-origin
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/socket.io')) return

  // Navigations + the entry HTML: NETWORK-FIRST so a new deploy's index.html
  // (pointing at the new hashed bundles) is fetched whenever online; fall back
  // to the cached shell offline. Refresh the cached copy on every online hit.
  const isEntryHtml = url.pathname === '/' || url.pathname === '/index.html'
  if (req.mode === 'navigate' || isEntryHtml) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok && res.type === 'basic') {
            const copy = res.clone()
            caches.open(CACHE).then((c) => c.put('/index.html', copy)).catch(() => {})
          }
          return res
        })
        .catch(() => caches.match(req).then((hit) => hit || caches.match('/index.html'))),
    )
    return
  }

  // Content-hashed assets: cache-first, then network (and cache the result).
  if (isHashedAsset(url)) {
    e.respondWith(
      caches.match(req).then((hit) =>
        hit ||
        fetch(req).then((res) => {
          if (res && res.ok && res.type === 'basic') {
            const copy = res.clone()
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {})
          }
          return res
        }),
      ),
    )
    return
  }

  // Everything else same-origin (e.g. /manifest.webmanifest, /about.html):
  // network-first with a cache fallback, so it's fresh when online but still
  // works offline.
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok && res.type === 'basic') {
          const copy = res.clone()
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {})
        }
        return res
      })
      .catch(() => caches.match(req)),
  )
})
