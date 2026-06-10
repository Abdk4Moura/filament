import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'

// Dev-only: receive in-page annotations (PNG + note) from AnnotationOverlay and
// drop them into frontend/.annotations/ so Claude can read what the user marked up.
const annotatorSink = {
  name: 'annotator-sink',
  apply: 'serve',
  configureServer(server) {
    server.middlewares.use('/__annotate', (req, res) => {
      if (req.method !== 'POST') { res.statusCode = 405; return res.end('POST only') }
      let body = ''
      req.on('data', (c) => { body += c; if (body.length > 30e6) req.destroy() })
      req.on('end', () => {
        try {
          const { png, note, url } = JSON.parse(body)
          const dir = path.resolve(process.cwd(), '.annotations')
          fs.mkdirSync(dir, { recursive: true })
          const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
          const b64 = String(png).replace(/^data:image\/png;base64,/, '')
          fs.writeFileSync(path.join(dir, `ann-${stamp}.png`), Buffer.from(b64, 'base64'))
          fs.writeFileSync(path.join(dir, `ann-${stamp}.txt`), `url: ${url || ''}\n\n${note || '(no note)'}\n`)
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ ok: true, file: `ann-${stamp}.png` }))
        } catch (e) {
          res.statusCode = 500; res.end(JSON.stringify({ ok: false, error: String(e) }))
        }
      })
    })
  },
}

// Dev-only: `firebase` is an optional signaling backend, imported dynamically in
// src/lib/signaling.js and externalized in the real build. It isn't installed,
// so Vite's dev transformer 500s when it pre-transforms that import. Resolve it
// to a harmless empty stub in dev (firebase mode is unused locally). No effect
// on the production build, which keeps externalizing firebase/*.
const stubFirebaseDev = {
  name: 'stub-firebase-dev',
  enforce: 'pre',
  apply: 'serve',
  resolveId(id) {
    if (id === 'firebase/app' || id === 'firebase/firestore') return '\0firebase-stub:' + id
  },
  load(id) {
    if (id.startsWith('\0firebase-stub:')) {
      return 'export const initializeApp=()=>({});export const getFirestore=()=>({});export default {};'
    }
  },
}

// In dev: Vite serves the UI on :5173 with hot reload and proxies the API +
// websocket to Flask on :5000, so the app behaves as a single origin.
// In build: emits the default ./dist (frontend/dist) — Cloudflare serves it via
// wrangler.jsonc, and Flask serves it for local single-service runs.
export default defineConfig({
  plugins: [stubFirebaseDev, annotatorSink, react()],
  build: {
    emptyOutDir: true,
    rollupOptions: {
      // Firebase is an optional, lazily-imported signaling backend. Keep it out
      // of the default build so it isn't required unless you opt into it.
      external: [/^firebase(\/|$)/],
    },
  },
  server: {
    port: 5173,
    // Allow reaching the dev server over Tailscale (host header is the tailnet
    // name/IP). `true` disables the host-allowlist check for local dev.
    host: true,
    allowedHosts: true,
    proxy: {
      '/api': 'http://localhost:5000',
      '/socket.io': { target: 'http://localhost:5000', ws: true },
    },
  },
})
