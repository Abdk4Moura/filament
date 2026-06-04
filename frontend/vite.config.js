import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In dev: Vite serves the UI on :5173 with hot reload and proxies the API +
// websocket to Flask on :5000, so the app behaves as a single origin.
// In build: emits the default ./dist (frontend/dist) — Cloudflare serves it via
// wrangler.jsonc, and Flask serves it for local single-service runs.
export default defineConfig({
  plugins: [react()],
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
    proxy: {
      '/api': 'http://localhost:5000',
      '/socket.io': { target: 'http://localhost:5000', ws: true },
    },
  },
})
