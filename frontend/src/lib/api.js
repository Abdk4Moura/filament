// Where the backend (signaling + REST) lives.
//
// Single-service / dev: leave VITE_FILAMENT_API unset → same origin (the Vite
// dev proxy or the Flask app forward /api and /socket.io locally).
// Split deploy (Cloudflare Pages + droplet): set VITE_FILAMENT_API at build time
// to the backend origin, e.g. https://api.filament.example.com — every REST call
// and the Socket.IO connection target it.
export const API_BASE = (import.meta.env.VITE_FILAMENT_API || '').replace(/\/$/, '')

export const api = (path) => `${API_BASE}${path}`
