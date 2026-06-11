import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'

// Dev-only visual previews, gated by ?preview=… so the real app is untouched.
// Both roots are lazy so the preview never pulls App's module graph (signaling,
// firebase, etc.) and vice-versa.
const preview = new URLSearchParams(window.location.search).get('preview')
const Root = preview === 'terminal'
  ? React.lazy(() => import('./ui/TerminalPreview.jsx'))
  : preview === 'webterm'
  ? React.lazy(() => import('./ui/WebTermPreview.jsx'))
  : React.lazy(() => import('./App.jsx'))

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <React.Suspense fallback={null}>
      <Root />
    </React.Suspense>
  </React.StrictMode>,
)

// PWA: register the service worker only in production builds — in dev it would
// cache Vite's module graph and fight HMR.
//
// Deploy-freshness: a new deploy ships a new /sw.js (versioned cache name). We
// (1) register, (2) poll registration.update() on load + when the tab regains
// focus so a waiting SW is discovered promptly, (3) show a small on-theme
// "update ready — reload" nudge when a new SW is installed and waiting, and
// (4) auto-reload ONCE on controllerchange (the new SW taking control), guarded
// against the classic reload loop.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  const showUpdateNudge = (waitingSW) => {
    if (document.getElementById('fil-sw-update')) return
    const bar = document.createElement('div')
    bar.id = 'fil-sw-update'
    bar.setAttribute('role', 'status')
    bar.style.cssText = [
      'position:fixed', 'left:50%', 'bottom:18px', 'transform:translateX(-50%)',
      'z-index:9000', 'display:flex', 'align-items:center', 'gap:12px',
      'padding:9px 12px 9px 14px', 'background:#0F1113', 'color:#D9DEE3',
      'border:1px solid #1E2227', 'box-shadow:0 8px 30px rgba(0,0,0,.45)',
      "font:12px 'JetBrains Mono',ui-monospace,monospace", 'letter-spacing:.01em',
      'max-width:calc(100vw - 24px)',
    ].join(';')
    const dot = document.createElement('span')
    dot.style.cssText = 'width:7px;height:7px;background:#7CF6C8;box-shadow:0 0 7px #7CF6C8;flex:0 0 auto'
    const msg = document.createElement('span')
    msg.textContent = 'New version available'
    msg.style.cssText = 'white-space:nowrap'
    const btn = document.createElement('button')
    btn.textContent = 'reload'
    btn.style.cssText = [
      'font:inherit', 'cursor:pointer', 'padding:5px 11px', 'background:transparent',
      'color:#7CF6C8', 'border:1px solid #7CF6C8', 'letter-spacing:.04em',
    ].join(';')
    btn.onclick = () => {
      btn.disabled = true
      btn.textContent = 'updating…'
      // Ask the waiting SW to activate; controllerchange then reloads us once.
      if (waitingSW) waitingSW.postMessage({ type: 'SKIP_WAITING' })
      else window.location.reload()
    }
    bar.append(dot, msg, btn)
    document.body.appendChild(bar)
  }

  // Auto-reload ONCE when the new SW takes control (debounced against a loop).
  let reloaded = false
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloaded) return
    reloaded = true
    window.location.reload()
  })

  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((reg) => {
        // If a new SW is already waiting at register time, nudge immediately.
        if (reg.waiting && navigator.serviceWorker.controller) showUpdateNudge(reg.waiting)

        // A new SW found on this load — watch it install, then nudge.
        reg.addEventListener('updatefound', () => {
          const sw = reg.installing
          if (!sw) return
          sw.addEventListener('statechange', () => {
            // installed + an existing controller => an UPDATE (not first install)
            if (sw.state === 'installed' && navigator.serviceWorker.controller) {
              showUpdateNudge(reg.waiting || sw)
            }
          })
        })

        // Proactively check for a new SW now and whenever the tab refocuses, so
        // an existing install picks up a deploy within a normal reload/visit.
        const checkForUpdate = () => { reg.update().catch(() => {}) }
        checkForUpdate()
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') checkForUpdate()
        })
        window.addEventListener('focus', checkForUpdate)
      })
      .catch(() => {})
  })
}
