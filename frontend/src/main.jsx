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
