// DiagPanel: the link-diagnostics export affordance for the web shell. A small,
// theme-matched panel (portaled to body so it floats over either layout) that
// shows a compact LIVE status (route direct/relay, RTT, last event, buffered
// count) and lets a mobile user EXPORT the captured timeline after a blip via
// (a) Download, (b) Copy-to-clipboard, and (c) Send (through the existing tel.js
// sink). It is opened from a tiny floating button; the button itself only shows
// when capture is enabled (default-on, or ?diag=1), so it is unobtrusive.
//
// The export is a clean, self-contained JSON (see linkdiag.snapshot()): a header
// with userAgent, screen size, and the capture window, plus the timeline. The
// user filament-sends it back to themselves for analysis.
import { useEffect, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import * as linkdiag from '../lib/linkdiag.js'
import { tel, flush as telFlush } from '../lib/tel.js'

export default function DiagPanel({ T, accent, font }) {
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState(() => linkdiag.liveStatus())
  const [toast, setToast] = useState('')
  // Re-pull the compact live status on every recorded entry (cheap), so the
  // panel reflects route/RTT/last-event in real time while open.
  useEffect(() => {
    const refresh = () => setStatus(linkdiag.liveStatus())
    refresh()
    return linkdiag.subscribe(refresh)
  }, [])

  const flash = useCallback((m) => {
    setToast(m)
    setTimeout(() => setToast(''), 1600)
  }, [])

  const onDownload = useCallback(() => {
    const blob = new Blob([linkdiag.exportJson()], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'filament-linkdiag-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.json'
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    flash('downloaded')
  }, [flash])

  const onCopy = useCallback(async () => {
    const text = linkdiag.exportJson()
    try {
      await navigator.clipboard.writeText(text)
      flash('copied')
      return
    } catch {}
    // Fallback for contexts that block the async clipboard (common on mobile).
    try {
      const tmp = document.createElement('textarea')
      tmp.value = text
      tmp.style.position = 'fixed'
      tmp.style.opacity = '0'
      document.body.appendChild(tmp)
      tmp.focus()
      tmp.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(tmp)
      flash(ok ? 'copied' : 'copy blocked')
    } catch {
      flash('copy blocked')
    }
  }, [flash])

  // Send through the existing tel.js sink. We chunk the timeline into tel events
  // so the server-side sink receives it without a bespoke endpoint; the user can
  // still Download/Copy for the full clean blob.
  const onSend = useCallback(() => {
    const snap = linkdiag.snapshot()
    tel('linkdiag-header', { header: snap.header })
    for (let i = 0; i < snap.timeline.length; i += 25) {
      tel('linkdiag-chunk', { i, e: snap.timeline.slice(i, i + 25) })
    }
    telFlush()
    flash('sent to telemetry')
  }, [flash])

  if (!linkdiag.isEnabled()) return null

  const routeColor = status.route === 'relayed' ? T.warn : status.route ? T.ok : T.dim
  const lastTxt = status.last ? status.last.k : '-'

  const fab = (
    <button
      data-testid="diag-fab"
      onClick={() => setOpen((o) => !o)}
      title="link diagnostics"
      style={{
        position: 'fixed', right: 12, bottom: 12, zIndex: 9500,
        width: 40, height: 40, borderRadius: 20, cursor: 'pointer',
        display: 'grid', placeItems: 'center', fontSize: 16, lineHeight: 1,
        border: '1px solid ' + (accent + '66'), color: accent, background: T.panel,
        boxShadow: '0 2px 10px rgba(0,0,0,.4)', fontFamily: font,
      }}
    >
      {/* a small pulse-style glyph; doubles as a route-state dot */}
      <span style={{ width: 9, height: 9, borderRadius: 9, background: routeColor, boxShadow: '0 0 8px ' + routeColor }} />
    </button>
  )

  const panel = open ? (
    <div
      data-testid="diag-panel"
      style={{
        position: 'fixed', right: 12, bottom: 60, zIndex: 9600,
        width: 300, maxWidth: 'calc(100vw - 24px)',
        background: T.panel, color: T.text, fontFamily: font, fontSize: 12,
        border: '1px solid ' + T.line, borderRadius: 8,
        boxShadow: '0 8px 30px rgba(0,0,0,.5)', padding: 12,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <span style={{ width: 8, height: 8, borderRadius: 8, background: routeColor, boxShadow: '0 0 8px ' + routeColor }} />
        <span style={{ letterSpacing: '.04em' }}>LINK DIAGNOSTICS</span>
        <span style={{ marginLeft: 'auto', cursor: 'pointer', color: T.dim }} onClick={() => setOpen(false)}>✕</span>
      </div>

      {/* compact live status */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', rowGap: 5, columnGap: 10, color: T.sub, marginBottom: 12 }}>
        <span style={{ color: T.dim }}>route</span>
        <span data-testid="diag-route" style={{ color: routeColor }}>{status.route || '(none yet)'}</span>
        <span style={{ color: T.dim }}>rtt</span>
        <span data-testid="diag-rtt">{status.rttMs != null ? status.rttMs + ' ms' : '-'}</span>
        <span style={{ color: T.dim }}>events</span>
        <span data-testid="diag-count">{status.count}{status.dropped ? ' (+' + status.dropped + ' evicted)' : ''}</span>
        <span style={{ color: T.dim }}>last</span>
        <span data-testid="diag-last">{lastTxt}</span>
      </div>

      {/* export actions */}
      <div style={{ display: 'flex', gap: 8 }}>
        {[
          { l: 'Download', fn: onDownload, t: 'diag-download' },
          { l: 'Copy', fn: onCopy, t: 'diag-copy' },
          { l: 'Send', fn: onSend, t: 'diag-send' },
        ].map((b) => (
          <button
            key={b.l}
            data-testid={b.t}
            onClick={b.fn}
            style={{
              flex: 1, padding: '8px 6px', cursor: 'pointer', font: 'inherit', fontSize: 12,
              border: '1px solid ' + T.lineSoft, color: T.sub, background: 'transparent', borderRadius: 5,
            }}
          >
            {b.l}
          </button>
        ))}
      </div>

      {toast && (
        <div data-testid="diag-toast" style={{ marginTop: 10, fontSize: 11, color: accent, textAlign: 'center' }}>{toast}</div>
      )}
      <div style={{ marginTop: 10, fontSize: 10.5, color: T.dim, lineHeight: 1.4 }}>
        Capturing the last ~{linkdiag.isEnabled() ? '500' : '0'} link events. After a blip, Download or Copy and send it back.
      </div>
    </div>
  ) : null

  return createPortal(
    <>
      {fab}
      {panel}
    </>,
    document.body,
  )
}
