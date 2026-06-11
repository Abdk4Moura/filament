/* DeviceSheet — the per-device actions surface (design model H).
   A tile stays a file-send target (tap/click still sends); the secondary
   triggers (a tile `⋯` button and desktop right-click) open this sheet, which
   is the home for the per-device intents: Open terminal, Send files, Forget.

   Responsive, one component:
     - MOBILE: a bottom sheet — full-width, anchored to the bottom, with a scrim
       backdrop. Dismiss on backdrop tap, swipe-down, or Esc.
     - DESKTOP: an anchored popover positioned near the invoking tile. Dismiss on
       outside-click or Esc.

   Presentation only, on the app's tokens (theme T, density D, accent, font):
   dark, mono, hairline borders, square corners; accent used only on the primary
   affordance (Open terminal, when present). */

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

// Re-derive the same small pieces the tile shows, so the sheet header reads as
// the same device. Kept inline (no shared import) to avoid coupling the tile's
// internals; these are tiny and presentation-only.
function routeMeta(route, T) {
  if (route === 'local') return { label: 'LAN', color: T.ok }
  if (route === 'direct') return { label: 'P2P', color: T.recv }
  // relayed is the only route with a middleman on the wire — loud amber ⚠ + the
  // honest explainer (still E2E-encrypted). Wording mirrors Filament.jsx §3.5.
  if (route === 'relayed') return { label: '⚠ RELAY', color: T.warn, relay: true }
  return null
}

// The honest one-line relay explainer, shown in the sheet's Info section so the
// no-middleman caveat is legible on demand, not just a hover tooltip.
const RELAY_EXPLAINER =
  'Routed through a TURN server, not a direct link. Still end-to-end encrypted; the relay forwards bytes it can’t read.'

const PEER_STATUS_LABEL = { ready: 'ready', connecting: 'connecting', failed: 'unreachable', away: 'away — be right back' }

// A single tappable action row. ≥44px tall for touch; accent only when primary.
function ActionRow({ glyph, label, hint, onClick, tone, accent, T, danger, autoFocus }) {
  const [hov, setHov] = useState(false)
  const color = danger ? T.bad : tone === 'primary' ? accent : T.text
  const border = tone === 'primary' ? accent : T.line
  return (
    <button
      autoFocus={autoFocus}
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 11, width: '100%',
        minHeight: 46, padding: '11px 13px', cursor: 'pointer', textAlign: 'left',
        font: 'inherit', fontSize: 13, letterSpacing: '.01em',
        color, border: '1px solid ' + border,
        background: hov
          ? (tone === 'primary' ? accent + '14' : danger ? T.bad + '12' : (T.mode === 'light' ? 'rgba(0,0,0,.03)' : 'rgba(255,255,255,.03)'))
          : (tone === 'primary' ? accent + '0C' : 'transparent'),
        transition: 'background .12s, border-color .12s',
      }}
    >
      <span style={{ fontWeight: tone === 'primary' ? 700 : 500, fontSize: 13, width: 18, flexShrink: 0, textAlign: 'center', color }}>{glyph}</span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
        {hint && <span style={{ display: 'block', fontSize: 10.5, color: T.dim, marginTop: 2 }}>{hint}</span>}
      </span>
    </button>
  )
}

// A compact read-only info line: dim label on the left, value on the right.
function InfoLine({ label, value, color, T }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11, lineHeight: 1.5, minWidth: 0 }}>
      <span style={{ color: T.faint, letterSpacing: '.04em', flexShrink: 0 }}>{label}</span>
      <span style={{ marginLeft: 'auto', color: color || T.sub, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'right' }}>{value}</span>
    </div>
  )
}

export default function DeviceSheet({ peer, anchorRect, narrow, sendFirst, T, D, accent, font, onOpenShell, onSendFiles, onForget, onRename, onClose }) {
  const panelRef = useRef(null)
  const inp = useRef(null)
  const [dragY, setDragY] = useState(0) // mobile swipe-down offset
  const dragStart = useRef(null)

  const ready = peer.status === 'ready'
  const known = !!peer.known
  const displayName = peer.known || peer.verified || peer.name
  const showShell = ready && known && peer.shell && onOpenShell
  const canForget = !!peer.known && !!onForget // forget is keyed by the stored petname
  // Rename edits the stored petname — keyed by peer.known (the current label),
  // so it's offered only for a remembered device with a rename handler wired.
  const canRename = !!peer.known && !!onRename
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(displayName)
  const nameInp = useRef(null)
  useEffect(() => { if (editing && nameInp.current) { nameInp.current.focus(); nameInp.current.select() } }, [editing])
  const commitRename = () => {
    const next = draft.trim()
    if (next && next !== peer.known) onRename(peer.known, next)
    setEditing(false)
  }
  const sc = ready ? T.ok : peer.status === 'connecting' || peer.status === 'away' ? T.warn : T.bad
  const rm = routeMeta(peer.route, T)

  // Esc to close; outside-click (desktop) / backdrop (mobile) handled on the scrim.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const openPicker = () => { if (inp.current) inp.current.click() }

  const header = (
    <div style={{ padding: '14px 14px 12px', borderBottom: '1px solid ' + T.line }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
        <span style={{ width: 14, height: 14, background: peer.color, display: 'block', flexShrink: 0 }} />
        <span style={{ fontSize: D.dispName, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, minWidth: 0 }}>{displayName}</span>
        {known && (
          <span style={{ fontSize: 8.5, letterSpacing: '.1em', color: accent, border: '1px dashed ' + accent, padding: '2px 5px', whiteSpace: 'nowrap', flexShrink: 0 }}>REMEMBERED</span>
        )}
        {peer.shell && (
          <span style={{ fontSize: 8.5, letterSpacing: '.1em', color: accent, border: '1px solid ' + accent, padding: '2px 5px', whiteSpace: 'nowrap', flexShrink: 0 }}>SHELL</span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 9, fontSize: 11, color: T.dim }}>
        {rm && <span style={{ color: rm.color, letterSpacing: '.06em' }}>{rm.label}</span>}
        <span style={{ width: 6, height: 6, background: sc, display: 'block', boxShadow: ready ? '0 0 6px ' + sc : 'none' }} />
        <span style={{ color: sc }}>{PEER_STATUS_LABEL[peer.status] || peer.status}</span>
        {peer.lastSeen && <span style={{ marginLeft: 'auto', color: T.faint }}>{peer.lastSeen}</span>}
      </div>
    </div>
  )

  // Read-only "Info": the same facts the tile derives, gathered in one place.
  // Compact, on-theme; only shows fields the peer actually carries.
  const info = (
    <div style={{ padding: '10px 13px', borderTop: '1px solid ' + T.lineSoft, display: 'flex', flexDirection: 'column', gap: 5 }}>
      <div style={{ fontSize: 9, letterSpacing: '.14em', color: T.faint, marginBottom: 3 }}>INFO</div>
      {rm && <InfoLine label="route" value={rm.label} color={rm.color} T={T} />}
      {/* Relay honesty: the route line alone is terse — when relayed, spell out
          the no-middleman caveat in plain language right under it (still E2E). */}
      {rm && rm.relay && (
        <div data-testid="sheet-relay-explainer" style={{
          fontSize: 10.5, lineHeight: 1.5, color: T.warn,
          border: '1px solid ' + T.warn,
          background: T.mode === 'light' ? 'rgba(154,107,0,.08)' : 'rgba(255,200,87,.10)',
          padding: '7px 9px', marginTop: 2, marginBottom: 2,
        }}>
          {RELAY_EXPLAINER}
        </div>
      )}
      <InfoLine label="status" value={PEER_STATUS_LABEL[peer.status] || peer.status} color={sc} T={T} />
      <InfoLine label="shell" value={peer.shell ? 'capable' : 'no'} color={peer.shell ? accent : T.sub} T={T} />
      {known && <InfoLine label="paired" value="remembered" color={accent} T={T} />}
      {peer.lastSeen && <InfoLine label="last seen" value={peer.lastSeen} T={T} />}
    </div>
  )

  const rows = (
    <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 9 }}>
      <input ref={inp} type="file" multiple style={{ display: 'none' }}
        onChange={(e) => { if (e.target.files.length) { onSendFiles(peer.id, e.target.files); onClose() } e.target.value = '' }} />
      {/* Row order is context-driven (tile-interaction-v2 §5): when the sheet is
          the PRIMARY surface (mobile, sendFirst) Send must lead — first, accent,
          auto-focused so the second tap is immediate. Otherwise (desktop, where a
          tile click already sends) keep terminal-first, the action you came for. */}
      {sendFirst ? (
        <>
          <ActionRow glyph="⇪" label="Send files" hint="pick files to send" tone="primary" autoFocus
            accent={accent} T={T} onClick={openPicker} />
          {showShell && (
            <ActionRow glyph="›_" label="Open terminal" hint={`a shell on ${displayName}`}
              accent={accent} T={T} onClick={() => { onClose(); onOpenShell(peer) }} />
          )}
        </>
      ) : (
        <>
          {showShell && (
            <ActionRow glyph="›_" label="Open terminal" hint={`a shell on ${displayName}`} tone="primary"
              accent={accent} T={T} onClick={() => { onClose(); onOpenShell(peer) }} />
          )}
          <ActionRow glyph="⇪" label="Send files" hint="pick files to send" accent={accent} T={T}
            onClick={openPicker} />
        </>
      )}
      {canRename && (
        editing ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '6px 4px' }}>
            <input
              ref={nameInp}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') { e.preventDefault(); commitRename() }
                // swallow Esc so the sheet's document-level listener doesn't close
                // the whole sheet — Esc just cancels the rename.
                if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setDraft(displayName); setEditing(false) }
              }}
              placeholder="device name"
              style={{
                flex: 1, minWidth: 0, font: 'inherit', fontSize: 13, padding: '9px 10px',
                background: T.bg, color: T.text, border: '1px solid ' + accent, outline: 'none',
              }}
            />
            <button onClick={commitRename} title="save name" style={{
              flexShrink: 0, font: 'inherit', fontSize: 12, padding: '9px 12px', cursor: 'pointer',
              background: accent, color: T.onAccent, border: '1px solid ' + accent }}>save</button>
            <button onClick={() => { setDraft(displayName); setEditing(false) }} title="cancel" style={{
              flexShrink: 0, font: 'inherit', fontSize: 12, padding: '9px 11px', cursor: 'pointer',
              background: 'transparent', color: T.dim, border: '1px solid ' + T.line }}>✕</button>
          </div>
        ) : (
          <ActionRow glyph="✎" label="Rename" hint="edit this device's name" accent={accent} T={T}
            onClick={() => { setDraft(displayName); setEditing(true) }} />
        )
      )}
      {canForget && (
        <ActionRow glyph="⊘" label="Forget device" hint="stop auto-reconnecting" danger accent={accent} T={T}
          onClick={() => { onForget(peer.known); onClose() }} />
      )}
    </div>
  )

  // ── Mobile: bottom sheet ───────────────────────────────────────
  if (narrow) {
    const onTouchStart = (e) => { dragStart.current = e.touches[0].clientY }
    const onTouchMove = (e) => {
      if (dragStart.current == null) return
      const dy = e.touches[0].clientY - dragStart.current
      if (dy > 0) setDragY(dy)
    }
    const onTouchEnd = () => {
      if (dragY > 70) onClose()
      else setDragY(0)
      dragStart.current = null
    }
    return createPortal(
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 4500, background: 'rgba(0,0,0,.45)', display: 'flex', alignItems: 'flex-end', font: '13px ' + font }}>
        <div
          ref={panelRef}
          onClick={(e) => e.stopPropagation()}
          style={{
            width: '100%', background: T.panel, borderTop: '1px solid ' + T.line,
            transform: 'translateY(' + dragY + 'px)', transition: dragStart.current == null ? 'transform .18s ease-out' : 'none',
            paddingBottom: 'env(safe-area-inset-bottom, 8px)',
            boxShadow: '0 -12px 40px rgba(0,0,0,.4)',
          }}
        >
          <div onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}
            style={{ padding: '9px 0 4px', display: 'flex', justifyContent: 'center', cursor: 'grab', touchAction: 'none' }}>
            <span style={{ width: 36, height: 4, background: T.line, display: 'block' }} />
          </div>
          {header}
          {rows}
          {info}
        </div>
      </div>,
      document.body,
    )
  }

  // ── Desktop: anchored popover ──────────────────────────────────
  // Anchor near the invoking tile; clamp into the viewport so it never clips.
  const W = 268
  const vw = typeof window !== 'undefined' ? window.innerWidth : 1280
  const vh = typeof window !== 'undefined' ? window.innerHeight : 800
  let left = anchorRect ? anchorRect.left : 80
  let top = anchorRect ? anchorRect.bottom + 6 : 80
  if (left + W > vw - 12) left = Math.max(12, (anchorRect ? anchorRect.right : vw) - W)
  // Rough height guess for flip-up when near the bottom edge.
  const estH = 92 + (showShell ? 68 : 0) + 68 + (canRename ? 68 : 0) + (canForget ? 68 : 0) + 120 /* info block */
  if (top + estH > vh - 12 && anchorRect) top = Math.max(12, anchorRect.top - estH - 6)

  return createPortal(
    <div onClick={onClose} onContextMenu={(e) => { e.preventDefault(); onClose() }}
      style={{ position: 'fixed', inset: 0, zIndex: 4500, font: '13px ' + font }}>
      <div
        ref={panelRef}
        onClick={(e) => e.stopPropagation()}
        style={{
          position: 'absolute', left, top, width: W,
          background: T.panel, border: '1px solid ' + T.line,
          boxShadow: '0 14px 44px rgba(0,0,0,.45)',
        }}
      >
        {header}
        {rows}
        {info}
      </div>
    </div>,
    document.body,
  )
}
