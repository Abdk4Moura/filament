/* Filament — polished "Terminal" presentation component.
   Ported from the Claude Design handoff (Variant A · Terminal). Presentation
   only: driven by `state` + callbacks whose names match useFilament(). An
   optional `ui` prop carries display options (theme/accent/density/columns/font);
   omit it for sensible defaults (dark / green / airy). */

import { useState, useRef, useCallback, useEffect } from 'react'

// ---- data helpers (inlined from the handoff's data.js) --------------------
function formatBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return n + ' B'
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do {
    n /= 1024
    i++
  } while (n >= 1024 && i < u.length - 1)
  return (n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i]
}

function fileTag(t) {
  const ext = (t.name.split('.').pop() || '').toUpperCase()
  return ext.length <= 4 ? ext : (t.mime.split('/').pop() || 'FILE').toUpperCase()
}

const STATUS_LABEL = {
  offered: 'offered',
  transferring: 'transferring',
  paused: 'paused',
  complete: 'complete',
  declined: 'declined',
  failed: 'failed',
}
const PEER_STATUS_LABEL = { ready: 'ready', connecting: 'connecting', failed: 'unreachable', away: 'away — be right back' }

// ---- theme system ----------------------------------------------------------
const MONOS = {
  jetbrains: "'JetBrains Mono',ui-monospace,monospace",
  plex: "'IBM Plex Mono',ui-monospace,monospace",
  space: "'Space Mono',ui-monospace,monospace",
}

const ACCENTS = {
  green: { d: '#7CF6C8', l: '#0C8A60' },
  cyan: { d: '#5BE7FF', l: '#0B7C93' },
  amber: { d: '#FFC857', l: '#9A6B00' },
  magenta: { d: '#FF8AD6', l: '#A11890' },
}

function makeTheme(mode, accent) {
  if (mode === 'light') {
    return {
      mode, accent,
      bg: '#F1EFE9', panel: '#FAF8F3', panel2: '#F5F2EB',
      line: '#DEDACF', lineSoft: '#E9E5DB', grid: '#E7E3D9',
      text: '#191A1B', sub: '#54574F', dim: '#7C7E74', faint: '#AAA89C',
      ok: '#0C8A60', warn: '#9A6B00', bad: '#C0322B', recv: '#1F5FC0',
      onAccent: '#0B1116',
    }
  }
  return {
    mode, accent,
    bg: '#0A0B0C', panel: '#0F1113', panel2: '#0C0E10',
    line: '#1E2227', lineSoft: '#15181C', grid: '#121417',
    text: '#D9DEE3', sub: '#9AA1A8', dim: '#666C73', faint: '#3C424A',
    ok: '#7CF6C8', warn: '#FFC857', bad: '#E5484D', recv: '#5B9DFF',
    onAccent: '#06120D',
  }
}

const DENS = {
  airy: { pad: 24, gap: 14, tilePad: 16, rowPad: 14, name: 14, dispName: 15 },
  cozy: { pad: 18, gap: 12, tilePad: 13, rowPad: 12, name: 13.5, dispName: 14 },
  compact: { pad: 13, gap: 9, tilePad: 10, rowPad: 10, name: 13, dispName: 13 },
}

function useCopied() {
  const [hit, setHit] = useState(false)
  const fire = useCallback((fn) => {
    try {
      fn && fn()
    } catch (e) {}
    setHit(true)
    setTimeout(() => setHit(false), 1300)
  }, [])
  return [hit, fire]
}

function StatusDot({ color, glow }) {
  return <span style={{ width: 7, height: 7, background: color, display: 'block', boxShadow: glow ? '0 0 7px ' + color : 'none' }} />
}

function routeMeta(route, T) {
  if (route === 'local') return { label: 'LAN', color: T.ok, tip: 'files go straight across your WiFi' }
  if (route === 'direct') return { label: 'P2P', color: T.recv, tip: 'peer-to-peer over the internet' }
  if (route === 'relayed') return { label: 'RELAY', color: T.warn, tip: 'via a relay' }
  return null
}

function RouteBadge({ route, T }) {
  const m = routeMeta(route, T)
  if (!m) return null
  const premium = route === 'local'
  return (
    <span title={m.tip} style={{
      display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9.5, letterSpacing: '.08em',
      padding: '2px 5px', border: '1px solid ' + (premium ? m.color : T.line),
      background: premium ? (T.mode === 'light' ? 'rgba(12,138,96,.10)' : 'rgba(124,246,200,.12)') : 'transparent',
      color: premium ? m.color : T.sub, cursor: 'default', whiteSpace: 'nowrap',
    }}>
      <span style={{ width: 12, height: 2, background: m.color, display: 'block', boxShadow: premium ? '0 0 6px ' + m.color : 'none' }} />{m.label}
    </span>
  )
}

function PeerTile({ peer, onSendFiles, T, D, accent }) {
  const ready = peer.status === 'ready'
  const [over, setOver] = useState(false)
  const [hov, setHov] = useState(false)
  const inp = useRef(null)
  // 'away' (C21): the peer announced a benign absence (e.g. it is choosing a
  // file on a phone) — amber, calm, explicitly not an error.
  const sc = ready ? T.ok : peer.status === 'connecting' || peer.status === 'away' ? T.warn : T.bad
  return (
    <div
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      onClick={() => ready && inp.current && inp.current.click()}
      onDragOver={(e) => { if (ready) { e.preventDefault(); setOver(true) } }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); if (ready && e.dataTransfer.files.length) onSendFiles(peer.id, e.dataTransfer.files) }}
      style={{
        position: 'relative', aspectRatio: '1 / 1', minWidth: 0,
        background: over ? (T.mode === 'light' ? '#EAF7F1' : '#0E1A16') : T.panel,
        border: '1px solid ' + (over ? accent : hov && ready ? T.text : T.line),
        padding: D.tilePad, display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
        cursor: ready ? 'pointer' : 'default', opacity: ready ? 1 : 0.4,
        transition: 'border-color .12s, background .12s, transform .12s',
        transform: hov && ready ? 'translateY(-2px)' : 'none',
      }}
    >
      <input ref={inp} type="file" multiple style={{ display: 'none' }}
        onChange={(e) => { if (e.target.files.length) onSendFiles(peer.id, e.target.files); e.target.value = '' }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 6 }}>
        <span style={{ width: 14, height: 14, background: peer.color, display: 'block', flexShrink: 0 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
          {peer.route && <RouteBadge route={peer.route} T={T} />}
          <StatusDot color={sc} glow={ready} />
        </div>
      </div>
      <div>
        <div style={{ fontSize: D.name, color: T.text, letterSpacing: '-.01em', marginBottom: 5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{peer.name}</div>
        <div style={{ fontSize: 10.5, display: 'flex', justifyContent: 'space-between', color: T.dim }}>
          <span style={{ color: sc }}>{PEER_STATUS_LABEL[peer.status]}</span>
          <span>{peer.lastSeen}</span>
        </div>
        <div style={{ fontSize: 10, color: ready ? (hov ? accent : T.faint) : T.faint, marginTop: 8, height: 12, transition: 'color .12s' }}>
          {ready ? (over ? 'release to send' : hov ? '↳ drop or click to send' : 'click · drop to send') : '—'}
        </div>
      </div>
    </div>
  )
}

function Bar({ p, color, T, animate }) {
  return (
    <div style={{ height: 4, background: T.lineSoft, position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', inset: 0, width: Math.max(0, Math.min(1, p)) * 100 + '%', background: color, transition: 'width .3s linear',
        backgroundImage: animate ? 'linear-gradient(90deg,' + color + ' 0 60%,rgba(255,255,255,.45) 80%,' + color + ' 100%)' : 'none',
        backgroundSize: '200% 100%', animation: animate ? 'filShimmer 1.4s linear infinite' : 'none' }} />
    </div>
  )
}

function TransferRow({ t, onAccept, onDecline, onSave, onClear, T, D, accent }) {
  const recv = t.direction === 'receive'
  const sc = t.status === 'complete' ? T.ok : t.status === 'failed' ? T.bad : t.status === 'declined' ? T.dim : T.warn
  const btn = (label, fn, tone) => (
    <button onClick={fn} style={{
      font: 'inherit', fontSize: 11, padding: '5px 11px', cursor: 'pointer', background: 'transparent',
      color: tone, border: '1px solid ' + tone, transition: 'background .1s,color .1s',
    }}
      onMouseEnter={(e) => { e.currentTarget.style.background = tone; e.currentTarget.style.color = T.mode === 'light' ? '#fff' : T.onAccent }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = tone }}
    >{label}</button>
  )
  const active = t.status === 'transferring'
  return (
    <div style={{ borderBottom: '1px solid ' + T.lineSoft, padding: D.rowPad + 'px 0' }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
        <span style={{ color: recv ? T.recv : T.ok, fontSize: 13, width: 10 }}>{recv ? '↓' : '↑'}</span>
        <span style={{ flex: 1, fontSize: 13, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{t.name}</span>
        <span style={{ fontSize: 11, color: T.dim, whiteSpace: 'nowrap' }}>{formatBytes(t.size)}</span>
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', margin: '8px 0 9px', fontSize: 10.5, color: T.dim }}>
        <span style={{ color: T.faint, border: '1px solid ' + T.line, padding: '1px 5px' }}>{fileTag(t)}</span>
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{recv ? 'from ' : 'to '}{t.peerName}</span>
        <span style={{ marginLeft: 'auto', color: sc, whiteSpace: 'nowrap' }}>{STATUS_LABEL[t.status]}{active ? ' ' + Math.round(t.progress * 100) + '%' : ''}</span>
      </div>
      {(active || t.status === 'failed' || t.status === 'paused') && <Bar p={t.progress} color={t.status === 'failed' ? T.bad : accent} T={T} animate={active} />}
      <div style={{ display: 'flex', gap: 8, marginTop: active || t.status === 'failed' || t.status === 'paused' ? 11 : 0, flexWrap: 'wrap' }}>
        {recv && t.status === 'offered' && (<>{btn('accept', () => onAccept(t.id), T.ok)}{btn('decline', () => onDecline(t.id), T.bad)}</>)}
        {recv && t.status === 'complete' && btn('save', () => onSave(t.id), accent)}
        {!recv && t.status === 'offered' && <span style={{ fontSize: 11, color: T.dim }}>waiting for accept…</span>}
        {t.status === 'paused' && <span style={{ fontSize: 11, color: T.dim }}>paused — resumes on reconnect</span>}
        {(t.status === 'complete' || t.status === 'declined' || t.status === 'failed' || t.status === 'paused') && btn('clear', () => onClear(t.id), T.dim)}
      </div>
    </div>
  )
}

function Pill({ children, T }) {
  return <span style={{ fontSize: 10.5, color: T.dim, border: '1px solid ' + T.line, padding: '2px 7px', whiteSpace: 'nowrap' }}>{children}</span>
}

function LanChip({ localHelper, T }) {
  if (!localHelper || !localHelper.available) return null
  const n = (localHelper.peers || []).length
  const names = (localHelper.peers || []).map((p) => p.name + ' · ' + p.addr).join('\n')
  return (
    <span title={names} style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 11, color: T.dim, whiteSpace: 'nowrap', cursor: 'default' }}>
      <span style={{ color: T.ok, fontSize: 12 }}>◇</span>
      <span><span style={{ color: T.sub }}>{n} on your LAN</span> · offline-ready</span>
    </span>
  )
}

function DiscoveryBar({ state, onPairWithCode, onGenerateCode, onUseAutoRoom, onCopyRoomLink, T, D, accent }) {
  const scope = state.roomScope || 'link'
  const [copied, fireCopy] = useCopied()
  const [entering, setEntering] = useState(false)
  const [code, setCode] = useState('')

  const ghostBtn = (label, fn, primary) => (
    <button onClick={fn} style={{
      font: 'inherit', fontSize: 11, padding: '7px 12px', cursor: 'pointer', whiteSpace: 'nowrap',
      background: primary ? accent : 'transparent', color: primary ? T.onAccent : T.text,
      border: '1px solid ' + (primary ? accent : T.line),
    }}>{label}</button>
  )

  const submitCode = () => { const c = code.trim(); if (c) { onPairWithCode(c); setCode(''); setEntering(false) } }

  const wrap = {
    border: '1px solid ' + T.line, background: T.panel, padding: '12px ' + D.tilePad + 'px',
    marginBottom: 16, display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', minHeight: 56,
  }

  if (scope === 'code') {
    return (
      <div style={{ ...wrap, flexDirection: 'column', flexWrap: 'nowrap', alignItems: 'stretch', gap: 10 }}>
        <span style={{ fontSize: 9.5, letterSpacing: '.14em', color: T.dim, whiteSpace: 'nowrap' }}>ONE-TIME CODE · SAY IT ALOUD · WORKS ONCE</span>
        <span style={{ width: '100%', flexShrink: 0, fontSize: 'clamp(26px,3.2vw,38px)', lineHeight: 1.1, letterSpacing: '.14em', color: T.text, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{state.roomCode}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <LanChip localHelper={state.localHelper} T={T} />
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={() => fireCopy(() => { try { navigator.clipboard.writeText(state.roomCode) } catch (e) {} })} style={{
              font: 'inherit', fontSize: 11, padding: '7px 12px', cursor: 'pointer', whiteSpace: 'nowrap',
              background: copied ? accent : 'transparent', color: copied ? T.onAccent : accent, border: '1px solid ' + accent }}>{copied ? 'copied ✓' : 'copy code'}</button>
            {ghostBtn('← back to nearby', onUseAutoRoom)}
          </div>
        </div>
      </div>
    )
  }

  if (scope === 'pair') {
    return (
      <div style={wrap}>
        <span style={{ fontSize: 13, color: T.text, whiteSpace: 'nowrap' }}>Paired privately</span>
        <Pill T={T}>one-time code · burned</Pill>
        <LanChip localHelper={state.localHelper} T={T} />
        <span style={{ marginLeft: 'auto' }}>{ghostBtn('← back to nearby', onUseAutoRoom)}</span>
      </div>
    )
  }

  if (scope === 'link') {
    return (
      <div style={{ ...wrap, flexDirection: 'column', flexWrap: 'nowrap', alignItems: 'stretch', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: T.sub, whiteSpace: 'nowrap' }}>Share room link</span>
          <span style={{ flex: 1, minWidth: 160, fontSize: 11, color: accent, border: '1px solid ' + T.line, padding: '7px 10px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', background: T.bg }}>{state.roomUrl}</span>
          <button onClick={() => fireCopy(onCopyRoomLink)} style={{ font: 'inherit', fontSize: 11, padding: '7px 12px', cursor: 'pointer', whiteSpace: 'nowrap', background: 'transparent', color: accent, border: '1px solid ' + accent }}>{copied ? 'copied ✓' : 'copy link'}</button>
          <LanChip localHelper={state.localHelper} T={T} />
        </div>
        {/* Codes work from ANY room — minting is additive (the claimer joins
            THIS room) — so the affordance belongs here too, not just in auto. */}
        {entering ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <input autoFocus value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') submitCode(); if (e.key === 'Escape') { setEntering(false); setCode('') } }}
              placeholder="ENTER CODE" style={{ font: 'inherit', fontSize: 12, letterSpacing: '.1em', textTransform: 'uppercase', padding: '7px 10px', flex: 1, minWidth: 130,
                background: T.bg, color: T.text, border: '1px solid ' + accent, outline: 'none' }} />
            {ghostBtn('pair', submitCode, true)}
            {ghostBtn('cancel', () => { setEntering(false); setCode('') })}
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {ghostBtn('pair with code', () => setEntering(true))}
            {ghostBtn('create code', onGenerateCode, true)}
          </div>
        )}
      </div>
    )
  }

  // scope === "auto"
  return (
    <div style={{ ...wrap, flexDirection: 'column', flexWrap: 'nowrap', alignItems: 'stretch', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13, color: T.text, whiteSpace: 'nowrap' }}>People near you</span>
        {state.network && <Pill T={T}>{state.network}</Pill>}
        <div style={{ marginLeft: 'auto' }}><LanChip localHelper={state.localHelper} T={T} /></div>
      </div>
      {entering ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <input autoFocus value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') submitCode(); if (e.key === 'Escape') { setEntering(false); setCode('') } }}
            placeholder="ENTER CODE" style={{ font: 'inherit', fontSize: 12, letterSpacing: '.1em', textTransform: 'uppercase', padding: '7px 10px', flex: 1, minWidth: 130,
              background: T.bg, color: T.text, border: '1px solid ' + accent, outline: 'none' }} />
          {ghostBtn('pair', submitCode, true)}
          {ghostBtn('cancel', () => { setEntering(false); setCode('') })}
        </div>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {ghostBtn('pair with code', () => setEntering(true))}
          {ghostBtn('create code', onGenerateCode, true)}
        </div>
      )}
    </div>
  )
}

export default function Filament(props) {
  const { state, onSendFiles, onAccept, onDecline, onSave, onClear, onCopyRoomLink,
    onPairWithCode, onGenerateCode, onUseAutoRoom, ui = {} } = props
  const mode = ui.theme === 'light' ? 'light' : 'dark'
  const accentSet = ACCENTS[ui.accent] || ACCENTS.green
  const accent = accentSet[mode === 'light' ? 'l' : 'd']
  const T = makeTheme(mode, accent)
  const D = DENS[ui.density] || DENS.airy
  const font = MONOS[ui.font] || ui.font || MONOS.jetbrains
  const cols = ui.columns && ui.columns !== 'auto' ? 'repeat(' + ui.columns + ',minmax(0,1fr))' : 'repeat(auto-fill,minmax(150px,1fr))'

  const [copied, fireCopy] = useCopied()
  const hasPeers = state.peers.length > 0
  const onToggleTheme = ui.onToggleTheme

  // Responsive: measure our own width so the same component works on desktop
  // and inside a phone frame. ui.forceMobile lets a host pin the mobile layout.
  const rootRef = useRef(null)
  const [narrow, setNarrow] = useState(!!ui.forceMobile)
  const [tab, setTab] = useState('peers')
  useEffect(() => {
    if (ui.forceMobile) {
      setNarrow(true)
      return
    }
    const el = rootRef.current
    if (!el) return
    const measure = () => setNarrow(el.clientWidth < 720)
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [ui.forceMobile])

  const themeBtn = onToggleTheme && (
    <button onClick={onToggleTheme} title="Toggle theme" style={{ font: 'inherit', fontSize: 11, padding: '6px 10px', cursor: 'pointer', whiteSpace: 'nowrap',
      background: 'transparent', color: T.sub, border: '1px solid ' + T.line }}>
      {mode === 'light' ? '◑ dark' : '◐ light'}
    </button>
  )

  const copyBtn = (label) => (
    <button onClick={() => fireCopy(onCopyRoomLink)} style={{ font: 'inherit', fontSize: 11, padding: '6px 12px', cursor: 'pointer', whiteSpace: 'nowrap',
      background: copied ? accent : 'transparent', color: copied ? T.onAccent : accent, border: '1px solid ' + accent, transition: 'background .12s,color .12s' }}>
      {copied ? 'copied ✓' : label}
    </button>
  )

  const emptyPeers = (
    <div style={{ border: '1px dashed ' + T.line, padding: narrow ? 20 : 28, color: T.dim, maxWidth: 560 }}>
      <div style={{ color: T.text, fontSize: 15, marginBottom: 8 }}>No threads yet</div>
      <div style={{ fontSize: 12, lineHeight: 1.6, marginBottom: 18 }}>Share the room link to spin up a thread. Anyone who opens it joins room {state.roomId} and appears here.</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <span style={{ flex: 1, fontSize: 11, color: accent, border: '1px solid ' + T.line, padding: '9px 11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', background: T.panel }}>{state.roomUrl}</span>
        <button onClick={() => fireCopy(onCopyRoomLink)} style={{ font: 'inherit', fontSize: 11, padding: '0 14px', cursor: 'pointer', background: 'transparent', color: accent, border: '1px solid ' + accent }}>{copied ? 'copied ✓' : 'copy'}</button>
      </div>
    </div>
  )

  const peerGrid = (gridCols) =>
    hasPeers ? (
      <div style={{ display: 'grid', gridTemplateColumns: gridCols, gap: D.gap }}>
        {state.peers.map((p) => <PeerTile key={p.id} peer={p} onSendFiles={onSendFiles} T={T} D={D} accent={accent} />)}
      </div>
    ) : (
      emptyPeers
    )

  const transfersList =
    state.transfers.length === 0 ? (
      <div style={{ fontSize: 12, color: T.faint, padding: '24px 0' }}>No transfers yet.</div>
    ) : (
      state.transfers.map((t) => <TransferRow key={t.id} t={t} onAccept={onAccept} onDecline={onDecline} onSave={onSave} onClear={onClear} T={T} D={D} accent={accent} />)
    )

  const discovery = (
    <DiscoveryBar state={state} onPairWithCode={onPairWithCode || (() => {})} onGenerateCode={onGenerateCode || (() => {})}
      onUseAutoRoom={onUseAutoRoom || (() => {})} onCopyRoomLink={onCopyRoomLink} T={T} D={D} accent={accent} />
  )

  const rootStyle = {
    position: 'absolute', inset: 0, background: T.bg, color: T.text, font: '13px ' + font,
    display: 'flex', flexDirection: 'column', overflow: 'hidden',
    backgroundImage: 'linear-gradient(' + T.grid + ' 1px,transparent 1px),linear-gradient(90deg,' + T.grid + ' 1px,transparent 1px)',
    backgroundSize: '34px 34px',
  }

  // ── Mobile layout ──────────────────────────────────────────────
  if (narrow) {
    const tabBtn = (k, n) => (
      <button onClick={() => setTab(k)} style={{ flex: 1, padding: '13px 8px', cursor: 'pointer', font: 'inherit', fontSize: 12,
        letterSpacing: '.08em', textTransform: 'uppercase', background: tab === k ? T.panel : 'transparent',
        color: tab === k ? T.text : T.dim, border: 'none', borderBottom: '2px solid ' + (tab === k ? accent : 'transparent'),
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7 }}>
        {k}<span style={{ color: tab === k ? accent : T.faint }}>{n}</span>
      </button>
    )
    return (
      <div ref={rootRef} style={rootStyle}>
        {/* stacked top bar */}
        <div style={{ flexShrink: 0, borderBottom: '1px solid ' + T.line, background: T.bg, padding: '11px 16px', display: 'flex', flexDirection: 'column', gap: 9 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 16, letterSpacing: '.01em', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="fil-caret" style={{ width: 9, height: 15, background: accent, display: 'inline-block', boxShadow: '0 0 10px ' + accent + '88' }} />
              filament
            </span>
            <Pill T={T}>{state.roomId}</Pill>
            <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
              <StatusDot color={state.connected ? T.ok : T.bad} glow={state.connected} />
              {themeBtn}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {state.me && (
              <>
                <span style={{ width: 11, height: 11, background: state.me.color, display: 'block' }} />
                <span style={{ fontSize: 12 }}>{state.me.name}</span>
                <Pill T={T}>{state.signalingKind}</Pill>
              </>
            )}
            <span style={{ marginLeft: 'auto' }}>{copyBtn('copy link')}</span>
          </div>
        </div>
        {/* scroll body */}
        <div style={{ flex: 1, overflow: 'auto', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '16px 16px 0' }}>{discovery}</div>
          <div style={{ position: 'sticky', top: 0, zIndex: 2, display: 'flex', background: T.bg, borderBottom: '1px solid ' + T.line, flexShrink: 0 }}>
            {tabBtn('peers', state.peers.length)}
            {tabBtn('transfers', state.transfers.length)}
          </div>
          <div style={{ padding: 16 }}>
            {tab === 'peers' ? (
              <>
                <div style={{ fontSize: 11, color: T.faint, marginBottom: 12 }}>tap a tile to send a file</div>
                {peerGrid('repeat(2,minmax(0,1fr))')}
              </>
            ) : (
              transfersList
            )}
          </div>
        </div>
      </div>
    )
  }

  // ── Desktop layout ─────────────────────────────────────────────
  return (
    <div ref={rootRef} style={rootStyle}>
      {/* top bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '0 ' + D.pad + 'px', height: 58, flexShrink: 0,
        borderBottom: '1px solid ' + T.line, background: T.bg }}>
        <span style={{ fontSize: 16, letterSpacing: '.01em', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="fil-caret" style={{ width: 10, height: 16, background: accent, display: 'inline-block', boxShadow: '0 0 10px ' + accent + '88' }} />
          filament
        </span>
        <Pill T={T}>room {state.roomId}</Pill>
        <span style={{ fontSize: 11, color: state.connected ? T.ok : T.bad, display: 'flex', alignItems: 'center', gap: 6 }}>
          <StatusDot color={state.connected ? T.ok : T.bad} glow={state.connected} />{state.connected ? 'online' : 'offline'}
        </span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {state.me && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 12, height: 12, background: state.me.color, display: 'block' }} />
              <span style={{ fontSize: 12 }}>{state.me.name}</span>
              <Pill T={T}>{state.signalingKind}</Pill>
            </div>
          )}
          {copyBtn('copy room link')}
          {themeBtn}
        </div>
      </div>

      {/* body */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* peers */}
        <div style={{ flex: '1 1 62%', padding: D.pad, borderRight: '1px solid ' + T.line, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          {discovery}
          <div style={{ fontSize: 11, color: T.dim, marginBottom: 14, display: 'flex', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ letterSpacing: '.06em' }}>PEERS · {state.peers.length}</span>
            <span style={{ color: T.faint }}>click a tile or drop files to send</span>
          </div>
          <div style={{ overflow: 'auto', minHeight: 0 }}>{peerGrid(cols)}</div>
        </div>

        {/* transfers */}
        <div style={{ flex: '1 1 38%', minWidth: 300, padding: D.pad + 'px ' + D.pad + 'px 0', background: T.panel, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div style={{ fontSize: 11, color: T.dim, marginBottom: 6, letterSpacing: '.06em', flexShrink: 0 }}>TRANSFERS · {state.transfers.length}</div>
          <div style={{ overflow: 'auto', minHeight: 0, paddingBottom: D.pad }}>{transfersList}</div>
        </div>
      </div>
    </div>
  )
}
