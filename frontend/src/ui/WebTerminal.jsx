// WebTerminal — a real browser shell wired to a peer's PTY over the data channel.
// Given a live PeerLink, it opens a pty (pty-open), bridges xterm <-> the PTY
// byte stream, handles resize, and provides a mobile accessory key bar (the
// missing-special-keys fix) with a sticky-toggle modifier model + an escape-
// sequence map, plus visualViewport keyboard avoidance. Per docs/mobile-terminal-
// ergonomics.md.
import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

const enc = new TextEncoder()

// label -> exact bytes sent to the PTY (xterm/ANSI). From the research doc.
const KEYS = {
  Esc: '\x1b', Tab: '\x09', Enter: '\r',
  Up: '\x1b[A', Down: '\x1b[B', Right: '\x1b[C', Left: '\x1b[D',
  Home: '\x1b[H', End: '\x1b[F', PgUp: '\x1b[5~', PgDn: '\x1b[6~',
  Del: '\x1b[3~', '|': '|', '/': '/', '~': '~', '-': '-',
}
const isTouch = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(pointer: coarse)').matches

function xtermTheme(T, accent) {
  return {
    background: T.bg, foreground: T.text, cursor: accent, cursorAccent: T.bg,
    selectionBackground: accent + '40',
    black: T.mode === 'light' ? '#C9C4B5' : '#15181C', red: T.bad, green: T.ok,
    yellow: T.warn, blue: T.recv, magenta: '#FF8AD6', cyan: '#5BE7FF', white: T.sub,
    brightBlack: T.dim, brightRed: T.bad, brightGreen: T.ok, brightYellow: T.warn,
    brightBlue: T.recv, brightMagenta: '#FF8AD6', brightCyan: '#5BE7FF', brightWhite: T.text,
  }
}
const haptic = (ms = 8) => { try { navigator.vibrate && navigator.vibrate(ms) } catch (e) {} } // Android only

export default function WebTerminal({ link, peerName, route, T, accent, font, onClose, onBackground, hidden, instanceId }) {
  const hostRef = useRef(null)
  const termRef = useRef(null)
  const fitRef = useRef(null)
  const ctrl = useRef(false) // 'armed' modifiers, read inside onData
  const alt = useRef(false)
  const [ctrlOn, setCtrlOn] = useState(false) // mirror for the UI
  const [altOn, setAltOn] = useState(false)
  const [status, setStatus] = useState('connecting')
  const [kbInset, setKbInset] = useState(0) // visualViewport keyboard height

  const write = useCallback((s) => link && link.sendPtyInput(enc.encode(s)), [link])

  // apply sticky Ctrl/Alt to a single typed char, then disarm (unless locked)
  const applyMods = useCallback((data) => {
    let out = data
    if (ctrl.current && data.length === 1) {
      const c = data.toLowerCase().charCodeAt(0)
      if (c >= 97 && c <= 122) out = String.fromCharCode(c - 96) // Ctrl-A..Z
      else if (data === ' ') out = '\x00'
      else if (data === '[') out = '\x1b'
      ctrl.current = false; setCtrlOn(false)
    }
    if (alt.current) { out = '\x1b' + out; alt.current = false; setAltOn(false) }
    return out
  }, [])

  // mount xterm + open the pty
  useEffect(() => {
    if (!link) return
    const term = new Terminal({
      fontFamily: font, fontSize: isTouch ? 13 : 13.5, lineHeight: 1.3, letterSpacing: 0.2,
      cursorBlink: true, cursorStyle: 'bar', cursorWidth: 2, scrollback: 5000,
      theme: xtermTheme(T, accent), allowProposedApi: true,
      // mobile: stop the OS keyboard from "helping"
      ...(isTouch ? { screenReaderMode: false } : {}),
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    try { fit.fit() } catch (e) {}
    termRef.current = term; fitRef.current = fit

    // harden the hidden textarea for mobile (no autocorrect/autocap/spellcheck)
    const ta = hostRef.current.querySelector('textarea')
    if (ta) { ta.setAttribute('autocorrect', 'off'); ta.setAttribute('autocapitalize', 'off'); ta.setAttribute('autocomplete', 'off'); ta.setAttribute('spellcheck', 'false') }

    // bridge: PTY -> xterm
    link.onPtyData = (u8) => term.write(u8)
    link.onPtyClose = () => { setStatus('closed'); term.write('\r\n\x1b[90m— session ended —\x1b[0m\r\n') }
    link.onPtyReady = () => setStatus('ready')
    // bridge: xterm -> PTY (with sticky modifiers)
    const dataSub = term.onData((d) => write(applyMods(d)))
    const sizeSub = term.onResize(({ cols, rows }) => link.resizePty(cols, rows))

    // open the shell once the channel is up
    const begin = () => {
      if (link.channel && link.channel.readyState === 'open') {
        const { cols, rows } = term
        link.openPty(cols || 80, rows || 24)
        setStatus('ready')
        return true
      }
      return false
    }
    let poll = null
    if (!begin()) poll = setInterval(() => { if (begin()) clearInterval(poll) }, 200)

    const ro = new ResizeObserver(() => { try { fit.fit() } catch (e) {} })
    ro.observe(hostRef.current)
    term.focus()

    return () => {
      if (poll) clearInterval(poll)
      dataSub.dispose(); sizeSub.dispose(); ro.disconnect()
      try { link.closePty() } catch (e) {}
      link.onPtyData = () => {}; link.onPtyClose = () => {}; link.onPtyReady = () => {}
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link])

  // live theme
  useEffect(() => { if (termRef.current) termRef.current.options.theme = xtermTheme(T, accent) }, [T, accent])

  // Sessions dock: when this instance is un-hidden (reopened from the background)
  // its host had display:none, so xterm couldn't measure — refit + refocus now
  // that it's visible again. The terminal was NEVER unmounted, so scrollback and
  // the live PTY are intact. requestAnimationFrame waits for the layout to apply.
  useEffect(() => {
    if (hidden) return
    const raf = requestAnimationFrame(() => {
      try { fitRef.current && fitRef.current.fit() } catch (e) {}
      try { termRef.current && termRef.current.focus() } catch (e) {}
    })
    return () => cancelAnimationFrame(raf)
  }, [hidden])

  // visualViewport keyboard avoidance: lift the bar above the soft keyboard
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const onVV = () => {
      const inset = Math.max(0, window.innerHeight - vv.height - vv.offsetTop)
      setKbInset(inset)
      try { fitRef.current && fitRef.current.fit() } catch (e) {}
    }
    vv.addEventListener('resize', onVV); vv.addEventListener('scroll', onVV)
    return () => { vv.removeEventListener('resize', onVV); vv.removeEventListener('scroll', onVV) }
  }, [])

  const sendKey = (label) => {
    haptic()
    const base = KEYS[label]
    if (base == null) return
    write(applyMods(base))
    termRef.current && termRef.current.focus()
  }
  const toggleCtrl = () => { ctrl.current = !ctrl.current; setCtrlOn(ctrl.current); haptic(); termRef.current?.focus() }
  const toggleAlt = () => { alt.current = !alt.current; setAltOn(alt.current); haptic(); termRef.current?.focus() }

  const dot = status === 'ready' ? T.ok : status === 'closed' ? T.bad : T.warn

  // accessory bar key spec (default row)
  const ROW = [
    { l: 'Esc' }, { l: 'Tab' }, { l: 'ctrl', on: ctrlOn, fn: toggleCtrl }, { l: 'alt', on: altOn, fn: toggleAlt },
    { l: 'Up', g: '↑' }, { l: 'Down', g: '↓' }, { l: 'Left', g: '←' }, { l: 'Right', g: '→' },
    { l: '|' }, { l: '/' }, { l: '~' }, { l: '-' }, { l: 'Home', g: '⤒' }, { l: 'End', g: '⤓' }, { l: 'Del' },
  ]

  return (
    <div data-session-id={instanceId} style={{ position: 'absolute', inset: 0, background: T.bg, color: T.text, fontFamily: font, display: 'flex', flexDirection: 'column' }}>
      {/* header */}
      <div style={{ height: 40, flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 10, padding: '0 14px', borderBottom: `1px solid ${T.line}` }}>
        <span style={{ width: 8, height: 8, borderRadius: 8, background: dot, boxShadow: `0 0 8px ${dot}` }} />
        <span style={{ fontSize: 13 }}>{peerName || 'shell'}</span>
        <span style={{ fontSize: 10.5, color: accent, border: `1px solid ${accent}55`, padding: '2px 6px', background: accent + '14' }}>
          {route || 'direct'}{status === 'connecting' ? ' · connecting…' : ''}
        </span>
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 14, color: T.dim, fontSize: 13 }}>
          {/* Background: hide the overlay WITHOUT tearing down the PTY (the
              instance stays mounted, reachable from the SESSIONS strip). */}
          {onBackground && (
            <span title="background (keep running)" onClick={onBackground}
              style={{ cursor: 'pointer', fontSize: 12, letterSpacing: '.04em' }}>— hide</span>
          )}
          <span title="close (end session)" onClick={onClose} style={{ cursor: 'pointer', fontSize: 15 }}>✕</span>
        </span>
      </div>
      {/* terminal */}
      <div ref={hostRef} style={{ flex: 1, minHeight: 0, padding: '8px 10px' }} />
      {/* accessory key bar (always on touch; handy on desktop too) */}
      <div style={{
        flex: '0 0 auto', display: 'flex', gap: 6, padding: '7px 10px', borderTop: `1px solid ${T.line}`,
        overflowX: 'auto', background: T.panel2, marginBottom: kbInset, WebkitOverflowScrolling: 'touch',
      }}>
        {ROW.map((k, i) => {
          const active = k.on
          return (
            <button key={i} onClick={k.fn || (() => sendKey(k.l))} style={{
              flex: '0 0 auto', minWidth: 38, padding: '9px 11px', fontFamily: font, fontSize: 12,
              cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all .1s',
              border: `1px solid ${active ? accent : T.lineSoft}`, color: active ? T.onAccent : T.sub,
              background: active ? accent : 'transparent',
            }}>{k.g || k.l}</button>
          )
        })}
      </div>
    </div>
  )
}
