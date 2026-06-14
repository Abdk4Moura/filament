// WebTerminal: a real browser shell wired to a peer's PTY over the data channel.
// Given a live PeerLink, it opens a pty (pty-open), bridges xterm <-> the PTY
// byte stream, handles resize, and provides a mobile accessory key bar (the
// missing-special-keys fix) with a sticky-toggle modifier model + an escape-
// sequence map, plus visualViewport keyboard avoidance. Per docs/mobile-terminal-
// ergonomics.md.
//
// Persistence (issue #4): the PTY session id is owned HERE and is STABLE across a
// reconnect. When the `link` prop changes (a dropped data channel superseded by a
// fresh one) we re-open with the SAME session id, so the CLI reattaches us to the
// still-running PTY and replays the buffered output, instead of spawning a fresh
// shell. The session id is derived from `instanceId` so it survives a re-render
// and a link swap, but a brand-new WebTerminal (new tab/session) gets a new one.
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

// A WebTerminal instance keeps ONE stable PTY session id for its whole lifetime,
// across any number of link swaps (reconnects). Derived from instanceId so two
// renders of the same session agree; a fallback random id covers the preview.
function makeSessionId(instanceId) {
  const base = instanceId || ('s' + Math.random().toString(36).slice(2, 10))
  return 'pty-' + base
}

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
  const [atBottom, setAtBottom] = useState(true) // false => show scroll-to-bottom
  const sessionIdRef = useRef(makeSessionId(instanceId))

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

  // --- scrollback helpers (mobile scroll, issue #5) -----------------------
  // "At the bottom" means the viewport top equals the buffer base (the live
  // prompt is visible). We track this to (a) show/hide the scroll-to-bottom
  // affordance and (b) decide whether a resize should auto-stick to bottom or
  // preserve the reader's position. In the alternate screen (a full-screen TUI)
  // there is no scrollback, so we always treat it as "at bottom" and hide the
  // button: the TUI owns the viewport (issue #1, correct xterm behavior).
  const computeAtBottom = useCallback(() => {
    const term = termRef.current
    if (!term || !term.buffer || !term.buffer.active) return true
    if (term.buffer.active.type === 'alternate') return true
    return term.buffer.active.viewportY >= term.buffer.active.baseY
  }, [])
  const scrollToBottom = useCallback(() => {
    const term = termRef.current
    if (!term) return
    term.scrollToBottom()
    setAtBottom(true)
    haptic()
    try { term.focus() } catch (e) {}
  }, [])
  // Page up/down for the accessory bar (a touch-friendly chunk scroll). A near-
  // full-page step (rows - 1) keeps a line of context, like a pager.
  const scrollPage = useCallback((dir) => {
    const term = termRef.current
    if (!term) return
    if (term.buffer && term.buffer.active && term.buffer.active.type === 'alternate') return
    term.scrollLines(dir * Math.max(1, (term.rows || 24) - 1))
    haptic()
  }, [])

  // --- resize hardening (issue #2) ----------------------------------------
  // The Android soft keyboard fires a burst of visualViewport resizes; the
  // ResizeObserver fires its own. ALL of them funnel through this one
  // rAF-coalesced, guarded path so we never refit twice in a frame, never refit
  // a hidden or zero-size element (which makes the FitAddon throw / compute a
  // bogus 0x0 and wedge the renderer), and the IO loop is never blocked.
  const fitRaf = useRef(0)
  const safeFit = useCallback(() => {
    if (fitRaf.current) return // already scheduled this frame
    fitRaf.current = requestAnimationFrame(() => {
      fitRaf.current = 0
      const host = hostRef.current
      const fit = fitRef.current
      const term = termRef.current
      if (!host || !fit || !term) return
      // Never fit a hidden / un-laid-out / zero-size element: offsetParent is
      // null when display:none (backgrounded session), and a 0 width/height
      // makes the fit dims NaN/0 and corrupts the buffer.
      if (host.offsetParent === null) return
      if (host.clientWidth < 2 || host.clientHeight < 2) return
      let dims
      try { dims = fit.proposeDimensions() } catch (e) { return }
      if (!dims || !dims.cols || !dims.rows || !isFinite(dims.cols) || !isFinite(dims.rows)) return
      if (dims.cols === term.cols && dims.rows === term.rows) return // no-op, skip churn
      // Soft-keyboard open/close must NOT yank the reader away from scrollback.
      // Remember where we were (and how far from the live tail) BEFORE the fit,
      // then: if we were at the bottom, stick to the bottom (the common case, so
      // the prompt stays visible); otherwise restore the same distance-from-tail
      // so the lines being read stay put (issue #4 / #5).
      const wasBottom = computeAtBottom()
      const b = term.buffer && term.buffer.active
      const fromTail = b ? (b.baseY - b.viewportY) : 0
      try { fit.fit() } catch (e) {}
      try {
        if (wasBottom) term.scrollToBottom()
        else if (fromTail > 0) {
          const nb = term.buffer && term.buffer.active
          if (nb) term.scrollToLine(Math.max(0, nb.baseY - fromTail))
        }
      } catch (e) {}
      setAtBottom(computeAtBottom())
    })
  }, [computeAtBottom])

  // mount xterm + open the pty. Re-runs when `link` changes (a reconnect hands
  // us a fresh PeerLink); the SAME session id makes that a reattach, not a new
  // shell.
  useEffect(() => {
    if (!link) return
    const term = new Terminal({
      fontFamily: font, fontSize: isTouch ? 13 : 13.5, lineHeight: 1.3, letterSpacing: 0.2,
      cursorBlink: true, cursorStyle: 'bar', cursorWidth: 2, scrollback: 5000,
      theme: xtermTheme(T, accent), allowProposedApi: true,
      // A full-screen TUI (vim/htop/opencode) drives the alternate screen buffer
      // and expects unmodified passthrough: convertEol off (the PTY already sends
      // CRLF), the alt buffer scrollback clamped so the TUI owns the viewport.
      convertEol: false, altClickMovesCursor: false,
      // mobile: stop the OS keyboard from "helping"
      ...(isTouch ? { screenReaderMode: false } : {}),
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    termRef.current = term; fitRef.current = fit
    // Dev-only: expose the live Terminal for the ?preview= harness so Playwright
    // can assert alt-screen state / dimensions. Inert in the real app (no query).
    try {
      if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('preview')) {
        window.__webterm = term
      }
    } catch (e) {}
    // Initial fit MUST land before we report a size to the PTY, otherwise the
    // shell allocates 80x24 while xterm shows a different geometry and a TUI
    // draws into the wrong region (issue #1).
    try { fit.fit() } catch (e) {}

    // harden the hidden textarea for mobile (no autocorrect/autocap/spellcheck)
    const ta = hostRef.current.querySelector('textarea')
    if (ta) { ta.setAttribute('autocorrect', 'off'); ta.setAttribute('autocapitalize', 'off'); ta.setAttribute('autocomplete', 'off'); ta.setAttribute('spellcheck', 'false') }

    // bridge: PTY -> xterm. Raw bytes, written through unmodified so alternate
    // screen / cursor-addressing escapes reach the parser intact (issue #1).
    link.onPtyData = (u8) => term.write(u8)
    link.onPtyClose = () => { setStatus('closed'); term.write('\r\n\x1b[90m( session ended )\x1b[0m\r\n') }
    link.onPtyReady = () => {
      setStatus('ready')
      // The PTY is live (fresh or reattached): make sure its window size matches
      // what we actually render, then nudge a SIGWINCH so a TUI redraws to fit.
      safeFit()
      const t = termRef.current
      if (t) link.resizePty(t.cols || 80, t.rows || 24)
    }
    // bridge: xterm -> PTY (with sticky modifiers)
    const dataSub = term.onData((d) => write(applyMods(d)))
    const sizeSub = term.onResize(({ cols, rows }) => link.resizePty(cols, rows))
    // Track scroll position so the scroll-to-bottom affordance shows only when
    // the reader has scrolled up off the live tail. Fires on wheel, touch swipe,
    // and programmatic scrolls alike.
    const scrollSub = term.onScroll(() => setAtBottom(computeAtBottom()))

    // --- touch scrolling (issue #5) -----------------------------------------
    // On mobile a one-finger swipe over the terminal must scroll the SCROLLBACK,
    // not type into the PTY and not start a text selection. xterm's own viewport
    // is touch-finicky, so we translate vertical swipe delta into scrollLines on
    // the host element directly. We never preventDefault on a clear horizontal
    // move (let the accessory bar / page scroll), and we skip the alternate
    // screen (a TUI owns touch there, e.g. scrolling a list). A swipe under a
    // small threshold is treated as a tap so the keyboard/selection still work.
    const host = hostRef.current
    let tY = 0, tX = 0, tAccum = 0, tMoved = false, tActive = false
    const cellH = () => {
      const t = termRef.current
      // approximate row height in px from the viewport; fall back to font-based.
      const vp = host && host.querySelector('.xterm-viewport')
      if (vp && t && t.rows) return Math.max(8, vp.clientHeight / t.rows)
      return 18
    }
    const onTouchStart = (e) => {
      if (e.touches.length !== 1) { tActive = false; return }
      const t = termRef.current
      if (t && t.buffer && t.buffer.active && t.buffer.active.type === 'alternate') { tActive = false; return }
      tActive = true; tMoved = false; tAccum = 0
      tY = e.touches[0].clientY; tX = e.touches[0].clientX
    }
    const onTouchMove = (e) => {
      if (!tActive || e.touches.length !== 1) return
      const y = e.touches[0].clientY, x = e.touches[0].clientX
      const dy = y - tY, dx = x - tX
      // Ignore a mostly-horizontal drag (let it be / allow text selection drag).
      if (!tMoved && Math.abs(dx) > Math.abs(dy)) { tActive = false; return }
      if (!tMoved && Math.abs(dy) < 6) return // below the tap threshold, keep watching
      tMoved = true
      // Swiping the content DOWN (finger moves down, dy>0) reveals older lines:
      // scroll up. Accumulate sub-cell motion so slow drags still move.
      tAccum += dy
      const h = cellH()
      const lines = Math.trunc(tAccum / h)
      if (lines !== 0) {
        tAccum -= lines * h
        const t = termRef.current
        if (t) t.scrollLines(-lines)
      }
      tY = y; tX = x
      if (e.cancelable) e.preventDefault() // stop selection + PTY input on a scroll
    }
    const onTouchEnd = () => {
      // A genuine tap (no scroll) falls through so xterm focuses + the soft
      // keyboard opens; a scroll swallowed its motion above. Nothing to do here
      // beyond resetting; focus on tap is xterm's own job.
      tActive = false
    }
    host.addEventListener('touchstart', onTouchStart, { passive: true })
    host.addEventListener('touchmove', onTouchMove, { passive: false })
    host.addEventListener('touchend', onTouchEnd, { passive: true })
    host.addEventListener('touchcancel', onTouchEnd, { passive: true })

    // open (or reattach to) the shell once the channel is up, carrying our
    // stable session id so the CLI can rebind a surviving PTY (issue #4).
    const begin = () => {
      if (link.channel && link.channel.readyState === 'open') {
        const cols = term.cols || 80
        const rows = term.rows || 24
        link.openPty(cols, rows, sessionIdRef.current)
        setStatus('connecting')
        return true
      }
      return false
    }
    let poll = null
    if (!begin()) poll = setInterval(() => { if (begin()) clearInterval(poll) }, 200)

    const ro = new ResizeObserver(() => safeFit())
    ro.observe(hostRef.current)
    term.focus()

    return () => {
      if (poll) clearInterval(poll)
      if (fitRaf.current) { cancelAnimationFrame(fitRaf.current); fitRaf.current = 0 }
      dataSub.dispose(); sizeSub.dispose(); scrollSub.dispose(); ro.disconnect()
      host.removeEventListener('touchstart', onTouchStart)
      host.removeEventListener('touchmove', onTouchMove)
      host.removeEventListener('touchend', onTouchEnd)
      host.removeEventListener('touchcancel', onTouchEnd)
      // Detach our handlers from THIS link but do NOT closePty here on a link
      // swap: the unmount-vs-reconnect distinction is that a true unmount runs
      // the close button (closeSession), which detaches the session. A bare
      // link swap should leave the remote PTY running. We still send a detach
      // (closePty) only when the whole component unmounts; React runs this
      // cleanup on both, so we rely on the CLI keeping the PTY alive on a
      // channel drop and only treat an explicit `l2-close` as a teardown.
      link.onPtyData = () => {}; link.onPtyClose = () => {}; link.onPtyReady = () => {}
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link])

  // Explicit teardown: closing the session (the ✕) must end the remote PTY.
  // Kept separate from the link-swap cleanup above so a reconnect never kills it.
  const endSession = useCallback(() => {
    try { link && link.closePty() } catch (e) {}
    onClose && onClose()
  }, [link, onClose])

  // live theme
  useEffect(() => { if (termRef.current) termRef.current.options.theme = xtermTheme(T, accent) }, [T, accent])

  // Sessions dock: when this instance is un-hidden (reopened from the background)
  // its host had display:none, so xterm couldn't measure: refit + refocus now
  // that it's visible again. The terminal was NEVER unmounted, so scrollback and
  // the live PTY are intact. requestAnimationFrame waits for the layout to apply.
  useEffect(() => {
    if (hidden) return
    const raf = requestAnimationFrame(() => {
      safeFit()
      try { termRef.current && termRef.current.focus() } catch (e) {}
    })
    return () => cancelAnimationFrame(raf)
  }, [hidden, safeFit])

  // visualViewport keyboard avoidance: lift the bar above the soft keyboard.
  // The inset state-set is cheap; the refit is the guarded, coalesced safeFit so
  // a keyboard-open/close burst can never wedge the terminal (issue #2).
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const onVV = () => {
      const inset = Math.max(0, window.innerHeight - vv.height - vv.offsetTop)
      setKbInset(inset)
      safeFit()
    }
    vv.addEventListener('resize', onVV); vv.addEventListener('scroll', onVV)
    return () => { vv.removeEventListener('resize', onVV); vv.removeEventListener('scroll', onVV) }
  }, [safeFit])

  // --- copy / paste (issue #3) --------------------------------------------
  // Desktop: select-to-copy (auto-copies the current selection) + Ctrl/Cmd+V
  // paste. Mobile: an explicit Paste accessory button, since selection + the OS
  // clipboard are awkward on touch. Both write pasted text straight to the PTY.
  const copySelection = useCallback(async () => {
    const term = termRef.current
    if (!term) return false
    const sel = term.getSelection()
    if (!sel) return false
    try { await navigator.clipboard.writeText(sel); haptic(); return true } catch (e) { return false }
  }, [])
  const pasteClipboard = useCallback(async () => {
    let text = ''
    try { text = await navigator.clipboard.readText() } catch (e) { return false }
    if (!text) return false
    write(text) // bracketed-paste-safe: the PTY/app decides how to treat it
    haptic()
    termRef.current && termRef.current.focus()
    return true
  }, [write])

  // Auto-copy on selection (desktop): mirrors a normal terminal's behavior and
  // gives mobile a no-op-safe path. Wired once per mounted terminal.
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    const sub = term.onSelectionChange(() => {
      if (isTouch) return // touch selection is too jumpy to auto-copy
      const sel = term.getSelection()
      if (sel && sel.length) navigator.clipboard && navigator.clipboard.writeText(sel).catch(() => {})
    })
    // Ctrl/Cmd+Shift+C copy, Ctrl/Cmd+Shift+V / Ctrl+Cmd+V paste. We attach a
    // key handler that returns false to let xterm forward keys we don't claim.
    const keySub = term.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true
      const mod = e.ctrlKey || e.metaKey
      if (mod && e.shiftKey && (e.key === 'C' || e.key === 'c')) { copySelection(); return false }
      if (mod && e.shiftKey && (e.key === 'V' || e.key === 'v')) { pasteClipboard(); return false }
      return true
    })
    return () => { try { sub.dispose() } catch (e) {} }
    // attachCustomKeyEventHandler has no disposer; replaced on remount. keySub unused.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [copySelection, pasteClipboard])

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

  // accessory bar key spec (default row). Copy/Paste live at the end so they are
  // always reachable on touch (issue #3).
  const ROW = [
    { l: 'Esc' }, { l: 'Tab' }, { l: 'ctrl', on: ctrlOn, fn: toggleCtrl }, { l: 'alt', on: altOn, fn: toggleAlt },
    { l: 'Up', g: '↑' }, { l: 'Down', g: '↓' }, { l: 'Left', g: '←' }, { l: 'Right', g: '→' },
    { l: '|' }, { l: '/' }, { l: '~' }, { l: '-' }, { l: 'Home', g: '⤒' }, { l: 'End', g: '⤓' }, { l: 'Del' },
    // Scrollback page controls (scroll the xterm buffer, NOT PgUp/PgDn to the
    // PTY): a touch-friendly way to move through history a page at a time.
    { l: 'ScrollUp', g: '⇞', fn: () => scrollPage(-1) }, { l: 'ScrollDn', g: '⇟', fn: () => scrollPage(1) },
    { l: 'Copy', g: 'copy', fn: copySelection }, { l: 'Paste', g: 'paste', fn: pasteClipboard },
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
              style={{ cursor: 'pointer', fontSize: 12, letterSpacing: '.04em' }}>hide</span>
          )}
          <span title="close (end session)" onClick={endSession} style={{ cursor: 'pointer', fontSize: 15 }}>✕</span>
        </span>
      </div>
      {/* terminal (position:relative anchors the scroll-to-bottom affordance) */}
      <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        {/* Let the xterm viewport own vertical panning; our touch handler does the
            actual scroll, this just stops the browser from rubber-banding the page
            or zooming on a swipe over the terminal. */}
        <style>{`[data-testid="term-host"] .xterm-viewport{touch-action:pan-y}`}</style>
        <div ref={hostRef} data-testid="term-host" style={{ position: 'absolute', inset: 0, padding: '8px 10px', touchAction: 'none' }} />
        {/* scroll-to-bottom: appears only when scrolled up off the live tail.
            Touch-sized (44px), unobtrusive, jumps back to the prompt. */}
        {!atBottom && (
          <button data-testid="scroll-to-bottom" aria-label="scroll to bottom"
            onClick={scrollToBottom}
            style={{
              position: 'absolute', right: 14, bottom: 14, width: 44, height: 44,
              borderRadius: 22, cursor: 'pointer', zIndex: 5,
              display: 'grid', placeItems: 'center', fontSize: 18, lineHeight: 1,
              border: `1px solid ${accent}66`, color: T.onAccent, background: accent,
              boxShadow: '0 2px 10px rgba(0,0,0,.45)', opacity: 0.92,
            }}>↓</button>
        )}
      </div>
      {/* accessory key bar (always on touch; handy on desktop too) */}
      <div style={{
        flex: '0 0 auto', display: 'flex', gap: 6, padding: '7px 10px', borderTop: `1px solid ${T.line}`,
        overflowX: 'auto', background: T.panel2, marginBottom: kbInset, WebkitOverflowScrolling: 'touch',
      }}>
        {ROW.map((k, i) => {
          const active = k.on
          return (
            <button key={i} data-key={k.l} onClick={k.fn || (() => sendKey(k.l))} style={{
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
