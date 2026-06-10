// TerminalPreview — a pure-visual, no-backend comparison of three "web-ssh"
// terminal looks (Step 0 of the web-shell feature). Gated behind ?preview=terminal
// in main.jsx; it never touches the real app. Reuses the Filament design tokens so
// what you see here is what the shipped terminal will feel like.
import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import AnnotationOverlay from './AnnotationOverlay.jsx'

// ---- design tokens (mirrored from Filament.jsx so the preview is self-contained) ----
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
function makeTheme(mode) {
  if (mode === 'light') {
    return {
      mode, bg: '#F1EFE9', panel: '#FAF8F3', panel2: '#F5F2EB',
      line: '#DEDACF', lineSoft: '#E9E5DB', grid: '#E7E3D9',
      text: '#191A1B', sub: '#54574F', dim: '#7C7E74', faint: '#AAA89C',
      ok: '#0C8A60', warn: '#9A6B00', bad: '#C0322B', recv: '#1F5FC0', onAccent: '#0B1116',
    }
  }
  return {
    mode, bg: '#0A0B0C', panel: '#0F1113', panel2: '#0C0E10',
    line: '#1E2227', lineSoft: '#15181C', grid: '#121417',
    text: '#D9DEE3', sub: '#9AA1A8', dim: '#666C73', faint: '#3C424A',
    ok: '#7CF6C8', warn: '#FFC857', bad: '#E5484D', recv: '#5B9DFF', onAccent: '#06120D',
  }
}
const accentOf = (T, name) => ACCENTS[name][T.mode === 'light' ? 'l' : 'd']

// ---- ANSI helpers for the scripted session ----
const hexRgb = (h) => {
  const n = parseInt(h.slice(1), 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}
const fg = (hex) => { const [r, g, b] = hexRgb(hex); return `\x1b[38;2;${r};${g};${b}m` }
const RST = '\x1b[0m'
const BOLD = '\x1b[1m'

function xtermTheme(T, accent) {
  return {
    background: T.bg, foreground: T.text,
    cursor: accent, cursorAccent: T.bg, selectionBackground: accent + '40',
    black: T.mode === 'light' ? '#C9C4B5' : '#15181C',
    red: T.bad, green: T.ok, yellow: T.warn, blue: T.recv,
    magenta: accentOf(T, 'magenta'), cyan: accentOf(T, 'cyan'), white: T.sub,
    brightBlack: T.dim, brightRed: T.bad, brightGreen: T.ok, brightYellow: T.warn,
    brightBlue: T.recv, brightMagenta: accentOf(T, 'magenta'), brightCyan: accentOf(T, 'cyan'),
    brightWhite: T.text,
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// The scripted "alive" session — types commands, prints output, loops gently.
async function runSession(term, T, accent, alive, host = 'do-vm') {
  const prompt = `${BOLD}${fg(accent)}root@${host}${RST}${fg(T.dim)}:${RST}${fg(T.recv)}~${RST}${fg(T.sub)}$ ${RST}`
  const type = async (s, base = 42) => {
    for (const ch of s) {
      if (!alive.current) return
      term.write(ch)
      await sleep(base + Math.random() * 50)
    }
  }
  const line = async (s, d = 16) => { if (!alive.current) return; term.write(s + '\r\n'); await sleep(d) }

  term.write('\x1b[2J\x1b[H')
  await line(`${fg(accent)}●${RST} ${fg(T.text)}filament shell${RST} ${fg(T.dim)}· connected to ${RST}${fg(T.text)}${host}${RST} ${fg(T.dim)}· direct · 12ms${RST}`)
  await line(`${fg(T.faint)}  trusted device · end-to-end encrypted · no sshd${RST}`)
  await line('')
  await sleep(260)

  const steps = [
    { cmd: 'ls', out: [`${fg(T.recv)}Filament${RST}  ${fg(T.recv)}docs${RST}  ${fg(T.recv)}experiments${RST}  ${fg(T.recv)}src${RST}  README.md`] },
    { cmd: 'uptime', out: [` 14:22:07 up 6 days,  2:14,  1 user,  load average: ${fg(T.ok)}0.04${RST}, 0.08, 0.02`] },
    { cmd: 'filament devices', out: [
      `  pixel-6a   ${fg(T.dim)}(channel 14c4ee23)${RST}`,
      `  popos      ${fg(T.dim)}(channel aab6b53d)${RST}  ${fg(accent)}[transfer, shell]${RST}`,
    ] },
    { cmd: 'echo "hello from the browser"', out: ['hello from the browser'] },
  ]
  for (const s of steps) {
    if (!alive.current) return
    term.write(prompt)
    await type(s.cmd)
    await line('')
    for (const o of s.out) await line(o, 60)
    await line('')
    await sleep(700)
  }
  term.write(prompt)
  // leave the caret blinking at a ready prompt
}

// ---- the xterm instance (one per style mount; theme updates live) ----
function XTermView({ T, accent, font, fontSize = 13.5, host = 'do-vm' }) {
  const hostRef = useRef(null)
  const termRef = useRef(null)
  const fitRef = useRef(null)
  const aliveRef = useRef({ current: true })

  useEffect(() => {
    const term = new Terminal({
      fontFamily: font, fontSize, lineHeight: 1.35, letterSpacing: 0.3,
      cursorBlink: true, cursorStyle: 'bar', cursorWidth: 2,
      allowTransparency: true, scrollback: 1000, theme: xtermTheme(T, accent),
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    // Default DOM renderer (no WebGL/canvas addon): renders terminal text as DOM,
    // which html2canvas in the annotator captures natively.
    try { fit.fit() } catch (e) {}
    termRef.current = term
    fitRef.current = fit
    const alive = { current: true }
    aliveRef.current = alive
    runSession(term, T, accent, alive, host)

    const ro = new ResizeObserver(() => { try { fit.fit() } catch (e) {} })
    ro.observe(hostRef.current)
    return () => { alive.current = false; ro.disconnect(); term.dispose() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // live theme update (accent / light-dark) — no replay
  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = xtermTheme(T, accent)
  }, [T, accent])

  return <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
}

// ---- small UI atoms ----
const Dot = ({ c, glow }) => (
  <span style={{ width: 8, height: 8, borderRadius: 8, background: c, display: 'inline-block', boxShadow: glow ? `0 0 8px ${c}` : 'none' }} />
)
function RouteChip({ T, accent }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 10.5, letterSpacing: '.06em',
      padding: '2px 7px', border: `1px solid ${accent}55`, color: accent, whiteSpace: 'nowrap',
      background: accent + '14', fontFamily: MONOS.jetbrains,
    }}>
      <span style={{ width: 12, height: 2, background: accent, display: 'block', boxShadow: `0 0 6px ${accent}` }} />direct · 12ms
    </span>
  )
}

// ============================================================ STYLE A: native pane
// The real interaction model: a devices list where ONLY shell-advertising paired
// devices show a "shell" button. Clicking it opens a scoped `terminal · <device>`
// tab beside transfers (riding the already-trusted connection). Default = clean.
const DEVICES = [
  { name: 'do-vm', online: true, shell: true },
  { name: 'popos', online: true, shell: true },
  { name: 'pixel-6a', online: false, shell: false },
]

function NativePane({ T, accent, font }) {
  const [shells, setShells] = useState([])      // open terminal tabs (device names), in order
  const [active, setActive] = useState('transfers') // 'transfers' | device name
  const [hover, setHover] = useState(null)

  const openShell = (name) => {
    setShells((s) => (s.includes(name) ? s : [...s, name]))
    setActive(name)
  }
  const closeShell = (name) => {
    setShells((s) => s.filter((n) => n !== name))
    setActive((a) => (a === name ? 'transfers' : a))
  }

  const ShellBtn = ({ name }) => {
    const hot = hover === name
    return (
      <button
        onMouseEnter={() => setHover(name)} onMouseLeave={() => setHover(null)}
        onClick={(e) => { e.stopPropagation(); openShell(name) }}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: font, fontSize: 11,
          padding: '4px 9px', cursor: 'pointer', letterSpacing: '.02em',
          border: `1px solid ${hot ? accent : accent + '66'}`, color: hot ? T.onAccent : accent,
          background: hot ? accent : accent + '14', transition: 'all .12s',
        }}
        title={`open a terminal on ${name}`}
      >
        <span style={{ fontWeight: 700 }}>›_</span> shell
      </button>
    )
  }

  const tab = (key, label, closable) => {
    const on = active === key
    return (
      <span key={key} onClick={() => setActive(key)} style={{
        display: 'inline-flex', alignItems: 'center', gap: 7, padding: '7px 12px', cursor: 'pointer',
        fontSize: 11.5, letterSpacing: '.03em', color: on ? T.text : T.dim,
        borderBottom: `2px solid ${on ? accent : 'transparent'}`, background: on ? T.bg : 'transparent',
      }}>
        {label}
        {closable && (
          <span onClick={(e) => { e.stopPropagation(); closeShell(key) }} style={{ color: T.faint, fontSize: 13, lineHeight: 1 }}>✕</span>
        )}
      </span>
    )
  }

  return (
    <div style={{ position: 'absolute', inset: 0, background: T.bg, color: T.text, fontFamily: font, display: 'flex', flexDirection: 'column' }}>
      <div style={{ height: 54, borderBottom: `1px solid ${T.line}`, display: 'flex', alignItems: 'center', gap: 12, padding: '0 18px' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 15, fontWeight: 600 }}>
          <span style={{ width: 3, height: 16, background: accent, display: 'inline-block', boxShadow: `0 0 8px ${accent}99` }} />filament
        </span>
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 8, alignItems: 'center', fontSize: 11.5, color: T.sub }}>
          <Dot c={T.ok} glow />connected
        </span>
      </div>
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* left: devices */}
        <div style={{ width: '36%', maxWidth: 380, borderRight: `1px solid ${T.line}`, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 10.5, letterSpacing: '.1em', color: T.dim }}>DEVICES</div>
          {DEVICES.map((d) => (
            <div key={d.name} style={{
              display: 'flex', alignItems: 'center', gap: 9, padding: '11px 12px',
              border: `1px solid ${active === d.name ? accent + '66' : T.lineSoft}`, fontSize: 13,
              background: active === d.name ? accent + '0C' : 'transparent',
            }}>
              <Dot c={d.online ? T.ok : T.dim} glow={d.online} />
              <span style={{ color: d.online ? T.text : T.dim }}>{d.name}</span>
              <span style={{ marginLeft: 'auto' }}>{d.online && d.shell && <ShellBtn name={d.name} />}</span>
            </div>
          ))}
          <div style={{ marginTop: 'auto', fontSize: 10.5, color: T.faint, lineHeight: 1.5 }}>
            devices running <span style={{ color: T.dim }}>filament up --shell</span> show a terminal.
          </div>
        </div>
        {/* right: transfers + on-demand terminal tabs */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, background: T.panel }}>
          <div style={{ display: 'flex', borderBottom: `1px solid ${T.line}`, paddingLeft: 6, minHeight: 36 }}>
            {tab('transfers', 'transfers', false)}
            {shells.map((n) => tab(n, <span>terminal <span style={{ color: T.dim }}>· {n}</span></span>, true))}
          </div>
          <div style={{ flex: 1, minHeight: 0, background: T.bg }}>
            {active === 'transfers' ? (
              <div style={{ height: '100%', display: 'grid', placeItems: 'center', color: T.dim, fontSize: 12.5, textAlign: 'center', padding: 24 }}>
                <div>
                  <div style={{ fontSize: 22, color: T.faint, marginBottom: 10 }}>↓</div>
                  drop a file on a device to send it<br />
                  <span style={{ color: T.faint }}>no terminal here unless you open one — the 90% never see it</span>
                </div>
              </div>
            ) : (
              <div style={{ height: '100%', padding: 12 }}>
                <XTermView key={active} T={T} accent={accent} font={font} host={active} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ============================================================ STYLE B: floating glass
function GlassWindow({ T, accent, font }) {
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const drag = useRef(null)
  const onDown = (e) => { drag.current = { sx: e.clientX, sy: e.clientY, ox: pos.x, oy: pos.y } }
  useEffect(() => {
    const move = (e) => { if (drag.current) setPos({ x: drag.current.ox + e.clientX - drag.current.sx, y: drag.current.oy + e.clientY - drag.current.sy }) }
    const up = () => { drag.current = null }
    window.addEventListener('mousemove', move); window.addEventListener('mouseup', up)
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
  }, [])
  const glass = T.mode === 'light' ? 'rgba(250,248,243,.72)' : 'rgba(16,18,21,.62)'
  return (
    <div style={{
      position: 'absolute', inset: 0, display: 'grid', placeItems: 'center',
      background: T.mode === 'light'
        ? 'radial-gradient(1200px 700px at 30% 0%, #fff 0%, #ece8df 60%, #e2ddd1 100%)'
        : 'radial-gradient(1200px 700px at 30% 0%, #14171b 0%, #0b0d0f 55%, #060708 100%)',
    }}>
      <div style={{
        transform: `translate(${pos.x}px, ${pos.y}px)`,
        width: 'min(820px, 86vw)', height: 'min(520px, 76vh)',
        borderRadius: 14, overflow: 'hidden', border: `1px solid ${T.mode === 'light' ? 'rgba(0,0,0,.10)' : 'rgba(255,255,255,.10)'}`,
        background: glass, backdropFilter: 'blur(22px) saturate(140%)', WebkitBackdropFilter: 'blur(22px) saturate(140%)',
        boxShadow: T.mode === 'light'
          ? '0 30px 80px -20px rgba(0,0,0,.30), 0 2px 8px rgba(0,0,0,.10)'
          : '0 40px 90px -20px rgba(0,0,0,.75), 0 0 0 1px rgba(255,255,255,.03), 0 2px 10px rgba(0,0,0,.5)',
        display: 'flex', flexDirection: 'column', animation: 'tpRise .42s cubic-bezier(.2,.8,.2,1)',
      }}>
        <div onMouseDown={onDown} style={{
          height: 42, display: 'flex', alignItems: 'center', gap: 10, padding: '0 13px', cursor: 'grab',
          borderBottom: `1px solid ${T.mode === 'light' ? 'rgba(0,0,0,.07)' : 'rgba(255,255,255,.06)'}`,
        }}>
          <span style={{ display: 'inline-flex', gap: 7 }}>
            <span style={{ width: 11, height: 11, borderRadius: 11, background: '#FF5F57' }} />
            <span style={{ width: 11, height: 11, borderRadius: 11, background: '#FEBC2E' }} />
            <span style={{ width: 11, height: 11, borderRadius: 11, background: '#28C840' }} />
          </span>
          <span style={{ marginLeft: 8, fontFamily: font, fontSize: 12.5, color: T.text, display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <Dot c={accent} glow />do-vm
          </span>
          <span style={{ marginLeft: 'auto' }}><RouteChip T={T} accent={accent} /></span>
        </div>
        <div style={{ flex: 1, minHeight: 0, padding: '12px 14px', background: T.mode === 'light' ? 'rgba(255,255,255,.35)' : 'rgba(8,9,11,.45)' }}>
          <XTermView T={T} accent={accent} font={font} />
        </div>
      </div>
    </div>
  )
}

// ============================================================ STYLE C: full-bleed
function FullBleed({ T, accent, font }) {
  const keys = ['esc', 'tab', 'ctrl', 'alt', '↑', '↓', '←', '→', '|', '/', '~', '-']
  return (
    <div style={{ position: 'absolute', inset: 0, background: T.bg, color: T.text, fontFamily: font, display: 'flex', flexDirection: 'column' }}>
      <div style={{ height: 40, display: 'flex', alignItems: 'center', gap: 12, padding: '0 16px', borderBottom: `1px solid ${T.line}` }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13 }}><Dot c={accent} glow />do-vm</span>
        <RouteChip T={T} accent={accent} />
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 16, color: T.dim, fontSize: 14 }}>
          <span style={{ cursor: 'default' }}>⤢</span><span style={{ cursor: 'default' }}>✕</span>
        </span>
      </div>
      <div style={{ flex: 1, minHeight: 0, padding: '10px 16px' }}>
        <XTermView T={T} accent={accent} font={font} fontSize={14} />
      </div>
      <div style={{ display: 'flex', gap: 6, padding: '8px 12px', borderTop: `1px solid ${T.line}`, overflowX: 'auto' }}>
        {keys.map((k) => (
          <span key={k} style={{
            padding: '7px 12px', minWidth: 34, textAlign: 'center', fontSize: 12, color: T.sub,
            border: `1px solid ${T.lineSoft}`, background: T.panel2, fontFamily: font, whiteSpace: 'nowrap',
          }}>{k}</span>
        ))}
      </div>
    </div>
  )
}

// ============================================================ switcher + root
const STYLES = [
  { id: 'native', label: 'Native pane', Comp: NativePane },
  { id: 'glass', label: 'Floating glass', Comp: GlassWindow },
  { id: 'full', label: 'Full-bleed', Comp: FullBleed },
]

export default function TerminalPreview() {
  const [styleId, setStyleId] = useState('native')
  const [mode, setMode] = useState('dark')
  const [accentName, setAccentName] = useState('green')
  const [fontName, setFontName] = useState('jetbrains')

  const T = makeTheme(mode)
  const accent = accentOf(T, accentName)
  const font = MONOS[fontName]
  const Active = STYLES.find((s) => s.id === styleId).Comp

  const chip = (active) => ({
    padding: '6px 12px', fontSize: 12, cursor: 'pointer', fontFamily: MONOS.jetbrains,
    border: `1px solid ${active ? accent : T.line}`, color: active ? T.onAccent : T.sub,
    background: active ? accent : 'transparent', transition: 'all .12s', whiteSpace: 'nowrap',
  })

  return (
    <div style={{ position: 'fixed', inset: 0, background: T.bg }}>
      {/* the active terminal style, keyed so a style switch cleanly re-fits */}
      <div style={{ position: 'absolute', inset: 0, bottom: 64 }}>
        <Active key={styleId + mode} T={T} accent={accent} font={font} />
      </div>

      {/* control bar */}
      <div style={{
        position: 'fixed', left: 0, right: 0, bottom: 0, height: 64, zIndex: 50,
        display: 'flex', alignItems: 'center', gap: 14, padding: '0 16px', flexWrap: 'wrap',
        background: T.mode === 'light' ? 'rgba(241,239,233,.86)' : 'rgba(10,11,12,.86)',
        backdropFilter: 'blur(12px)', borderTop: `1px solid ${T.line}`, fontFamily: MONOS.jetbrains,
      }}>
        <span style={{ fontSize: 11, letterSpacing: '.12em', color: T.dim }}>STYLE</span>
        {STYLES.map((s) => (
          <button key={s.id} onClick={() => setStyleId(s.id)} style={chip(styleId === s.id)}>{s.label}</button>
        ))}
        <span style={{ width: 1, height: 22, background: T.line, margin: '0 4px' }} />
        <button onClick={() => setMode(mode === 'dark' ? 'light' : 'dark')} style={chip(false)}>{mode === 'dark' ? '☾ dark' : '☀ light'}</button>
        <span style={{ display: 'inline-flex', gap: 7, alignItems: 'center' }}>
          {Object.keys(ACCENTS).map((a) => (
            <button key={a} onClick={() => setAccentName(a)} title={a} style={{
              width: 20, height: 20, borderRadius: 20, cursor: 'pointer', padding: 0,
              background: ACCENTS[a][mode === 'light' ? 'l' : 'd'],
              border: accentName === a ? `2px solid ${T.text}` : '2px solid transparent',
              boxShadow: accentName === a ? `0 0 8px ${ACCENTS[a][mode === 'light' ? 'l' : 'd']}` : 'none',
            }} />
          ))}
        </span>
        <span style={{ width: 1, height: 22, background: T.line, margin: '0 4px' }} />
        <button onClick={() => setFontName(fontName === 'jetbrains' ? 'plex' : fontName === 'plex' ? 'space' : 'jetbrains')} style={chip(false)}>
          {fontName}
        </button>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: T.faint }}>?preview=terminal · visual mock, no backend</span>
      </div>

      <AnnotationOverlay />

      <style>{`@keyframes tpRise{from{opacity:0;transform:translate(0,14px) scale(.98)}to{opacity:1;transform:translate(0,0) scale(1)}}`}</style>
    </div>
  )
}
