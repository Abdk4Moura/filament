// WebTermPreview — mounts the REAL WebTerminal against a MOCK PeerLink running a
// tiny in-browser shell (echo + a few commands), so the terminal UI, the mobile
// accessory key bar, sticky modifiers, and keyboard handling can be felt and
// verified live without a paired device. ?preview=webterm.
import React, { useMemo, useState } from 'react'
import WebTerminal from './WebTerminal.jsx'

const T_DARK = {
  mode: 'dark', bg: '#0A0B0C', panel: '#0F1113', panel2: '#0C0E10',
  line: '#1E2227', lineSoft: '#15181C', grid: '#121417',
  text: '#D9DEE3', sub: '#9AA1A8', dim: '#666C73', faint: '#3C424A',
  ok: '#7CF6C8', warn: '#FFC857', bad: '#E5484D', recv: '#5B9DFF', onAccent: '#06120D',
}
const dec = new TextDecoder()
const enc = new TextEncoder()

// A mock PeerLink: a tiny line-discipline shell so typing, Enter, Backspace,
// Ctrl-C and the accessory keys all visibly do something.
function makeMockLink() {
  const prompt = '\x1b[1m\x1b[38;2;124;246;200mguest@filament\x1b[0m:\x1b[38;2;91;157;255m~\x1b[0m$ '
  let line = ''
  const link = {
    channel: { readyState: 'open', send: () => {} },
    _ptySid: null,
    onPtyData: () => {}, onPtyClose: () => {}, onPtyReady: () => {},
    openPty(cols, rows) {
      this._ptySid = 1
      setTimeout(() => {
        this.onPtyReady()
        this.onPtyData(enc.encode(
          '\x1b[38;2;124;246;200m●\x1b[0m mock shell — this is the real WebTerminal UI\r\n' +
          '\x1b[90m  type, use the key bar, try `help` (no real device attached)\x1b[0m\r\n\r\n' + prompt,
        ))
      }, 60)
    },
    resizePty() {},
    closePty() { this._ptySid = null },
    sendPtyInput(u8) {
      const s = dec.decode(u8)
      for (const ch of s) {
        if (ch === '\r' || ch === '\n') {
          this.onPtyData(enc.encode('\r\n'))
          run(line, this)
          line = ''
          this.onPtyData(enc.encode(prompt))
        } else if (ch === '\x7f' || ch === '\b') {
          if (line.length) { line = line.slice(0, -1); this.onPtyData(enc.encode('\b \b')) }
        } else if (ch === '\x03') { // Ctrl-C
          this.onPtyData(enc.encode('^C\r\n' + prompt)); line = ''
        } else if (ch === '\x1b' || ch.charCodeAt(0) < 0x20) {
          // escape/control (arrows etc.) — echo a dim marker so taps are visible
          this.onPtyData(enc.encode('\x1b[90m·\x1b[0m'))
        } else {
          line += ch; this.onPtyData(enc.encode(ch))
        }
      }
    },
  }
  function run(cmd, l) {
    const c = cmd.trim()
    if (c === 'help') l.onPtyData(enc.encode('commands: help, ls, whoami, echo <text>, date\r\n'))
    else if (c === 'ls') l.onPtyData(enc.encode('\x1b[38;2;91;157;255mFilament\x1b[0m  docs  src  README.md\r\n'))
    else if (c === 'whoami') l.onPtyData(enc.encode('guest\r\n'))
    else if (c.startsWith('echo ')) l.onPtyData(enc.encode(c.slice(5) + '\r\n'))
    else if (c === 'date') l.onPtyData(enc.encode('Wed Jun 10 14:22:07 UTC 2026\r\n'))
    else if (c.length) l.onPtyData(enc.encode('\x1b[38;2;229;72;77m' + c.split(' ')[0] + ': command not found\x1b[0m\r\n'))
  }
  return link
}

export default function WebTermPreview() {
  const link = useMemo(makeMockLink, [])
  const [closed, setClosed] = useState(false)
  const T = T_DARK
  const accent = '#7CF6C8'
  const font = "'JetBrains Mono',ui-monospace,monospace"
  if (closed) return <div style={{ position: 'fixed', inset: 0, background: T.bg, color: T.dim, display: 'grid', placeItems: 'center', fontFamily: font }}>closed — reload to reopen</div>
  return (
    <div style={{ position: 'fixed', inset: 0, background: T.bg }}>
      <WebTerminal link={link} peerName="mock-device" route="direct" T={T} accent={accent} font={font} onClose={() => setClosed(true)} />
    </div>
  )
}
