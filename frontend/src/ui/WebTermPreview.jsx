// WebTermPreview: mounts the REAL WebTerminal against a MOCK PeerLink running a
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

// Dev knobs (harness only, inert in the real app):
//   ?echodelay=N  delay the mock's echo by N ms so predictive local echo is
//                 actually VISIBLE (styled) before the round-trip lands, and so
//                 the per-prediction timeout can be exercised.
//   ?noecho=1     the mock stops echoing printable chars entirely (a password-
//                 prompt stand-in), so we can prove prediction stays OFF / a
//                 ghost is cleared by the timeout when the server never echoes.
const Q = (() => { try { return new URLSearchParams(window.location.search) } catch (e) { return new URLSearchParams() } })()
const ECHO_DELAY = Math.max(0, parseInt(Q.get('echodelay'), 10) || 0)
const NO_ECHO = Q.get('noecho') === '1'

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
          '\x1b[38;2;124;246;200m●\x1b[0m mock shell: this is the real WebTerminal UI\r\n' +
          '\x1b[90m  type, use the key bar, try `help` (no real device attached)\x1b[0m\r\n\r\n' + prompt,
        ))
      }, 60)
    },
    resizePty() {},
    closePty() { this._ptySid = null },
    sendPtyInput(u8) {
      const s = dec.decode(u8)
      // ALL output (echoes, erases, prompt, command output) rides one delayed
      // emitter so the mock faithfully models a real PTY where every byte back to
      // us shares the same latency. ECHO_DELAY=0 keeps it synchronous (the default
      // preview feel); a non-zero delay makes the predictive overlay visible and
      // lets the timeout be exercised. emit() preserves ordering.
      const emit = (str) => {
        const out = enc.encode(str)
        if (ECHO_DELAY) setTimeout(() => this.onPtyData(out), ECHO_DELAY)
        else this.onPtyData(out)
      }
      for (const ch of s) {
        if (ch === '\r' || ch === '\n') {
          emit('\r\n')
          run(line, this, emit)
          line = ''
          emit(prompt)
        } else if (ch === '\x7f' || ch === '\b') {
          if (line.length) { line = line.slice(0, -1); emit('\b \b') }
        } else if (ch === '\x03') { // Ctrl-C
          emit('^C\r\n' + prompt); line = ''
        } else if (ch === '\x1b' || ch.charCodeAt(0) < 0x20) {
          // escape/control (arrows etc.), echo a dim marker so taps are visible
          emit('\x1b[90m·\x1b[0m')
        } else {
          line += ch
          // NO_ECHO simulates a non-echoing prompt (password) so prediction must
          // stay off and a ghost must be cleared by the timeout.
          if (!NO_ECHO) emit(ch)
        }
      }
    },
  }
  function run(cmd, l, emit) {
    const c = cmd.trim()
    if (c === 'help') emit('commands: help, ls, whoami, echo <text>, date, seq [n], tui\r\n')
    else if (c === 'ls') emit('\x1b[38;2;91;157;255mFilament\x1b[0m  docs  src  README.md\r\n')
    else if (c === 'whoami') emit('guest\r\n')
    else if (c.startsWith('echo ')) emit(c.slice(5) + '\r\n')
    else if (c === 'date') emit('Wed Jun 10 14:22:07 UTC 2026\r\n')
    else if (c === 'seq' || c.startsWith('seq ')) {
      // Emit N numbered lines so scrollback (and the custom scrollbar) can be
      // exercised in the harness. Default 200.
      const n = Math.max(1, Math.min(5000, parseInt(c.split(' ')[1], 10) || 200))
      let out = ''
      for (let i = 1; i <= n; i++) out += 'line ' + i + '\r\n'
      emit(out)
    }
    else if (c === 'tui') {
      // Issue #1 stand-in: enter the alternate screen and draw a full-screen
      // frame, exactly like vim/htop/opencode. If xterm passes our raw escapes
      // through (the #1 fix), buffer.active.type flips to 'alternate' and the
      // banner renders. Leaves the alt screen up so Playwright can assert it.
      emit(
        '\x1b[?1049h' + // switch to alternate screen buffer
        '\x1b[2J' +     // clear it
        '\x1b[1;1H' +   // home
        '\x1b[7m TUI-MODE-ACTIVE \x1b[0m\r\n' + // reverse-video banner
        '\x1b[3;3Hopencode-style full-screen TUI is drawing here\r\n' +
        '\x1b[5;3Hpress q (or run `exit-tui`) to leave',
      )
    } else if (c === 'exit-tui') {
      emit('\x1b[?1049l') // back to the normal screen buffer
    } else if (c.length) emit('\x1b[38;2;229;72;77m' + c.split(' ')[0] + ': command not found\x1b[0m\r\n')
  }
  return link
}

export default function WebTermPreview() {
  const link = useMemo(makeMockLink, [])
  const [closed, setClosed] = useState(false)
  const T = T_DARK
  const accent = '#7CF6C8'
  const font = "'JetBrains Mono',ui-monospace,monospace"
  if (closed) return <div style={{ position: 'fixed', inset: 0, background: T.bg, color: T.dim, display: 'grid', placeItems: 'center', fontFamily: font }}>closed, reload to reopen</div>
  return (
    <div style={{ position: 'fixed', inset: 0, background: T.bg }}>
      <WebTerminal link={link} peerName="mock-device" route="direct" T={T} accent={accent} font={font} onClose={() => setClosed(true)} />
    </div>
  )
}
