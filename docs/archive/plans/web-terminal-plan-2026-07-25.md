# Web terminal: resilience (1-6) + ergonomics redesign

## How 1-6 fit together
They are not 6 separate features, they are layers of one mosh-class terminal on a
resilient transport. Build order is chosen so each phase ships value on its own.

### Phase 1 (now, frontend-only, no daemon restart)
- **#1 Predictive / local echo.** Client shows your keystrokes instantly
  (underlined until the server confirms), reconciles when real bytes arrive.
  Typing feels instant and never freezes on a blip. Biggest immediate relief.

### Phase 2 (resilient transport, one CLI change + a coordinated daemon restart)
- **WS-relay** transport for the shell (browser to server WebSocket, server
  forwards to the CLI), E2E-encrypted with the pairing secret so the server still
  sees nothing.
- **#3 Connectionless, keyed by secret.** The session is keyed to the secret, not
  a connection, so any reconnect from any IP resumes. Roaming wifi to cellular
  becomes a non-event.
- **#6 Two-way byte numbering + replay.** Number every byte each direction; on
  reconnect each side says "I have up to N" and the gap is resent. No loss, no
  corruption across drops. (We already do server to client replay.)

### Phase 3 (best-path selection)
- **#4 Dual transport, happy-eyeballs.** Run WebRTC P2P and WS-relay together,
  use whichever is alive, switch silently. P2P speed when it works, relay
  resilience when it does not.
- **#5 WebTransport / QUIC** as a transport option where supported (Chrome,
  Android), with built-in connection migration. iOS Safari falls back to WS-relay.

### Phase 4 (the gold standard)
- **#2 State-sync (mosh SSP).** Server sends the diff between what your screen
  shows and what it should show, instead of a byte stream. Lost or late packets
  self-heal; reconnects are instant and exact. Largest change, done last on top of
  a solid transport.

## Ergonomics redesign (let's talk: react to these)
Goal: max out usability, especially one-handed mobile. Candidate set, tell me
which to prioritize or cut:

1. **Accessory key bar** (sticky): Esc, Tab, Ctrl (sticky tap-then-key), Alt,
   arrows, Home/End, PgUp/PgDn, and common symbols (| / ~ - * " ' etc.),
   customizable order.
2. **Font + zoom**: +/- buttons and pinch-to-zoom, remembered per device.
3. **One-tap paste** and a command palette / recent-commands list.
4. **Selection**: long-press to select, select word / line / all, big copy button.
5. **Clear reconnect status**: a visible "reconnecting" pill and a "live/relayed"
   indicator, so a blip is legible instead of a frozen screen.
6. **Keyboard-aware layout**: the input row and accessory bar ride above the soft
   keyboard, never hidden; landscape optimized.
7. **Sessions**: multiple tabs / quick switch, maybe split.
8. **Readability**: high-contrast theme, larger default text on phones, themes.
9. **Quick actions**: Ctrl-C, clear, scroll-to-bottom (have), interrupt, send-EOF.
10. **Haptics** on key taps (Android).

Which of these matter most to you? Anything missing? Once you pick, I will design
the layout and build it alongside the transport phases.
