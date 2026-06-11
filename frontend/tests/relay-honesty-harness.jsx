// Focused render harness for the relay-honesty UX (transport-resilience P1).
// Driving a REAL relayed peer here would need two filament CLI peers paired in
// over `--relay` plus live signaling, and the relay state we assert is PURELY
// presentation — Filament derives every relay affordance from `peer.route ===
// 'relayed'` (set browser-side by webrtc.js `_detectRoute`). So, exactly as the
// PakeKeep harness does, we mount Filament directly with an injected roster:
// two relayed peers (loud ⚠ expected) + one direct peer (no warning expected),
// and assert the tile chip, the status line, the device-sheet explainer, and
// the global "N on relay" indicator. ?theme=light|dark drives both palettes.
import React from 'react'
import ReactDOM from 'react-dom/client'
import Filament from '../src/ui/Filament.jsx'

const params = new URLSearchParams(window.location.search)
const theme = params.get('theme') === 'light' ? 'light' : 'dark'
// ?allDirect=1 flips every peer to a direct route — used to assert the global
// "N on relay" indicator is HIDDEN when nothing is on relay.
const allDirect = params.get('allDirect') === '1'

const baseState = {
  roomScope: 'auto',
  roomId: 'relay-demo',
  roomUrl: 'http://127.0.0.1/rooms/relay-demo',
  roomCode: '',
  network: 'Wi-Fi',
  localHelper: null,
  connected: true,
  signalingKind: 'ws',
  me: { name: 'me', uid: 'meuid', color: '#7CF6C8' },
  peers: [
    // A relayed, remembered, shell-capable peer — the ⚠ chip must show even
    // alongside REMEMBERED + SHELL (relay honesty exception in the tile).
    { id: 'peer-relay-1', name: 'pixel-7', color: '#FF8AD6', status: 'ready', route: 'relayed', lastSeen: 'now', known: 'pixel-7', shell: true },
    // A second relayed peer — exercises the global "2 on relay" count.
    { id: 'peer-relay-2', name: 'do-vm', color: '#FFC857', status: 'ready', route: 'relayed', lastSeen: 'now' },
    // A direct peer — MUST carry no relay warning at all.
    { id: 'peer-direct', name: 'my-laptop', color: '#5BE7FF', status: 'ready', route: 'direct', lastSeen: 'now', known: 'my-laptop' },
  ],
  transfers: [],
  pendingKeeps: [],
  pendingPakeKeep: [],
  getLink: () => null,
}

if (allDirect) baseState.peers = baseState.peers.map((p) => ({ ...p, route: 'direct' }))

const noop = () => {}

function Harness() {
  return React.createElement(Filament, {
    state: baseState,
    ui: { theme, accent: 'green', density: 'airy', columns: 'auto', font: 'jetbrains', onToggleTheme: noop },
    onSendFiles: noop, onAccept: noop, onDecline: noop, onSave: noop, onClear: noop,
    onCopyRoomLink: noop, onPairWithCode: noop, onGenerateCode: noop, onUseAutoRoom: noop,
    onAcceptKeep: noop, onDeclineKeep: noop, onAcceptPakeKeep: noop, onDeclinePakeKeep: noop,
    onForgetDevice: noop, onRenameDevice: noop,
  })
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Harness))
