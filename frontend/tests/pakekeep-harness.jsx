// Focused render harness for the L1-a PakeKeepBanner consent prompt.
// Full E2E PAKE pairing needs two crypto peers + a live SPAKE2 ceremony, which
// isn't feasible headless. Filament is a PURE presentation component driven by
// `state` + callbacks, so we mount it directly with an injected pendingPakeKeep
// and assert the banner renders with an editable name + remember/not-now. The
// accept callback writes its (peerId, name) onto window so the test can assert
// the editable-name path actually fires.
import React from 'react'
import ReactDOM from 'react-dom/client'
import Filament from '../src/ui/Filament.jsx'

const baseState = {
  roomScope: 'link',
  roomId: 'demo-room',
  roomUrl: 'http://127.0.0.1/rooms/demo-room',
  roomCode: '',
  network: 'Wi-Fi',
  localHelper: null,
  connected: true,
  signalingKind: 'ws',
  me: { name: 'me', uid: 'meuid' },
  peers: [],
  transfers: [],
  pendingKeeps: [],
  // The L1-a queue under test: one v2 pairing awaiting remember-consent.
  pendingPakeKeep: [{ peerId: 'peer-abc123', name: 'pixel', secret: 'S', caps: {} }],
}

window.__pakeAccept = null
window.__pakeDecline = null

function Harness() {
  return React.createElement(Filament, {
    state: baseState,
    onAcceptPakeKeep: (peerId, name) => { window.__pakeAccept = { peerId, name } },
    onDeclinePakeKeep: (peerId) => { window.__pakeDecline = { peerId } },
    onSendFiles: () => {},
    onAccept: () => {}, onDecline: () => {}, onSave: () => {}, onClear: () => {},
    onCopyRoomLink: () => {}, onPairWithCode: () => {}, onGenerateCode: () => {},
    onUseAutoRoom: () => {}, onAcceptKeep: () => {}, onDeclineKeep: () => {},
  })
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Harness))
