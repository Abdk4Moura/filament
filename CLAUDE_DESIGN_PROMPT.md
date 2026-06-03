# Claude Design prompt — Filament UI

Paste the block below into Claude Design (claude.ai). It is written so the
output **drops straight onto the real networking layer** with no rewrites: it
pins the exact data shape (`useFilament()` from CONTRACT.md), forbids any real
networking in the artifact, and fixes the visual direction (square interface).

Why it's split this way: Claude Design runs in a sandbox — it cannot do real
WebRTC against your Flask server. So you ask it for the **presentation only**,
driven by a single `state` prop + callback props whose names/shape match the
hook. You then wire it in by replacing the mock with `useFilament()`.

---

## THE PROMPT (copy from here) ⬇

Build a single-file React component for a peer-to-peer file-sharing web app
called **Filament**. This is the **presentation layer only** — do NOT add any
real networking (no WebRTC, no sockets, no fetch). Drive everything from props
and local UI state. Use **plain CSS or styled JSX**, no UI libraries, no
Tailwind. Export a default `<App>` and ship a `mockState` object so it renders
standalone.

### Visual direction — a SQUARE interface
- The whole aesthetic is built on **squares and right angles**. Sharp corners
  (border-radius 0–4px max), a strict grid, hairline 1px borders. No circles, no
  blobs, no orbit/radar metaphor.
- Peers are shown as a **grid of square tiles** (CSS `aspect-ratio: 1`). The
  grid is the centerpiece.
- Modern, calm, high-contrast. Dark theme by default. Monospace or a clean
  geometric sans. Think "engineered tool," not "consumer cute."
- Each peer has a stable accent `color` (provided in the data) — use it as a
  small square swatch / tile accent, not a full fill.
- Motion is minimal and mechanical: quick fades, a progress bar that fills
  left-to-right. No bouncy easing.

### Data it renders (this shape is FIXED — match names exactly)
The component receives one prop, `state`, plus action callbacks. In production
`state` comes from a `useFilament()` hook; in the artifact, feed it `mockState`.

```js
state = {
  me: { id, name, color } | null,         // you
  connected: boolean,
  signalingKind: "socketio" | "firebase",
  roomId: string | null,
  roomUrl: string | null,                 // share to pair
  peers: [
    { id, name, color, status: "connecting" | "ready" | "failed" }
  ],
  transfers: [
    {
      id, peerId, peerName,
      direction: "send" | "receive",
      name,                               // file name
      size,                               // bytes
      mime,
      progress,                           // 0..1
      status: "offered" | "transferring" | "complete" | "declined" | "failed",
      url                                 // present on completed receives
    }
  ],
}
```

Action callbacks (call these — don't implement them):
- `onSendFiles(peerId, fileList)` — fired when the user picks files for a peer
- `onAccept(transferId)` / `onDecline(transferId)` — for an `offered` receive
- `onSave(transferId)` — download a `complete` receive
- `onClear(transferId)` — dismiss a finished transfer
- `onCopyRoomLink()` — copy `state.roomUrl`

### Screens / states to cover
1. **Top bar:** brand "filament", your identity (`me.name` + color swatch +
   `signalingKind` badge), and a "copy room link" button (calls `onCopyRoomLink`).
2. **Peer grid:** square tiles. Show name, color accent, and a status hint.
   - `ready` → tile is interactive; clicking it opens a file picker, then calls
     `onSendFiles(peer.id, files)`. Also accept **drag-and-drop of files onto a
     tile**.
   - `connecting` / `failed` → tile dimmed, not interactive.
   - **Empty state:** when `peers` is empty, show a clear "share the room link to
     pair a device" panel with the link and copy button.
3. **Transfers panel:** a list, newest first. Each row shows direction (↑ send /
   ↓ receive), file name, size (human-readable), a progress bar (`progress`),
   and status. Controls by state:
   - receive + `offered` → **accept** / **decline**
   - receive + `complete` → **save**
   - send + `offered` → "waiting for accept…" (no buttons)
   - any `complete` / `declined` / `failed` → **clear**
4. Be responsive: the grid reflows from multi-column on desktop to 2-column on
   mobile; the top bar stacks.

### Deliverable
One self-contained file: the `<App>` component, a realistic `mockState` (4–6
peers across all statuses, 2–3 transfers across different states/directions so
every control is visible), and all styles inline. It must render and look
finished on first load.

## THE PROMPT (copy to here) ⬆

---

## Wiring the result back in
1. Save Claude Design's output as `frontend/src/App.jsx` (replace the placeholder).
2. At the top of its `App`, swap the mock for the real hook and spread it as `state`:

   ```jsx
   import { useFilament } from './lib/useFilament.js'

   export default function App() {
     const qs = useFilament()
     return <Filament
       state={qs}
       onSendFiles={qs.sendFiles}
       onAccept={qs.acceptTransfer}
       onDecline={qs.declineTransfer}
       onSave={qs.saveTransfer}
       onClear={qs.clearTransfer}
       onCopyRoomLink={() => navigator.clipboard.writeText(qs.roomUrl)}
     />
   }
   ```
   (Rename `Filament` to whatever Claude Design called its component.)
3. `npm run build` and reload Flask — done. The names line up because the prompt
   was written against CONTRACT.md.
