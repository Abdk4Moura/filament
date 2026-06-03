# Claude Design — follow-up prompt (A/B/C)

Paste this as a **follow-up message** in the same Claude Design conversation,
once the initial square UI is done. It adds three surfaces; everything else stays.

---

## THE PROMPT (copy from here) ⬇

Add three things to the Filament UI you just built. Keep the same square,
engineered, dark aesthetic and the same `state` + callback prop contract — these
are new fields/actions on it. Don't restyle what's already there.

**A · Connection-path badge (per peer tile).** Each peer now has
`peer.route: "local" | "direct" | "relayed" | null`. When set, show a tiny
square badge on the tile:
- `local` → green, label "LAN" — *data never leaves the network*
- `direct` → blue, label "P2P"
- `relayed` → amber, label "RELAY"
Make `local` feel like the reassuring, premium state (it's the privacy win).
Tooltip: "files go straight across your WiFi" / "peer-to-peer over the internet"
/ "via a relay".

**B · Discovery bar (above the peer grid).** New state:
`roomScope: "auto"|"code"|"link"`, `roomCode: string|null`, `network: "ipv4"|"ipv6"|"raw"|null`,
and actions `pairWithCode(code)`, `generateCode()`, `useAutoRoom()`.
- `roomScope === "auto"`: show "People near you" + the `network` tag, plus two
  buttons — **Pair with code** (opens a small input → `pairWithCode`) and
  **Create code** (`generateCode`).
- `roomScope === "code"`: show the `roomCode` BIG and monospaced, letter-spaced,
  built to read aloud, with a copy button and a **← Back to nearby** (`useAutoRoom`).
- `roomScope === "link"`: just the existing copy-link affordance.

**C · LAN-helper hint (subtle).** New state
`localHelper: { available: boolean, peers: [{id,name,addr}] }`. Only when
`available`, show a quiet inline chip like "◇ 3 on your LAN · offline-ready".
Hidden entirely when not available. Don't make it loud — it's a bonus signal.

Update `mockState` so all of it is visible: peers across `local`/`direct`/`relayed`,
one mock in `roomScope:"code"` with a `roomCode`, and `localHelper.available:true`
with a couple of peers. Keep it one self-contained file.

## THE PROMPT (copy to here) ⬆
