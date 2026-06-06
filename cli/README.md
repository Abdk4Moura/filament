# filament CLI

The terminal end of [Filament](https://filament.autumated.com) — P2P file
transfer where **a browser is a first-class peer**. Send from a headless
server straight to a phone with nothing installed on it, or between two
terminals, or terminal → browser → terminal. Same signaling, same WebRTC
wire protocol, same one-time codes as the web app.

```
# the croc-style flow, except the other end can be a browser
filament send video.mp4 --code
#   code: clever-lynx-63
# other machine:
filament recv clever-lynx-63
# or: open filament.autumated.com on any phone and claim the code there

# same network? no code needed — auto-discovery
filament recv -y --dir ~/Drops          # this terminal
filament send report.pdf                # any device on the same network

# directories tar on the fly; stdin works
filament send ./photos --code
tar c logs | filament send - --name logs.tar --code

# self-hosters
filament send x.bin --server https://your-instance.example
```

## What it does that the web app can't

- **Resume across process restarts.** Receivers keep `<name>.part` +
  `<name>.part.meta`; a re-offer of the same file (name + size) continues
  from the bytes on disk. Browsers lose the file handle on reload — the CLI
  has a real filesystem, so it doesn't.
- **Headless.** `filament recv -y --dir` on a server is a drop target for
  any browser or CLI that can reach the signaling server.

## What it shares with the web app

- One-time pairing codes (burn on first claim, atomic, additive).
- Route transparency: prints `route: local | direct | relayed` from the
  selected ICE candidate pair, same taxonomy as the peer-tile badges.
- TURN fallback via the same `/api/config` ephemeral credentials.

## Build

```
cargo build --release        # → target/release/filament
```

## Architecture notes

`net.rs` exposes a `Transport` trait (control JSON + sid-framed binary);
`DataChannelTransport` (webrtc-rs) is implementation #1. The transfer logic
in `main.rs` never touches WebRTC types — a QUIC transport for CLI↔CLI bulk
speed slots in behind the same trait without touching transfer logic.

Chunks are capped at 60 KiB payload + 4-byte stream-id header to stay under
SCTP's 65535-byte default max message size (webrtc-rs enforces it strictly).

Protocol reference: `../CONTRACT.md` and `../docs/resilience.md`.

## Known failure modes / current limits

Every known flaw is tracked with a status in
[`../docs/cli-resilience.md`](../docs/cli-resilience.md) — the rule is that
nothing gets fixed without flipping its entry there, and nothing ships while
a suspected-breakage item is open. Headlines as of v1: browser→CLI direction
untested and suspected broken on chunk size (C1); no watchdog/retry/credential
refresh yet (C3–C5); resume trusts name+size (C7); throughput is modest until
the QUIC transport lands (C8).
