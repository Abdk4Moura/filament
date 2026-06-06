# filament CLI

The terminal end of [Filament](https://filament.autumated.com): P2P file
transfer that works anywhere, where **a browser is a first-class peer**. Send from a headless
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

# same network? no code needed: auto-discovery
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
  from the bytes on disk. Browsers lose the file handle on reload: the CLI
  has a real filesystem, so it doesn't.
- **Headless.** `filament recv -y --dir` on a server is a drop target for
  any browser or CLI that can reach the signaling server.

## What it shares with the web app

- One-time pairing codes (burn on first claim, atomic, additive).
- Route transparency: prints `route: local | direct | relayed` from the
  selected ICE candidate pair, same taxonomy as the peer-tile badges.
- TURN fallback via the same `/api/config` ephemeral credentials.

## Install

```
# Linux / macOS: verifies checksums, installs to ~/.local/bin, no sudo
curl -fsSL https://filament.autumated.com/install | sh

# Windows
winget install Abdk4Moura.Filament

# Homebrew / Cargo
brew tap abdk4moura/filament https://github.com/Abdk4Moura/filament
brew install abdk4moura/filament/filament
cargo install filament-cli
```

Already installed? `filament update` fetches and checksum-verifies the latest
release and swaps itself atomically. Shell completions: `filament completions
<bash|zsh|fish>` (the installer wires them up automatically). Releases carry
SHA256SUMS + GitHub build provenance attestations; the Linux binary is fully
static. No telemetry: the binary talks to the signaling server you point it
at and to your peer, nothing else.

## Build from source

```
cargo build --release                                          # -> target/release/filament
cargo build --release --target x86_64-unknown-linux-musl --features static   # fully static
```

Releasing (maintainer): `git tag cli-vX.Y.Z && git push origin cli-vX.Y.Z` -
CI builds the matrix, checksums, attests, and publishes; then
`packaging/release-followup.sh cli-vX.Y.Z --pr` refreshes the Homebrew tap and
opens the winget PR.

## Architecture notes

`net.rs` exposes a `Transport` trait (control JSON + sid-framed binary);
`DataChannelTransport` (webrtc-rs) is implementation #1. The transfer logic
in `main.rs` never touches WebRTC types: a QUIC transport for CLI↔CLI bulk
speed slots in behind the same trait without touching transfer logic.

Chunks are capped at 60 KiB payload + 4-byte stream-id header to stay under
SCTP's 65535-byte default max message size (webrtc-rs enforces it strictly).

Protocol reference: `../CONTRACT.md` and `../docs/resilience.md`.

## Failure modes & tests

Every known failure mode is tracked with a status in
[`../docs/cli-resilience.md`](../docs/cli-resilience.md); the standing test
suite is `tests/gates.sh` (13 checks: code pairing + burn, kill-mid-transfer
resume chaos, corruption guard, both browser directions via Playwright,
`--to` selection, consent, throughput floor, TURN relay via coturn).
Resilience now matches the browser: establishment watchdog, disconnect grace +
ICE restart, reconnect attempts with fresh TURN credentials, uid supersede, a
120 s rejoin window with partials parked on disk, and content-hash-guarded
resume (`head` of first 256 KiB in every offer).

Remaining by design: persistent device identity (pairing layer), QUIC bulk
transport, PAKE: roadmap items, tracked in the ledger.

```
cd tests && npm i playwright          # once; chromium fetched on first run
./gates.sh                            # gates 0-9
./gates.sh --with-relay               # + gate 10 (needs docker)
```
