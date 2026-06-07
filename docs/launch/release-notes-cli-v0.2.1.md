# Filament CLI v0.2.1

This is the field-testing hardening release. Every change here came out of live multi-device testing across Android, iPad, and the CLI, with each diagnosis confirmed by telemetry rather than guesswork. The result is a calmer, more honest CLI that holds connections through real-world hiccups and tells you what is actually happening.

## New

- `filament pair`: a first-class pairing ceremony, so you can add and remember a device without pretending to send a file.
- `filament up` is now an interactive session: type a code to pair, or run `pair`, `devices`, and `forget` right in the prompt.
- New `filament devices rename` and `filament devices forget` subcommands to fix or remove your device names.
- Colored peer-status roster lines show every peer side by side, with the one that just changed carrying the note.

## Fixed

- Away peers now hold the line instead of being dropped, including the brief disconnect when a phone opens its file picker to choose what to send.
- Questions stay on screen as permanent lines, and a stray keypress can no longer silently decline an offer.
- Rejected claims now explain why, including telling you when the sender who made that code has already left.
- Stale "zombie" codes that nobody could claim now self-heal at creation time.
- Known devices reconnect on their own without a page reload or restart, because presence is asserted, verified, and reconciled.

## Protocol

- Added brb/back, pair-keep-ack, pair-proof-ack, and subscribe acknowledgements. All changes are additive, so older clients keep working unchanged.

## Web app

- A consent banner now asks before the browser remembers a device, so nothing is stored without your approval.
- Remembered devices get a clear REMEMBERED tile treatment that explains why they can reach you in any room.
- "Create code" is now available in pinned rooms.

## Install or update

```
# Already installed
filament update

# Linux / macOS installer
curl -fsSL https://filament.autumated.com/install | sh

# Homebrew
brew tap Abdk4Moura/tap
brew install abdk4moura/tap/filament
```
