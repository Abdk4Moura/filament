# Web shell resilience: tricks beyond WS-relay

Roughly best to niche.

## 1. Predictive / local echo (mosh's killer trick)
Show your keystrokes instantly on the client (optimistically), then reconcile
when the server's bytes arrive. Typing feels instant and never freezes during a
blip, even on a bad link. Transport-independent, and probably the single biggest
win for the typing-under-disconnects pain. Mosh underlines predicted text until
the server confirms it.

## 2. State-sync instead of byte-stream (mosh SSP)
Instead of replaying every byte, the server sends the diff between what your
screen currently shows and what it should show. A lost or late packet does not
corrupt anything; the next diff just makes the screen correct. Reconnects become
instant and exact. Bigger change, but it is why mosh survives anything.

## 3. Connectionless / UDP-with-a-key (mosh + WireGuard model)
Do not key the session to a TCP connection; key it to a secret. Any datagram
from any IP with the key continues the session, so roaming wifi to cellular is a
non-event. WebRTC's data channel is already UDP-ish, so this can layer on it.

## 4. Dual transport, happy-eyeballs
Run WebRTC P2P and WS-relay at the same time, use whichever is alive, switch
silently. P2P speed when it works, relay resilience when it does not, no visible
drop. The "warm standby" idea applied to the shell.

## 5. WebTransport / QUIC relay
Modern browser transport with built-in connection migration (survives IP changes
like WireGuard). Cleaner than WebRTC. Good on Chrome/Android, weaker on iOS
Safari, so not universal yet.

## 6. Two-way byte numbering + replay
Number every byte each direction; on reconnect each side says "I have up to N"
and the gap is resent. Guarantees no loss or corruption across reconnects. We
already do server to client replay (the ring buffer); this adds the client to
server half.

## Recommendation
Predictive local echo (#1) plus WS-relay (the transport) is the high-impact pair.
WS-relay kills the drops; predictive echo makes typing feel instant regardless.
Full mosh-style state-sync (#2) is the gold standard if you want to go all the way.
