# Show HN draft — ready to paste

## Title (pick one; first is recommended)

> Show HN: Filament – P2P file sharing that shows you the route your bytes take

Alternates:
> Show HN: Filament – browser file transfer with visible routing and resumable P2P
> Show HN: I rebuilt my abandoned 2024 file-sharing app and documented every failure mode

## URL
https://filament.autumated.com

## Text (paste into the text field)

Filament sends files directly between two browsers over WebRTC — no upload, no
account, no size limit. Devices on the same WiFi find each other automatically;
across networks you pair with a one-time spoken code ("clever-lynx-63") that
burns on first use.

The part I think HN might find interesting: every peer tile shows a badge for
the route ICE actually selected — LAN (bytes never leave your network), P2P
(direct over the internet), or RELAY (through my coturn). I haven't seen other
tools surface this, and it turned out to be the best debugging and trust
feature in the app.

The honest origin: this started as an abandoned 2024 repo where I was trying to
understand how Flask and React fit together, with a half-finished hand-rolled
React clone inside it (that became its own repo). Reviving it turned into a
tour of everything that makes WebRTC file transfer flaky in the real world. I
documented each failure mode and fix — signaling glare, dropped ICE candidates,
zombie presence entries after server restarts, transfers stuck at
"transferring" forever, stale TURN credentials in long-lived tabs:
https://github.com/Abdk4Moura/filament/blob/main/docs/resilience.md

Transfers pause and resume across connection drops (offset handshake keyed by a
stable per-tab identity), chunks are framed so concurrent transfers can't
corrupt each other, and the whole backend is a small Flask + Redis + coturn
stack you can self-host with docker compose.

Stack: React/Vite frontend on a Cloudflare Worker, Flask-SocketIO signaling
behind a Cloudflare Tunnel on a shared $6 droplet, coturn for relay (raw IP on
:3478 and :443 because the orange-cloud proxy can't carry TURN — that one cost
me an evening).

Known limits, honestly: both devices must be online (nothing is ever stored,
which is the point, but it means no async drop); resume requires the sender's
tab to stay alive (browsers revoke file handles on reload); and iOS Safari
backgrounding is still the hardest environment.

Code: https://github.com/Abdk4Moura/filament

## Posting notes
- Tue–Thu, 8–10am US Eastern is the highest-traction window.
- Stay available 2–3 hours after posting — answering comments quickly is what
  keeps a Show HN on the front page.
- Expected questions to be ready for: "how is this different from
  Snapdrop/PairDrop?" (route visibility, resume, one-time codes, self-host
  guide), "why not magic-wormhole?" (browser, zero install, but wormhole's PAKE
  is stronger against a malicious server — fair point), "what about the
  signaling server seeing metadata?" (it sees who-talks-to-whom, never content;
  DTLS end-to-end), "TURN bandwidth costs?" (quota-capped coturn, ~90% of
  pairs connect direct).
