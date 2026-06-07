# Filament — Final Launch Pack (paste-ready)

Everything below is final and meant to be pasted as-is. The HN and Reddit
sections contain no em dashes on purpose. CLI is at v0.2.0 stable with a
v0.2.1-beta available. Product: https://filament.autumated.com ·
Source: https://github.com/Abdk4Moura/filament

---

## 1. Show HN

**Title (paste this exact line):**

```
Show HN: Filament - P2P file sharing that shows the route your bytes take
```

**URL field:**

```
https://filament.autumated.com
```

**Text field (paste as-is):**

Filament sends files directly between two browsers over WebRTC. No upload, no
account, no size limit. Devices on the same WiFi find each other automatically.
Across networks you pair with a one-time spoken code ("clever-lynx-63") that
burns on first use, so an overheard code is worthless.

The part I think HN might find interesting: every peer tile shows a badge for
the route ICE actually selected. LAN means the bytes never leave your network,
P2P means direct over the internet, and RELAY means through my coturn. I have
not seen other tools surface this, and it turned out to be the best debugging
and trust feature in the whole app. You can literally see what your data did.

The honest origin: this started as an abandoned 2024 repo where I was trying to
understand how Flask and React fit together, with a half-finished hand-rolled
React clone living inside it (that later became its own project). Reviving it
turned into a tour of everything that makes WebRTC file transfer flaky in the
real world: signaling glare, dropped ICE candidates, zombie presence entries
after server restarts, transfers stuck at "transferring" forever, and stale
TURN credentials in long-lived tabs. I wrote up each failure mode and its fix.

Transfers pause and resume across connection drops (an offset handshake keyed by
a stable per-tab identity, with content-hash verification on resume), chunks are
framed so concurrent transfers cannot corrupt each other, and the whole backend
is a small Flask plus Redis plus coturn stack you can self-host with one docker
compose. There is also a native Rust CLI (v0.2.0 stable, a v0.2.1-beta is up for
testing) so a headless Linux box can send to a phone that has nothing installed.

Stack: React/Vite frontend static on Cloudflare Pages, Flask-SocketIO signaling
reached through a Cloudflare Tunnel with no open ports, coturn for relay on
:3478 and :443 (the orange-cloud proxy cannot carry TURN, so clients get the raw
droplet IP; that one cost me an evening).

Known limits, honestly: both devices must be online, because nothing is ever
stored (that is the point, but it means no async drop). Resume needs the
sender's tab to stay alive, since browsers revoke file handles on reload. And
iOS Safari backgrounding is still the hardest environment.

Code: https://github.com/Abdk4Moura/filament

**First comment (post this yourself right after submitting):**

If anyone wants the gory details, I wrote up the WebRTC failure modes I hit and
how I fixed each one. It covers signaling glare, ICE candidates that arrive
before the remote description, presence entries that go zombie after a server
restart, transfers that hang at "transferring" forever, and TURN creds that go
stale in a tab left open overnight. HN tends to like a good failure-mode
writeup, so here it is:
https://abdk4moura.github.io/post.html?post=webrtc-file-transfer-failures.md

**Posting notes (for you, do not paste):**
- Tue to Thu, 8 to 10am US Eastern is the highest-traction window.
- Stay available 2 to 3 hours after posting. Answering comments quickly is what
  keeps a Show HN on the front page.
- Be ready for: "how is this different from Snapdrop/PairDrop?" (route
  visibility, resumable transfers, one-time burn codes, self-host guide), "why
  not magic-wormhole?" (browser, zero install, but wormhole's PAKE is stronger
  against a malicious server, which is a fair point), "what does the signaling
  server see?" (who-talks-to-whom, never content, DTLS end to end), "TURN
  bandwidth costs?" (quota-capped coturn, most pairs connect direct).

---

## 2. r/selfhosted

**Title (paste this exact line):**

```
Filament: self-hostable P2P file drop with visible routing (LAN/P2P/RELAY), resumable transfers, and one-time pairing codes
```

**Flair:** Release

**Body (paste as-is):**

I revived an old project of mine into something I now use daily with my family,
and it is fully self-hostable, so I am sharing it here.

Filament is browser-to-browser file transfer over WebRTC. Same-WiFi devices
discover each other automatically. Across networks you pair with a one-time
spoken code ("clever-lynx-63") that burns after a single use. Files are never
uploaded anywhere. They go direct peer to peer, with your own coturn as the
encrypted relay fallback for strict networks.

Things r/selfhosted might specifically care about:

- The whole backend is tiny: Flask-SocketIO signaling plus Redis plus coturn in
  one docker compose, every container resource-capped (it runs comfortably on a
  shared $6 droplet alongside other services).
- No open inbound ports needed for the API. I run it through a Cloudflare Tunnel
  that dials out, so only coturn needs real ports (3478 tcp+udp and 443 tcp+udp
  as the strict-network fallback). The frontend is a static build you can host
  anywhere; mine is on Cloudflare Pages.
- Route transparency: every peer tile shows whether bytes are going LAN-direct,
  P2P over the internet, or through your relay. Good for trust and for debugging
  your own NAT situation.
- The API is stateless behind Redis, so you can scale replicas up or down in
  seconds. Signaling is cheap (small SDP/ICE messages only); the component that
  grows with usage is coturn, since it relays real bytes for hard-NAT peers.
- Resilience is documented, not vibes. Every failure mode I hit (signaling
  glare, dropped ICE candidates, zombie presence after restarts, stale TURN
  creds in long-lived tabs) is written up with its fix:
  https://abdk4moura.github.io/post.html?post=webrtc-file-transfer-failures.md
- Transfers pause and resume across drops with content-hash verification, and
  multiple concurrent transfers are chunk-framed so they cannot corrupt each
  other.

Honest limits: both ends must be online (nothing is stored, by design), and
resume needs the sender's tab alive, since a page reload revokes browser file
handles.

Live instance: https://filament.autumated.com
Code plus deploy guide: https://github.com/Abdk4Moura/filament

Happy to answer anything about the WebRTC failure modes. That turned out to be
the real project.

---

## 3. AlternativeTo

**Name:**

```
Filament
```

**URL:**

```
https://filament.autumated.com
```

**Category:** File Sharing / File Transfer

**License:** Open Source (MIT) · https://github.com/Abdk4Moura/filament

**Platforms:** Web (any browser: Android, iPhone, Mac, Windows, Linux). Native
CLI on Linux, macOS, and Windows.

**Short description (tagline field, paste as-is):**

Send files directly between devices from the browser. Peer to peer over WebRTC,
no upload, no app, no account, no size limit.

**Full description (paste as-is):**

Filament transfers files straight between two browsers. Devices on the same WiFi
discover each other automatically (like AirDrop, but cross-platform). Devices on
different networks pair with a one-time spoken code that works exactly once.
Files never touch a server: they stream peer to peer over an encrypted WebRTC
data channel, with an encrypted relay as fallback for strict networks. A route
badge shows exactly how the bytes travel (LAN, P2P, or RELAY). Interrupted
transfers pause and resume from the same byte, verified by content hash. There
is also a native CLI so a headless server can send to a phone with nothing
installed. Fully open source (MIT) and self-hostable as a small Flask plus Redis
plus coturn stack with one docker compose.

**Mark as alternative to:**

```
Snapdrop · PairDrop · AirDrop · Send Anywhere · WeTransfer · magic-wormhole · croc
```

**Tags / features to tick:**

```
No registration · No file size limit · Peer-to-peer · End-to-end encrypted transport · Self-hostable · Open source · Resumable transfers · Cross-platform · No account · Web-based · CLI
```

**Verification of each "alternative to" claim:**
- Snapdrop / PairDrop: same-WiFi browser file drop. Filament does this plus
  cross-network burn codes and resume. Defensible.
- AirDrop / Quick Share: local device-to-device sharing. Filament is the
  cross-platform browser equivalent. Defensible (Quick Share dropped from the
  paste line to keep it tight; add it back if you want).
- Send Anywhere: code-based cross-device transfer. Direct analog. Defensible.
- WeTransfer: link-based file sending. Filament is the no-upload, no-link,
  no-account counterpart. Defensible (positioned as the opposite model, which is
  the selling point).
- magic-wormhole / croc: code-phrase peer-to-peer transfer. Filament's pitch is
  that the other end can be a browser with nothing installed. Defensible.

---

## 4. Google Search Console checklist

Property is for **filament.autumated.com** (the product site). Note the blog
lives on a **different domain**, abdk4moura.github.io, so it needs its own
property if you want the blog post indexed there.

- [ ] Add the property for `filament.autumated.com`. Easiest path: Domain
      property via a DNS TXT record in Cloudflare (covers all subdomains). The
      HTML-file method also works since the site is served by the CF Worker/Pages,
      but DNS is cleaner here.
- [ ] Submit the sitemap. It already exists and is referenced by robots.txt:
      `https://filament.autumated.com/sitemap.xml` (lists `/`, `/about`, `/faq`).
      No action needed beyond submitting it in Search Console.
- [ ] Request indexing for `https://filament.autumated.com/` (URL Inspection
      tool, then "Request indexing").
- [ ] For the blog deep-dive
      (`https://abdk4moura.github.io/post.html?post=webrtc-file-transfer-failures.md`),
      request indexing under the **abdk4moura.github.io** property, not the
      filament one. Note: it is a query-string route off post.html, so Google may
      index it slowly; the canonical page is post.html.

Sitemap/robots status: PRESENT (not missing). robots.txt allows all and points
to the sitemap; sitemap covers the three real pages. Optional follow-up: the
sitemap does not and cannot list the github.io blog post (different domain), so
no change is needed there.

---

## 5. What changed vs your old drafts

- Stripped every em dash from the Show HN, r/selfhosted, and AlternativeTo body
  text so the posts paste clean (the user pastes them as-is).
- First-comment text added to Show HN (the drafts had none) built around the
  live blog failure-mode writeup, which is stronger HN material than the inline
  repo doc link.
- Swapped the failure-mode link from the in-repo `docs/resilience.md` to the
  live blog URL in the first comment and in the Reddit body, per the launch
  plan; the Show HN body keeps the narrative and defers the link to the comment.
- Did NOT add `filament pair` or remembered-devices as a selling point. Those
  are v0.2.1-beta features, and the drafts lean on the stable one-time burn
  codes; promoting beta features as stable was explicitly out of scope.
- Added the CLI version reality (v0.2.0 stable, v0.2.1-beta available) and the
  MIT license (a root LICENSE now exists) where natural.
- Trimmed the AlternativeTo "alternative to" line to defensible analogs and
  reordered to lead with the closest matches (Snapdrop/PairDrop/AirDrop).
