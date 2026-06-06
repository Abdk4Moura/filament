# r/selfhosted post — ready to paste (flair: Release)

**Title:** Filament — self-hostable P2P file drop with visible routing (LAN/P2P/RELAY), resumable transfers, and one-time pairing codes

**Body:**

I revived an old project of mine into something I now use daily with my family,
and it's fully self-hostable, so sharing it here.

Filament is browser-to-browser file transfer (WebRTC). Same-WiFi devices
discover each other automatically; across networks you pair with a one-time
spoken code ("clever-lynx-63") that burns after a single use. Files are never
uploaded anywhere — direct peer-to-peer, with your own coturn as the encrypted
relay fallback.

Things r/selfhosted might specifically care about:

- **The whole backend is tiny**: Flask-SocketIO signaling + Redis + coturn,
  one docker compose, resource-capped (~100MB RAM total on my shared $6
  droplet). The frontend is a static build you can host anywhere.
- **No open inbound ports needed for the API** — I run it through a Cloudflare
  Tunnel; only coturn needs real ports (3478 + 443/udp+tcp).
- **Route transparency**: every peer tile shows whether bytes are going
  LAN-direct, P2P over the internet, or through your relay. Great for trust
  and for debugging your NAT situation.
- **Resilience is documented, not vibes**: every failure mode I hit (signaling
  glare, dropped ICE candidates, zombie presence after restarts, stale TURN
  creds in long-lived tabs) is written up with its fix:
  https://github.com/Abdk4Moura/filament/blob/main/docs/resilience.md
- Transfers pause/resume across drops; multiple concurrent transfers are
  chunk-framed so they can't corrupt each other.

Honest limits: both ends must be online (nothing is stored, by design), and
resume needs the sender's tab alive — page reload revokes browser file handles.

Live instance: https://filament.autumated.com
Code + deploy guide: https://github.com/Abdk4Moura/filament

Happy to answer anything about the WebRTC failure modes — that turned out to
be the real project.
