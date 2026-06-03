# Quickshare Local — offline LAN discovery (spike)

**Experiment, not production.** A sketch of how Quickshare could discover peers
on the same WiFi with **no internet and no signaling server at all** — the model
LocalSend / Syncthing / Tailscale use.

## Why a native helper?

A browser tab cannot discover LAN devices on its own: JavaScript has no UDP,
no multicast, and no mDNS/Bonjour. So the only way to get AirDrop-style "people
near you" that works on a plane with WiFi-but-no-internet is a small native
process on each device. This is that process, in dependency-free Node.

```
 device A                         device B
 ┌───────────────┐   UDP multicast  ┌───────────────┐
 │ discovery.js  │ ◄──────────────► │ discovery.js  │   announce + listen on
 │   announce ●  │  239.255.79.17   │   ● announce  │   the LAN (no server)
 │   bridge :53317                   bridge :53317  │
 └──────┬────────┘                  └───────┬───────┘
        │ http://127.0.0.1:53317/peers      │
        ▼                                    ▼
   browser (Quickshare web app reads the local bridge)
```

- **Presence:** each helper multicasts a tiny `{id, name, http}` datagram every
  2s and listens for everyone else's, expiring peers after 6s. TTL=1 keeps it on
  the local link — it never routes off the LAN.
- **Bridge:** it serves whoever it found at `http://127.0.0.1:53317/peers`
  (loopback only). The Quickshare web app polls that and lights up LAN devices
  even offline. `useQuickshare()` already probes this and exposes `localHelper`.

## Try it

Two instances on one machine (different HTTP ports) discover each other via
multicast loopback:

```bash
node discovery.js --name alice
node discovery.js --name bob --http 53319    # second terminal

curl http://127.0.0.1:53317/peers
# { "peers": [ { "id": "...", "name": "bob", "http": 53319, "addr": "..." } ] }
```

On a real network, run one per device on the same WiFi.

## Endpoints

| Method | Path      | Returns |
|--------|-----------|---------|
| GET    | `/peers`  | `{ peers: [{ id, name, http, addr }] }` |
| GET    | `/me`     | `{ id, name }` |
| GET    | `/health` | `{ ok: true }` |

## Where this would go next

This spike only does **discovery + presence**. To make it transfer files
offline you'd add, on top of the discovered `addr`/`http`:
- a WebRTC handoff with a **local** signaling exchange over the bridge (no
  internet rendezvous), or a direct HTTP/QUIC stream like LocalSend, and
- a security handshake (per-device key + a confirm prompt) so you don't accept
  files from anyone who can send multicast on the LAN.

## Caveats

- Many corporate/guest WiFis block multicast and client-to-client traffic
  (AP isolation) — discovery silently finds nothing there.
- This is presence only; there's no auth yet. Don't run it on untrusted
  networks expecting privacy.
