# Design: the filament product interface (local API + SDK)

> Status: design (2026-07-26). Formalizes the existing control socket (`ctl.rs`)
> into the stable interface that PRODUCTS build on. Stress-tested adversarially.
> Not yet built. See [`docs/status/CURRENT.md`](status/CURRENT.md) for the current
> core/product boundary this serves.

## Why

filament is the core/platform; products (a GPU compute product, and others) are
SEPARATE codebases that consume it. Today `ctl.rs` is an internal, unstable local
socket the CLI uses to talk to its own `up` daemon (~15 ops: open/dial/pty/mount/
...). This design turns that seam into a stable, versioned, documented public
contract plus a thin SDK, so a product builds ON filament instead of shelling out
to the CLI or reaching into internals.

Boundary it enforces: filament owns pairing, authorized channels, streams, grants,
transfer, mount, and this interface. Products own their domain logic (GPU sandbox,
job protocol, inference routing) on the consumer side of the SDK. Nothing
product-specific lives in filament core.

## Transport and protocol

- **Local unix-domain socket** (0600, same authority as the user), `ctl.rs` stays
  the foundation. Local-only: a product is a local process using the local daemon.
  No gRPC, no library-embed, no remote API (revisit only for a non-Rust-remote
  need). Steal Tailscale's LocalAPI shape (UDS + JSON), not containerd's gRPC.
- **Versioned JSON-NDJSON.** A version handshake at connect. Every request carries
  an `id`; every reply references it. Async events are separate NDJSON lines on the
  connection.

## Op set (grouped by primitive)

- identity / pairing: `pair` (introduce), `whoami`, `list-devices`
- peers: `peers`, `peer-status`
- streams: `open {peer, action}` (the core op), `close`
- transfer: `send`, `recv` (a blob to/from a peer)
- grants (the authz primitive): `grant`, `revoke`, `check`
- mount: `mount {cid | peer-fs}`, `unmount`, `mount-health`
- registration: `register {action, manifest}` (service discovery + consent routing,
  NOT authz)
- events: `subscribe {topics, last_event_id}`, `unsubscribe`

## Events model

Persistent subscription: a product opens a connection, sends `subscribe {topics,
last_event_id}`, and receives NDJSON event lines. (Webhooks/callbacks are overkill
for a local socket; polling is wasteful and too slow for consent prompts.)

- **Topics**: `peer`, `stream`, `grant`, `transfer`, `mount`, `job`, `consent`. A
  product subscribes only to what it needs.
- **Delivery**: at-least-once, **ordered within a topic**. Monotonic event ids;
  `last_event_id` on reconnect replays the gap; the daemon persists the last N
  events (at minimum the consent events) so a restarted product catches up.
- **Backpressure, two lanes** (this is load-bearing):
  - *Critical lane* (consent prompts, grant requests): small bounded buffer; block
    the daemon briefly, then surface. If the product is stuck, the daemon **times
    out and DENIES** the request. Fail-safe by default.
  - *Telemetry lane* (peer online/offline, transfer progress): bounded buffer,
    drop-oldest on overflow. Lossy by nature, and that is fine.
- **Scoping (no cross-product leakage)**: events are scoped by the calling
  product's grants and registered actions. A product only sees peers and streams it
  has a capability relationship with. If multiple products share a peer, that peer's
  events are visible only to products holding a grant for it.

## `open` and capabilities (the authz integration, done once)

**Grants are the single source of truth for authorization. Registration is service
discovery + consent routing, not authz.** Do not collapse them. The clean split:
the grant decides WHO can ask; the consent policy decides HOW the product responds
to the ask.

- **Action names are URI-like**: `gpu:run`, `file:read`, `file:write`, `file:sync`.
  A grant references an action.
- **Outbound** `open {peer, action}`: the local call is a REQUEST. The daemon checks
  the peer offers `action` and that we hold a grant, then forwards; the REMOTE
  peer's grant gate authorizes. The local side does not decide.
- **Inbound** (a peer opens `action` on us): the daemon checks OUR grant to that
  peer, routes to the product that registered `action`, and if that action's consent
  policy is `prompt`, emits a `consent` event and waits for accept/deny, then bridges
  the stream.
- **Registration manifest** (per offered action): `{action, consent: none | prompt
  | policy, max_concurrent, requires_display, ...}`. Registration says "I serve this
  action, here is my consent behavior"; it never grants authority.

### Two consent modes, and the no-surface fallback

`consent: prompt` presumes a registered product with a display (`requires_display`)
that can answer the ask in real time; the tray/companion app is that surface. This
is **live approval (push)**. A CLI cannot be a prompt surface, so when no display
product is connected the daemon must not hang: the critical-lane timeout DENIES
(fail-safe), and the request drops into a **pending-requests queue** the owner sees
in-band (`filament requests`, plus a line in `filament devices`) alongside any
configured notify hook. The other mode, **deliberate grant (pull)**, needs none of
this: the owner issues `grant` ahead of time and the inbound `open` authorizes with
no prompt at all. See `docs/design-identity-access-ux.md`, "the one recurring
pattern", for the split. Rule of thumb: `consent: prompt` is only meaningful with a
display product connected; without one, design the flow around deliberate,
time-bounded grants.

## Socket authorization

- **Now**: 0600, same-user, full authority. Products are local trusted code; the
  main socket stays for the owner CLI. Do not add tokens before a real need.
- **Designed to become scope-able**: when a sandboxed/limited product needs
  restriction, issue per-product restricted sockets OR scoped session tokens (a
  token maps to a capability list; file permissions keep it in the right process).
  Do NOT use `getpeercred` + process-name policy mapping, it is fragile and breaks
  under sandboxes/flatpak/appimage.

## The SDK

A thin client wrapping the socket protocol into idiomatic calls, hiding the NDJSON
framing, request ids, reconnect + `last_event_id` replay, and the two-lane events.
Python first (the lend-gpu MVP is Python), then Rust/JS.

Surface sketch:
```
  fil.pair(...)               fil.grant(peer, action) / revoke / check
  fil.peers()                 fil.register(action, manifest, handler)
  fil.open(peer, action)      fil.on(topic, cb)  /  fil.events(topics)
  fil.send(peer, blob) / recv fil.mount(cid) / unmount
```

## Prior art

- **Steal**: Tailscale LocalAPI (local UDS + JSON request/response, exactly the
  right shape; their events are weak, do not copy those). ssh-agent (the agent
  mediates and holds secrets, a clean trust boundary to model).
- **Avoid**: Docker socket (no scoping, massive over-privilege, footgun),
  containerd (gRPC-over-UDS is overkill for a local product API), systemd dbus
  (overkill).

## Build sequence

1. Version handshake + request-id / reply-ref framing on `ctl.rs` (no behavior
   change; back-compat with the current internal callers).
2. The events subscription channel: topics, per-topic ordering, `last_event_id`
   replay, the two backpressure lanes.
3. Registration (service discovery + consent routing) and wire `open` to grants:
   outbound-request / remote-authorize, inbound grant-check + consent-route.
4. The grant ops (`grant`/`revoke`/`check`) as first-class API, tied to the
   capability model (`docs/design-identity-access-ux.md`).
5. The Python SDK; port the lend-gpu MVP from CLI-shell-out to the SDK as the first
   real consumer and the proof the boundary works.

## Open / deferred

- Per-product socket scoping / scoped tokens (deferred until a sandboxed product
  needs it; ops are designed to allow it).
- Event-persistence depth (N) and exactly which topics persist beyond consent.
- Cross-product event-scoping edge cases when many products share peers.
