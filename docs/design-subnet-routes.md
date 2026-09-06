# Subnet routes: reaching a network, not just a machine

> Status: **partly built (2026-09-01).** The routing table and the policy surface
> are in (`l3::RouteTable`, `advertise-routes` / `accept-routes`). Wire
> advertisement and forwarding are not, and the authorization model is an open
> decision. This records what was built, what was deliberately not, and why.

## What the overlay gives you today, and what it does not

Every node has an overlay address, and packets sent to it arrive wherever that
machine is. That reaches **machines you control**.

The things people actually want to reach are usually not nodes: the NAS, the
printer, a Postgres box on `10.0.0.5` nobody will install anything on, an office
LAN. Those will never run filament, and some cannot run anything.

A **subnet router** closes that gap: one node on the LAN announces "I can reach
`10.0.0.0/24`", peers route that prefix to it, and it forwards. One install
onboards a whole network.

## The four pieces

1. **A routing table that understands prefixes.** DONE (`d7a8105a`).
2. **A policy surface** for who offers what and who believes it. DONE (`8457d587`).
3. **Forwarding on the router node.** NOT DONE.
4. **Authorization of advertisement.** OPEN DECISION.

## 1. Route table (built)

Routing was `HashMap<IpAddr, Transport>`, exact match. It is now `RouteTable`:
host routes in their own map with the exact-match fast path **unchanged**, and
prefixes consulted ONLY on a host miss. Precedence is most-specific-wins; keeping
hosts separate is a blast-radius and performance choice, not a semantic one,
because a host route is just a /32 or /128.

`set_subnets` treats an advertisement as a **full restatement, not a delta**. A
peer that stops advertising a prefix has it withdrawn. Diffing deltas is how a
retracted route survives its own retraction.

`prefix_contains` is pure and tested on the cases that catch a wrong
implementation: `/0` (where the naive `<< (32 - len)` is undefined behaviour),
full-length prefixes, over-long lengths refused rather than wrapping, and
**families never mixing**, so a v4 destination cannot match a v6 prefix even
where the bits line up.

## 2. Policy surface (built)

Two settings, not one, because advertising and accepting are different trust
decisions made by different people:

- `advertise-routes` (global, list of CIDRs): what this machine offers to carry.
- `accept-routes` (bool, per-peer via `--peer`, **default off**): whether to
  install what a peer offers.

## 3. Forwarding (not built)

On the router: enable IP forwarding, and NAT the LAN side, because the LAN host
replies to an overlay address it has never heard of and needs either a masquerade
or a route back. Platform-specific (`sysctl` + `iptables` on Linux, `pf` on
macOS, different again on Windows) and it needs elevated privileges, which the
existing `ensure_net_admin_for_l3` machinery already handles for the TUN.

**Deliberately not written yet, for one reason: it cannot be verified here.** It
needs a real second network. Writing it and asserting it works would be the
failure mode this tree has been repeatedly bitten by, most recently the
fault-injection hook that was dead for ~620 commits while its gate reported
green.

## 4. Authorization (the open decision)

The announce already proves a lot: signature, channel binding, possession, and a
sequence number that stops replay and address rollback. But note the asymmetry it
rests on.

**An overlay address is self-certifying.** It DERIVES from the peer's public key
(Yggdrasil-style), so "my address is X" is provable from the key alone, and no
approval is needed or meaningful.

**A prefix derives from nothing.** "I can reach `10.0.0.0/24`" is an unbacked
claim no signature can make true. Signing proves WHO said it, never that they may.
This is why production meshes make an operator approve advertised routes, and it
is why `accept-routes` defaults to off.

Three ways to close it:

- **Operator approval per route**, like the existing `requests` flow. Conservative
  and familiar, but adds a second approval concept beside capabilities.
- **A capability**: `grant <device> route:10.0.0.0/24`. RECOMMENDED. It reuses the
  signed capability machinery, makes advertisement the same shape as every other
  permission, and needs no new concept. It also answers the same question the
  #161 gate asks (see WORK-STATE 1v), because both are "a claim that must be
  authorized before it is trusted".
- **Owner-signed route grants** distributed like cap ops. Strongest, most work,
  and the natural end state if fleets ever advertise routes to each other.

`accept-routes` defaulting to off is correct under ALL THREE, which is why it
could ship before the decision.

## Wire format, when advertisement is built

Prefixes must live INSIDE the signed announce payload or they are forgeable in
transit. `Announce` lives in the `filament-overlay` crate, so this is a published
wire-format change and needs forward compatibility: an older peer must ignore an
unknown field rather than reject the announce. There is precedent in the same
message (`dg_relay`, which older peers discard silently).

## What the two-machine experiment changed (2026-09-01)

The design above was complete and every unit test passed while the feature did
not work at all. Running it between two real machines (do-vm and a KVM VPS,
`experiments/subnet-route-e2e.sh`) found six defects, five of which no unit test
could have caught because each lived in the seam between two components that
were individually correct.

1. **The advertisement was never sent.** Both announce paths called
   `announce()`, which hardcodes `routes: Vec::new()`. The router configured its
   own forwarding and printed "carrying 10.66.0.0/24 for peers"; the receiver
   called `verify_routes`, got an empty set, and installed nothing. Neither end
   was wrong on its own, so neither logged an error.

2. **No kernel route was installed.** An accepted prefix updated only the
   in-process `RouteTable`, which decides which transport a packet rides *after*
   it reaches us. It cannot make the kernel deliver the packet in the first
   place. `filament` printed "routes via <peer>" while `ip route` showed nothing.

3. **`route` was missing from the invitation bitmask**, and the encoder ended in
   `.unwrap_or(0)`, so an unencodable capability silently collapsed the WHOLE
   ceiling to empty. `add --allow transfer,mount,route` minted a valid, signed
   invitation conferring nothing. Now rejected at mint, with a round-trip test
   over `CANONICAL_CAPABILITIES` so a future capability cannot repeat it.

4. **`mint_capability` was a second hardcoded capability list** that never
   learned about `route`, so `add --allow route` was refused outright. The CLI
   printed "re-invite with route in the invitation" as the remedy for a ceiling
   error and then rejected that exact command. Now derived from
   `CANONICAL_CAPABILITIES`.

5. **Enforcement read the owner key the wrong way.** `UserKey::load` returns
   `None` on a joined device, so deriving the resource id from it made every
   fleet member refuse every route: precisely the population subnet routes exist
   for. Verification needs only the owner's PUBLIC key, which a joined device
   carries in its own certificate.

6. **The ceiling was read from the link's principal.** A peer reconnecting
   through fleet-hello is admitted by `admit_fleet` as `FleetDevice`, which
   carries no caps; only a fresh enrollment yields `Delegated { caps }`. Matching
   on `Delegated` worked exactly once per join and silently stopped after the
   first reconnect. The persisted record is now the single source, the same one
   `devices` renders and `grant` consults.

### Authorization model, as it actually resolved

For a FLEET MEMBER the invitation ceiling IS the grant. No CapOp can bind to
one: a CapOp targets the owner user key that every member presents, so it cannot
name a single device, and `grant` refuses outright rather than report a success
enforcement would not honour. Authorization therefore comes from the
owner-signed invitation, the same place `transfer` and `mount` come from.

**The coarseness is closed (2026-09-05).** A ceiling used to carry an ACTION and
no resource, so `route` in a ceiling authorised ANY prefix that member
advertised, `0.0.0.0/0` included: an exit node the owner never agreed to.

Ceilings now carry their scope. `--allow route:10.66.0.0/24` puts the prefixes
inside the invitation, in the SIGNED domain, so a member cannot widen its own
grant; a test asserts that tampering with the prefixes invalidates the signature.
Minting `--allow route` with no prefix is refused outright, because a ceiling
that cannot say which prefix is not a scope. `Invitation::to_auth_key` is the one
conversion into everything downstream, so it emits `route:<cidr>` rather than a
bare `route`, and the stored ceiling, the `devices` display and enforcement all
read the same scoped entry.

Enforcement asks CONTAINMENT, not equality (`cidr_within_any`): a ceiling of
`10.0.0.0/8` permits advertising `10.66.0.0/24`, and a ceiling of `10.66.0.0/24`
refuses `10.0.0.0/8` and refuses `0.0.0.0/0`. An exit node is therefore only
possible when the owner wrote `--allow route:0.0.0.0/0`.

The invitation format was NOT versioned for this. There is one format tag and one
parser: an invitation is a short-lived credential, so carrying a second encoding
forever costs more than it buys.

### The result

Two real machines, one prefix, one code path; the only difference between the
two phases is the owner-signed ceiling.

    ceiling without route:  refused, LAN unreachable
    ceiling with route:     10.66.0.0/24 dev filament0, LAN REACHABLE

## Exit nodes (2026-09-02): the plan, and why only the guard is landed

An exit node is a subnet router advertising a default route, so the wire
protocol, the capability, the ceiling and the forwarding are already done. The
ADVERTISING side works today: set `advertise-routes 0.0.0.0/0` and the router
masquerades and forwards exactly as it does for a LAN prefix.

Accepting one is a different problem. `10.66.0.0/24 dev filament0` is additive.
`0.0.0.0/0 dev filament0` captures every packet the machine sends, including the
ones carrying the overlay. Installed into the main table it routes the tunnel
through the tunnel: the link dies, the route is withdrawn, the link returns, and
the machine oscillates. The first packet lost is usually the one to the
signaling server, so the node cannot even be told to stop.

### The plan

Put the default route in a dedicated table (51820) with a rule at priority 5182,
above the main-table rule, and carve the untouchable traffic back out by longest
prefix INSIDE that table. Carve-outs belong in the table rather than as
higher-priority rules so that tearing the table down removes them too; a
carve-out that outlives its default route is a silent hole in the user's routing.

Carved out, each mandatory rather than tidy:

- **the peer's own underlay address**, or the tunnel runs through the tunnel.
- **the signaling server**, or the node cannot renegotiate, cannot be told to
  stop, and cannot recover by itself.
- **loopback and link-local**, which were never ours to capture.
- **RFC1918 by default.** An exit node is for reaching the internet. Silently
  capturing the LAN breaks printers and NAS boxes with no symptom other than
  "the network broke when I turned this on". A subnet route deliberately
  advertised for a LAN prefix still wins inside the table by being longer.

Two ordering constraints make partial states safe. On the way IN, carve-outs are
installed before the default route: a crash then leaves a table of exceptions,
which is harmless, rather than a table containing only a trap. On the way OUT,
the rule is deleted before the table is flushed: while the rule exists a
consulted-but-empty table black-holes instead of falling through.

### What is landed, and what blocks the rest

Landed and wired: detection, plus a guard in `L3::sync_kernel_subnets` that
refuses a peer's default route out loud instead of installing it. That guard
fixes a real hazard introduced when subnet routes landed, because until now a
peer advertising `0.0.0.0/0` to a node with `accept-routes` on would have had it
written straight into the main table.

Not landed: the planner. The carve-out for the peer needs its underlay address
and `net::Transport` has no endpoint accessor, so the code would have been
correct, tested, and called by nothing. This repository has already been burned
by exactly that (the WireGuard L3 module: declared, zero callers, described in
the roadmap as ready), and the artifact registry's own rule is that the unwired
set may only shrink. Adding `Transport::remote_endpoint` is the next step, and
the plan above is the specification for what to wire to it.

## Exit nodes: working, measured on two machines (2026-09-03)

`experiments/exit-node-e2e.sh` measures the only thing that settles it, the public
address the receiver presents to the world:

    before:         165.22.207.231   (the receiver's own address)
    with exit node: 162.35.114.254   (the router's address)

Reproduced on three consecutive runs. The link carrying the route stays up
throughout, which is the hard part.

The receiver runs inside a network namespace while the control channel runs in
the root namespace. That is not tidiness: a wrong default route disconnects the
machine that installs it, and this arrangement means a failure costs a namespace
rather than the box.

### Corrections the rig forced, none of which a unit test could reach

1. **`Transport::remote_addr` already existed.** An earlier note here claimed
   exit nodes were blocked on adding it. That was wrong, and wrong in a specific
   way worth naming: the trait was inspected with a line-range that stopped at
   line 400, and the method is at 474. A blocker asserted from a truncated read.
2. **IPv6 carve-outs killed every install.** `signaling_addrs` returns AAAA
   records too, and `ip route ... via <v4 gateway>` rejects a v6 destination
   ("inet6 address is expected"). An IPv4 default route never captures v6
   traffic, so those carve-outs were both impossible and unnecessary.
3. **The router masqueraded to loopback.** `egress_for` asked
   `ip route get 0.0.0.0`, which answers `local 0.0.0.0 dev lo`, because 0.0.0.0
   is a local special address and not a destination. The receiver's policy
   routing was perfect and the packets went nowhere. A default route must probe
   a routable address to learn which interface reaches the internet.
4. **Clearing a list setting was refused.** `set advertise-routes ''` failed with
   "needs a comma-separated list", so a node could start carrying its peers'
   traffic with no supported way to stop.
5. **An empty advertisement was treated as nothing to do.** Both the outer and
   inner guards skipped the block when a peer advertised no routes, but
   `set_peer_subnets` is a full restatement, so an empty set is precisely how a
   WITHDRAWAL is applied. A withdrawn route stayed installed forever.

### Withdrawal and dead links (closed)

The exit route is now torn down both when a peer WITHDRAWS it and when the link
carrying it DIES, and the difference matters: a withdrawal arrives as an
announce, and a dead peer sends nothing at all. An announce-driven reconciler is
deaf to exactly the event it most needs to hear, so reconciliation also runs on a
15s timer.

Liveness is applied to default routes ONLY, deliberately. A stale subnet route is
a nuisance, packets for one prefix go nowhere until the link returns, and links
drop and re-establish constantly, so evicting on every transient drop would churn
the table for no gain. A stale default route is a disconnected machine, because
it captures everything, so it must not outlive its link even briefly.

Measured end to end, the full cycle:

    before:           165.22.207.231
    with exit node:   162.35.114.254
    after withdrawal: 165.22.207.231
