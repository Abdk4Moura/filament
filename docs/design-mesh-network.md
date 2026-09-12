# Mesh networking: why filament stays pairwise

> Status: **partly superseded (2026-08-15).** The 2026-07-16 analysis below
> answered "should filament grow an open mesh control plane" and answered no.
> That answer stands for what it was asked about. It was then read as "filament
> is not a mesh", which is no longer the decision. Read the reconciliation
> first; the original note is kept unedited underneath because its reasoning
> about federation and transitive trust is still the reasoning we hold.
>
> **Amendment (2026-08-25):** one narrow exception was accepted, and it is not
> a weakening of the reconciliation below but an instance of it. Devices
> certified by the SAME owner key auto-discover and connect without pairwise
> pairing, which is exactly "membership requires a signature descending from
> that mesh's owner" applied within one person's own mesh. Everything here
> still holds between DIFFERENT owners, which is the case this note actually
> reasoned about. See `docs/design-fleet-automesh.md` and the "Amendment"
> section before "Guardrails".

## Reconciliation, 2026-08-15

**filament is a mesh.** Specifically: every user has their own personal, private
mesh. Two meshes can be connected, by a user sharing one device into another
mesh. Two meshes can be merged. That is the model, and the line below saying
"filament will not build a mesh" is stale.

**There is no open join.** Membership in a mesh requires a signature descending
from that mesh's owner, so nothing can insert itself. No admission policy to
subvert, no coordinator to compromise into membership. The mesh is bounded by
whose key signed you in, which is the same property that makes the rest of the
authorization model work.

That is the true claim and it is deliberately weaker than the one that stood
here until 2026-08-15, which said "Sybil resistance is what the bounded shape
buys." Adversarial review took that apart three ways and it was right each time.
It is **vacuous today**, because Sybil resistance only means something relative
to something that counts identities, and nothing in the mesh counts: no vote, no
quorum, no majority. It **breaks exactly where counting arrives**, because once
k-of-n primaries exist, a single compromised primary can add devices and promote
them, each descending from an owner-delegated signer and each a distinct
identity, so k-of-n resists a compromised primary no better than 1-of-n. And it
**does not survive a merge**, because any owner may legitimately sign unlimited
devices into their own mesh, so merging with them imports that unbounded minting
capability. Owner-signature resistance is a per-mesh property; merge is a
cross-mesh operation.

No-open-join holds, is worth having, and does not imply the rest. Do not restore
the stronger sentence without a mechanism that counts and a reason it is safe.

### Decided 2026-08-15: enrolment and primacy are two rights, not one

**Changing the set of primaries always needs the root. Changing the set of
devices never does.**

- **Enrolment delegation.** May add ordinary devices within a ceiling.
  Short-lived, root-signed, held by as many devices as the owner likes. Cannot
  touch the primary set.
- **The primary right.** May change who is a primary. Root only, which in
  practice means the recovery phrase. A primary may neither promote nor demote.
- **Two primaries** by default. Not for convenience, which enrolment
  delegations now cover, but so that losing one device does not drop the owner
  into recovery-phrase-only operation.

This started as a conflict and turned out not to be one. `design-pairing-ux.md`
rule 3 says primary is a security role and warns against making every device one
"so joining is easier". The owner's requirement is that adding a device works
from whatever machine is in his hand. Those only collide while "may add a
device" and "may change who may add devices" are the same right. Split them and
both hold in full: enrolment works everywhere, and the containment rule 3 is
protecting is untouched.

Why each half is closed rather than merely chosen:

**A primary may not promote.** Otherwise a stolen primary promotes a device the
root has never seen, and demoting the stolen primary leaves the promoted one
signing, which promotes another. Demotion stops being a bounded operation, and
the recovery phrase does not recover the mesh.

**A primary may not demote.** Otherwise a stolen primary demotes every other
primary and becomes the sole remaining signer, and the root's removal then has
to be delivered through a mesh where the attacker is the only authority left.

**Two, not more.** Removal must reach every primary; renewal needs only one to
have missed it. An expired device shops for the primary that has not heard about
its removal, and the attacker chooses which one to ask, so the defender needs
unanimity while the attacker needs a single stale observer. Each additional
primary is another sampling point. Under "possibly every device is a primary"
this is trivially exploitable, which is the second independent argument against
the drift rule 3 warns about.

**k-of-n is not being built.** It is the right long-term answer to coercion, it
costs k devices awake for every membership change, and per the Sybil section
above it buys no resistance against a compromised primary. It is a coercion
mitigation wearing a Sybil costume. Later, deliberately, or not at all.

Availability cost, which is the question that prompted this: promote and demote
need the recovery phrase, both are rare, and both already have their ceremony
designed. With every primary offline the owner can still **add devices**, since
that is an enrolment delegation and not a primary right. So the cost falls
entirely on rare operations and the common path is untouched.

### What the original note got right and still holds

- **No hub federation.** Unchanged.
- **No transitive trust.** A device does not gain reach to a peer because two
  hubs were paired. Connecting two meshes is an explicit act by an owner
  sharing a specific device, not an emergent consequence of adjacency.
- **No coordinator.** The meeting point still authorizes nobody and routes
  nothing.
- **The reachability layer is the private graph**, not an open substrate. That
  is more true now, not less.

### The premise that broke

The note's sharpest argument against a control plane was this:

> **The gossip has nothing to carry.** With authorization strictly device-level,
> rosters and capabilities are per-pair [...] So the control plane has no job.

That was sound when it was written. It is not sound now. Bounded invitations
introduced a delegated principal whose authority comes from an owner-signed
ceiling rather than from a pairing, so **membership now exists as an object**:
the set of devices under an owner key, with their ceilings. That is exactly the
payload the note said did not exist.

Observed today on `b9808062`: alpha enrolled bravo, foxtrot and india. Each of
the three lists only alpha, and each files alpha under `EXTERNAL / other people,
deny-by-default`. So a spoke does not currently know it is in a mesh at all. The
membership object exists only in the issuer's local index. That is the gap, and
it is a real one now that meshes are meant to connect and merge.

### Rendezvous: prefer your own public peers, fall back to a hosted one

Decided in principle 2026-08-16, mechanism open. This is items 1 and 2 of the
signaling trajectory at the bottom of this note, promoted from "eventual" to
"the default behaviour", plus one rule that was not there before.

**The rule that is not optional.** If a mesh contains a peer that is publicly
reachable, that peer is the rendezvous for the mesh. The hosted server is a hard
fallback, not the normal path. A user may change which hosted server is their
fallback, and `--server` / `FILAMENT_SERVER` already allows this.

**Considered and dropped.** Volunteering a public peer as a rendezvous for
strangers was part of the original proposal. It does not survive #237 and is not
being built; the reasoning is below, because it is the kind of idea that returns.

Preference order: public peers in your own mesh, then any rendezvous explicitly
configured, then the hosted fallback. Volunteering to strangers was considered
and dropped; see below.

#### Why this is worth doing beyond ideology

The hosted server's only powers are denial of service and metadata observation
(see the trajectory below). Denial of service is already handled by fallback.
**Metadata observation is the one that does not have an answer today**, and it is
the whole of it: a hosted rendezvous sees who wants to connect to whom, across
every mesh at once. Moving rendezvous onto a peer the user already owns removes
that observation for that user entirely, rather than moving it somewhere more
trustworthy. That is a categorical improvement, not an incremental one.

#### Four things that have to be solved, and one that looks solved and is not

**1. Both ends must choose the same rendezvous.** This is the one that breaks
implementations. Signaling only works if both peers meet at the same place, so
this cannot be a per-device preference: if A prefers A's public peer and B
prefers B's, they never meet. It has to be a per-**mesh** ordered set, carried in
the roster, so every member computes the same answer. Cross-mesh, the connection
itself has to name one, because two meshes have two sets.

**2. A new device has no roster.** It holds an invitation and nothing else, so
the invitation is the bootstrap and must carry the rendezvous hint. That is a
natural home for it and it means the invitation format has to change before any
of this ships.

**3. "Public" is a claim, and it is not binary.** A peer reachable from one
network is not reachable from another, and a peer that advertises public and is
not breaks rendezvous for the whole mesh. It needs verification rather than
self-declaration, and the verification result is per-observer.

**4. Availability.** A public peer that goes down must fail over fast enough that
nobody notices, which is the same never-flaky discipline as the transport work,
applied to a new dependency.

**The one that looked solved, and does not.** Volunteering appeared to need no
trust decision, on the reasoning that a rendezvous can neither read nor forge, so
a hostile one could only deny service or observe metadata. That is wrong, and
`#237` is why: the rendezvous is not a courier in this protocol, it is an
**oracle**. `direct.rs` asks it for our own public address over `/api/whoami` and
advertises the answer as a candidate unchecked, so a wrong answer kills the
direct path and lands the pair on relay. If the same party relays, it has
converted a signalling position into a data-path position: a rendezvous learns
"A wanted B at time T" once, a relay observes volume and timing continuously.

That changes the character of the third leg completely. Today, occupying that
position requires being the hosted server, which is one known party. Volunteering
makes it self-service, so **anyone who wants to sit on strangers' paths can opt
in by running a peer and offering it.** That inverts the trust story rather than
decentralising it.

**So the third leg is dropped.** Own public peers need no discovery, because you
already know them. Explicitly configured needs none, because the user chose it.
Only strangers need a directory, and strangers are also the only case with the
trust problem above, so cutting one optional feature removes both. Passing a
volunteer's address out of band is not a neutral deferral either: it is
trust-on-first-use with no authentication and no revocation path, on a party with
path-selection power.

If it is ever revisited, the peer-reflexive fix in #237 is a precondition and not
a follow-up.

**#237 is independent of all of this and should be fixed regardless**, because
the hosted rendezvous has the same power today and the hosted relay is run by the
same party.

#### Relay gets the same treatment, separately

Rendezvous and relay are different services and item 4 below already forbids
assuming one implies the other. A public peer may serve either, both, or
neither, and the preference order is computed per service. Tailscale parity needs
both decentralised, since a DERP-equivalent that is always the hosted relay is
the same dependency wearing a different hat.

#### Honest parity scorecard

Written carefully, because this is the paragraph most likely to end up in launch
copy and two earlier drafts of it overclaimed.

**What is true.** This removes a rendezvous dependency that Tailscale requires.
A filament rendezvous holds no policy and no node registry.

**What that is not.** It is not "matching Tailscale on coordination
decentralisation". A Tailscale coordination server does rendezvous *and*
distributes the node registry and keys. This decentralises rendezvous only.
filament does not decentralise membership distribution because filament does not
do membership distribution at all: on `b9808062` each spoke lists only the
issuer. The scope is smaller, not the achievement larger.

**And it is not "ahead of Tailscale on trust model", in the present tense.** Their
coordination server holds a registry because something has to hold membership.
When filament solves membership it will hold something too. The current candidate,
an encrypted blob at a meeting point, genuinely is better, and it does not exist.

**On "a Tailscale replacement for a personal mesh".** Defensible as an
architectural statement, and dangerous as product copy, because a Tailscale user's
baseline expectation is that removing a device removes its access, and today
filament has no renewal, no membership distribution, and a revocation that does
not tear down an established session (#235, live in 0.8.5). That sentence would
be true about the architecture and read as a claim about the product, which is
the shape `docs/ui/OUTPUT.md` now names.

**What to keep saying:** filament declines subnet routers and exit nodes. Anyone
who needs to reach a printer that will never run filament needs a different tool.
That half is accurate and does real work by naming what is excluded.

### Decided 2026-08-16: subnet routers and exit nodes are IN scope

This **reverses** the founding scope decision at the bottom of this note, which
declined both. Recording the argument rather than letting the old line quietly
disappear, because a guardrail that goes missing instead of being overturned is
how #198 shipped and how `design-pairing-ux.md` rule 3 nearly went.

**What the old decision got right, and why it no longer decides this.** The
argument was: anything needing multi-hop segmented routing is out of scope,
because "if two nodes already share a tailnet, that mesh has already connected
them and filament adds nothing between them". That reasoning is about filament
stacking *onto* another mesh to gain reach. Subnet routing is the opposite case:
filament *being* the mesh, for devices that will never run it. A printer, a
camera, a NAS appliance, a landlord's thermostat. The old argument does not
address that case, it addresses a different one.

**And the mechanism now exists.** `l3.rs` already runs a TUN with a route table
that maps a destination to a peer transport and cryptokey-routes packets to it.
It is keyed on a single `IpAddr`, so today it does host routes only. Subnet
routing is that table keyed on a prefix with longest-match, not a new subsystem.
`expose` and `forward` already do this one port at a time at L4; this is the same
idea at L3.

**Order: after revocation, not before.** Subnet routing multiplies the
consequence of every revocation defect currently open. A revoked device that
keeps an established session (#235) today keeps a mount; with a subnet route it
keeps a path into a LAN. Widening reach before revocation binds is the wrong
sequence, so this lands after #235, renewal, and membership distribution.

#### The constraint that must not be relaxed

**Destinations behind a subnet router have no filament identity, so the
capability system cannot govern them.** A printer at `192.168.1.50` has no key,
no certificate and no ceiling. Access to it can only be governed by prefix policy
on the router.

That means a **second authorization model**, living beside the first. Given that
#226 and #228 were both literally "two places compute authority and disagree",
this has to be structurally separated rather than carefully coordinated:

- Prefix policy on the router is the **sole** authority for identity-less
  destinations.
- It must be impossible to express a capability grant that resolves to a bare IP.
- A device's ceiling governs what it may ask *the router* to do, and never what
  lies behind it.

If those three cannot be enforced by construction, this should not ship.

#### Route acceptance is local, explicit, and never automatic

An advertisement is an **offer**. Acceptance is local configuration. This keeps
the invariant that the roster is never an authorization input, since the roster
may carry the offer while only local state decides, and it forecloses route
hijack by a peer advertising a prefix it should not serve.

`0.0.0.0/0`, which is what an exit node is, requires a separate and louder
decision than a `/24`. Same mechanism, different consent.

#### Exit nodes: yes, and the cross-mesh case is already solved

Technically an exit node is a subnet router advertising a default route, so it is
nearly free once the prefix work exists. The risk is not free: the operator
observes all traffic that is not otherwise encrypted.

An earlier draft said a cross-mesh exit node is **forbidden**. That was wrong,
and wrong twice. It is paternalistic, since people knowingly route traffic
through operators they have chosen every time they use a VPN. And it is
unnecessary, because the mechanism for the legitimate case already exists.

**If Bob wants to give Alice egress, Bob shares that device into Alice's mesh.**
Sharing a device is already a primitive, it already carries per-mesh ceilings
keyed `(issuing root, device, ceiling)`, and the act of sharing is the explicit
two-sided consent that a cross-boundary route otherwise lacks. From Alice's side
it is then an ordinary intra-mesh exit node, governed by the rules above. No new
concept, and the consent is a deliberate act rather than a checkbox.

So the rule is not a prohibition, it is a placement:

> **L3 crosses no mesh boundary. What crosses a boundary is either a shared
> device, which becomes intra-mesh, or an L4 service, which is
> capability-governed.**

That line is principled rather than arbitrary. An L3 destination behind a router
has no identity, so it can only be governed by prefix policy. An L4 service sits
on an identified peer, so the capability system governs it and revocation works
through the path that already exists. **Crossing a trust boundary should use the
model that has identity in it.**

**And for narrower cases there is already a tool.** `filament forward
<peer>:<port> --socks` runs a SOCKS5 proxy through a peer. That is
per-application rather than device-wide, does not capture DNS by default, is a
service on an identified device so the capability system covers it, and is
revocable through the normal path. Anyone who wants "route this one tool through
my friend's connection" should get that, not a default route.

The ergonomic cost is real and worth stating: cross-mesh egress is per-application
unless the device is shared. That is the intended shape, since device-wide egress
through someone else's machine should require them to have handed you the machine.

#### What this reopens, stated honestly

The old note declined hub federation partly on the grounds that federation's
value "genuinely reappears in one place: segmented / enterprise networks [...]
That is precisely the subnet-router / exit-node space filament chose not to
enter." Entering that space removes that justification.

Federation is still declined, on the surviving argument rather than that one:
accepting a route is a local decision by a device about a peer it already
authorized, which is delegated reachability. It is not transitive trust, because
no device gains authority over a new principal, and nothing is authorized on
anyone's behalf.

### A ceiling belongs to a (mesh, device) pair, never to a device

Stated separately because an implementer reading "membership is a set of
devices with their ceilings" will key on the device public key, and that is a
defect rather than a shortcut.

Alice shares device D into Bob's mesh, so D appears in both rosters. Alice's
ceiling on D and Bob's ceiling on D constrain different things: what D may do
*in Alice's mesh* and what D may do *in Bob's*. Key a roster on the device and
any merge rule that takes the narrower of two ceilings will apply Bob's across
the boundary. Concretely, Alice shares her NAS into Bob's mesh so he can drop
files, Bob narrows its ceiling inside his own mesh as he is entitled to do, and
**Alice can no longer mount her own NAS**. An outsider turned off a capability
inside her mesh without compromising anything.

So a roster is a set of `(issuing root, device, ceiling)` triples, and there is
no cross-mesh comparison of ceilings at all.

The general lesson is worth keeping in front of whoever builds this: that
failure is #226 and #228 in their purest form, two places computing authority
for what looks like the same subject while using different keys for identity.

It also refutes a rule of thumb that sounds safe. "When two statements disagree,
take the lesser authority" is wrong when the capability being removed is itself
a recovery path. Availability is a security property when the unavailable thing
is what you recover with.

### The open question: O(1) without gossip

Requirement: per-machine cost stays O(1) as a mesh grows. Note what that rules
out.

**Gossip is what breaks O(1), not what delivers it.** A gossiped roster means
every node holds every member (O(N) state) and pays for every membership change
(O(N) churn). It is the wrong tool for the stated requirement, which is a
stronger reason to decline it than the one in the original note.

O(1) per machine comes from resolving on demand instead of replicating. A device
holds its own certificate plus a cache, and asks when it needs to reach someone.

That leaves a three-way tension, and it is genuinely unresolved:

1. O(1) state per machine, so no replicated roster.
2. No gossip, so no peer-to-peer propagation.
3. The meeting point holds no roster, per the constraint at the bottom of this
   note, so it cannot answer membership queries either.

All three cannot hold with a naive design. Options worth thinking through, none
chosen:

- **Owner's primary as the authority.** Membership queries go to the owner's
  primary device. O(1) for every other device; O(N) at one machine the user
  already controls. Fails when the primary is offline.
- **Signed roster blob at the meeting point.** The owner authors a roster,
  signs it, and the meeting point stores it as bytes it can neither read nor
  forge. This arguably does not violate constraint 3: the server is not a source
  of truth, it is carrying an object whose authority lives entirely under the
  owner's key. Encrypting it to the members closes the metadata leak the note
  worries about. Devices fetch on demand and cache, so steady state stays O(1).
- **Connecting two meshes is an edge, not a merge of rosters.** A device shared
  into another mesh is a cross-signed grant. The other mesh's members resolve it
  the same way, against a scoped subset the owner chose to expose. Merging two
  meshes is the harder case and needs its own treatment.

The second option is the one that appears to thread all three constraints, and
it is the one to attack first when this is picked up. It is written here as a
candidate, not a decision.

### Consequence for the near-term build list

Nothing in the "Build" list below is invalidated. The "Do not build" list keeps
hub federation, transitive trust, third-party store-and-forward, the centralized
coordinator and the full decentralized overlay. What moves out of "do not build"
is membership itself, which is now a first-class object and needs a home.

`/root/filament-l3-plan.md` step 3 is titled "roster gossip via C30". Given the
above, the title is wrong for the requirement even if the step is right: what is
needed is roster *resolution*, and gossip is the implementation that O(1) rules
out.

---

*Everything below is the original 2026-07-16 note, unedited.*

## Summary / decision

filament will **not** build a mesh: no hub federation, no gossip control plane,
no transitive trust, no kernel-L3 mesh, no third-party store-and-forward. These
were steelmanned and rejected on the merits.

What filament builds instead, to serve both small trusted teams and larger
agent/team meshes with the *same* primitives:

- **Transport hardening** (highest-utility move): happy-eyeballs path racing,
  QUIC lossy-link tuning, connection migration, faster dead-link detection,
  warm-hold (done).
- **Self-hosted relay flag**: let a user supply their own relay, solving the
  relay-privacy concern with zero group state.
- **Single-hop peer-relay among authorized peers** (static/manual first): a
  stable peer can relay for its authorized peers.
- **Introducer-TOFU onboarding**: reduce pairing friction. The introducer is a
  key-exchange helper, not an authorization delegate; the user always confirms.

Anything that genuinely needs multi-hop segmented routing is **out of scope**.
For that need, a mesh product (Tailscale, WireGuard, Yggdrasil) is the right tool
*instead of* filament, not under it: if two nodes already share a tailnet, that
mesh has already connected them and filament adds nothing between them. This is
the same boundary filament already draws by having no subnet routers and no exit
nodes, and it comes with the coordinator / account / admin-controlled-membership
tradeoff filament exists to avoid. filament does not compose *onto* a mesh to
gain reach; it declines the use case. (Distinct and legitimate: filament may
select an existing `tailscale0` interface as one candidate path for its own
pairwise connection, per `cli/docs/filament-routing.md`. That is transport-interface
selection, not a mesh-reach strategy, and it is redundant if raw connectivity is
all you want.)

## The question

Warm-hold turns the daemon from a set of on-demand tunnels into a standing graph
of connected peers. That standing graph is the substrate a mesh control plane
would need, so the natural question was: should filament grow one? Propagate
presence, rosters, and capabilities by gossip; route to peers through on-path
peers ("reach C through B"); hold mail for offline peers. And could a single
design serve both small trusted teams and an agent/team mesh at scale?

## The design space

Every strategy is a choice on a handful of mostly-orthogonal axes:

- **Membership / trust**: none · static roster · introducer-TOFU · gossip (SWIM) ·
  central coordinator · global DHT
- **Relay / reachability**: direct+holepunch only · public relay · self-hosted
  relay · manual peer-hub · auto-selected peer-relay · full source-routing
- **Who you can reach**: directly-paired only · paired-but-relayed ·
  transitively-trusted · open
- **Path selection**: fixed serial ladder · happy-eyeballs race ·
  measured-adaptive · multi-path bonding
- **Layer**: app-L7 · userspace-L4 · kernel-L3
- **Async delivery**: none · your-own-node queues your outbound · third-party
  store-and-forward · delegate to email/Matrix
- **Naming**: petnames · static-roster names · MagicDNS

Coherent end-to-end paths through those axes: (0) status quo, (1) transport-only
hardening, (2) static minimal mesh, (3) discovered Tier-A mesh, (4)
transitive-trust Tier-B mesh, (5) centralized coordinator (become Tailscale), (6)
full decentralized overlay (libp2p/Yggdrasil), (7) compose over an existing mesh,
(8) async-without-storage (own-node queue), (9) introducer-TOFU pairing.

## The frontier

Two independent analyses converged on the same live frontier: **1, 2, 7, 8, 9**,
with transport hardening (1) as the top move. Rejected as dominated or
against filament's ethos: (4) transitive trust kills the pairwise identity, (5)
loses to Tailscale on its own turf, (6) is the wrong scale and a research-grade
routing protocol, kernel-L3 mesh loses to WireGuard/Tailscale/Yggdrasil. Third-
party store-and-forward is a distributed untrusted encrypted storage system
(quotas, GC, replication-needs-consensus, and a real CSAM-hosting liability),
not a networking feature; the useful part is covered by an own-node send queue
(8).

The one hard disagreement was Path 3/4 (the mesh proper). Resolving it produced
the core argument below.

## The core argument: reachability vs authorization

filament's word "pairwise" quietly conflates two different things:

- **Reachability**: who can route bytes to me (a network property).
- **Authorization**: who I will open a secure channel with (a trust property).

The tempting synthesis was "federate hubs, not individuals": keep every trust
link an explicit pairing, but let hubs relay so reach scales. Under scrutiny this
splits by what the hub is allowed to authorize, and every branch fails:

1. **If a hub relays ciphertext only (no authorization power):** then two peers
   can talk only if they *already* authorized each other (direct pairing or an
   introducer the user confirmed). In that case they already have each other's
   keys and addressing, and filament already connects them via
   direct/holepunch/relay. Federation adds value *only* in the corner case where
   direct fails, single-hop relay fails, but a multi-hop hub path works, which
   requires two authorized peers each reachable to different hubs but to no
   common relay. Rare in filament's topologies.

2. **If a hub authorizes on peers' behalf:** that is transitive trust (Path 4).
   A reaches B because an admin paired the hubs, not because A decided about B.
   That breaks filament's actual user contract ("I only talk to devices I
   authorized") and is exactly the identity-killer the project rejects.

There is no third option. And two further observations close it:

- **The gossip has nothing to carry.** With authorization strictly
  device-level, rosters and capabilities are per-pair, and reachability gossip is
  redundant with the addressing you already needed in order to authorize. The
  only hub-gossip-worthy payload is transitive membership, which is Path 4. So
  the control plane has no job.
- **The internet analogy leaks.** On the internet the reachability layer is
  *open* (any host may send to any host; TLS then authorizes). In filament the
  reachability layer is *already* the private graph of authorized pairs, so there
  is no general substrate for federation to optimize. It is "pairwise tunnels
  plus optional multi-hop stitching," and the stitching only pays in the corner
  case above.

Conclusion: separating reachability from authorization does not *save*
federation, it *dissolves* it. What survives is "a stable peer can relay for its
authorized peers" (single-hop peer-relay), which is a deployment pattern, not a
new architecture.

Federation's value genuinely reappears in one place: segmented / enterprise
networks where no single relay crosses a boundary but local nodes can bridge
segments. That is precisely the subnet-router / exit-node space filament chose
not to enter. So this whole analysis re-derives filament's founding scope
decision from first principles: no federation, for the same reason there are no
subnet routers. That segmented use case belongs to a mesh product used *instead
of* filament (with its coordinator/trust-model tradeoff), not to filament stacked
on top of one.

## Decision

**Build.** Transport hardening (in flight); self-hosted relay flag; single-hop
peer-relay among authorized peers (static/manual first, no auto-discovery until
proven necessary); introducer-TOFU onboarding.

**Do not build.** Hub federation; hub-tier gossip; transitive trust (Path 4);
third-party store-and-forward; centralized coordinator / become Tailscale (Path
5); kernel-L3 mesh; full decentralized overlay (Path 6).

**Out of scope.** Multi-hop segmented routing. If a user needs it, a mesh product
(Tailscale/WireGuard/Yggdrasil) is the right tool *instead of* filament for that
need, with its coordinator/trust tradeoff; filament does not stack on top of a
mesh to gain reach.

## Amendment (2026-08-25): same-owner fleets auto-mesh

The argument above is sound, and it closed the question it asked. It reasoned
about A, B and C as **different people**. Applied to one user's own devices it
proves less than it appears to, because the step it turns on, "A reaches B
because an admin paired the hubs, not because A decided about B", has no
referent when there is one human and one key. The owner already made the
decision, once, by certifying both devices.

So the exception: a device that presents a `DeviceCert` chaining to the owner
key a peer already holds is admitted without a separate pairing. This is not
Path 4. Under Path 4 the trust flows along the graph (A trusts C because B
vouches). Here B's assertion is not an input: remove B from the network and A
still accepts C on identical evidence. Guardrail 1's real content, that no peer
authorizes on another's behalf, is untouched.

Two of the closing observations above also need a correction in this scope.
"The gossip has nothing to carry" was right, and the amendment does not
contradict it: fleet auto-mesh adds NO gossip and NO CRDT. It reuses the
existing channel-presence roster, so the control plane still has no job. And
"the reachability layer is already the private graph of authorized pairs"
remains true, because the owner key is what authorizes, not the meeting point.

What stays rejected, unchanged: hub federation, hub-tier gossip, transitive
trust across owners, third-party store-and-forward, a central coordinator,
multi-hop segmented routing, and any `hub` concept in the protocol. The
mechanism is in `docs/design-fleet-automesh.md`.

## Guardrails

1. **Cross-user authorization is absolute.** A talks securely to B only if A
   made an explicit A-to-B trust decision. No relay, hub, or admin ever
   authorizes on a peer's behalf. (Amended 2026-08-25: within ONE owner key the
   owner's signature on a DeviceCert is that explicit decision, made once and
   covering every device it certifies. Trust still flows from the owner key, never
   along the peer graph.)
2. **The introducer reduces friction, not trust.** It is a key-exchange helper;
   the user (A) always confirms. It must not become an authorization delegate or
   a de facto coordinator.
3. **No `hub` concept in the protocol.** A relay-peer is "filament on a stable
   node with a public address," an ordinary peer that happens to be reachable.
   The protocol treats it as a peer. Adding a `hub` type to the protocol starts
   selling a different product.
4. **"Agent-mesh-at-scale" means many pairwise-authorized endpoints mediated by
   a stable relay.** It never means a large group where agents reach each other
   transitively without individual authorization. The xats bridge is a valid
   model only because each agent-to-agent channel is separately authorized; the
   bridge does not authorize on agents' behalf.
5. **Confidentiality is stated honestly per path.** Authorized flows are
   end-to-end encrypted and a relay-peer only ever moves ciphertext. There is no
   silent plaintext-at-relay tier.

## The signaling server is not the coordinator we rejected

Rejecting a central coordinator (Path 5) raises an obvious question: filament
already has a hosted signaling server, so isn't that a central dependency? No,
and the distinction matters. The signaling server is a **rendezvous /
NAT-traversal helper** (STUN-like), not a coordinator of trust or policy:

- It does not authorize anyone. Pairing establishes E2E trust; signaling never
  decides who may talk to whom.
- It does not route traffic. It helps two peers exchange candidates so they can
  holepunch, then steps out once the direct link is up.
- It holds no rosters, capabilities, or policy. It is a meeting point, not a
  source of truth.

So it lives in the reachability layer we keep and harden, not the authorization
or control layer we constrain. The decisions above give it a clear trajectory,
by the same logic as the self-hosted relay flag:

1. **Make it self-hostable** (a team runs its own rendezvous, no hosted infra).
2. **Let the stable relay-peer double as the rendezvous**, so a self-hosted setup
   needs one public-address node for both relay and signaling and depends on zero
   hosted filament infrastructure. Consistent with "a relay-peer is an ordinary
   peer," no new protocol concept.
3. **Keep it minimal**: rendezvous only (addresses/candidates, ephemeral). It
   becomes a coordinator in disguise the moment it gains any of: persistent
   roster/membership storage, a capability directory ("B exposes sshd:22"),
   name resolution (MagicDNS), admission/rate policy, or social-graph analytics
   logging. A pure rendezvous has none of these. Its only powers are
   denial-of-service and metadata observation, not authorization or policy,
   which is why the STUN-vs-coordinator line holds.
4. **Keep rendezvous and relay distinct in the protocol**, even when one
   self-hosted node hosts both (`filament rendezvous <addr>` and
   `filament relay <addr>` are separate services). Co-locating them is a
   deployment choice; the protocol must not assume "signaling = relay," or that
   monoculture becomes a hidden single point.

Honest caveat: the signaling server is filament's one genuinely centralized
dependency and a metadata vantage point (it sees who wants to connect to whom,
never content). The principled trajectory is to minimize dependence on it, not
grow it: LAN peers via mDNS need no signaling, known-address peers need no
signaling, and everything else can use a self-hosted rendezvous. The hosted
server is then a convenience default for zero-config first-connect, not a
requirement, which keeps filament honestly self-hostable end to end.

## Relationship to the roadmap

None of this blocks or changes the near-term work: transport hardening,
self-hosted relay, and introducer-TOFU are the shared primitives regardless of
how far any mesh idea might have gone. This note simply records that the mesh
destination was explored to its end and the road stops at the pairwise core.

See also: `cli/docs/filament-routing.md` (the pairwise route model), `ROADMAP.md`
(the Exploration entries this note supersedes), `/root/xats/BRIDGE-M0-SPEC.md`
(the app-level federation prototype that motivated the question).
