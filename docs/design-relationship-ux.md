# Relationship UX: derived states, code-addressable verbs, guests

> Status: design, 2026-09-17. Docs only, no Rust. Companion pieces:
> `CONTRACT.md` (the wire-visible frames) and `docs/ux-tickets.md` (the build
> order). Sits on top of `docs/design-identity-access-ux.md` (capabilities, not
> an ACL file), `docs/design-pairing-ux.md` (the two relationships),
> `docs/design-mesh-ux.md` (what `devices` may honestly assert),
> `docs/design-groups-tags-caps.md` (target kinds and wildcards), and the
> capability ledger contract on `work/cap-ledger-model`.
>
> The decisions below were taken by the owner. This document designs them; it
> does not re-open them. Where a decision collides with something already
> written down, the collision is named in §6 rather than quietly resolved.

## 0. Why this document exists

Filament already has every piece of a relationship model. It has a pair secret
in `devices.json`, an owner-signed device certificate, a capability store, a
mesh roster, and a tier computed for display in `cli/src/device_view.rs:307-315`.
What it does not have is one account of what a relationship **is**, how it
deepens, how it decays, and what the other side sees while it changes.

The absence shows up as four concrete defects a user can hit today:

1. **The tier is computed from one fact.** `device_view.rs:308-315` decides
   FLEET / EXTERNAL / NEEDS REVIEW purely on whether a certificate exists and
   whose owner key it chains to. A device with a live certificate and no live
   grant renders identically to one with both. #240 already had to delete a
   remedy line from the NEEDS REVIEW row because the row asserted a blocked
   state that was not blocked.
2. **Deepening is a one-way ratchet with no rung below it.** `add`/`join`
   enrol a device into the mesh. There is no verb for "we are done, but keep
   the record", and no verb for "not right now" short of `revoke`, which is
   destructive (`CapOpKind::Revoke` removes the row, so the reason an action
   is refused stops existing the moment it takes effect).
3. **Only two verbs are code-addressable.** `send` and `receive` mint and claim
   a speakable one-time code. `shell`, `exec`, `forward` and `mount` all
   require a pre-existing petname, so the fastest thing in the product is
   available to the one job that needs it least.
4. **A waiting party is blind.** When one side does something that needs the
   other side's consent, nothing tells the other side. The consent inbox
   (`filament requests`) only carries requests that came *in*.

## 1. The state model

### 1.1 Two axes, not one list

A relationship has a **base**, derived from facts, and at most one **overlay**,
derived from verdicts. Rendering them as one flat list is what makes today's
tiers lie: PAUSED is not an alternative to FLEET, it is something true *about* a
fleet device right now.

```
base     STRANGER  ->  SESSION  ->  PAIRED  ->  FLEET
                       (one shot)   (secret)    (owner cert + ceiling)

overlay  (none) | PAUSED (a live Pause covers them) | DORMANT (nothing is live)
```

Neither axis is stored. Both are a function of (records on disk, live ops in
the ledger, `now`). This is the ledger contract's "tiers are views, not state"
rule (`CONTRACT.md`, *Tiers are views, not state*), extended from three tiers
to two axes, and it is what the CLI already does per call today with
`PrincipalKind` / `BindingStrength` / `same_owner`.

| base | the fact that makes it true | what it buys |
|---|---|---|
| `STRANGER` | no record, no live session | nothing; the default |
| `SESSION` | a live PAKE-derived session key, no stored secret | exactly the one verb the code was scoped to, until the session ends |
| `PAIRED` | a mutually acked pair secret in `devices.json` | a findable, authenticated link; no authority beyond what is granted |
| `FLEET` | an owner-signed device cert that chains to my owner key, live at `now` | an `fdf1` overlay address, roster membership, and a ceiling |

| overlay | the verdict that makes it true | what it changes |
|---|---|---|
| `PAUSED` | a live `Pause` op authored by me naming them | every allow I would give is suppressed, reason `paused`, distinct from `denied` |
| `DORMANT` | a record exists and no op about them is live | nothing is allowed, nothing is deleted, and the row says when it lapsed |

`GUEST` is deliberately **not** a base. A guest is a principal whose entire
authority is one `Pass` I signed (§3.8). That is a property of the ops, so it
renders as a note on a `PAIRED` or `SESSION` row: `PAIRED · guest of mine ·
2 of 3 devices · 5d left`. Making it a base would be storing a tier.

### 1.2 The three laws of movement

- **Widening needs both parties.** Deepening the relationship, or adding a
  capability, is an offer the subject accepts. This is ledger law L5, surfaced
  as UX: an unaccepted `Grant` authorizes nothing and shows in `requests` on
  both sides as *offered, not yet accepted*.
- **Narrowing is unilateral.** `pause`, `deny`, a tighter `certify`, a shorter
  expiry, and `forget` all take effect on the author's signature alone. You can
  always reduce what you handed out.
- **Time moves things by itself.** Certificates lapse, grants expire, a
  `--expires 1h` elevation falls back, and a pause ends. Nothing needs a
  ticker: every verdict already carries `valid_until`, and one generic
  re-evaluation at that instant replaces every per-path timer.

### 1.3 The table

`who` is who runs the verb. `consent` is what the other side must do for the
move to take effect. `kept` is what survives the move; it is the column that
makes the model non-destructive.

| # | from | to | verb | who | consent needed | what changes | what is kept |
|---|---|---|---|---|---|---|---|
| T1 | STRANGER | SESSION | `serve <verb>` / `<verb> <code>` | either | holding the code, plus PAKE confirmation | a session key scoped to one verb; the code burns | nothing on disk; one `diag.jsonl` line |
| T2 | SESSION | PAIRED | `remember <name>` | either, after the fact | the other side's `remember` or its interactive accept | a pair secret is stored on both sides | the live session continues uninterrupted |
| T3 | STRANGER | PAIRED | `add` + `join`, or `send --remember` | either | the existing `pair-keep-ack` | pair secret, petname, record created | n/a |
| T4 | PAIRED | FLEET | `add --for <n>` + `join`, or `certify <dev>` | owner | subject's `Accept` of the cert and its ceiling | owner-signed cert, `fdf1` address, roster entry, ceiling | the pair secret; the cert does not replace it |
| T5 | FLEET | FLEET | `certify <dev> --scope … --expiry …` | owner | none to narrow; subject `Accept` to widen | a newer version of my `Certify` + `Ceiling` | the device key, the pair secret, the petname, the history |
| T6 | FLEET | PAIRED | `revoke <dev> --cert`, or the cert lapses | owner, or time | none (narrowing) | no cert, no `fdf1` address, no roster entry | the pair secret and the record: they are still reachable, just not a member |
| T7 | any | PAUSED | `pause <dev> --until <t>` | either side, about the other | none (narrowing) | every allow I author is suppressed for the interval | every grant, cert and secret underneath, untouched |
| T8 | PAUSED | (prior base) | `resume <dev>`, or the interval ends | author, or time | none | the suppression lifts | everything |
| T9 | any | DORMANT | *(nothing; time)* | time | n/a | no verdict allows anything | the whole record, so the row can say what lapsed and when |
| T10 | DORMANT | PAIRED / FLEET | `grant`, `certify`, or the peer claims a fresh code/card | either | subject `Accept` (widening) | new live ops | the petname and the history |
| T11 | PAIRED / FLEET | STRANGER | `forget <dev>` | either, locally | none | the record and every op about it are deleted | nothing, deliberately |
| T12 | STRANGER | PAIRED / FLEET | `join <code>` or `join --invite-file` | the returning device | the owner minted the code or card | a new record | nothing; see the tombstone question in §6 |
| T13 | STRANGER / SESSION | guest-shaped PAIRED | `pass <person> …` + `join` | the grantor | the holder's `Accept` of the pass | one `Pass` op with a ceiling, a direction and a device budget | n/a |
| T14 | PAIRED / FLEET | briefly wider | `grant … --expires 1h` | the grantor | subject `Accept` | one time-boxed widening | the prior authority, which is what it falls back to |

Two properties of the table are load-bearing.

**Every row that widens has a non-empty consent column, and every row that
narrows has an empty one.** If a future verb violates that, it is a contract
change, not a UX change.

**Only T11 has an empty `kept` column.** `forget` is the single exit, and it is
a storage action, not an op: nothing in the log can describe its own erasure.

## 2. Derivation: how each state falls out of verdicts and facts

### 2.1 The facts

Everything below is already on disk or already computed per call. Nothing new is
persisted.

| fact | where it lives today |
|---|---|
| a record exists | a `name` entry in `devices.json` (`cli/src/devices_store.rs:22-24`) |
| a pair secret exists | the record's `secret` field, absent for an index-only fleet sibling (`devices_store.rs:55-173`) |
| an owner-signed cert exists | the record's `deviceCert` (`DeviceCert { device_pub, user_pub, expires, issued, sig }`, `crates/filament-id/src/lib.rs:200-206`) |
| the cert chains to me | `same_owner` = my owner key, else my own cert's `user_pub` (`cli/src/device_view.rs:289-292`) |
| the ceiling | `principalCeiling` / `principalExpires` / `principalMaxOffline` on the record (`devices_store.rs:83-98`) |
| a terminal state | `principalState` = `lapsed` / `revoked`, and `certRevoked` |
| a live session key | in-process only; PAKE-derived, never written |
| the roster | `crate::roster::stored_roster()` (`device_view.rs:373-410`) |

### 2.2 The base, in order

Evaluated top to bottom; the first match wins.

```
1. no record AND no live session key                      -> STRANGER
2. no record AND a live session key                       -> SESSION
3. record has a live cert whose user_pub == same_owner    -> FLEET
4. record has a pair secret (acked)                       -> PAIRED
5. record exists, no secret, roster names them            -> FLEET (no channel yet)
6. record exists, nothing else                            -> PAIRED
```

Three changes from `device_view.rs:308-316` are worth stating plainly, because
each one is a behaviour change, not a rename:

- **The cert's expiry is consulted.** `device_cert_for` deliberately does not
  check expiry today (`device_view.rs:44-51`), so a device with a cert that
  lapsed a year ago still renders FLEET. Under this model an expired cert drops
  the base to PAIRED and the row says when it lapsed. `device_cert_valid_for`
  (`device_view.rs:71`) already exists and does exactly this check.
- **`EXTERNAL` disappears as a tier.** A cert issued by somebody else is
  evidence about *them*, not authority over *me*. A peer carrying a foreign
  cert is `PAIRED`, with a note: `PAIRED · carries jane's cert`. Today's
  `External` arm (`device_view.rs:315`) becomes that note.
- **`NEEDS REVIEW` disappears.** It was "a cert does not exist", which is
  simply `PAIRED`. #240 already deleted its remedy line for asserting a state
  that was not real; this deletes the state.

| today | under this model |
|---|---|
| `Fleet` | `FLEET`, and only while the cert is live |
| `External` | `PAIRED` + the note `carries <owner>'s cert` |
| `NeedsReview` | `PAIRED` |
| `MeshRoster` | `FLEET` + the note `known via owner, no channel yet` |

### 2.3 The overlay, from verdicts

The overlay is the only part that needs the ledger. Ask `decide(facts, request)`
once per capability I would otherwise offer this peer:

```
PAUSED   iff some verdict is Deny(paused)
           -- a live Pause I authored naming them (ledger L12)
DORMANT  iff every verdict is Deny, and no op naming them is live at `now`
           -- distinct from "denied", which means an op is live and says no
(none)   otherwise
```

`PAUSED` outranks `DORMANT`: a pause over a relationship that also has nothing
live is still a pause, because it will not come back on its own when the grants
would have.

The row renders `base · overlay · why`, and the `why` is the ledger's `because`
(law L7, a minimal sufficient cause), rendered as one clause:

```
  laptop      FLEET    paused until 18:00        by you, 20m ago
  nas         FLEET    dormant                   ceiling lapsed 3d ago
  jane        PAIRED   guest of mine             2 of 3 devices, 5d left
  gpu-box     FLEET                              shell mount forward
```

### 2.4 Before the ledger exists

The ledger is not built yet, so §2.3 cannot ship on day one. Until it does, the
overlay is computed from the two state strings the store already persists:
`principalState` (`lapsed` / `revoked`) and `certRevoked` map to `DORMANT`, and
`PAUSED` does not exist. This is why the ticket list in `docs/ux-tickets.md`
splits at the ledger: everything in §2.2 is buildable now, and only §2.3 waits.

The split is also the honest test of "tiers are views". If the base can be
recomputed from a different substrate without a migration, it was never state.

## 3. The verb surface

| verb | status | what it reuses |
|---|---|---|
| `init` | **changed**: happens silently on first use | `identity_flow.rs:285` (`PendingIdentity::generate`), moved behind a lazy accessor; the precedent is `local_device_cert()` (`identity_flow.rs:119-176`), which already mints a device cert on demand |
| `send` / `receive` | unchanged in shape; `--remember` gets fixed (§3.9) | `send_cmd.rs:576`, `recv_cmd.rs` |
| `add` / `join` | unchanged | `pair_cmd.rs:106` |
| `serve <verb>` | **new** | `words::mint_pair_nameplate` + `mint_words` (`crates/filament-pair/src/words.rs:99,119`), `pair-create` (`pair_cmd.rs:278`), `Ceremony::new` (`pake_ceremony.rs:143`) |
| `shell`/`exec`/`forward`/`mount` `<code>` | **changed**: accept a code where a petname goes | `norm_code` / `split_code` (`crates/filament-pair/src/lib.rs:195,221`), `pair-claim` (`pair_cmd.rs:253`), then the existing `l2` session openers |
| `remember <name>` | **new** | the `pair-keep` / `pair-keep-ack` frames (`recv_cmd.rs:2998-3006,4798-4841`), `devices_store_v2` (`device_view.rs:37`) |
| `pause` / `resume` | **new** | the ledger's `Pause` op; before the ledger, a local suppression record |
| `certify <dev>` | **new as a verb** | `DeviceCert::certify` (`crates/filament-id/src/lib.rs:209`) and `certify_local_device` (`identity_state.rs:284-299`), both internal today |
| `grant --expires --direction` | **changed** | `parse_grant_spec` (`crates/filament-cap/src/capability.rs:86-115`), `CapOp` (`:394-403`) |
| `requests` | **changed**: both directions, `accept` replaces `approve` | `status_cmd.rs:213-282` |
| `pass` / `guests` | **new** | `Invitation::mint_with_bounds` (`crates/filament-cap/src/ephemeral.rs:157,173`) for the card; the ledger's `Pass` op for the authority |
| `reach --until-direct` | **new flag** | `ctl::try_ping` (`cli/src/ping.rs:22`) polled until the route is direct |
| `forget` | **changed**: promoted to top level, alias of `devices forget` | `cli_def.rs:806-807` |

### 3.1 `init`, by not existing

A keypair is not a ceremony. A name and a fleet are.

Today `UserKey::generate` has exactly one call site, `identity_flow.rs:285`,
reachable only from `filament init`, and seven separate places bail with some
variant of "no identity. Run `filament init` first"
(`add_for.rs:206-207`, `dispatch.rs:701,762,1449,1515`, `status_cmd.rs:68`).
Every one of those is a dead end a user hits for a reason that is not their
problem.

The change: one lazy accessor mints the keypair on first use and says so in one
line. `filament init` stays, and keeps every flag it has, because naming the
device, choosing the drop directory and installing the service *are* ceremonies.
What it stops being is a precondition.

```
A$ filament send report.pdf --code
  created your identity  b7f2 3a91 …  (filament id to see it)
  code: clever-lynx-631
  waiting for the other side …
```

One line, past tense, not a prompt. The recovery phrase is not shown here: an
implicit identity has nothing worth recovering yet, and `filament id` prints the
phrase on demand. The first verb that creates something worth losing — `add`,
`certify`, `pass` — prints the "write this down" screen instead.

### 3.2 `serve <verb>`, and the verb code

`filament serve shell|exec|forward|mount` mints a speakable code scoped to
**one verb and one session**, prints it, and waits. The other side runs the verb
with the code in the slot where a petname goes. The code burns on first use.

```
A$ filament serve shell
  serving  shell  to whoever speaks this code, once.
  code: gigantic-osprey-4417
  expires in 10 minutes, or when it is used.

  ! this is a shell on this machine. anyone who hears the code, once,
    before it is used, gets it. no pairing, nothing remembered.
  serve shell to whoever speaks this code? [y/N] y
  waiting …
```

```
B$ filament shell gigantic-osprey-4417
  gigantic-osprey-4417 → alex-desktop   verified, direct over wl1
  this is a SESSION: nothing was remembered, and only `shell` was served.
  to keep it:  filament remember alex-desktop

alex@desktop:~$
```

and back on A, the moment the code is claimed:

```
  claimed by  brenda-laptop  (fp 9c41 …)   direct over wl1
  serving one shell session. ^C ends it and the code is already spent.
```

The code is `adjective-animal-NNNN`, the four-digit nameplate
(`words::mint_pair_nameplate`, `words.rs:119`), reusing the existing split: the
words are the SPAKE2 password and never leave the machine, only the nameplate is
registered with the signaling server (`lib.rs:195,221,237`). Burn-on-use is
already server-side and already surfaces as `Ev::PairUsed` / `Ev::PairError`
("taken") (`pair_cmd.rs:783,806-818`).

**What is new is the scope.** `Ceremony` already binds a scope byte into the
confirmation MAC (`pake_ceremony.rs:114-116`, `pake::our_confirm`, `lib.rs:151`),
and both existing call sites hardcode `IntroScope::Device`
(`pair_cmd.rs:341`, `send_cmd.rs:625`). The verb code widens that byte into a
verb scope, so a code minted for `shell` cannot be spent on `mount`: the
confirmation MAC will not verify, and the mismatch is a cryptographic failure,
not a policy check the receiver could forget. Specified in `CONTRACT.md` under
*One-shot verb codes*.

`serve` is also where the per-verb caution lives. `serve shell` warns; `serve
forward 8080` does not, because the blast radius differs by three orders of
magnitude and a uniform warning teaches people to skip it.

### 3.3 `remember <name>`, after the fact, on either side

A session becomes a relationship when both sides say so, and either may say it
first. `remember` works during a session (over the open link), or afterwards
against a peer still in the recent list.

```
B$ filament remember alex-desktop
  offering to remember alex-desktop, and to be remembered by it.
  waiting for the other side to accept …
```

```
A$                                        ← the waiting shell prints, in place
  ! brenda-laptop wants to be remembered, as `brenda-laptop` here.
    this stores a shared secret so you can find each other with no code.
    it grants nothing.
  accept? [y/N] y
  remembered. brenda-laptop is now PAIRED.
```

```
B$   remembered. alex-desktop is now PAIRED.
```

Two-party by construction: the offer is `pair-keep`, the answer is
`pair-keep-ack`, both already specified (`CONTRACT.md`, *Known devices*) and
already implemented on the browser side. A one-sided store is the exact defect
C12/C27 cured, so `remember` refuses to persist until the ack arrives.

`--yes` accepts without the prompt; non-interactively without `--yes` the
accepting side exits 2 and prints the flag. The offering side does not need a
prompt: running the verb is the consent.

### 3.4 `pause` and `resume`

```
A$ filament pause laptop --until 18:00
  laptop is paused until 18:00 (4h 12m).
  its certificate, its grants and your shared secret are all untouched;
  nothing of yours will answer it until then.
  resume early with:  filament resume laptop
```

```
B$ filament shell alex-desktop
  refused: paused by alex-desktop until 18:00.
  this is not a revocation. nothing was removed.
```

`paused` is a distinct refusal from `denied` (ledger L12) and the CLI says which
one it is, because the remedy differs: one is "wait", the other is "ask".
`resume` publishes a newer version of the pause with a shorter interval; both
are unilateral and neither prompts.

### 3.5 `certify <dev> --scope … --expiry …`

Re-scoping a cert today means re-enrolling. `DeviceCert` carries no scope field
(`crates/filament-id/src/lib.rs:200-206`); the ceiling lives beside it on the
record as `principalCeiling` / `principalExpires`
(`devices_store.rs:83-98`), and `upsert_peer_record` documents that a fresh
enrolment's bounds *win over* a prior record's, never merge (`:89-93`). So the
only way to change a device's ceiling is to walk to the other machine.

`certify` makes the re-scope a verb. It publishes a new version of my `Certify`
and my `Ceiling` for that device, against the device key already on file.

```
A$ filament certify nas --scope transfer,mount --expiry 90d
  nas is FLEET, certified by you, expires in 6d.

  narrowing:   shell      removed
  keeping:     transfer   mount
  widening:    expiry     6d  →  90d

  narrowing takes effect now. the longer expiry needs nas to accept it.
  apply? [y/N] y
  narrowed now. offered the new expiry; nas accepts on its side.
```

```
B$ filament requests
  IN   waiting on you
    r9   alex-desktop   offers  certificate expiry 90d   sent 1m ago
         filament requests accept r9
```

The split in that transcript is the whole design. A single command produced one
unilateral narrowing and one two-party widening, and the output says which is
which and which one is already true. Widening the ceiling without the subject's
`Accept` would violate L5.

### 3.6 `grant … --expires 1h` — elevation that falls back

```
A$ filament grant laptop shell --expires 1h
  offered laptop `shell` for 1h. it expires at 15:40 on its own;
  you do not need to revoke it, and forgetting to will not leave it open.
  waiting for laptop to accept …
```

```
B$ filament requests accept r4
  accepted: shell from alex-desktop, until 15:40.
```

and at 15:40, with nothing run on either side:

```
B$ filament shell alex-desktop
  refused: the shell grant expired at 15:40.
  it has fallen back to what you had before: transfer, mount.
```

No ticker. The verdict at 15:39 already carried `valid_until = 15:40`, and one
generic re-evaluation at that instant replaces every per-path revoke timer
(ledger L3, L9).

### 3.7 `requests`, in both directions

`requests approve` becomes `requests accept`, with `approve` kept as an alias.
The rename is not cosmetic: what the subject signs is an `Accept` op naming one
grant id (ledger L13), and a verb that says `approve` invites the reading that
the *grantor* is approving, which is the one thing it is not.

```
A$ filament requests
  IN   waiting on you
    r7   jane           wants    shell                    4m ago
  OUT  waiting on them
    o3   laptop         offered  forward:nas:8080         2m ago
    o4   phone          offered  certificate + ceiling    yesterday

  accept:  filament requests accept <id>     deny: filament requests deny <id>
  nothing to do for OUT rows; they accept on their side.
```

An `OUT` row is derived, not stored: one of my live `Grant`/`Pass`/`Certify` ops
with no live subject `Accept` naming its id.

### 3.8 `pass` and `guests`

A guest is a principal with a ceiling, described by five things: **who** (a
person key, or a device), **what** (the verb), **where** (device · port · path ·
tag · fleet), **which way** (in, out, both), and **how long**.

```
A$ filament pass jane \
     --allow forward:ws:8080,receive:nas:~/share \
     --expires 7d --devices 3
  a pass for jane, good for 7 days, on at most 3 of her devices.

    what          where                  which way   how long
    forward       ws:8080                in          7d
    receive       nas:~/share            in          7d

  jane gets nothing else. she cannot pass any of it on.
  she does not become a member of your fleet and gets no fdf1 address.
  mint? [y/N] y

  card written to ./jane.pass  (owner-only)
  or read this aloud:  copper-heron-8830   (one device, 10 minutes)
```

```
J$ filament join ./jane.pass
  alex offers you a pass:
    forward  ws:8080       in     7d
    receive  nas:~/share   in     7d
  this is 1 of 3 devices alex allowed. accept? [y/N] y
  accepted. `filament guests` on alex's side now shows this device.
```

```
A$ filament guests
  jane            2 of 3 devices     5d 4h left
    ├ jane-laptop    forward ws:8080 · receive nas:~/share    last seen 2m ago
    └ jane-phone     forward ws:8080 · receive nas:~/share    last seen 3h ago
    revoke the person: filament revoke jane --pass
    revoke one device: filament revoke jane-phone --pass
```

Three properties the transcripts are chosen to show:

- **Attenuation only.** A `Pass` can never grant more than its author holds, and
  the holder cannot re-pass. The card shows "she cannot pass any of it on"
  because the alternative — silent non-delegability — is the kind of thing users
  discover by being surprised.
- **A device budget, not a device list.** The pass names a person key and a
  count. Each device that claims it consumes one slot, and the slots are visible
  on the grantor's side, which is where the cost lands.
- **Both rows say `in`, and that is the point.** `in` is the only direction that
  authorizes the subject: jane may reach my `ws:8080` and write into my
  `nas:~/share`. An `out` row would say *I* may reach something of jane's, and
  it would grant jane nothing — it is a statement of my side only, and it does
  not work until jane separately grants me the matching `in`. The reverse never
  exists unless it is separately granted
  (`docs/design-identity-access-ux.md`, §5). Direction is a bit on the grant,
  not a property of the relationship.

`pass` needs resource-scoped grants, which do not exist yet:
`parse_grant_spec` accepts a `:`-suffixed resource only for `route`, and every
other action resolves to the fixed resource `"self"`
(`crates/filament-cap/src/capability.rs:86-115,158-169`). The capability
grammar and its lattice are specified in `CONTRACT.md` under *Resource-scoped
capabilities*; the ticket that lands it is in `docs/ux-tickets.md`.

### 3.9 The `--remember` defect this design inherits

`send --remember` and `receive --remember` are documented as "after a code
pairing, remember the other device under this name"
(`cli_def.rs:171-173,212-214`). On the send side that is not what happens.
`send_cmd.rs` runs the same SPAKE2 ceremony `pair` runs and then **discards**
the secret by design (`send_cmd.rs:613-619,633`); it never calls
`devices_store*`, and it emits no `pair-keep` anywhere in the file. What it does
do is listen for `pair-keep-ack` and print "mutually remembered" or "declined"
based on whether `--remember` was passed (`send_cmd.rs:1613-1634`).

The working remember ceremony lives in `recv_cmd.rs` and is the *older*,
non-PAKE path: a locally minted `ceremony_secret` (`recv_cmd.rs:186`) handed
over as `pair-keep` (`:2998-3006`, `:4844-4856`) and stored by the peer only if
it too passed `--remember` (`:4798-4841`). It is armed from the interactive REPL
inside a running `receive`, and it emits `pair-create` without a nameplate
(`:6283-6309`), i.e. the pre-PAKE code path.

So there are two remember mechanisms, one of which is half-wired, and the flag
that names the feature is on the half that does not do it. `remember` as a verb
(§3.3) is the single implementation both sides call, and `--remember` becomes a
shorthand for it rather than a second path. That is a ticket, and it is listed
as a fix, not a feature, because the current help text is a false claim.

### 3.10 `reach --until-direct`

Not a relationship verb, but the one thing a waiting party asks that the CLI
cannot currently answer: *is it direct yet?*

```
A$ filament reach nas --until-direct --timeout 30s
  nas   relay        rtt 148ms   ← 0s
  nas   relay        rtt 151ms   ← 4s
  nas   direct-quic  rtt  11ms   ← 9s   via 192.168.1.40:41221
  direct after 9.2s
```

`ctl::try_ping` (`cli/src/ping.rs:22`) already returns the route and RTT of the
link the `up` daemon holds, and `ping_cmd` already re-samples it in a loop
(`:33-44`). `--until-direct` polls that until `route` is a direct label
(`is_relay` at `:52-55` already classifies), then exits 0; on timeout it exits
5 with the last route it saw. It is in this document because it is the smallest
verb that proves the "never blind" rule, and it needs no ledger, no wire change
and no new crypto.

## 4. The non-interactive contract

Every prompt in this design obeys one rule, and the rule is already implemented.

**The gate.** A prompt may open only when `UiCapability.interactive` is true,
which is `stdin.is_terminal() && !--no-interactive && !--json &&
FILAMENT_NONINTERACTIVE is unset` (`cli/src/main.rs:459-462`, mirrored by
`policy::interactive_allowed`, `cli/src/policy.rs:38-42`). No new verb may
compute its own notion of interactivity.

**The default is no.** `UiCapability::confirm` reads one key and treats bare
Enter, EOF, Ctrl-C and anything that is not `y`/`Y` as a refusal
(`cli/src/main.rs:470-500`). Every consent in this document is a `confirm`, so
a stray newline can never widen a relationship.

**`--yes` is the only bypass.** `confirm` returns `Ok(())` immediately when
`self.yes` (`main.rs:471`). `--yes` is global (`cli_def.rs:127-130`), so
`filament remember phone --yes` is the scripted form of accepting an offer.

**Non-interactive without `--yes` exits 2 and says which flag.** This matches
`interact::render_steer`, which prints what the command needs, one example, and
exits 2 (`cli/src/interact.rs:71-86`). It is a usage error, not a denial: the
user did not say no, the user was never asked.

**`--json` never prompts and never prints prose.** Under `--json` the prompt is
not rendered at all; the verb emits `ui::json_err(verb, "needs_consent", …)` and
exits 2. This depends on tickets 1-3 of `docs/agent-output-audit.md` (the
envelope, the `ExitKind` enum, and the `--json` honesty gate) and is the one
place this design takes a hard dependency on that work.

The table, prompt by prompt. `exit` is the non-interactive, no-`--yes` code.

| prompt | verb | widens? | TTY | `--yes` | non-TTY | exit |
|---|---|---|---|---|---|---|
| "remember <peer> as `<name>`?" | `remember`, and the `--remember` path in `send`/`receive` | yes | ask, default N | accept | refuse | 2 |
| "accept <owner>'s certificate and ceiling?" | `join`, `certify` on the subject side | yes | ask, default N | accept | refuse | 2 |
| "accept the grant <cap> from <peer>?" | `requests accept` | yes | ask, default N | accept | refuse | 2 |
| "accept this pass? <ceiling>, <n> devices, <expiry>" | `join <card>` | yes | ask, default N | accept | refuse | 2 |
| "serve `shell` to whoever speaks this code?" | `serve shell` | yes | ask, default N | accept | refuse | 2 |
| "pause <dev> until <t>?" | `pause` | no | proceed, no prompt | n/a | proceed | 0 |
| "forget <dev>? this deletes the record and every op about it" | `devices forget` | no, but destructive | ask, default N | accept | refuse | 2 |
| "revoke <dev> <cap>?" | `revoke` | no, but destructive | ask, default N | accept | refuse | 2 |

Only the destructive-but-narrowing rows prompt without widening. That is
deliberate: `pause` and a tighter `certify` are reversible and bounded, so they
do not earn a prompt; `forget` and `revoke` are not, and they already prompt
today via the global `-y` (`cli_def.rs:127-130`).

**The one prompt that is not a confirm.** `serve <verb>` at a TTY blocks,
displaying the code, until a peer claims it or the user interrupts. That is a
wait, not a question. Non-interactively it prints the code as its ready record
and keeps waiting, so a script can read the code from stdout and hand it to the
other side. Under `--json` the ready record is the envelope
`{"ok":true,"verb":"serve","data":{"state":"waiting","code":"…","scope":"shell","expires":…}}`,
following ticket 15's rule that the ready line lands where readiness actually
begins.

## 5. What the counterpart sees next

A waiting party must never be blind. Three mechanisms, in increasing cost.

### 5.1 The offer inbox, both directions

`filament requests` exists and lists only requests that came *in*
(`cli/src/status_cmd.rs:213-230`, with `approve` / `deny` at `:238-282`). Under
this model every widening move produces an inbox row on **both** sides, because
a `Grant` without its `Accept` authorizes nothing and both parties need to know
which half is missing.

```
$ filament requests
  IN   waiting on you
    r7   jane        wants  shell            asked 4m ago
         filament requests accept r7   ·   filament requests deny r7

  OUT  waiting on them
    o3   laptop      offered  forward:nas:8080      sent 2m ago
    o4   phone       offered  certificate + ceiling  sent yesterday
         nothing to do here; they accept on their side
```

The `OUT` half is new. It is derivable with no new storage: an outgoing row is
one of my live `Grant` / `Pass` / `Certify` ops for which no live subject
`Accept` names its id. Before the ledger, it is the subset of my `CapOp`s whose
target has not answered.

### 5.2 The nudge on the next command

`fleet_ui::devices::render_devices(devices, pending_requests, roster_heading)`
already takes a pending count and renders it (`cli/src/fleet_ui/devices.rs:37`).
Extend that one line to any verb that prints a banner, so the *next* thing the
waiting party runs tells them:

```
$ filament status
  ● daemon running, 3 devices, 1 exposed port

  ! 1 offer waiting on you (jane · shell) — filament requests
```

One line, on stderr via `ui::say`, suppressed by `-q` and by `--json` (where it
belongs in `data.pending`, not in the prose). It fires on `status`, `devices`,
`reach`, `up` and `id`, which is every verb a person runs while waiting.

### 5.3 Live, on the link that is already open

When the two sides are connected — a `SESSION` from a verb code, or a warm link
held by `up` — the offer travels the link and the other terminal prints it
immediately, the way `pair-keep` already reaches a connected browser
(`CONTRACT.md`, *Known devices*). This is the only mechanism that needs a wire
frame, and it is specified in `CONTRACT.md` under *Remember offer and accept*.

Nothing here polls. §5.1 and §5.2 read local state; §5.3 rides a link that is
already up. A peer that is offline learns about the offer the next time it runs
anything, which is the honest bound: the mesh has no push and this document
does not pretend otherwise.

## 6. Open questions

Listed, not resolved. Each one is a place where this design would have to guess,
and a guess recorded as a decision is worse than a question left standing.

1. **`forget` versus "a removed key stays removed".** Decision 1 says `forget`
   is the only exit and a code or card brings a device back.
   `docs/design-mesh-ux.md` (*The one conflict a user can see*) says the
   opposite for the mesh: "a removal always wins" and "it will need a new device
   key, because a removed key stays removed." Both can be true if `forget` is
   local and the roster tombstone is owner-level, but then T12 restores a
   *different* principal with the same petname, and the row must say so. Which
   scope does `forget` have?
2. **Does `forget` erase my own `Deny`?** The ledger says forget removes the
   record and every op about it. My `Deny` about a peer is my protection, and
   erasing it means a returning peer arrives clean. Is `forget` "forget them",
   or "forget everything I ever decided about them"?
3. **Is `SESSION` visible in `devices`?** It has no record, so by §2.2 it is
   invisible, and a user who just opened a code session will look for it there.
   A synthetic row is a lie about storage; no row is a lie about what is
   happening. Third option: a separate `SESSIONS` block with its own heading.
4. **Whose clock.** Ledger intervals are UTC seconds, but `pause --until 18:00`
   is read locally, and skew between two machines makes "paused until 18:00" a
   different instant on each side. Render local and sign UTC — but which side's
   rendering is authoritative in the refusal message the *other* side sees?
5. **Where the verb scope binds.** Binding the verb into the SPAKE2 identity
   (the nameplate) tells the signaling server which verb is being served.
   Binding it only into the confirmation MAC keeps it private but turns a
   wrong-verb claim into a confirmation failure, which reads to the user as
   "wrong code". Privacy or legibility; this design assumes the MAC and flags it.
6. **Direction defaults per verb.** §3.8 asserts `in` for receive-shaped verbs
   and `out` for reach-shaped ones. That is an invention of this document. The
   safe alternative is no default at all: require `--way` on every
   resource-scoped grant and let the annoyance be the teacher.
7. **How hard is the device budget.** `--devices 3` is enforced by the grantor
   counting live `Accept`s. Two devices claiming while the grantor is offline can
   both succeed. Hard cap (needs a rendezvous the mesh does not have) or
   best-effort with a visible audit in `guests`?
8. **Who is `pass <person>` before they have a key.** A card handed to someone
   you have never met has no subject key to name, so the first claimer's key
   binds it. That quietly weakens "who" to "whoever holds the card first",
   which is exactly the property a device budget is supposed to bound.
9. **A guest's route.** A pass grants no `fdf1` address (§3.8), but
   `forward:ws:8080 out` requires the guest to reach my device. Over a
   relay-only path, or a scoped overlay address that exists for the life of the
   pass?
10. **Does `certify --scope` count as a "fresh signed claim"?**
    `devices_store.rs:89-93` says a fresh enrolment's bounds win over a prior
    record's and are never merged. A re-scope is a new signed claim by the same
    owner against a device key already on file. If it takes that path, a
    re-scope silently resets `principalMaxOffline` and every other bound the
    flags did not mention.
11. **`EXTERNAL` as a word.** §2.2 removes the tier.
    `docs/design-pairing-ux.md` uses "inter-user (external share)" as one of the
    two relationships the wizard must distinguish. Removing the row label is
    safe; removing the concept is not, and the two are one grep apart.
12. **How `--json` renders two axes.** One field (`"state":"fleet.paused"`) is
    easy to parse and lossy; two fields (`"base":"fleet","overlay":"paused"`) are
    honest and break every consumer that reads `tier`. There is no consumer yet,
    which makes this the cheapest it will ever be to decide.
