# Relationship UX: the build order

The tickets that turn `docs/design-relationship-ux.md` and the *Relationship
frames* section of `CONTRACT.md` into shipped behaviour. One PR each, in
dependency order.

**Lanes.** `pi` is the lane that owns the wire and the crypto: anything that
changes a signed blob, a MAC input, a frame, or `CONTRACT.md`. `worker` is
substantial CLI work behind an already-pinned contract. `helper` is small,
self-contained, and safe to hand to anyone.

**The ledger split.** `work/cap-ledger-model` pins the capability ledger
(`decide`, `Accept`, `Pause`, `Ceiling`, `valid_until`) but the extraction is
not done. Tickets marked **B** land before it and must not assume it exists;
tickets marked **A** land after and should not be started early, because the
half of them that could be faked now would have to be unfaked later.

**What this list does not contain.** The `--json` envelope, the `ExitKind`
enum, and the `--json` honesty gate are tickets 1-3 of
`docs/agent-output-audit.md`. Several tickets here depend on them; none of them
re-implement them, and where a ticket needs JSON it says so and blocks.


## Status board (kept current; update in the same PR that moves a ticket)

Legend: `done` merged to main · `in PR` open pull request · `building` branch exists, not yet a PR · `queued` assigned, not started · `blocked` waiting on a named item · `not started`.

| Ticket | What | Lane | State | Where |
|---|---|---|---|---|
| U1 | implicit `init` | helper | not started | |
| U2 | `serve shell` + `shell <code>` | pi | not started | |
| U3 | `reach --until-direct` | helper | in PR | #315 (gate 3/3, waits on registry hotfix #317) |
| U4 | `serve exec/forward/mount` | worker | not started | needs U2 |
| U5 | `remember`, `--remember` repair | pi | not started | hotfix for the false "mutually remembered" message requested |
| U6 | tier becomes the base | worker | not started | |
| U7 | `forget` at top level | helper | not started | |
| U8 | resource-scoped caps + lattice | pi | contract done, code not started | CONTRACT "Relationship frames" (#313) |
| U9 | direction bit | pi | contract done, code not started | CONTRACT "Relationship frames" (#313) |
| U10 | `certify <dev> --scope --expiry` | worker | contract in PR, code queued | #305 (contract); worker queue position 3 |
| U11 | `requests accept`, OUT rows | worker | not started | |
| U12 | `pause` / `resume` | worker | not started | |
| U13 | ledger boundary | pi | blocked on ledger extraction | ledger contract L1-L13 merged (#311); L14-L18 in PR #319; Rust extraction not started |
| U14 | overlay tiers from verdicts | worker | blocked on U13 | |
| U15 | `grant --expires` fall-back | worker | blocked on U13 | |
| U16 | `Accept` end to end | worker | blocked on U13 | |
| U17 | `pass` and `guests` | pi | blocked on U13 | design in docs/design-relationship-ux.md |
| U18 | tag visibility | worker | blocked on U13 | |
| U19 | two-axis state in `--json` | helper | blocked on U13 + audit tickets 1-3 | |

Adjacent work the tickets depend on or that came out of the same design:

| Item | State | Where |
|---|---|---|
| `filament exec` | done | main (#302) |
| SSH certificates from the shell grant | done | main (#303) |
| Enrolment-ceiling `scoped_in_bounds` + settle-then-evaluate | in PR, 23/23 gates | #309 (draft lifts on green CI) |
| Bootstrap card (fc1) contract + vectors | in PR | #314 (rebased 2026-09-18) |
| Capability ledger contract L1-L13 + model | done | main (#311) |
| Capability ledger L14-L18 + model | in PR, under review | #319 |
| Relationship UX design + contract frames + this ticket list | done | main (#313) |
| `filament sync` (delta transfer verb) | building | work/sync-verb2 |
| `devices --caps` (what can this device do to me, until when) | building | work/device-caps2 |
| Agent-grade output audit (23 tickets, envelope, exit codes) | in PR | #307 (rebased 2026-09-18) |
| CLI fixes: shell help text, `logs -f` teardown | in PR | #308 (rebased 2026-09-18) |
| Half-dead transport reader (#312) | queued | worker queue position 2 |
| Registry hotfix (7 expired diagnostics) | in PR, blocks every merge | #317 |
| Token carrier decision (Biscuit) | doc not yet committed | pi's checkout, docs/design-token-carrier.md |

---

## The first three, buildable today

### U1 — `init` stops being a precondition · `helper` · **B**

Add a lazy accessor that mints the user keypair on first use and prints one
past-tense line. `UserKey::generate` has one call site today
(`identity_flow.rs:285`); route the seven "no identity. Run `filament init`
first" bails through the accessor instead
(`add_for.rs:206-207`, `dispatch.rs:701,762,1449,1515`, `status_cmd.rs:68`).
`filament init` keeps every flag; it stops being required. The precedent to
follow is `local_device_cert()` (`identity_flow.rs:119-176`), which already
mints a device cert on demand.

*Accept:* from a clean config dir, `filament send f --code` prints
`created your identity` once and proceeds; a second run prints no such line.
`filament init` on a machine that already has an identity still fails with the
existing message (`identity_flow.rs:246`), unchanged. A gate in
`cli/tests/gates.sh` runs both halves against a temp `FILAMENT_CONFIG`.

### U2 — `serve shell` and `shell <code>` · `pi` · **B**

The verb scope byte, the `serve` verb for `shell` only, and the code-in-the-
petname-slot form of `shell`. Mint with `mint_words` + `mint_pair_nameplate`
(`crates/filament-pair/src/words.rs:99,119`), register with the existing
`pair-create` (`pair_cmd.rs:278`), run `Ceremony::new` with the new scope byte
`0x10` instead of `IntroScope::Device` (`pake_ceremony.rs:143`,
`pair_cmd.rs:341`), and hand off at the point `Ceremony::secret()` first
returns `Some` (`pake_ceremony.rs:190`) into the existing PTY session opener
rather than into `devices_store_v2`. Refuse an unknown scope byte on the
confirm path. Persist nothing.

*Accept:* two terminals in `cli/tests/gates.sh`. `filament serve shell --yes`
prints a code matching `^[a-z]+-[a-z]+-[0-9]{4}$`; `filament shell <code>` on
the second opens a PTY and prints the `this is a SESSION` line; a second
`filament shell <code>` with the same code fails saying the code is spent; and
`filament mount <code>:/tmp` with a `shell` code fails key confirmation, with
no mount attempted. After all of it, `devices.json` is byte-identical to before.

### U3 — `reach --until-direct` · `helper` · **B**

Poll `ctl::try_ping` (`cli/src/ping.rs:22`) on the interval `ping_cmd` already
uses (`:33-44`), printing one line per sample, until `route` is not a relay
label (`is_relay`, `:52-55`) or `--timeout` elapses. Exit 0 on direct, 5 on
timeout with the last route seen. No new transport code.

*Accept:* `filament reach <peer> --until-direct --timeout 2s` against a peer
with no daemon exits 5 and its last line names a route; against a warm direct
link it exits 0 within one sample. `filament reach <peer> --until-direct --json`
emits one record per sample on stdout and all of stdout parses as JSONL.

---

## Before the ledger

### U4 — `serve exec`, `serve forward`, `serve mount` · `worker` · **B**

The other three scope bytes (`0x11`-`0x13`) and their claim sides:
`exec <code> -- …`, `forward <code>:<port>`, `mount <code>:<path>`. Each reuses
U2's ceremony wholesale and differs only in the scope byte and which session
opener receives the handoff. `serve shell` warns; the other three do not.

*Accept:* one gate per verb, each asserting the round trip, the burn, and a
cross-verb refusal (a `forward` code presented to `exec` fails confirmation).

### U5 — `remember <name>`, and the `--remember` repair · `pi` · **B**

Implement `pair-keep` v2 (`offer_id`, `name`, silence-is-refusal) per
`CONTRACT.md`, add the `remember` verb on both the offering and accepting side,
and make `send --remember` / `receive --remember` call it instead of the two
half-wired paths they use now. Today `send_cmd.rs` discards the PAKE secret by
design (`:613-619,633`), never stores, and never emits `pair-keep`, while
listening for the ack and printing "mutually remembered" off the flag alone
(`:1613-1634`); the working ceremony is the older non-PAKE one in `recv_cmd.rs`
(`:186,2998-3006,4798-4841`). One implementation replaces both.

*Accept:* `filament remember <peer>` on one side and `--yes` on the other leaves
a record on BOTH; declining leaves a record on NEITHER; letting the session end
with no answer leaves a record on neither (the v2 behaviour change). A gate
asserts `send --remember` now writes a record, which it does not today, and the
browser-side v1 path still round-trips unchanged.

### U6 — the tier becomes the base · `worker` · **B**

Replace the three-arm tier in `device_view.rs:308-316` with §2.2 of the design:
consult the cert's expiry via `device_cert_valid_for` (`:71`) instead of
`device_cert_for` (`:52`), fold `External` into `PAIRED` plus a note, fold
`NeedsReview` into `PAIRED`, keep `MeshRoster` as `FLEET` plus a note. No new
persistence; the row is still computed per call.

*Accept:* a unit test over synthetic records: a live same-owner cert renders
`FLEET`; the same record with `expires` in the past renders `PAIRED` and the
row names the lapse date; a foreign-owner cert renders `PAIRED · carries <x>'s
cert`; a record with neither renders `PAIRED`. Grep gate: `NEEDS REVIEW` and
`EXTERNAL` appear in no rendered string.

### U7 — `forget` at top level · `helper` · **B**

Promote `DevicesAction::Forget` (`cli_def.rs:806-807`) to `filament forget
<name>`, keeping `devices forget` as an alias, and make the confirmation state
what it deletes. Answers question 1 in the design's open list only if the answer
is "local"; if it is not, this ticket blocks on that decision.

*Accept:* `filament forget nope; echo $?` prints 3 (`UnknownDevice`, per the
audit's §3); `filament devices forget <x>` and `filament forget <x>` take the
same path; without a TTY and without `-y` it exits 2.

### U8 — resource-scoped capability strings and the lattice · `pi` · **B**

Extend `parse_grant_spec` (`crates/filament-cap/src/capability.rs:86-115`)
beyond `route` to the grammar in `CONTRACT.md`, and implement `covers` as a
component-wise lattice with `*` as top. Device and fleet targets are keys on the
wire; the CLI resolves petnames to keys on the way in and back on the way out.
Refuse unknown actions and unparseable targets at ingest. Refuse a path pattern
containing `..` rather than normalizing it.

*Accept:* a property test that `covers` is reflexive, transitive, and that
`covers("forward:K:8080", "forward:K")` is FALSE; `filament grant ws
forward:ws:8080` succeeds and `filament grant ws forward:ws:../etc` exits 2;
existing `route:10.0.0.0/24` behaviour is unchanged, pinned by the existing
gate.

### U9 — the direction bit · `pi` · **B**

Add `way: In | Out | Both` to `CapOp` (`capability.rs:394-403`), inside the
signed blob, with `In` as the wire default so existing ops keep their meaning.
`Out` authorizes the subject nothing and must be evaluated as such, not merely
rendered differently. Add `--way` to `grant`.

*Accept:* a unit test asserting an `Out` grant produces no allow for the subject
under any request; a second asserting `Both` produces exactly the allows its
`In` half would; a canonical-blob test pinning that an op with `way: In`
round-trips byte-identically to a pre-`way` op.

### U10 — `certify <dev> --scope --expiry` · `worker` · **B**

Promote the internal `certify_local_device` (`identity_state.rs:284-299`) /
`DeviceCert::certify` (`crates/filament-id/src/lib.rs:209`) into a verb that
re-scopes an existing device without re-enrolling. Print the narrowing and the
widening separately, apply the narrowing immediately, and hold the widening as
an offer. Before U14 lands the offer has nowhere to go, so this ticket ships the
narrowing half and prints the widening half as "not yet available; re-enrol".

*Accept:* `filament certify nas --scope transfer,mount` on a device whose
ceiling includes `shell` removes `shell` immediately and `filament devices`
shows it gone; the same command with a longer `--expiry` prints the widening as
deferred and does NOT extend anything; the record's `principalMaxOffline` is
unchanged by both (the silent-reset hazard in open question 10).

### U11 — `requests accept`, and OUT rows · `worker` · **B**

Rename `requests approve` to `requests accept`, keep `approve` as a hidden
alias, and add the `OUT` section listing my own grants that no counterpart has
taken up. Before the ledger the OUT set is approximated from `CapOp`s whose
target has never connected since the op was written; the heading says
`waiting on them` and the row says how it was determined, because an
approximation rendered as a fact is the defect this whole document is about.

*Accept:* `filament requests` prints both sections with an empty OUT section on
a fresh machine; `filament requests approve <id>` still works and is absent from
`--help`; `filament requests --json | jq -e '.data.in and .data.out'` (blocked
on audit ticket 3).

### U12 — `pause` and `resume` · `worker` · **B**

A local, interval-bounded suppression: `filament pause <dev> --until <t>` and
`filament resume <dev>`. Before the ledger it is a local record consulted by the
same gate that consults grants, and the refusal it produces says `paused`, never
`denied`. U14 re-points it at the `Pause` op without changing the verb or the
message.

*Accept:* two terminals: after `filament pause <b> --until +1h` on A, `filament
shell A` on B is refused with a message containing `paused` and the time, and
`filament devices` on A shows the overlay; `filament resume <b>` restores it
within one command. The refusal's exit code is 4 (`Denied`) and a gate asserts
the word `revoked` appears nowhere in it.

---

## After the ledger

### U13 — the boundary · `pi` · **A**

The capability ledger extraction itself (`work/cap-ledger-model`) is not a
ticket here. Everything below assumes `decide(facts, request) -> Verdict` with
`valid_until` and `because`, and the `Accept` / `Pause` / `Ceiling` / `Pass` op
kinds, are landed and gated by `proofs/capability_ledger_model.py`.

### U14 — the overlay from verdicts · `worker` · **A**

Compute `PAUSED` and `DORMANT` per §2.3: `PAUSED` when a verdict is
`Deny(paused)`, `DORMANT` when every verdict denies and no op naming the peer is
live at `now`. Render `base · overlay · why`, where `why` is the verdict's
`because` rendered as one clause. Re-point U12's local suppression at the
`Pause` op. Delete the pre-ledger approximation in U11's OUT section and derive
it from unaccepted ops.

*Accept:* a table test over synthetic ledgers covering each of
`(none) / PAUSED / DORMANT` for each base; a gate asserting no tier string is
ever written to `devices.json`; and one asserting that a record whose cert and
grants have all lapsed renders `DORMANT` with the lapse date, not `STRANGER`.

### U15 — `grant … --expires` and fall-back · `worker` · **A**

Time-boxed elevation, scheduled off `valid_until` rather than a per-path timer.
One re-evaluation at `valid_until` replaces every revoke ticker (L3, L9).

*Accept:* `filament grant <b> shell --expires 30s`, accepted; at +31s `filament
shell` from B is refused and the message names the prior authority it fell back
to; no timer thread exists for the grant (gate: grep for a spawned ticker in the
grant path returns nothing).

### U16 — `Accept` end to end · `worker` · **A**

The subject side of every widening: `requests accept <id>` signs an `Accept`
naming one op id, ships it, and the author ingests it. Completes U10's widening
half and U11's OUT rows.

*Accept:* `filament certify nas --expiry 90d` shows as an OUT row on the owner
and an IN row on `nas`; after `filament requests accept` on `nas`, both rows
clear and the expiry is live; an `Accept` signed by anyone but the subject is
refused at ingest.

### U17 — `pass` and `guests` · `pi` · **A**

The `Pass` op, the device budget, the card carrier, and the `guests` view.
Depends on U8 (resource scoping), U9 (direction) and U16 (`Accept`). Refuse
re-delegation and over-budget `Accept`s at ingest, with reason `budget`.

*Accept:* `filament pass jane --allow forward:ws:8080 --expires 7d --devices 2`
mints a card; two of jane's devices accept and the third is refused with
`budget`; `filament guests` shows `2 of 2`; a pass authored by a principal whose
own authority is a pass is refused at ingest; revoking the person's pass cuts
both devices in one command.

### U18 — tag visibility · `worker` · **A**

`see:tag:<id>` as a capability, so a guest can be shown a slice of the fleet
without being in it. Builds on `docs/design-groups-tags-caps.md` §3.2.

*Accept:* a guest granted `see:tag:lab` sees exactly the tagged devices in
`filament devices` and nothing else; removing the tag binding removes the rows
within one command.

### U19 — two-axis state in `--json` · `helper` · **A**

Whatever open question 12 resolves to, applied everywhere at once: `devices`,
`status`, `requests`, `guests`. Blocked on audit tickets 1-3 and on that
decision.

*Accept:* `filament devices --json | jq -e '.data.devices[0]'` exposes the
agreed shape, and a schema test asserts every surface uses the same field names.

### U20 — `sync <dir> <device>:<dir>` · `worker` · **B** · shipped, PR #326

Delta directory transfer between paired devices, rsync-shaped: a manifest of
whole-file and per-chunk digests goes over one L2 stream, the receiver answers
with the chunks it lacks, only those move, and every landed file passes the
same whole-file verifier `send`/`receive` use. Consent is the existing pairing
and transfer grant, so there is no prompt on either end and a stranger cannot
sync. `<remote-dir>` is bounded to the receiver's drop directory. `--delete`
off by default; `--dry-run`/`-n` prints the plan and touches nothing.

*Accept:* `cli/tests/sync-gates.sh`: change one chunk of one file and add one
file, re-sync, and exactly those two move (bytes and lines); an unchanged
re-run moves 0 bytes; `boxB:../x` is refused with exit 4 and nothing created;
`-n` creates nothing on the receiver; an unknown device exits 3; a re-run after
a file is lost and another truncated on the receiver moves only what is missing.

---

## Dependency order, compressed

```
U1  U3  U20                 independent, any order
U2 ──► U4
U5                          independent (needs U2 only for the transcript)
U6  U7                      independent
U8 ──► U9 ──┐
U10 ────────┤
U11 ────────┤
U12 ────────┘
            └─► U13 (ledger lands) ─► U14 ─► U15
                                       └──► U16 ─► U17 ─► U18
                                                      └──► U19
```
