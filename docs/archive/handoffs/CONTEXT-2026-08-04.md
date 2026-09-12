# CONTEXT: filament transfer-path work, handoff for a fresh agent

Everything needed to continue without reading any history.

Labels are **SECTIONAL**, not per-claim: a heading marked VERIFIED covers the
items under it. An unlabelled claim is **unclassified, not verified** — check it
before you build on it. (Flagged by `claude-advisor`: most individual claims here
carry no marker, and a reader told "the doc is labelled" will read absence as
confirmation.)

---

## 1. The problem (RESOLVED 2026-08-03, kept for the trail)

> **STATUS: this section describes the state BEFORE the root cause was found.**
> `pair_and_transfer_smoke` now passes on all three platforms. The cause and fix
> are in section 3b. Everything below in this section is the investigation as it
> stood, preserved because the wrong turns are instructive, not because it is
> current.

`pair_and_transfer_smoke` fails on two of three platforms on `main`.

| tree | roster reconciliation | fallback fixes | macOS | ubuntu | windows |
|---|---|---|---|---|---|
| `main` (before #71) | no | no | FAIL | pass | FAIL |
| PR #73 (control) | no | no | FAIL | pass | - |
| PR #74 (control) | no | yes | FAIL | pass | - |
| **PR #71 (MERGED)** | yes | yes | **pass** | pass | **pass** |

VERIFIED. Windows fails with the identical signature (`peer did not come back
within 45s`, `capability_harness.rs:414`) in 50s rather than 647s.

**This was framed as a macOS bug for two days. It is not.** Ubuntu is the only
platform where the transfer path worked, and it is the platform CI is tuned
around.

## 2. The mechanism (VERIFIED)

`main.rs`, "Option A", fires after PAKE authentication:

```rust
// Option A: drop WebRTC link and race direct-quic FIRST.
// If direct fails: expired_direct -> establish -> WebRTC fallback (~5s gap).
conn.drop_link(&from);
conn.start_direct(&from, &from, &sec).await;   // sec = the PAKE secret
```

The teardown is **deliberate and correct by design**. The failure is that the
promised fallback does not arrive:

```
direct authenticated -> intentional Option A drop
+30s   fallback establish rebuilds, ICE CONNECTS
       ...no second auth, no transfer          <- the real defect
+600s  sender hits claim_deadline, exits
+45s   receiver rejoin window expires           (600 + 45 = 645 vs 647 observed)
```

**Why the rebuilt link cannot authenticate:** once `pake_done` is true the
ceremony never re-runs (`if use_code && !is_direct && !pake_done`). The only
remaining auth path is the post-channel pair-proof, which needs
`l.expected_secret`. `establish()` built every link with `expected_secret: None`.

**Why macOS specifically, and this is the HEADLINE (VERIFIED):**
`FILAMENT_DIRECT_PER_OS=0` on macOS in CI, forwarded by `capability_harness` to
every spawned daemon as `FILAMENT_DIRECT` (it reads in six places; an earlier
grep of `cli/src` alone missed it and nearly deleted it as dead).

`FILAMENT_DIRECT=0` is **a documented, supported, user-facing opt-out**:

```rust
direct.rs:57  // Default ON. Opt out with FILAMENT_DIRECT=0.
```

So this is a PRODUCT bug, not a CI artifact. A user who takes the documented
"skip the fast path" option gets: Option A drops the WebRTC link, `start_direct`
returns at the first guard (`!self.direct_ok`, ~165 lines before
`direct_pending.insert`), `expired_direct` has nothing to expire, and the link is
destroyed with no successor. **The transfer wedges for 600 seconds.** The option
offered for AVOIDING the risky path is the one that breaks transfers outright.

An earlier version of this file said macOS CI "tests a configuration no user
runs". That was backwards, corrected by `claude-advisor`: macOS was the ONLY
place testing something realistic, and it is what found this.

`FILAMENT_DIRECT_LOOPBACK_ONLY=1` on ubuntu/windows pins ICE candidates to
loopback, so same-host direct works trivially there; it is 0 on macOS because
webrtc-rs gathers no loopback host candidates on ARM64.

## 3. What landed (PR #71, MERGED into main)

All VERIFIED in source by `claude-advisor`:

- `establish()` does all fallible work (incl. a network round trip) **before**
  dropping. Drop and insert are adjacent with no `await` between, so the
  destroy-without-rebuild window is eliminated, not narrowed.
- `expected_secret` carried across every rebuild path, not just the expiry site.
- Three `let _ = self.establish(...)` discards now log. Two are the WebRTC
  fallback by their own comments.
- All `on_synced` sites reconcile the digest roster; `#[must_use]` makes a
  silent discard a compile error.
- `#[track_caller]` on `drop_link` — a teardown names its call site. Answered in
  one CI cycle what a 17-site audit had not.
- Gate P: `FILAMENT_TEST_DROP_PUSH` server-side push dropper.

**#71 works by RECOVERY, not prevention.** Roster re-adoption re-establishes
after the teardown.

> **SUPERSEDED 2026-08-03 by #83 (47f756c).** The sentence that stood here said
> "the designed fallback is still broken, do not describe it as fixed". That was
> true when written and is now wrong. The root cause was never the fallback: the
> offer site documented that *"on confirm the Signal handler sets `pake_done`
> and re-emits ChannelReady to fall through here and offer"*, and the Signal
> handler never re-emitted anything. The Option A teardown was performing that
> dispatch by accident. See section 3b.

## 3b. What the macOS wedge actually was (2026-08-03, RESOLVED)

The `--code` path DEFERS every offer until the PAKE confirms, and the offer site
names who is supposed to wake it:

```rust
// ...on confirm the Signal handler sets `pake_done` and re-emits
// ChannelReady to fall through here and offer.
if use_code && !is_direct && !pake_done {
    continue; // offers/remember wait for PAKE confirm
}
```

**The Signal handler sets `pake_done`. It never re-emitted anything.** What woke
the loop was the Option A teardown: dropping the link forced a rebuild, and the
rebuilt link's fresh `ChannelReady` fell through the now-satisfied guard carrying
the offer. A destroy-and-rebuild cycle was standing in for an event dispatch, and
no test could tell the difference because every platform either promoted to
direct or rebuilt WebRTC. No configuration ever RETAINED the post-PAKE link and
needed it to work, until the promote-intent restructure created one.

Fixed by `rearm_channel_ready` at both PAKE sites (#83, 47f756c).

## 4. Where things stand (2026-08-04)

Twenty-three PRs merged on 2026-08-03. The transport-path investigation is
closed. `main` is green on all three platforms.

**Landed**: #71 roster reconciliation, #72 copy, #81 `channel_peers`, #82 the
transport-upgrade proof, #83 the ChannelReady contract, #84 the
transport-recovery obligation, #85 pending-survives-setup-failure, #86 the
announce seq check, #87 the transition-staleness detector, #89 the fallback gate
that had run nowhere, #90 this file onto main, #91 the role-comparison guard,
#92 first-contact eligibility, #93 the coverage map, #94 the unrunnable NAT gate
annotated, #95 the NAT prober, #96 exhausted-give-up suppression, #97 the SAS
no-constructor guard, #98 config-mode repair, #99 the shell owner-equivalence
gate, #100 the delegated ceiling, #101 owner-equivalent copy, #103 the pattern
record, #104 the shell posture docs, #105 the OOM shield assertion.

**Closed as superseded**: #70, #73, #74, #75, #76 (stacked on a pre-#71 base,
went CONFLICTING, and **GitHub schedules zero checks on a conflicting PR**, which
reads exactly like "CI pending" and cost two wake cycles), #77, #78 and #79
(the promote-intent restructure alone was a REGRESSION: it removed the accidental
teardown that was dispatching ChannelReady, so it re-landed inside #83 with the
re-emit that makes it correct).

## 5. Open, in priority order

1. **#49 `pair --word` mints a code its own router rejects.** `mint_nameplate()`
   returns 3 digits; `looks_like_pake_code` requires >=4; the bare-token router
   sends 2-3 digits to `recv`. A test at `words.rs:215` PINS the wrong width, so
   the suite defends the mismatch. Fix needs a separate pairing mint plus a
   ROUND-TRIP assertion: what `pair --word` mints must satisfy
   `looks_like_pake_code`. Pinning widths independently is what let them drift.
2. **#50 the first-ever NAT pairing attempt FAILED**, ICE stuck then timeout.
   Cause UNKNOWN between lab and product and **must not be guessed**. The
   `FILAMENT_BIN=/bin/true` control proves the topology and prober, NOT that the
   lab can carry WebRTC. Needs a control proving WebRTC works in that lab at all.
   Do NOT resolve it by adding TURN and observing a relay: that proves relay and
   says nothing about hole-punch.
3. **#31 recovery does not converge.** Detector arms, freeze engages, detector
   fires, recovery STARTS, transfer terminates without completing. A 240s bound
   went unused: the receiver exited on its own at 149.48s. Exit reason
   deliberately UNATTRIBUTED, because the log line that would name it is not
   emitted. Adding an establish/adopt marker is the next step, and it is a code
   change, not another run.
4. **#51 the 6.0s fallback figure is narrower than published.** `expired_direct`
   at `main.rs:7535` only falls back when the link is ABSENT at expiry
   (`!self.links.contains_key(pid)`). If the link returns first the pending is
   silently discarded and no `DIRECT-FALLBACK` is emitted. So 6.032 / 6.006 /
   6.015s is *the designed fallback WHEN the other recovery route loses the
   race*, not the only route. CI took one route, Linux takes the other.
5. **#43 PATHSET** (build alongside, promote on proof). Unblocked by #83:
   `proofs/transport_upgrade_model.py` scores it 8/8 with `ctrl_carries=True`
   versus main's 7/8. Not urgent; the remaining break is real, not a formality.
6. **#20 fleet-cert enrollment** stays deliberately UNWIRED. The escalation chain
   is documented and guarded (#100), and no live path can produce the artefact it
   needs. Do not implement it to unblock something.
7. **#48 follow-up**: `deploy/assert-oom-shield.sh` exists and is not wired to a
   cron or healthcheck. It must be RUN to be useful.

## 6. RULED OUT — do not re-investigate

- **`SO_RCVBUF` / `kern.ipc.maxsockbuf`.** Probed on the actual runner: macOS
  grants 6 MiB and **clamps rather than erroring**, so `bind_endpoint`'s fallback
  chain never fails. macOS is *more* permissive than Linux (416 KiB).
- **A missed `peer-joined` as the macOS cause.** The sender authenticated and was
  sending; nothing inbound arrived in the 40ms window before the close.
- **A drop/re-adopt loop.** Four drops across a six-test job is not once per sync
  interval.
- **"macOS runners are slow."** Ten minutes is not a timing race; five sibling
  tests finished inside the same 647s.
- **`FILAMENT_DIRECT_PER_OS` being dead.** It is live via the harness.

## 6b. RETRACTED — stated confidently, then withdrawn

Recorded because the reasoning that produced these is available to whoever reads
this next, and most were believed by two agents at the time.

| claim | what was actually true |
|---|---|
| "23 OOM kills today" | **3.** `grep -c` counted log LINES; one event emits many. Count `"Killed process"`. |
| "sccache was OOM-killed" | It was the *rustc child*. sccache reports `Compile terminated by signal 9` and survives. |
| "the harness 600s timeout was an OOM" | Window predated the kills by ten minutes. External prerequisites was the better reading. |
| "first-contact direct is structurally ineligible" | Option A already promotes to direct using the PAKE secret. |
| "the sender never got a peer" | It paired, authenticated and was sending; the link then died. The bail message cannot distinguish the two. |
| "macOS CI tests a config no user runs" | `FILAMENT_DIRECT=0` is a documented opt-out. Inverted the severity. |
| "`FILAMENT_DIRECT_PER_OS` is a dead knob" | Live via `capability_harness`; a grep of `cli/src` alone missed `cli/tests`. |
| "`establish()` was the dominant teardown caller" | `#[track_caller]` had detached onto `has_live_transport`; the instrument was reporting itself. |

The shape they share: **an absence read as a null.** A missing detector read as
no hangs, a missing instrument read as no stalls, an unfetched ref read as an
excluded commit, a grep of the wrong directory read as a dead knob, an
unscheduled check read as a pending one. The rule that covers all of them:
*an empty result is only as strong as your evidence that the thing which
produces results actually ran.*

## 7. Agents (xats bus, `cross-agent-teams` MCP, team `default`)

| name | role | state |
|---|---|---|
| `claude-advisor` | security reviewer, gates | Found most of the sharp defects. Gate its rulings; it has overruled the coordinator correctly many times. |
| `new-renewer` | worker, holds the build token | Owns PR #73/#74/#75 and the macOS controls. |
| `rig-verifier` | worker | Runs measurements. Excellent provenance discipline. |
| `optimizer` | worker | Design notes, capability/grant work. |
| `opencode-101` | worker | Finished #23 (PR #72). |
| `filament-new-guy` | worker | Finished #21. Currently idle. |

## 8. Machine + process rules (earned the hard way)

- **do-vm is 4 cores / 8 GB.** Six agent runtimes plus concurrent Rust builds
  caused 3 OOM kills, one of which took an agent runtime. **One build at a time**
  via a coordinator-held token, `-j2`, isolated `CARGO_TARGET_DIR`.
- Production is OOM-shielded at `oom_score_adj: -800` **in compose** (was a live
  `/proc` write that would silently lapse on `docker compose up -d`). Apply by
  walking `cgroup.procs`, never `docker inspect .State.Pid` — that returns the
  supervisor only and leaves gunicorn's single worker exposed.
- Never `pkill -f filament`; never touch a running `filament up`. Production
  containers: `deploy-api-1`, `deploy-redis-1`, `deploy-coturn-1`,
  `deploy-cloudflared-1`, `formly-cfd`. **Any port you did not start yourself on
  127.0.0.1 belongs to someone else.**
- House style: no em dashes, no AI attribution anywhere (commits, PRs, code).
- **The shared `CARGO_TARGET_DIR` voided a 30-trial run** by swapping the binary
  mid-measurement. Any run whose output is a number: own target dir, record the
  binary sha256, assert it matches the checked-out sha.
- The harness `binary()` ignores `CARGO_TARGET_DIR` and reads
  `<manifest>/target/...`; correct results depend on symlinking that into the
  isolated dir first.

## 9. Method rules that actually caught things

- **A green check after a fix cannot distinguish prevention from recovery.**
  Pre-register what a green result would and would not prove, before it exists.
  This caught #71 being recovery rather than a fix.
- **Verify a fix with a different query shape than the one that produced the
  claim.** Walking `cgroup.procs` caught a shield that `.State.Pid` reported
  complete.
- **Reach for the control before the alarm.** "Was this already failing on the
  base branch?" flipped "CI refutes our fix" into "a pre-existing defect".
- **Before explaining an observation, confirm the code that produced it was in
  the measured commit.** Three wrong root causes came from a log whose build
  predated the fix being discussed.
- **A missing measuring instrument silently rewrites every other number.** A
  branch advertised as "base + stall-detector + winner-rule" lacked the stall
  detector — the component producing the hang count being quoted.
- **Model protocol questions in Python first.** `experiments/py/hairpin_probe.py`
  and a signaling probe each answered in seconds what a build-plus-CI loop
  answers in twenty minutes.
- **"This change cannot affect anything" is a claim about the diff, and a diff
  cannot tell you what a file is FOR.** I twice told the user to merge the
  proof PR immediately because it was proofs-only. True of its contents, false
  of its role: a merged proof is a standing assertion, the same file unmerged
  is a document. Same bytes, different role, and **only the role can rot**. Its
  calibration was about to describe a world the next PR removed. Expect the
  next agent to read a proofs-only diff and reach the same wrong conclusion.
- **Test that the prescribed REMEDY clears the failure, not just that the
  detector fires.** Almost everyone tests a detector against the bug and stops.
  Checking the fix actually worked is what exposed that my expiry check's only
  possible remedy was deleting itself, and then that its replacement remedy was
  a one-line fake.
- **A comment is a claim with no enforcement.** Two defects this week were
  mechanisms that *said* they did something: the offer site promising "the
  Signal handler re-emits ChannelReady" (it never has, a teardown was standing
  in for the dispatch, and that was the whole macOS wedge), and `l3.rs`'s
  "monotonic announce sequence so a peer can ignore a stale re-announce" (the
  seq is signed and no receiver ever compares it). **A signature over a field
  creates a strong presumption that someone verifies it** — grep for the
  consumer before believing it.
- **"In the repo" and "running on the host" are different facts, and only one
  is visible in a diff.** `deploy/monitor/filament-monitor.timer` and `.service`
  were committed on 2026-06-27, but on 2026-08-04 the droplet had no unit under
  `/etc/systemd/system`, no timer in `systemctl list-timers`, and no cron entry;
  its state file was last written by a hand-run on 2026-07-31, even though the
  monitor had correctly recorded a real DOWN and recovery. Likewise,
  `oom_score_adj: -800` in `deploy/docker-compose.yml` left all four running
  containers at 0 because compose applies it at container creation. **Ship an
  installer plus a verify mode that inspects the live system**: `install-timers.sh
  verify` must require a scheduled next elapse, not merely enabled and active.
  It caught a timer that was enabled and active but had no next elapse, which
  `is-enabled` and `is-active` both reported as fine.
- **Every failed check catalogued this week was a false negative: a check that
  silently passes when it should fail.** The absence read as a null, the signed
  announce sequence had no verifier, the contract lived only in a comment, and
  roster reconciliation could not fire. A false positive of the right shape is
  more dangerous: `fuser -m <target-dir>` checked the mounted filesystem
  containing the path, reported every process including init, and made a
  catastrophic in-use finding out of an instrument error. The safe-looking
  response would have left a 98% disk untouched. **Ask about the thing, not a
  proxy for it**: a cargo target is held only by a build, so
  `pgrep -x cargo; pgrep -x rustc; pgrep -x mold` was the decisive check.
- **An invariant maintained by convention at N call sites will be missed at
  call site N+1**, and no test that gives each daemon its own config dir can
  ever catch a same-install filter. Put it in the type or in the signature.
- **A claim about CALL SITES expires the moment someone adds one. A claim about
  PRODUCERS OF THE ARTEFACT survives.** Asked whether a dangerous function was
  unused; the better answer checked every producer of the thing the attack needs
  (every `certify` call site), and found all live ones certify this machine's own
  key. Prefer the second shape.
- **A finding is not recorded until a person who does not already know it can
  find it from where they will be standing.** Four fragmentations in one day: the
  handoff doc on a feature branch and not main, a design spec surviving only in a
  stash, a blocking ceiling ruling existing as fragments across two docs and a
  comment, and a capability-ceiling change living in one unpushed worktree while
  the reviewer who ruled on it could not see it.
- **Testing the fixed path is not testing the deployed state.** `--shell-user`
  was verified effective using scratch files, which are 0600 *because the fixed
  writer had just created them*. The real `caps.json` was 0644 and would have
  stayed so indefinitely, because it is only rewritten when grants change.
- **A test needs the assertion that separates the right failure from a
  convenient one.** The best test written that day had three: nonzero exit, the
  specific message, and *the daemon never reached socket.io connect*. It points
  at an unusable port, so it would fail anyway; only the third proves the gate
  fired rather than the connection.
- **Report scope, not counts.** "365 tests plus all integration suites" was true
  and excluded the harness, which cannot compile without `--features test-hooks`.
  Say the feature flags and the platform; the count is the least informative part.
- **An unreferenced test cannot report its own death.** Nothing went red when a
  NAT lab was deleted, because no workflow ran the test that needed it.
- The recurring error shape, in one line: **a query narrower than the claim it
  supports, where the narrowing is invisible in the result.**

## 10. The 2026-08-03 pattern, in one place

Nine mechanisms that CLAIMED something nothing ENFORCED, found in one day, none
visible from a diff or a green board:

| where | claim | reality |
|---|---|---|
| offer site | "the Signal handler re-emits ChannelReady" | it never did; a teardown stood in for the dispatch. This was the macOS wedge. |
| `on_synced` | roster reconciliation repairs missed peers | `channel_peers` never reached `maybe_adopt` |
| `l3.rs` | "monotonic seq so a peer can ignore a stale re-announce" | signed on every announce, compared by nobody |
| `pair_ui` | no-constructor property "asserted in filament-pair" | no such assertion existed |
| `admit_delegated` | "the devices_json writer must exclude it" | no exclusion; a schema limitation was doing a guard's job |
| `transport-gates.sh` | a fallback gate driving a live hook | referenced by no workflow, never ran |
| `data_freeze_test.sh` | the stall-measurement instrument | unreferenced and stale |
| `holepunch-gates.sh` | the only NAT coverage | its lab was never committed and is gone |
| cap surfaces | `shell` listed as one bounded permission | owner-equivalent; the ceiling is decorative for it |

The through-line: **a bound that is described rather than enforced survives
indefinitely, because nothing it protects ever fails.** Each was found by reading
a specific claim and asking what enforces it. None would have been found by
another CI run.
