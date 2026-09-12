#!/usr/bin/env python3
"""Filament transport-UPGRADE model checker.

The third proof. `establishment_model.py` proves signaling reaches CONNECTED.
`transport_lifecycle_model.py` proves a CONNECTED pair can carry a file and tear
down cleanly. Both are green, and both were green through every defect below,
because each models a SINGLE transport slot. The upgrade -- two paths, one of
them destroyed in order to try the other -- is not representable in either, so
neither can see this layer at all. A clean run from an instrument that cannot
represent the fault is not evidence, and this file exists because we spent three
days reading one as if it were.

WHAT THIS MODELS

After the PAKE ceremony a pair holds an authenticated WebRTC link. The code then
tries to upgrade to direct QUIC ("Option A"): it DROPS the WebRTC link and races
a direct dial, intending to rebuild WebRTC if the race is lost.

    main.rs, both Option A call sites:
        conn.drop_link(&from);
        conn.start_direct(&from, &from, &sec).await;

Destroying a working transport in order to try a faster one has no precedent in
any comparable system (Happy Eyeballs, MPTCP, QUIC connection migration, and
Tailscale's DERP->direct upgrade all build the candidate ALONGSIDE and switch
only once it is proven). The gap it opens is acknowledged in the code comment
itself as a "bounded ~5s gap for NAT-blocked peers".

Six separate fixes over three days were each a way of making that gap smaller:

    PR #71   reorder establish() so its fallible work precedes the drop
    #71      carry expected_secret across the rebuild
    #78/#79  DirectIntent::Promote, so the drop happens after direct_pending
             is registered rather than before
    open     direct_pending.remove ahead of a bind_endpoint failure that
             returns 100 lines before the pending is re-registered
    #71      sync-digest roster reconciliation, which turned out to be
             REPAIRING the gap rather than serving its stated purpose
    open     the macOS regression in #78/#79

They are one defect. This model makes the defect a state predicate instead of
six patches, and checks the alternative design for the same predicate.

THE THREE DESIGNS

    EAGER    drop the WebRTC link, THEN attempt direct.          (main today)
    LATE     attempt direct, drop only after direct_pending is
             registered; a disabled or unbindable direct drops
             nothing at all.                                     (#78 / #79)
    PATHSET  never drop anything. Build the candidate alongside,
             promote by selecting it once it is LIVE, retire the
             old path only after the new one carries traffic.    (proposed)

THE FREE PARAMETER, AND WHY IT IS FREE

`ctrl_carries` is defined OBSERVATIONALLY, and the wording matters:

    can a transfer COMPLETE over the post-PAKE link without that link first
    being destroyed and rebuilt?

Not "does the link have a transport". The distinction is deliberate, because two
readings fit the evidence and they are not distinguished here:

    A  the retained link genuinely cannot carry data
    B  the link is fine, and the SENDER never progresses, because it waits on a
       state transition that only a rebuild emits

Both produce a transfer that never completes, which is what this model needs.
They imply very different fixes, so the model must not be read as asserting A.
The discriminator (claude-advisor's): did the sender ever ATTEMPT to send file
data on the retained link? Attempted-and-stalled is A; never-attempted is B.

CONFIRMED FALSE, by artifact, not by fit. Gate 0 derives ctrl_carries=False from
four CI outcomes, which is four points against one free bit and would be a fit as
much as a derivation. It is independently confirmed from the green `main` macOS
artifact of run 30825113095 (job 91724637129): sender peer xKm57McGHTIu6h-mAAAD
drops at the Option A site (main.rs:10871) after auth, ICE closes, a second
gather opens a new host port 57792, and the sha256 delivery success appears only
AFTER that rebuild. The green path rides a rebuilt link.

    Link { peer: Option<Arc<Peer>>, transport: Option<Arc<dyn Transport>>, .. }

`peer` is the WebRTC connection the PAKE rode; `transport` is the data plane and
is independently `None` until a data channel opens (main.rs:6614 builds a link
with `transport: None`). Which of A or B that reflects is still open.

VALIDATION GATE

Before this model is permitted to make any claim, it must reproduce all four
outcomes observed in CI on 2026-08-03. An instrument that cannot reproduce the
results we already have is not trusted with the ones we do not. If the gate
fails, the run exits non-zero and prints the mismatch: the model is wrong, not
the observation.

Faithfulness -- state <-> code:
  w = CTRL      main.rs Link with peer: Some, transport: None (post-PAKE)
  w = LIVE      Link.transport: Some(DataChannelTransport)  (net.rs:536)
  w = NONE      no links entry; drop_link removed it
  d = PENDING   main.rs direct_pending entry, expiry armed (expired_direct)
  d = LIVE      Link.transport: Some(DirectTransport)  (direct.rs:989)
  direct_ok     main.rs start_direct_inner rel 13, `if !self.direct_ok`
                (FILAMENT_DIRECT; CI forces 0 on macOS)
  bind_ok       direct::bind_endpoint, rel 70; failure returns at rel 86,
                which is 97 lines BEFORE the pending insert at rel 183
  roster        session.rs on_synced -> reconcile; rebuilds a missing link
"""
from collections import deque, namedtuple
from itertools import product
import glob
import os
import re
import sys

# design x the four environment/config axes
Cfg = namedtuple('Cfg', 'design direct_ok bind_ok roster ctrl_carries')

EAGER, LATE, PATHSET = 'EAGER', 'LATE', 'PATHSET'

# ---- WebRTC path ------------------------------------------------------------
# NONE  no link entry (never built, or drop_link removed it)
# CTRL  authenticated link exists, data-plane transport NOT attached
# LIVE  link exists AND carries a data transport
W_NONE, W_CTRL, W_LIVE = 'NONE', 'CTRL', 'LIVE'

# ---- direct-QUIC path -------------------------------------------------------
# NONE     not attempted (or attempt abandoned before registering)
# PENDING  direct_pending registered; an expiry IS armed, so a loss is observed
# LIVE     authenticated QUIC transport up
# FAILED   the race was lost and expired_direct fired
# BURNT    the one recovery attempt that D_FAILED buys has itself failed. NOT a
#          synonym for NONE: nothing further is scheduled. main.rs:7608
#              if let Err(e) = self.establish(info).await {
#                  ui::debug("  WebRTC fallback for {pid} failed: {e}");
#          establish() does a fetch_config network round trip; on failure this is
#          logged and the loop moves on. expired_direct has already REAPED the
#          pending, so the trigger is consumed and no successor exists. Making
#          the discard loud (which we did, and which was right) improved
#          VISIBILITY, not RECOVERABILITY.
D_NONE, D_PENDING, D_LIVE, D_FAILED, D_BURNT = \
    'NONE', 'PENDING', 'LIVE', 'FAILED', 'BURNT'

# ---- the transfer -----------------------------------------------------------
X_IDLE, X_RUNNING, X_DONE = 'IDLE', 'RUNNING', 'DONE'

State = namedtuple('State', 'w d x upgraded')


def initial():
    """Post-PAKE: an authenticated WebRTC link, no data plane yet, no direct."""
    return State(W_CTRL, D_NONE, X_IDLE, False)


def is_good_terminal(s):
    return s.x == X_DONE


def has_live_path(s):
    return s.w == W_LIVE or s.d == D_LIVE


def successors(s, cfg):
    out = []

    def add(label, **kw):
        out.append((label, s._replace(**kw)))

    # ================================================ WebRTC path maturation
    # A CTRL link attaches its data transport when the data channel opens.
    # Whether that happens on the POST-PAKE link is exactly `ctrl_carries`.
    if s.w == W_CTRL and cfg.ctrl_carries:
        add('dc_open', w=W_LIVE)

    # A freshly established link is built by establish(), which runs the full
    # offer/answer and opens a data channel, so a rebuild always yields LIVE.
    # This is the ONLY route to LIVE when ctrl_carries is false, and it is why
    # destroying the link can look like a repair.
    if s.w == W_NONE:
        # establish() is driven either by expired_direct (the designed fallback)
        # or by roster reconciliation (the accidental one).
        if s.d == D_FAILED:
            add('establish_after_direct_lost', w=W_LIVE, d=D_NONE)
            # ...and that attempt is FALLIBLE and UNRETRIED (main.rs:7608).
            # D_FAILED buys exactly one attempt, not a successor.
            add('establish_fails_abandoned', d=D_BURNT)

        # Roster re-adoption is gated on `!links.contains_key(&peer_id)`, so it
        # fires ONLY when the link is absent. That is why it never ran on
        # #78/#79: nothing dropped, so the precondition was never met. The
        # guard is why this transition sits under `w == W_NONE`.
        if cfg.roster:
            add('roster_reconcile', w=W_LIVE, d=D_NONE)

    # ============================================================= the upgrade
    # Fires once, from the post-PAKE state, before any transfer starts.
    if not s.upgraded and s.x == X_IDLE:

        if cfg.design == EAGER:
            # drop_link FIRST, unconditionally, then attempt direct.
            if not cfg.direct_ok:
                # start_direct_inner returns at rel 13. The link is already gone.
                add('eager_drop_then_direct_disabled', w=W_NONE, upgraded=True)
            elif not cfg.bind_ok:
                # bind_endpoint fails at rel 70 and returns at rel 86, before the
                # pending insert at rel 183. Link gone, no pending, no expiry.
                add('eager_drop_then_bind_fails', w=W_NONE, upgraded=True)
            else:
                add('eager_drop_then_pending', w=W_NONE, d=D_PENDING, upgraded=True)

        elif cfg.design == LATE:
            # DirectIntent::Promote. The drop moved to rel 199, AFTER the pending
            # insert at rel 183, so an early return drops nothing.
            if not cfg.direct_ok:
                add('late_direct_disabled_noop', upgraded=True)          # w untouched
            elif not cfg.bind_ok:
                add('late_bind_fails_noop', upgraded=True)               # w untouched
            else:
                # pending registered, THEN the link dropped.
                add('late_pending_then_drop', w=W_NONE, d=D_PENDING, upgraded=True)

        elif cfg.design == PATHSET:
            # Build alongside. Nothing is ever dropped here.
            if cfg.direct_ok and cfg.bind_ok:
                add('pathset_probe', d=D_PENDING, upgraded=True)
            else:
                add('pathset_no_candidate', upgraded=True)               # w untouched

    # ==================================================== direct race resolves
    if s.d == D_PENDING:
        add('direct_wins', d=D_LIVE)
        add('direct_lost', d=D_FAILED)

    # REMOVED (#85, merged as e0864ec): a pending used to be DESTROYED without
    # ever expiring. The link_dead branch removed it at rel 41 and bind_endpoint
    # returned at rel 86, ~100 lines before the re-insert, so nothing would ever
    # be reaped and nothing was scheduled. #85 makes the supersede decision
    # WITHOUT mutating (the insert replaces the entry at the first point a
    # replacement is certain), so that transition is now unreachable in the code
    # and has been deleted here rather than left describing a fixed defect.
    #
    # NO LONGER UNWATCHED: this deletion is registered in DELETED_TRANSITIONS
    # with the code fact that justifies it, and gate 0 asserts that fact against
    # the tree. Reintroduce the removal and the model says so, instead of
    # quietly describing a defect the code has re-grown.

    # PATHSET retires the old path only once the new one is LIVE, and only after
    # it is actually carrying the transfer. Modeled as legal but never required.
    if cfg.design == PATHSET and s.d == D_LIVE and s.w != W_NONE and s.x == X_DONE:
        add('retire_old_path', w=W_NONE)

    # A lost race under PATHSET is a no-op: the selector never pointed at it.
    if cfg.design == PATHSET and s.d == D_FAILED:
        add('discard_failed_candidate', d=D_NONE)

    # ============================================================== the transfer
    if s.x == X_IDLE and has_live_path(s):
        add('transfer_start', x=X_RUNNING)
    if s.x == X_RUNNING and has_live_path(s):
        add('transfer_done', x=X_DONE)

    return out


# ============================================================ safety invariant
def invariant_violations(s, cfg):
    """I-GAP is the whole point: a state with no live path AND no armed successor.

    "Armed successor" is deliberately narrow. A direct attempt counts ONLY when
    it is PENDING, because that is what expired_direct reaps to schedule the
    rebuild; an attempt abandoned before registering arms nothing. Roster
    reconciliation counts only when enabled. A CTRL link counts only when it can
    mature on its own."""
    v = []
    if has_live_path(s) or s.x == X_DONE:
        return v
    armed = (not s.upgraded                     # the upgrade itself is still to run
             or s.d == D_PENDING
             or s.d == D_FAILED                 # expired_direct will establish()
             or (s.w == W_CTRL and cfg.ctrl_carries)
             or (s.w == W_NONE and cfg.roster))
    if not armed:
        v.append(f'I-GAP: no live path (w={s.w} d={s.d}) and no armed successor')
    return v


# ================================================================ exhaustive BFS
def explore(cfg):
    init = initial()
    seen = {init: 0}
    edges = {}
    q = deque([init])
    while q:
        s = q.popleft()
        succ = successors(s, cfg)
        edges[s] = succ
        for _, ns in succ:
            if ns not in seen:
                seen[ns] = seen[s] + 1
                q.append(ns)
    return seen, edges


def can_reach(edges, targets):
    rev = {}
    for s, succ in edges.items():
        for _, ns in succ:
            rev.setdefault(ns, []).append(s)
    reach = set(targets)
    q = deque(targets)
    while q:
        s = q.popleft()
        for p in rev.get(s, ()):
            if p not in reach:
                reach.add(p)
                q.append(p)
    return reach


def trace_to(edges, start, pred, limit=40):
    q = deque([(start, [])])
    seen = {start}
    while q:
        s, path = q.popleft()
        if pred(s):
            return path + [('(here)', s)]
        if len(path) > limit:
            continue
        for label, ns in edges.get(s, ()):
            if ns not in seen:
                seen.add(ns)
                q.append((ns, path + [(label, ns)]))
    return None


def check(cfg):
    seen, edges = explore(cfg)
    states = list(seen)
    good = {s for s in states if is_good_terminal(s)}
    inv = [(s, m) for s in states for m in invariant_violations(s, cfg)]
    deadlocks = [s for s in states if not is_good_terminal(s) and not edges[s]]
    can_good = can_reach(edges, good)
    stuck = [s for s in states if s not in can_good]
    return {
        'cfg': cfg, 'states': len(states), 'invariant_violations': inv,
        'deadlocks': deadlocks, 'stuck': stuck, 'good_terminals': len(good),
        'edges': edges, 'init': initial(),
        'max_depth': max(seen.values()),
    }


def is_clean(r):
    return (not r['invariant_violations'] and not r['deadlocks']
            and not r['stuck'] and r['good_terminals'] > 0)


def env_label(cfg):
    return (f"direct={'on ' if cfg.direct_ok else 'off'} "
            f"bind={'ok ' if cfg.bind_ok else 'FAIL'} "
            f"roster={'on ' if cfg.roster else 'off'} "
            f"ctrl_carries={'yes' if cfg.ctrl_carries else 'no '}")


def banner(r, indent='  '):
    cfg = r['cfg']
    clean = is_clean(r)
    print(f"{indent}{cfg.design:8s} {env_label(cfg)} | states={r['states']:>3d} "
          f"-> {'CLEAN' if clean else 'BROKEN'}")
    if not clean:
        if r['invariant_violations']:
            print(f"{indent}      {r['invariant_violations'][0][1]}")
        elif r['stuck']:
            s = r['stuck'][0]
            print(f"{indent}      stuck, cannot reach a completed transfer: "
                  f"w={s.w} d={s.d} x={s.x}")
    return clean


def print_trace(r, title):
    bad = ([s for s, _ in r['invariant_violations']] or r['stuck'])
    if not bad:
        return
    target = bad[0]
    tr = trace_to(r['edges'], r['init'], lambda s: s == target)
    if not tr:
        return
    print(f"\n  counterexample trace -- {title}:")
    for label, s in tr:
        print(f"      {label:34s} -> w={s.w:5s} d={s.d:8s} x={s.x}")


# ======================================================================= main
if __name__ == '__main__':
    print("=" * 78)
    print("TRANSPORT-UPGRADE PROOF  (two paths; destroy-then-race vs build-alongside)")
    print("=" * 78)

    ok = True

    # -------------------------------------------------------------- gate 0
    # The model must reproduce what CI actually did on 2026-08-03 before it is
    # allowed to say anything about a design we have not run. Each row is a real
    # job result, not a prediction.
    #
    # macOS CI sets FILAMENT_DIRECT_PER_OS=0 -> direct_ok False.
    # ubuntu/windows run direct enabled and it succeeds -> direct_ok, bind_ok.
    # main carries #71's roster reconciliation; #79 deliberately does not.
    #
    # ctrl_carries is pinned False across the gate. That is the ONLY value under
    # which all four rows reproduce, which is how the model determines it rather
    # than assuming it. If new-renewer's log read comes back showing a green main
    # macOS transfer riding the ORIGINAL post-PAKE link, this gate is what will
    # fail, and the model is wrong.
    # Each row records the TREE STATE it was observed on. That is what stops
    # the expiry remedy from being fakeable: bumping CALIBRATED_FOR without
    # actually re-deriving leaves these tags behind, and the check below
    # catches it. Step 4 alone must not clear an expiry.
    # Each row records the TREE STATE it was observed on AND the CI run that
    # produced it. The tree-state tag stops a bumped CALIBRATED_FOR from being a
    # one-line fake remedy. The run reference stops the tags themselves from
    # being relabelled: editing a word is free, but pointing at a run anyone can
    # open and see contradicts the label is a categorically different act, and
    # it is checkable from OUTSIDE this repository by a reviewer with no context.
    #
    # This is the last rung of that kind. Below it you are asking whether the CI
    # provider is lying, which is a different threat model and not ours.
    #
    # A row with run=None is NOT anchored. That is reported rather than hidden,
    # because an unanchored row is weaker evidence than an anchored one and the
    # reader is entitled to know which is which. Do not invent a run id to make
    # the count look better; an unanchored row is honest, a fabricated one is not.
    OBSERVED = [
        # (label,           design, direct_ok, bind_ok, roster, expect, era, run, job)
        #
        # --- pre-rearm: before the ChannelReady contract was honoured (#83) ---
        ('main    macOS  GREEN', EAGER, False, True,  True,  True,  'pre-rearm', 30825113095, 91724637129),
        ('#78     macOS  RED  ', LATE,  False, True,  True,  False, 'pre-rearm', 30824271188, 91721922115),
        ('#79     macOS  RED  ', LATE,  False, True,  False, False, 'pre-rearm', None,        91719654747),
        ('#78/#79 ubuntu GREEN', LATE,  True,  True,  True,  True,  'pre-rearm', None,        None),
        #
        # --- post-rearm: main's OWN CI after #83 merged (47f756c) -------------
        # Not #83's branch runs. Gate 0 reproduces what was OBSERVED, and branch
        # runs sit on a base main no longer has, which would reintroduce
        # staleness inside the artefact built to detect it.
        #
        # The macOS row is the discriminator: LATE with direct DISABLED is
        # BROKEN under ctrl_carries=False and CLEAN under True, so main going
        # green there is only reproducible if the retained post-PAKE link can
        # now carry a transfer. ubuntu/windows are clean under both and are
        # recorded for completeness, not for discrimination.
        ('main    macOS  GREEN', LATE,  False, True,  True,  True,  'post-rearm', 30831946455, 91747790666),
        ('main    ubuntu GREEN', LATE,  True,  True,  True,  True,  'post-rearm', 30831946455, 91747790537),
        ('main    windows GREEN', LATE, True,  True,  True,  True,  'post-rearm', 30831946455, 91747790573),
    ]

    # Each era has its own value for the derived parameter. This is what turns
    # the prediction recorded in #83's PR body ("this flips ctrl_carries to
    # True") into an assertion the proof CHECKS, rather than a claim that was
    # right once and then deleted. Both eras must reproduce, each under its own
    # value, or the flip did not happen the way we said it would.
    ERA_CTRL = {'pre-rearm': False, 'post-rearm': True}
    print("\n[Gate 0: reproduce every outcome observed in CI, across BOTH eras]")
    print("ctrl_carries: can a transfer COMPLETE over the post-PAKE link without")
    print("that link first being destroyed and rebuilt?")
    print("  pre-rearm  False. Derived from 4 outcomes against 1 free bit, then")
    print("             CONFIRMED by artifact: green main run 30825113095 job")
    print("             91724637129 shows the drop at main.rs:10871, ICE closing,")
    print("             a second gather on a new host port, and sha256 delivery")
    print("             success only AFTER the rebuild.")
    print("  post-rearm True. #83 dispatched the ChannelReady the offer site's")
    print("             comment always claimed the Signal handler sent. main's")
    print("             own run 30831946455 then went green on macOS with direct")
    print("             DISABLED, which is BROKEN under False and CLEAN under")
    print("             True, so that row alone forces the flip.")
    print("  The flip was PREDICTED in #83's PR body before its checks ran, and")
    print("  is kept here as a checked assertion rather than a claim that was")
    print("  right once and then deleted. Both eras must reproduce.")
    print("  Cause, resolved: the retained link was always fine; the SENDER was")
    print("  never told. #78 artifact job 91721922115 shows no offer, stream,")
    print("  chunk, byte counter or send error with the debug channel live")
    print("  throughout, and the fix delivers a verified file 19ms after auth on")
    print("  a retained link. Kept observational regardless: the model only needs")
    print("  that no transfer COMPLETES without a rebuild.")
    gate_ok = True
    for label, design, dok, bok, ros, expect, era, _run, _job in OBSERVED:
        cfg = Cfg(design, dok, bok, ros, ERA_CTRL[era])
        r = check(cfg)
        got = is_clean(r)
        mark = 'ok ' if got == expect else 'MISMATCH'
        print(f"  {label}  [{era:10s} ctrl={str(ERA_CTRL[era]):5s}] "
              f"model={'CLEAN' if got else 'BROKEN'}  "
              f"observed={'GREEN' if expect else 'RED'}   {mark}")
        if got != expect:
            gate_ok = False
    if not gate_ok:
        print("\n  GATE 0 FAILED: the model does not reproduce observed CI.")
        print("  The model is wrong. Do not read anything below it.")
        sys.exit(1)

    # ---------------------------------------------------- gate 0 EXPIRY
    # Gate 0 is a STATIC table of outcomes observed on a specific tree. That is
    # what makes it a calibration and not a test, and it is also how it rots: it
    # would keep passing forever while asserting ctrl_carries=False, long after
    # the tree stopped behaving that way, and a green proof is more persuasive
    # than a green test. Nothing about the table itself would ever signal drift.
    #
    # So the calibration carries an expiry condition, and the condition is read
    # from the tree rather than remembered by a human.
    #
    # `rearm_channel_ready` is the fix that makes a transfer complete over the
    # RETAINED post-PAKE link (it dispatches the ChannelReady the offer site's
    # comment always claimed the Signal handler sent). Its presence means
    # ctrl_carries=False is no longer a true description of this tree, so every
    # number below it is answering a question about a world that no longer
    # exists, and gate 0 must be re-derived against post-fix CI.
    #
    # Failing LOUD here is the point. The alternative is a proof that stays
    # green while describing something that stopped being true, which is the
    # defect class this whole file exists to catch.
    here = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(here, os.pardir, "cli", "src")
    # Anchor is anywhere in cli/src since the 2026-09-12 main.rs
    # decomposition (fn rearm_channel_ready now lives in conn.rs).
    files = sorted(glob.glob(os.path.join(src_dir, "**", "*.rs"), recursive=True))
    try:
        if not files:
            raise OSError(f"no .rs files under {src_dir}")
        tree = "".join(
            open(p, encoding="utf-8", errors="replace").read() for p in files
        )
    except OSError as e:
        # An expiry check that cannot read the tree has not passed, it has
        # failed to run. Never let that read as a pass.
        print(f"\n  GATE 0 EXPIRY UNVERIFIABLE: cannot read {src_dir} ({e}).")
        print("  The calibration cannot be confirmed current. Refusing to report.")
        sys.exit(1)

    # The calibration names the tree state it was derived against. The check
    # compares, rather than testing for a symptom.
    #
    # This distinction is the difference between a detector that survives and
    # one that gets deleted. An earlier version fired on the mere PRESENCE of
    # `rearm_channel_ready`, which is in the tree permanently once it lands, so
    # it would have fired forever and re-deriving would not have cleared it.
    # The only way to get main green again would have been to DELETE the check,
    # under time pressure, by someone who just wanted a green board. A detector
    # whose sole available remedy is its own removal is not a detector.
    #
    # Here the remedy is the correct action: re-derive, bump this constant, the
    # check goes quiet and SURVIVES to catch the next drift.
    CALIBRATED_FOR = "post-rearm"
    tree_state = "post-rearm" if "fn rearm_channel_ready" in tree else "pre-rearm"

    unknown = [r[0] for r in OBSERVED if r[6] not in ERA_CTRL]
    if unknown:
        print(f"\n  GATE 0 INCOHERENT: rows tagged with an era that has no")
        print("  ctrl_carries value:")
        for lbl in unknown:
            print(f"      {lbl.strip()}")
        sys.exit(1)
    # The calibration must be ANCHORED in the tree it claims to describe. Rows
    # from older eras are kept deliberately (they are the evidence that the
    # parameter flipped), but at least one row must come from the current one,
    # or bumping the constant would again be a free way to silence an expiry.
    if not any(r[6] == CALIBRATED_FOR for r in OBSERVED):
        print(f"\n  GATE 0 INCOHERENT: CALIBRATED_FOR is {CALIBRATED_FOR!r} but no")
        print("  observed row comes from that tree state. Bumping the constant")
        print("  is not a re-derivation; add the observations.")
        sys.exit(1)

    if tree_state != CALIBRATED_FOR:
        print("\n  GATE 0 EXPIRED.")
        print(f"  calibrated for a {CALIBRATED_FOR} tree; this tree is {tree_state}.")
        print("  `rearm_channel_ready` makes a transfer complete over the RETAINED")
        print("  post-PAKE link, so ctrl_carries=False no longer describes this")
        print("  tree and the outcomes above predate the change.")
        print()
        print("  Re-derive gate 0 before trusting anything below it:")
        print("    1. take main's OWN post-merge CI outcomes for the three")
        print("       platforms, not a feature branch's runs against an older")
        print("       base. Gate 0's whole point is reproducing what was")
        print("       OBSERVED, so branch runs on a base main no longer has")
        print("       would reintroduce staleness inside the staleness detector")
        print("    2. set the OBSERVED table to those, with their run ids")
        print("    3. expect ctrl_carries=True to be the value that reproduces")
        print("       them, which flips LATE from 1/8 to 7/8 and unblocks")
        print("       PATHSET from 0/8 to 8/8 (T2/T4 predicted exactly this)")
        print(f'    4. set CALIBRATED_FOR = "{tree_state}" in this file')
        print("  Do NOT delete this check to clear it. Step 4 is the remedy.")
        sys.exit(1)

    # ---------------------------------------------- deleted-transition guard
    # The expiry above tracks ONE derived parameter. The model's TRANSITIONS are
    # a second staleness axis, and this file previously said so and left it
    # unwatched. claude-advisor's point: a transition deleted because the CODE
    # made it unreachable rests on a fact about the code, and that fact is as
    # readable from the tree as `fn rearm_channel_ready` was.
    #
    # So each such deletion records the fact that justified it, and the fact is
    # asserted. If someone reintroduces the shape, the model says a transition
    # it deleted is reachable again, instead of quietly describing a defect the
    # code has re-grown.
    #
    # Bounded on purpose: only transitions deleted for CODE reasons, which is a
    # handful, not every transition in the model.
    #
    # Brittle to renames, and deliberately so: a rename gives a false alarm, not
    # silent staleness. A spurious red on a proof costs one commit; the failure
    # it guards costs a subsystem.
    def start_direct_inner_body(tree_src):
        """The body of start_direct_inner, or None if it cannot be located."""
        try:
            i = tree_src.index("async fn start_direct_inner")
        except ValueError:
            return None
        m = re.search(r"\n    (?:pub )?(?:async )?fn ", tree_src[i + 10:])
        return tree_src[i:i + 10 + m.start()] if m else tree_src[i:]

    DELETED_TRANSITIONS = [
        (
            "pending_cancelled_then_bind_fails",
            "#85 (e0864ec) made the supersede decision without mutating, so a "
            "pending is never cancelled ahead of a bind failure that returns "
            "before the re-insert",
            "start_direct_inner must not remove a direct_pending at all",
            lambda body: "direct_pending.remove" not in body,
        ),
    ]

    body = start_direct_inner_body(tree)
    if body is None:
        print("\n  TRANSITION GUARD UNVERIFIABLE: cannot locate start_direct_inner.")
        print("  Failing to run is not passing. Fix the locator or the guard.")
        sys.exit(1)
    for name, why, fact, holds in DELETED_TRANSITIONS:
        if not holds(body):
            print(f"\n  DELETED TRANSITION IS REACHABLE AGAIN: {name}")
            print(f"  deleted because: {why}")
            print(f"  the fact that justified it: {fact}")
            print("  That fact no longer holds, so this model is describing a")
            print("  defect the code has re-grown. Restore the transition and")
            print("  re-run the matrix, or fix the code back.")
            sys.exit(1)
    print(f"  transition guard: {len(DELETED_TRANSITIONS)}/{len(DELETED_TRANSITIONS)} "
          "code facts behind deleted transitions still hold.")

    print(f"  calibration current: tree is {tree_state}, calibrated for")
    print(f"  {CALIBRATED_FOR}. Fails LOUD on drift; cleared by re-deriving and")
    print("  bumping CALIBRATED_FOR, never by deleting the check.")
    anchored = [r for r in OBSERVED if r[7] or r[8]]
    print(f"  evidence anchoring: {len(anchored)}/{len(OBSERVED)} rows cite a CI run.")
    for r in OBSERVED:
        if not (r[7] or r[8]):
            print(f"      UNANCHORED, weaker evidence: {r[0].strip()}")
    print(f"  gate passed: all {len(OBSERVED)} rows reproduce, each under its own")
    print("  era's ctrl_carries value.")
    ok &= gate_ok

    # Show that ctrl_carries=True does NOT reproduce, so the gate genuinely
    # determines the parameter instead of merely being consistent with it.
    flipped = [is_clean(check(Cfg(d, dok, bok, ros, not ERA_CTRL[era]))) == exp
               for _, d, dok, bok, ros, exp, era, _r, _j in OBSERVED]
    print(f"  with each era's ctrl_carries FLIPPED, rows still reproducing: "
          f"{sum(flipped)}/{len(OBSERVED)} -> "
          f"{'DISCRIMINATES' if not all(flipped) else 'does NOT discriminate'}")
    ok &= not all(flipped)

    # -------------------------------------------------------------- matrix
    print("\n[Full matrix: 3 designs x 2^4 environments]")
    results = {}
    for design in (EAGER, LATE, PATHSET):
        print(f"\n  --- {design} ---")
        for dok, bok, ros, cc in product((True, False), repeat=4):
            cfg = Cfg(design, dok, bok, ros, cc)
            r = check(cfg)
            results[cfg] = r
            banner(r, indent='  ')

    # ------------------------------------------------------------- theorems
    print("\n" + "=" * 78)
    print("THEOREMS")
    print("=" * 78)

    def survives(design, cc):
        """How many of the 8 environments this design is clean in."""
        return sum(1 for dok, bok, ros in product((True, False), repeat=3)
                   if is_clean(results[Cfg(design, dok, bok, ros, cc)]))

    print("\nT1. With the post-PAKE link unable to mature (ctrl_carries=False),")
    print("    every design that DESTROYS it depends on something else to")
    print("    rebuild it, and PATHSET is not better off, because it never")
    print("    rebuilds at all:")
    for d in (EAGER, LATE, PATHSET):
        print(f"      {d:8s} clean in {survives(d, False)}/8 environments")

    print("\nT2. With the post-PAKE link able to mature (ctrl_carries=True),")
    print("    the destroy-based designs still fail where their successor is")
    print("    not armed, and PATHSET is clean everywhere:")
    for d in (EAGER, LATE, PATHSET):
        print(f"      {d:8s} clean in {survives(d, True)}/8 environments")

    pathset_total = survives(PATHSET, True)
    if pathset_total != 8:
        print("\n  !! PATHSET is NOT clean in all 8 with ctrl_carries=True.")
        ok = False

    def dominance(cc):
        """Environments (at this ctrl_carries) where a destroy-based design is
        clean but PATHSET is not. Empty == PATHSET dominates."""
        bad = []
        for dok, bok, ros in product((True, False), repeat=3):
            ps = is_clean(results[Cfg(PATHSET, dok, bok, ros, cc)])
            for d in (EAGER, LATE):
                if is_clean(results[Cfg(d, dok, bok, ros, cc)]) and not ps:
                    bad.append((d, Cfg(d, dok, bok, ros, cc)))
        return bad

    print("\nT3. PATHSET dominates ONLY when the post-PAKE link can mature.")
    print("    This is the result that refutes the obvious first-principles")
    print("    argument, and it is the reason this model was worth writing.")
    dom_true, dom_false = dominance(True), dominance(False)
    print(f"      ctrl_carries=True : {len(dom_true)} environments where a")
    print(f"                          destroy-based design beats PATHSET")
    print(f"      ctrl_carries=False: {len(dom_false)} such environments")
    for d, cfg in dom_false[:3]:
        print(f"                          {d} clean, PATHSET broken: {env_label(cfg)}")
    # Dominance under ctrl_carries=True is the property we assert.
    if dom_true:
        print("      !! PATHSET fails to dominate even with ctrl_carries=True.")
        ok = False
    # Under ctrl_carries=False it MUST fail to dominate. If that ever stops being
    # true the model has drifted and T4's ordering no longer follows.
    if not dom_false:
        print("      !! expected PATHSET to be beaten under ctrl_carries=False.")
        ok = False

    print("\nT4. THE ORDER OF WORK WAS FORCED, AND HAS NOW BEEN SATISFIED.")
    print("    While the post-PAKE link could not carry a transfer on its own,")
    print("    destroying it was the ONLY route to a live data plane:")
    print(f"      EAGER   (main before #83)  ctrl_carries=False: {survives(EAGER, False)}/8")
    print(f"      LATE    (#78 / #79)        ctrl_carries=False: {survives(LATE, False)}/8")
    print(f"      PATHSET (proposed)         ctrl_carries=False: {survives(PATHSET, False)}/8")
    print("    Adopting PATHSET first would have been strictly worse than main,")
    print("    which is the result that refuted the redesign this model was")
    print("    written to justify. Data-plane attachment had to come FIRST.")
    print()
    print("    #83 did that, so the tree is now post-rearm and:")
    print(f"      LATE    (main today)       ctrl_carries=True:  {survives(LATE, True)}/8")
    print(f"      PATHSET (now unblocked)    ctrl_carries=True:  {survives(PATHSET, True)}/8")
    print("    PATHSET is no longer blocked. It is not thereby URGENT: main is")
    print("    at 7/8 and the remaining break is a real gap, not a formality.")
    if not (survives(PATHSET, False) < survives(EAGER, False)):
        print("      !! PATHSET was not worse under ctrl_carries=False; T4 is wrong.")
        ok = False

    print("\nT5. LATE was strictly worse than EAGER while the link could not")
    print("    mature, which is the regression #78/#79 shipped, derived rather")
    print("    than guessed from a red check. It is why they were CLOSED and")
    print("    then re-landed inside #83, where the re-emit makes them correct:")
    print(f"      EAGER {survives(EAGER, False)}/8   ->   LATE {survives(LATE, False)}/8")
    if not (survives(LATE, False) < survives(EAGER, False)):
        print("      !! LATE is not worse than EAGER; T5 does not hold.")
        ok = False

    # ------------------------------------------------------- the two traces
    print_trace(results[Cfg(EAGER, True, False, False, True)],
                "EAGER: drop, then bind_endpoint fails -> no link, no pending, "
                "nothing armed (the advisor's window)")
    print_trace(results[Cfg(LATE, False, True, False, False)],
                "LATE on macOS: nothing dropped, post-PAKE link never matures, "
                "sender waits forever (#79)")

    print("\nT6. Roster reconciliation is LOAD-BEARING on main, not incidental.")
    print("    Every environment where EAGER breaks has roster OFF; it is the")
    print("    only armed successor in those states. It must not be removed,")
    print("    and #79 removing it is why #79 was the worse of the two:")
    eager_broken = [Cfg(EAGER, dok, bok, ros, False)
                    for dok, bok, ros in product((True, False), repeat=3)
                    if not is_clean(results[Cfg(EAGER, dok, bok, ros, False)])]
    print(f"      EAGER breaks in {len(eager_broken)} environments, "
          f"roster off in {sum(1 for c in eager_broken if not c.roster)} of them")
    if any(c.roster for c in eager_broken):
        print("      !! EAGER breaks with roster ON; T6 as written is wrong.")
        ok = False

    print("\n" + "=" * 78)
    print("ALL TRANSPORT-UPGRADE PROPERTIES PROVEN" if ok
          else "PROOF FAILED -- see above")
    print("=" * 78)
    sys.exit(0 if ok else 1)
