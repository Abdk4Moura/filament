#!/usr/bin/env python3
"""Exhaustive model check for the capability ledger (CONTRACT.md, laws L1-L13).

Same discipline as establishment_model.py and fleet_automesh_model.py:
enumerate the ENTIRE op space of a bounded universe, then assert every law over
every cell, not over a trace we happened to hit. Exhaustive over a bounded
model is a definitive result FOR THAT BOUND.

WHAT IS MODELLED
----------------
An append-only log of signed ops and the pure verdict function over it.

  Op      (id, author, subject, action, resource, nb, na, kind, version, ref)
          interval is half-open [nb, na); `ref` is the referenced op id on an
          Accept and None elsewhere.
  kinds   grant | deny | ceiling | certify | pass | pause | accept
  Facts   now, subject, binding, cert, held_author_key, ops (pre-verified)
  Request (action, resource) -- a CONCRETE claim, daemon-derived
  Verdict (decision, reason, valid_until, because)

Universe: two keys used in BOTH the author and the subject role (a self-grant
and a cross-grant are both expressible, and an Accept can be authored by the
wrong key so L13 can fail), three capability PATTERNS over a small resource
lattice (shell@*, forward@ws:8080, forward@ws:*), three concrete REQUESTS that
those patterns cover differently (shell@dev:a, forward@ws:8080,
forward@ws:9090), intervals over a small integer clock, and every time step
that is an interval boundary or a neighbour of one (nb-1, nb, na-1, na).

No single tier carries the whole universe: each tier is exhaustive over the
dimensions its laws need and pinned on the ones they do not, so the product
stays inside a ten-second budget. The tier banner prints each bound.

WHAT IS *NOT* MODELLED
----------------------
- Signatures, key agreement, or any cryptography. `sig_ok` is a boolean input
  to ingest; the evaluator never sees it, which is exactly L6's claim.
- Tiers (external / paired / fleet / dormant / paused). CONTRACT.md states they
  are CLI-computed views over verdicts and facts and are never stored, so there
  is nothing here to model. Modelling them would create state the contract says
  does not exist.
- Forget. It is a STORAGE action, not an op: it removes a record and its ops.
  Its effect on a verdict is exactly "evaluate the smaller log", which every
  tier below already enumerates.
- The current Rust engine's shadow/authoritative split, its counters, and the
  cap-flip migration. This models the contract, not the transition to it.
- Wall-clock arithmetic, timezones, leap seconds. `now` is an integer.

READING CHOICES (stated, not silently resolved)
-----------------------------------------------
Three points in the approved design are under-constrained. Each is pinned here
to the most conservative reading consistent with L1-L13, and named in
CONTRACT.md under "Deliberately unresolved" rather than quietly decided:

  Certify   carries no authority: it never contributes to a verdict and never
            appears in `because`. Modelled as inert-but-ingested.
  Pass      widening, governed by exactly L5's rules for Grant. WHO may pass
            WHAT is not pinned by any law and is not modelled.
  Pause     scoped by its own capability pattern, so "every allow the author
            would give" is every allow WITHIN that pattern. A pause at the top
            of the lattice is the wholesale reading.

L10's plain-English form ("ops that each deny never combine into an allow") is
contradicted by L5, whose entire mechanism is a Grant and an Accept -- each
denying alone -- allowing together. Tier PAIR checks the restricted form and
requires that single exception to be the ONLY one, failing on any second.

GATE 0
------
Before any law is reported, the model reproduces behaviour the deployed gate
already has, taken from the oracle rows of
`exec_matches_pty_across_gate_matrix` in cli/src/shell_gate.rs and from
CONTRACT.md's SSH-certificate rules. What has NO analogue today (deny, pause
and accept are new primitives; `CapOpKind` is Grant | Revoke | Modify and
Revoke DELETES the row) is listed as new rather than claimed as reproduced.

Run:
    python3 proofs/capability_ledger_model.py
    python3 proofs/capability_ledger_model.py --self-test
"""
import inspect
import itertools
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- op encoding
ID, AUTHOR, SUBJECT, ACTION, RESOURCE, NB, NA, KIND, VERSION, REF = range(10)

KEYS = ("k0", "k1")
PATTERNS = (("shell", "*"), ("forward", "ws:8080"), ("forward", "ws:*"))
REQUESTS = (("shell", "dev:a"), ("forward", "ws:8080"), ("forward", "ws:9090"))
UNIVERSAL = ("*", "*")
ACC = ("accept", "-")
WIDENING = ("grant", "pass")

ALLOW, DENY = "Allow", "Deny"
R_DENIED, R_PAUSED, R_CEILING = "denied", "paused", "above-ceiling"
R_UNACCEPTED, R_NOGRANT = "unaccepted", "no-grant"

# The one knob --self-test turns. Production runs leave it None; each mutation
# is a single deliberate breach of one law, used to prove the checks bite.
MUTATION = None


def covers(pat_action, pat_resource, claim_action, claim_resource):
    """ResourceLattice::covers -- exact, `*`, and prefix patterns."""
    if pat_action != "*" and pat_action != claim_action:
        return False
    if pat_resource == "*" or pat_resource == claim_resource:
        return True
    return pat_resource.endswith("*") and claim_resource.startswith(pat_resource[:-1])


def effective(ops):
    """L4: newest version per op id wins; older versions are ignored entirely."""
    best = {}
    for o in ops:
        prev = best.get(o[ID])
        if prev is None:
            best[o[ID]] = o
        elif MUTATION == "stale-version-wins":
            if o[VERSION] < prev[VERSION]:
                best[o[ID]] = o
        elif MUTATION == "last-arrival-wins":
            best[o[ID]] = o
        elif (o[VERSION], o) > (prev[VERSION], prev):
            best[o[ID]] = o
    return tuple(sorted(best.values()))


_CORE = {}


def decide_core(ops, subject, now, request):
    """(decision, reason) for a pre-verified op set. Pure; memoised on inputs."""
    key = (ops, subject, now, request)
    hit = _CORE.get(key)
    if hit is None:
        _CORE[key] = hit = _decide_core(ops, subject, now, request)
    return hit


def _decide_core(ops, subject, now, request):
    req_action, req_resource = request
    live = [o for o in effective(ops)
            if o[SUBJECT] == subject and o[NB] <= now < o[NA]]
    applies = [o for o in live
               if o[KIND] == "accept"
               or covers(o[ACTION], o[RESOURCE], req_action, req_resource)]

    if MUTATION != "deny-not-absolute":
        for o in applies:
            if o[KIND] == "deny":
                return (DENY, R_DENIED)

    accepts = [o for o in applies if o[KIND] == "accept"]
    supported, unaccepted = [], []
    for o in applies:
        if o[KIND] not in WIDENING:
            continue
        if MUTATION == "accept-not-required":
            supported.append(o)
            continue
        # L13: one referenced op id, signed by that op's subject, both live.
        ok = any(a[REF] == o[ID] and a[AUTHOR] == o[SUBJECT]
                 and a[SUBJECT] == o[SUBJECT] for a in accepts)
        (supported if ok else unaccepted).append(o)

    paused_authors = {o[AUTHOR] for o in applies if o[KIND] == "pause"}
    allows = [o for o in supported if o[AUTHOR] not in paused_authors]

    if MUTATION == "ceiling-widens" and not allows:
        # A ceiling that GRANTS. Making a ceiling merely inert would still
        # satisfy "only narrows" (it narrows by nothing), so the mutation has
        # to be a real widening or it proves nothing.
        if any(o[KIND] == "ceiling" for o in applies):
            return (ALLOW, None)
    if allows:
        within = all(covers(c[ACTION], c[RESOURCE], req_action, req_resource)
                     for c in live if c[KIND] == "ceiling")
        return (ALLOW, None) if within else (DENY, R_CEILING)
    if supported:
        if MUTATION == "pause-reads-as-denied":
            return (DENY, R_DENIED)
        return (DENY, R_PAUSED)
    if unaccepted:
        return (DENY, R_UNACCEPTED)
    return (DENY, R_NOGRANT)


def boundaries(ops):
    out = set()
    for o in effective(ops):
        out.add(o[NB])
        out.add(o[NA])
    return sorted(out)


def valid_until(ops, subject, now, request):
    """L3/L9: the first instant > now at which the decision or reason changes."""
    here = decide_core(ops, subject, now, request)
    later = [b for b in boundaries(ops) if b > now]
    if MUTATION == "valid-until-too-late":
        return later[-1] if later else None
    for b in later:
        if decide_core(ops, subject, b, request) != here:
            return b
    return None


def because(ops, subject, now, request):
    """L7: a canonical minimal sufficient cause of (decision, reason).

    Deletion to a fixpoint in a fixed order. Sufficiency holds by construction
    (nothing is dropped that changes the verdict) and irredundancy holds at the
    fixpoint (no remaining op can be dropped). check_cell re-verifies both
    independently, so a broken minimiser is caught rather than trusted.
    """
    target = decide_core(ops, subject, now, request)
    current = effective(ops)
    if MUTATION == "because-not-minimal":
        return tuple(sorted(o[ID] for o in current)), current
    shrinking = True
    while shrinking:
        shrinking = False
        for o in current:
            trial = tuple(x for x in current if x != o)
            if decide_core(trial, subject, now, request) == target:
                current = trial
                shrinking = True
                break
    return tuple(sorted(o[ID] for o in current)), current


def decide(facts, request):
    """The contract surface. Reads now, subject and ops. NOTHING else."""
    ops, subject, now = facts["ops"], facts["subject"], facts["now"]
    if MUTATION == "reads-cert" and facts.get("cert") is not None:
        if facts["cert"]["revoked"]:
            return (DENY, R_DENIED, None, ())
    if MUTATION == "reads-name" and facts.get("display_name") == "laptop":
        return (DENY, R_NOGRANT, None, ())
    decision, reason = decide_core(ops, subject, now, request)
    ids, _ = because(ops, subject, now, request)
    return (decision, reason, valid_until(ops, subject, now, request), ids)


# ------------------------------------------------------------------ L6 ingest
def ingest(log, op_, sig_ok):
    """Ops enter the log only after signature and version checks."""
    if MUTATION != "ingest-admits-bad-sig" and not sig_ok:
        return None, "bad-signature"
    for x in log:
        if x[ID] == op_[ID] and x[AUTHOR] != op_[AUTHOR]:
            return None, "author-mismatch"
    high = max((x[VERSION] for x in log if x[AUTHOR] == op_[AUTHOR]), default=0)
    if MUTATION != "ingest-admits-stale" and op_[VERSION] <= high:
        return None, "stale-version"
    return log + [op_], None


# ------------------------------------------------------------ refuse to report
def source_guard():
    """This model describes CONTRACT.md. If it cannot read it, it says nothing."""
    contract = os.path.join(ROOT, "CONTRACT.md")
    try:
        text = open(contract, encoding="utf-8").read()
    except OSError as error:
        raise SystemExit(
            f"ledger guard: cannot read {contract} ({error}). This model checks "
            "the contract's laws, so it must be pointed at the contract rather "
            "than skipped. Refusing to report.")
    if "## Capability ledger (append-only signed ops)" not in text:
        raise SystemExit(
            "ledger guard: CONTRACT.md has no capability-ledger section. The "
            "laws this model checks are not in the document it claims to check. "
            "Refusing to report.")
    found = sorted(int(n) for n in re.findall(r"\*\*L(\d+) --", text))
    if found != list(range(1, 14)):
        raise SystemExit(
            f"ledger guard: CONTRACT.md declares laws {found}; this model checks "
            "L1..L13. Recalibrate the model against the contract before changing "
            "either. Refusing to report.")
    gate = os.path.join(ROOT, "cli", "src", "shell_gate.rs")
    if not os.path.exists(gate):
        raise SystemExit(
            f"ledger guard: cannot find {gate}, the source of gate 0's oracle "
            "rows. Refusing to report.")
    # L1, checked against this file's own source rather than by assertion.
    for fn in (_decide_core, effective, covers, valid_until, because, decide):
        body = inspect.getsource(fn)
        for banned in ("time.", "os.environ", "random.", "open(", "datetime"):
            if banned in body:
                raise SystemExit(
                    f"ledger guard: L1 violated in source -- {fn.__name__} "
                    f"references {banned!r}. The evaluator must be pure.")
    print("GUARD: CONTRACT.md declares L1..L13; shell_gate.rs present; "
          "evaluator source free of clock / store / env")


# -------------------------------------------------------------------- gate 0
def mk(i, author, subject, pattern, nb, na, kind, version=1, ref=None):
    return (i, author, subject, pattern[0], pattern[1], nb, na, kind, version, ref)


SHELL, FWD_ONE, FWD_ANY = PATTERNS
REQ_SHELL, REQ_8080, REQ_9090 = REQUESTS


def gate_0():
    """Reproduce what the deployed gate already does before reporting laws."""
    k, j = KEYS
    grant = mk(0, j, k, SHELL, 0, 10, "grant")
    accept = mk(1, k, k, ACC, 0, 10, "accept", ref=0)
    short = (mk(0, j, k, SHELL, 2, 6, "grant"), mk(1, k, k, ACC, 2, 6, "accept", ref=0))
    wide = (mk(0, j, k, FWD_ANY, 0, 10, "grant"),
            mk(1, k, k, ACC, 0, 10, "accept", ref=0),
            mk(2, j, k, FWD_ONE, 0, 10, "ceiling"))
    cases = [
        ("shell_gate: refusal without grant", (), REQ_SHELL, 5, (DENY, R_NOGRANT)),
        ("shell_gate oracle: trusted+granted must allow",
         (grant, accept), REQ_SHELL, 5, (ALLOW, None)),
        ("SSH: expiry IS the revocation mechanism (inside the window)",
         short, REQ_SHELL, 5, (ALLOW, None)),
        ("SSH: expiry IS the revocation mechanism (at not_after)",
         short, REQ_SHELL, 6, (DENY, R_NOGRANT)),
        ("SSH: a grant is not live before not_before",
         short, REQ_SHELL, 1, (DENY, R_NOGRANT)),
        ("shell_gate oracle: revoked must deny, over a live grant",
         (grant, accept, mk(2, j, k, SHELL, 0, 10, "deny")), REQ_SHELL, 5,
         (DENY, R_DENIED)),
        ("shell_gate oracle: narrow ceiling must deny", wide, REQ_9090, 5,
         (DENY, R_CEILING)),
        ("shell_gate: a ceiling that admits the request does not deny",
         wide, REQ_8080, 5, (ALLOW, None)),
        ("CONTRACT: exec rides the shell grant only after the BOUNDARY maps it",
         (grant, accept), ("exec", "dev:a"), 5, (DENY, R_NOGRANT)),
        ("capability.rs: resource match is containment, not equality",
         (mk(0, j, k, FWD_ANY, 0, 10, "grant"), mk(1, k, k, ACC, 0, 10, "accept", ref=0)),
         REQ_9090, 5, (ALLOW, None)),
        ("capability.rs: an exact resource grant does not reach a sibling",
         (mk(0, j, k, FWD_ONE, 0, 10, "grant"), mk(1, k, k, ACC, 0, 10, "accept", ref=0)),
         REQ_9090, 5, (DENY, R_NOGRANT)),
    ]
    failures = []
    for name, ops, request, now, expected in cases:
        got = decide_core(tuple(ops), KEYS[0], now, request)
        if got != expected:
            failures.append(f"  {name}: expected {expected}, got {got}")
    if failures:
        raise SystemExit("GATE 0 FAILED: model does not reproduce the deployed "
                         "gate\n" + "\n".join(failures))
    print(f"GATE 0: PASS ({len(cases)} deployed-gate behaviours reproduced)")
    print("GATE 0 NEW: deny / pause / accept have NO analogue in the engine today")
    print("            (CapOpKind is Grant|Revoke|Modify and Revoke deletes the")
    print("            row). They are new primitives, not reproductions.")


# ------------------------------------------------------------------- tallying
CELL = None
VERDICTS_SEEN = set()

# Every verdict shape the evaluator can produce. A run that never reaches one of
# these passed the checks guarding it WITHOUT TESTING THEM, which is the failure
# mode fleet_automesh_model.py's Intruder tier exists to prevent. Required, not
# reported: a bound that stops expressing a verdict is a bound to widen.
REQUIRED_VERDICTS = (
    (ALLOW, None), (DENY, R_DENIED), (DENY, R_PAUSED),
    (DENY, R_CEILING), (DENY, R_UNACCEPTED), (DENY, R_NOGRANT),
)
REQUIRED_NONEMPTY = ("L12 pause-distinct", "L13 accept-well-formed",
                     "L10 deny-is-a-tombstone", "L3 valid-until-is-a-change-point")


class Tally:
    def __init__(self):
        self.cells, self.bad, self.witness = {}, {}, {}

    def check(self, law, ok):
        self.cells[law] = self.cells.get(law, 0) + 1
        if not ok:
            self.bad[law] = self.bad.get(law, 0) + 1
            self.witness.setdefault(law, CELL)

    def clean(self):
        return not self.bad


# ----------------------------------------------------------------- enumeration
def pool(keys, subjects, patterns, intervals, kinds, slots):
    """Every op a slot may hold, in a canonical order."""
    out = []
    for author, subject, pattern, (nb, na), kind in itertools.product(
            keys, subjects, patterns, intervals, kinds):
        out.append((author, subject, pattern, nb, na, kind, None))
    for author, subject, (nb, na), ref in itertools.product(
            keys, subjects, intervals, range(slots)):
        out.append((author, subject, ACC, nb, na, "accept", ref))
    return tuple(out)


def ledgers(template_pool, slots):
    """All multisets of `slots` ops, ids by position, all at version 1.

    Multisets, not sequences: arrival order is tier ORDER's own subject, and
    every other tier would otherwise re-check one log once per permutation.
    """
    for combo in itertools.combinations_with_replacement(
            range(len(template_pool)), slots):
        ops = []
        for i, index in enumerate(combo):
            author, subject, pattern, nb, na, kind, ref = template_pool[index]
            ops.append(mk(i, author, subject, pattern, nb, na, kind, 1,
                          ref if ref is None else ref % slots))
        yield tuple(ops)


def singles(template_pool, op_id):
    for author, subject, pattern, nb, na, kind, ref in template_pool:
        yield mk(op_id, author, subject, pattern, nb, na, kind, 1,
                 ref if ref is None else (1 - op_id))


# ------------------------------------------------------------------ law checks
DENY_PROBES = tuple((key, UNIVERSAL) for key in KEYS)


def check_cell(tally, ops, subject, now, request, clock):
    """Every law that is a property of one (log, subject, now, request) cell."""
    decision, reason = decide_core(ops, subject, now, request)
    VERDICTS_SEEN.add((decision, reason))
    live = [o for o in effective(ops)
            if o[SUBJECT] == subject and o[NB] <= now < o[NA]]
    hits = [o for o in live if covers(o[ACTION], o[RESOURCE], *request)]
    any_deny = any(o[KIND] == "deny" for o in hits)

    # L4  deny absolute; ceiling only narrows.
    tally.check("L4 deny-absolute",
                (not any_deny) or (decision, reason) == (DENY, R_DENIED))
    tally.check("L4 ceiling-only-narrows",
                decision != ALLOW
                or decide_core(tuple(o for o in ops if o[KIND] != "ceiling"),
                               subject, now, request)[0] == ALLOW)

    # L5  widening needs two signatures; narrowing needs only the author's.
    tally.check("L5 widening-needs-accept",
                decision != ALLOW
                or decide_core(tuple(o for o in ops if o[KIND] != "accept"),
                               subject, now, request)[0] != ALLOW)
    if decision == ALLOW:
        for author, pattern in DENY_PROBES:
            probe = ops + (mk(len(ops), author, subject, pattern,
                              clock[0], clock[-1] + 1, "deny"),)
            tally.check("L5 narrowing-is-unilateral",
                        decide_core(probe, subject, now, request)[0] == DENY)
        # A pause suppresses only ITS OWN author's allows (L12), so the
        # unilateral-narrowing claim is that every author pausing leaves no
        # allow standing -- and that it reads as paused, never as denied.
        held = ops + tuple(
            mk(len(ops) + i, author, subject, UNIVERSAL,
               clock[0], clock[-1] + 1, "pause")
            for i, (author, _pattern) in enumerate(DENY_PROBES))
        tally.check("L5 pause-is-unilateral",
                    decide_core(held, subject, now, request) == (DENY, R_PAUSED))

    # L8  verb-agnostic: an allow always rests on an op that covers the claim.
    tally.check("L8 lattice-covers",
                decision != ALLOW or any(o[KIND] in WIDENING for o in hits))

    # L12 pause: author-only, interval-bounded, reason distinct from denied.
    if reason == R_PAUSED:
        tally.check("L12 pause-distinct",
                    (not any_deny) and any(o[KIND] == "pause" for o in hits))
    tally.check("L12 pause-not-deny", reason != R_DENIED or any_deny)

    # L13 an allow rests on an accept naming a live widening op, signed by its
    #     subject.
    if decision == ALLOW:
        tally.check("L13 accept-well-formed", any(
            a[KIND] == "accept" and g[KIND] in WIDENING and g[ID] == a[REF]
            and a[AUTHOR] == g[SUBJECT] and a[SUBJECT] == g[SUBJECT]
            for a in live for g in hits))

    # L3 / L9  valid_until soundness.
    vu = valid_until(ops, subject, now, request)
    span = [t for t in clock if t > now] if vu is None else \
           [t for t in clock if now < t < vu]
    tally.check("L9 stable-before-valid-until",
                all(decide_core(ops, subject, t, request) == (decision, reason)
                    for t in span))
    if vu is not None:
        tally.check("L3 valid-until-is-a-change-point",
                    decide_core(ops, subject, vu, request) != (decision, reason))

    # L7  because is a minimal sufficient cause.
    ids, chosen = because(ops, subject, now, request)
    tally.check("L7 because-sufficient",
                decide_core(chosen, subject, now, request) == (decision, reason))
    tally.check("L7 because-irredundant",
                all(decide_core(tuple(x for x in chosen if x != o), subject,
                                now, request) != (decision, reason)
                    for o in chosen))
    tally.check("L7 because-only-effective-ops",
                set(ids) <= {o[ID] for o in effective(ops)})
    tally.check("L7 because-omits-inert",
                not any(o[KIND] == "certify" for o in chosen))


# ----------------------------------------------------------------------- tiers
def tier_cells(tally, label, keys, subjects, patterns, intervals, kinds, slots,
               clock, requests, decided):
    global CELL
    tpool = pool(keys, subjects, patterns, intervals, kinds, slots)
    logs = 0
    for ops in ledgers(tpool, slots):
        logs += 1
        for subject in decided:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    check_cell(tally, ops, subject, now, request, clock)
    print(f"  {label:<28} logs={logs:<8d} pool={len(tpool):<4d} N={slots} "
          f"times={len(clock)} reqs={len(requests)}")


def tier_version(tally, keys, subjects, patterns, intervals, kinds, clock,
                 requests):
    """L4: newest version per author wins; older versions are ignored."""
    global CELL
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    olds = [o for o in singles(tpool, 0) if o[KIND] != "accept"]
    pairs = 0
    for old in olds:
        for new in olds:
            if new[AUTHOR] != old[AUTHOR]:
                continue  # ingest refuses an id whose author changes
            newer = tuple(list(new[:VERSION]) + [2, new[REF]])
            pairs += 1
            for subject in subjects:
                for request in requests:
                    for now in clock:
                        CELL = ((old, newer), subject, now, request)
                        tally.check("L4 newest-version-wins",
                                    decide_core((old, newer), subject, now, request)
                                    == decide_core((newer,), subject, now, request))
                        tally.check("L4 stale-version-inert",
                                    decide_core((newer, old), subject, now, request)
                                    == decide_core((newer,), subject, now, request))
    print(f"  {'L4 versioning':<28} pairs={pairs:<7d}  pool={len(olds)}")


def tier_pairs(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L10: no widening by combination, with L5's single exception named."""
    global CELL
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    left_ops = list(singles(tpool, 0))
    right_ops = list(singles(tpool, 1))
    pairs = 0
    for left in left_ops:
        for right in right_ops:
            pairs += 1
            for subject in subjects:
                for request in requests:
                    for now in clock:
                        CELL = ((left, right), subject, now, request)
                        la = decide_core((left,), subject, now, request)[0]
                        lb = decide_core((right,), subject, now, request)[0]
                        both = decide_core((left, right), subject, now, request)[0]
                        if la == DENY and lb == DENY and both == ALLOW:
                            widen = [o for o in (left, right) if o[KIND] in WIDENING]
                            acc = [o for o in (left, right) if o[KIND] == "accept"]
                            tally.check("L10 no-widening-by-combination",
                                        len(widen) == 1 and len(acc) == 1
                                        and acc[0][REF] == widen[0][ID]
                                        and acc[0][AUTHOR] == widen[0][SUBJECT])
                        else:
                            tally.check("L10 no-widening-by-combination", True)
                        # A live deny is a tombstone: nothing another op brings
                        # can retire it.
                        if (left[KIND] == "deny" and left[SUBJECT] == subject
                                and left[NB] <= now < left[NA]
                                and covers(left[ACTION], left[RESOURCE], *request)):
                            tally.check("L10 deny-is-a-tombstone", both == DENY)
    # Only the author's own newer, shorter version lifts its deny.
    lifts = 0
    for left in left_ops:
        if left[KIND] != "deny":
            continue
        for now in clock:
            if not left[NB] <= now < left[NA]:
                continue
            shorter = tuple(list(left[:NA]) + [now, "deny", 2, None])
            other = tuple([left[ID], (set(keys) - {left[AUTHOR]}).pop()]
                          + list(left[2:NA]) + [now, "deny", 2, None])
            lifts += 1
            for subject in subjects:
                for request in requests:
                    CELL = ((left, shorter), subject, now, request)
                    tally.check(
                        "L10 own-shorter-version-lifts",
                        decide_core((left, shorter), subject, now, request)[1]
                        != R_DENIED)
                    # The same op id under a different author never reaches the
                    # evaluator: ingest refuses it (L6). Assert that, rather
                    # than asserting the evaluator copes with it.
                    tally.check("L10 other-author-cannot-lift",
                                ingest([left], other, True)[0] is None)
    print(f"  {'L10 pairwise + tombstone':<28} pairs={pairs:<7d} lifts={lifts}")


def tier_order(tally, keys, subjects, patterns, intervals, kinds, slots, clock,
               requests):
    """L11: arrival order and replay change nothing."""
    global CELL
    tpool = pool(keys, subjects, patterns, intervals, kinds, slots)
    logs = 0
    for ops in ledgers(tpool, slots):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    base = decide_core(ops, subject, now, request)
                    base_ids, _ = because(ops, subject, now, request)
                    for perm in itertools.permutations(ops):
                        tally.check("L11 order-independent",
                                    decide_core(perm, subject, now, request) == base)
                        tally.check("L11 because-order-independent",
                                    because(perm, subject, now, request)[0]
                                    == base_ids)
                    tally.check("L11 replay-idempotent",
                                decide_core(ops + ops, subject, now, request) == base)
    print(f"  {'L11 order / replay':<28} logs={logs:<8d} pool={len(tpool):<4d} "
          f"N={slots} perms={len(list(itertools.permutations(range(slots))))}")


def tier_scope(tally, keys, patterns, intervals, kinds, clock, requests):
    """L2: ops about one subject never move another subject's verdict."""
    global CELL
    tpool = pool(keys, keys, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in keys:
            mine = tuple(o for o in ops if o[SUBJECT] == subject)
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    tally.check("L2 subject-scoped",
                                decide_core(ops, subject, now, request)
                                == decide_core(mine, subject, now, request))
    print(f"  {'L2 subject scoping':<28} logs={logs:<8d} pool={len(tpool)}")


def tier_ingest(tally, keys, patterns, clock, requests):
    """L6: sig and version checks at the boundary, not in the evaluator."""
    global CELL
    k, j = keys
    base = [mk(0, j, k, SHELL, 1, 9, "grant", 1),
            mk(1, k, k, ACC, 1, 9, "accept", 2, ref=0)]
    arrivals = []
    for version in (1, 2, 3):
        for author in keys:
            for kind in ("grant", "deny", "ceiling", "pause"):
                for pattern in patterns:
                    for op_id in (0, 1, 2):
                        arrivals.append(mk(op_id, author, k, pattern, 1, 9, kind,
                                           version))
    load_bearing = 0
    for sig_ok in (True, False):
        for arriving in arrivals:
            CELL = (arriving, sig_ok)
            log, _why = ingest(list(base), arriving, sig_ok)
            high = max((x[VERSION] for x in base if x[AUTHOR] == arriving[AUTHOR]),
                       default=0)
            clash = any(x[ID] == arriving[ID] and x[AUTHOR] != arriving[AUTHOR]
                        for x in base)
            should = sig_ok and not clash and arriving[VERSION] > high
            tally.check("L6 ingest-refuses-bad-ops", (log is not None) == should)
            if log is not None:
                tally.check("L6 admitted-log-is-append-only",
                            log[:len(base)] == base)
            # Non-vacuity: a refusal must be load-bearing at least once -- had
            # the op been admitted, a verdict would have changed.
            if not should and sig_ok:
                forced = tuple(base + [arriving])
                for request in requests:
                    for now in clock:
                        if decide_core(forced, k, now, request) != \
                                decide_core(tuple(base), k, now, request):
                            load_bearing += 1
    CELL = ("non-vacuity", load_bearing)
    tally.check("L6 refusal-is-load-bearing", load_bearing > 0)
    print(f"  {'L6 ingest':<28} arrivals={len(arrivals) * 2:<6d} "
          f"verdict-changing refusals={load_bearing}")


FACT_VARIANTS = tuple(
    (binding, cert, held, name)
    for binding in (None, "Proven")
    for cert in (None,
                 {"device_pub": "d", "user_pub": "u", "expires": 4, "revoked": False},
                 {"device_pub": "d", "user_pub": "u", "expires": 4, "revoked": True})
    for held in (None,) + KEYS
    for name in ("laptop", "phone"))


def tier_facts(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L1 + L2: binding, cert, held_author_key and display names move nothing."""
    global CELL
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    base = None
                    for binding, cert, held, name in FACT_VARIANTS:
                        facts = {"now": now, "subject": subject, "ops": ops,
                                 "binding": binding, "cert": cert,
                                 "held_author_key": held, "display_name": name}
                        got = decide(facts, request)
                        if base is None:
                            base = got
                            tally.check("L1 deterministic",
                                        decide(facts, request) == got)
                        tally.check("L1/L2 facts-irrelevance", got == base)
    print(f"  {'L1/L2 facts irrelevance':<28} logs={logs:<8d} "
          f"pool={len(tpool):<4d} variants={len(FACT_VARIANTS)}")


# ---------------------------------------------------------------------- runner
KINDS_ALL = ("grant", "deny", "ceiling", "pause", "certify", "pass")
KINDS_CORE = ("grant", "deny", "ceiling", "pause")
KINDS_MIN = ("grant", "deny", "pause")

FULL = {
    "core":    dict(keys=KEYS, subjects=KEYS[:1], patterns=PATTERNS,
                    intervals=((1, 3), (2, 4)), kinds=KINDS_ALL, slots=2,
                    clock=tuple(range(6)), requests=REQUESTS, decided=KEYS[:1]),
    # Every kind, because N=3 is the smallest log in which a ceiling or a pause
    # can sit beside a grant AND its accept -- at N=2 the pair fills the log, so
    # `above-ceiling` and `paused` are unreachable and their checks are vacuous.
    "depth":   dict(keys=KEYS, subjects=KEYS[:1], patterns=PATTERNS[1:],
                    intervals=((1, 3), (2, 4)), kinds=KINDS_CORE,
                    slots=3, clock=tuple(range(5)), requests=REQUESTS[1:],
                    decided=KEYS[:1]),
    "version": dict(patterns=PATTERNS, intervals=((1, 3), (2, 4), (3, 5)),
                    kinds=KINDS_CORE, clock=tuple(range(6)), requests=REQUESTS),
    "pairs":   dict(patterns=PATTERNS, intervals=((1, 3), (2, 4)),
                    kinds=KINDS_CORE, clock=tuple(range(6)), requests=REQUESTS),
    "order":   dict(patterns=PATTERNS[:1], intervals=((1, 3), (2, 4)),
                    kinds=KINDS_MIN, slots=3, clock=tuple(range(5)),
                    requests=REQUESTS[:1]),
    "scope":   dict(patterns=PATTERNS, intervals=((1, 3), (2, 4)),
                    kinds=KINDS_CORE, clock=tuple(range(6)), requests=REQUESTS[:1]),
    "facts":   dict(patterns=PATTERNS[:2], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
}

QUICK = {
    "core":    dict(keys=KEYS, subjects=KEYS[:1], patterns=PATTERNS[:2],
                    intervals=((1, 3),), kinds=KINDS_CORE, slots=2,
                    clock=tuple(range(4)), requests=REQUESTS[:2], decided=KEYS[:1]),
    "depth":   dict(keys=KEYS, subjects=KEYS[:1], patterns=PATTERNS[1:],
                    intervals=((1, 3),), kinds=("grant", "ceiling", "pause"),
                    slots=3, clock=tuple(range(4)), requests=REQUESTS[1:],
                    decided=KEYS[:1]),
    "version": dict(patterns=PATTERNS[:2], intervals=((1, 3), (2, 4)),
                    kinds=KINDS_CORE, clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "pairs":   dict(patterns=PATTERNS[:2], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "order":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), slots=3, clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "scope":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "facts":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant",), clock=tuple(range(3)), requests=REQUESTS[:1]),
}


def run_all(tally, plan):
    if plan["core"]:
        print("\nTier CORE  -- N=2, every op kind including the inert `certify`")
        print("  and the widening `pass`; all three patterns, all three requests.")
        tier_cells(tally, "L3..L13 over N=2", **plan["core"])
    if plan["depth"]:
        print("\nTier DEPTH -- N=3: composition needs three ops before a ceiling")
        print("  can sit between a grant and its accept.")
        tier_cells(tally, "L3..L13 over N=3", **plan["depth"])
    if plan["version"]:
        print("\nTier VER   -- two versions of one op id by one author.")
        tier_version(tally, KEYS, KEYS[:1], **plan["version"])
    if plan["pairs"]:
        print("\nTier PAIR  -- every ordered pair of single ops; L10, and L5's")
        print("  exception required to be the only widening combination.")
        tier_pairs(tally, KEYS, KEYS[:1], **plan["pairs"])
    if plan["order"]:
        print("\nTier ORDER -- every permutation of an N=3 log, plus replay.")
        tier_order(tally, KEYS, KEYS[:1], **plan["order"])
    if plan["scope"]:
        print("\nTier SCOPE -- two subjects; an op about one must not move the other.")
        tier_scope(tally, KEYS, **plan["scope"])
    print("\nTier INGEST -- L6 at the boundary, with a non-vacuity proof.")
    tier_ingest(tally, KEYS, PATTERNS, tuple(range(6)), REQUESTS)
    if plan["facts"]:
        print("\nTier FACTS -- L1/L2: everything in Facts the evaluator must ignore.")
        tier_facts(tally, KEYS, KEYS[:1], **plan["facts"])


MUTATIONS = (
    ("deny-not-absolute", "L4 deny-absolute"),
    ("accept-not-required", "L5 widening-needs-accept"),
    ("ceiling-widens", "L4 ceiling-only-narrows"),
    ("stale-version-wins", "L4 newest-version-wins"),
    # Only the version tier can express this one: every other tier gives each
    # op id a distinct slot, so there is no id under which two ops compete.
    ("last-arrival-wins", "L4 stale-version-inert"),
    ("pause-reads-as-denied", "L12 pause-not-deny"),
    ("valid-until-too-late", "L9 stable-before-valid-until"),
    ("because-not-minimal", "L7 because-irredundant"),
    ("ingest-admits-stale", "L6 ingest-refuses-bad-ops"),
    ("ingest-admits-bad-sig", "L6 ingest-refuses-bad-ops"),
    ("reads-cert", "L1/L2 facts-irrelevance"),
    ("reads-name", "L1/L2 facts-irrelevance"),
)


def self_test():
    """A green run means nothing unless the checks can go red. Prove they do."""
    global MUTATION
    print("SELF-TEST: one law broken at a time; each must be caught.\n")
    rows, ok = [], True
    for name, expected in MUTATIONS:
        MUTATION = name
        _CORE.clear()
        tally = Tally()
        keep, sys.stdout = sys.stdout, open(os.devnull, "w")
        try:
            run_all(tally, QUICK)
        finally:
            sys.stdout.close()
            sys.stdout = keep
        caught = sorted(tally.bad)
        hit = expected in caught
        ok &= hit
        rows.append((name, expected, hit, len(caught)))
    MUTATION = None
    _CORE.clear()
    width = max(len(r[0]) for r in rows)
    print(f"  {'mutation':<{width}}  {'law that must bite':<32} caught  laws-red")
    print("  " + "-" * (width + 50))
    for name, expected, hit, count in rows:
        print(f"  {name:<{width}}  {expected:<32} "
              f"{'YES' if hit else 'NO':<6}  {count}")
    print("\n" + ("SELF-TEST PASSED: every mutation was caught by the law it breaks"
                  if ok else "SELF-TEST FAILED: a broken law went unnoticed"))
    return ok


def main():
    started = time.time()
    if "--self-test" in sys.argv:
        source_guard()
        return 0 if self_test() else 1

    print("Capability-ledger model check (CONTRACT.md, laws L1-L13)")
    source_guard()
    gate_0()
    tally = Tally()
    VERDICTS_SEEN.clear()
    run_all(tally, FULL)

    vacuous = [f"verdict {v}" for v in REQUIRED_VERDICTS if v not in VERDICTS_SEEN]
    vacuous += [f"check {c}" for c in REQUIRED_NONEMPTY if not tally.cells.get(c)]

    print("\n  law check                                 cells    violations")
    print("  " + "-" * 60)
    for law in sorted(tally.cells):
        bad = tally.bad.get(law, 0)
        mark = "" if bad == 0 else "   <-- COUNTEREXAMPLE"
        print(f"  {law:<34} {tally.cells[law]:>11d} {bad:>11d}{mark}")
    print("  " + "-" * 60)
    print(f"  {'TOTAL':<34} {sum(tally.cells.values()):>11d} "
          f"{sum(tally.bad.values()):>11d}")
    for law, witness in sorted(tally.witness.items()):
        print(f"\n  e.g. {law}: {witness}")
    if vacuous:
        print("\n  VACUOUS (guarded but never exercised): " + ", ".join(vacuous))
    print(f"\n  runtime {time.time() - started:.2f}s")
    ok = tally.clean() and not vacuous
    print("\n" + ("ALL LAWS PROVEN over the bounds printed above; see the file "
                  "header\nfor what is NOT modelled."
                  if ok else "PROOF FAILED -- counterexample(s) above"))
    print("Validated by mutation, not by this clean run: "
          "`python3 proofs/capability_ledger_model.py --self-test`")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
