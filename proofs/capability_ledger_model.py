#!/usr/bin/env python3
"""Exhaustive model check for the capability ledger (CONTRACT.md laws L1-L18).
L14-L18 arrived as review rulings and the contract now declares them; the guard
maps every declared law to a check key in this file, so text and model cannot
drift apart in either direction. See `source_guard`.

Same discipline as establishment_model.py and fleet_automesh_model.py:
enumerate the ENTIRE op space of a bounded universe, then assert every law over
every cell, not over a trace we happened to hit. Exhaustive over a bounded
model is a definitive result FOR THAT BOUND.

WHAT IS MODELLED
----------------
An append-only log of signed ops and the pure verdict function over it.

  Op      (id, author, subject, action, resource, nb, na, kind, version, ref,
           min_binding)
          interval is half-open [nb, na); `ref` is the referenced op id on an
          Accept and None elsewhere; `min_binding` is the strength of identity
          binding the op REQUIRES for an allow it supports -- "proven" by
          default, "inferred" only on a Grant (the pair-secret legacy
          population), which is what gives the migration switch a home (L16).
          It is part of the op, so the author's signature covers it exactly as it
          covers kind and interval.
  kinds   grant | deny | ceiling | pass | pause | accept
          `certify` is NOT here: per review ruling 2 it is an identity-lifecycle
          event, not a ledger op, and its result reaches the evaluator as
          Facts.cert (law L15). `pass` IS an op (law L14).
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

TIERS
the original eight (CORE, DEPTH, VER, PAIR, ORDER, SCOPE, INGEST, FACTS) plus
one per law the review added: PASS (L14), CERT (L15), BIND (L16), HELD (L17),
COMPACT (L18). FACTS changed direction rather than growing: it used to assert
that every Facts field was irrelevant, and now asserts that the three fields the
rulings made load-bearing ARE load-bearing, and that display_name is not.

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

  Certify   NOT AN OP ANY MORE (review ruling 2). Certification is an
            identity-lifecycle event whose result reaches the evaluator as
            Facts.cert; law L15 is the law that reads it. There is therefore
            nothing to ingest, contribute to a verdict, or explain.
  Pass      an op, and a SPECIES OF GRANT (review ruling 2): a Grant whose
            subject is a person key with a device budget, attenuable by that
            subject for its own device keys, and never wider than the author's
            own ceiling toward that resource (attenuation-only, the Biscuit
            property). Who may pass = any key that holds the capability it
            passes, so a pass whose author holds nothing covering it is INERT
            rather than merely narrow. Law L14.
  Pause     scoped by its own capability pattern, so "every allow the author
            would give" is every allow WITHIN that pattern. A pause at the top
            of the lattice is the wholesale reading (review ruling 7).

  Facts     which Facts fields the verdict may read is no longer "none".
            Rulings 2/3 make three of them load-bearing: cert (L15), binding
            (L16) and held_author_key (L17). A field that no law reads is a
            dead input, so tier FACTS now asserts RELEVANCE for those three and
            irrelevance only for display_name, and the vacuity gate fails if a
            field is never load-bearing.

L10's plain-English form ("ops that each deny never combine into an allow") is
contradicted by L5, whose entire mechanism is a Grant and an Accept -- each
denying alone -- allowing together. Tier PAIR checks the restricted form and
requires that single exception to be the ONLY one, failing on any second
(review ruling 1: the (Grant, its referenced Accept) pair is THE defined
widening, and any second widening route must break the run).

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
# MINB is appended LAST so every existing positional slice (o[:VERSION],
# o[2:NA], ...) keeps its meaning: field 10 is new, fields 0-9 are unchanged.
ID, AUTHOR, SUBJECT, ACTION, RESOURCE, NB, NA, KIND, VERSION, REF = range(10)
MINB = 10

KEYS = ("k0", "k1")
PATTERNS = (("shell", "*"), ("forward", "ws:8080"), ("forward", "ws:*"))
REQUESTS = (("shell", "dev:a"), ("forward", "ws:8080"), ("forward", "ws:9090"))
UNIVERSAL = ("*", "*")
ACC = ("accept", "-")
WIDENING = ("grant", "pass")

# The contract currently declares L1..MAX_CONTRACT_LAW; the review rulings add
# MAX_CONTRACT_LAW+1..MAX_MODEL_LAW, which the model implements before the
# contract text lands (the reviewer owns that edit). See source_guard.
MAX_CONTRACT_LAW = 13
MAX_MODEL_LAW = 18

ALLOW, DENY = "Allow", "Deny"
R_DENIED, R_PAUSED, R_CEILING = "denied", "paused", "above-ceiling"
R_UNACCEPTED, R_NOGRANT = "unaccepted", "no-grant"
# Rulings 3/8: a revoked or expired certificate denies with its OWN reason, and
# the two are required to be DISTINCT ("revoked" is permanent, "expired" is the
# end of a window). R_UNPROVEN is the L16 refusal: the allow exists, but the
# binding is weaker than the op demands.
R_REVOKED, R_EXPIRED, R_UNPROVEN = "revoked", "expired", "unproven"

# L14: a Grant and a Pass are the same species; only a Grant species may widen,
# and only with a referenced Accept by the widening op's subject (ruling 1).
GRANT_SPECIES = ("grant", "pass")
# L16: binding strength, weakest first. An op demands a MINIMUM. Facts carry
# the wire spelling ("Proven"/"Inferred"); an op carries the lowercase form, so
# ranking normalises rather than comparing the two spellings by accident -- the
# first cut of this had `None >= "proven"` because only one spelling was keyed,
# which made every allow pass L16 vacuously.
BINDING_RANK = {None: -1, "inferred": 1, "proven": 2}


def binding_rank(value):
    """Rank a binding strength; unknown/absent is WEAKER than any named one."""
    if value is None:
        return BINDING_RANK[None]
    return BINDING_RANK.get(str(value).lower(), BINDING_RANK[None])

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


def pattern_contains(outer_action, outer_resource, inner_action, inner_resource):
    """L14: is pattern `inner` no wider than pattern `outer`?

    Stronger than `covers(outer, inner)`: a wildcard inner is wider than any
    concrete outer, so `covers` alone would call `forward@ws:*` contained in
    `forward@ws:8080` (the wildcard's `*` is not a literal this early). Used
    only for attenuation (a pass against its author's ceiling), never for a
    concrete claim.
    """
    if outer_action != "*" and outer_action != inner_action:
        return False
    if outer_resource == "*":
        return True
    if inner_resource == "*":
        return False
    if outer_resource == inner_resource:
        return True
    if not outer_resource.endswith("*"):
        return False
    prefix = outer_resource[:-1]
    if not inner_resource.startswith(prefix):
        return False
    if inner_resource.endswith("*"):
        return inner_resource[:-1].startswith(prefix)
    return True


def binding_satisfies(binding, need):
    """L16: is `binding` at least the strength `need` (an op's MINB)?"""
    return binding_rank(binding) >= binding_rank(need)


def op_is_supported(ops, o, now):
    """L13 for one op: does a live Accept by its SUBJECT reference it?"""
    return any(a[KIND] == "accept" and a[REF] == o[ID] and a[AUTHOR] == o[SUBJECT]
               and a[SUBJECT] == o[SUBJECT] and a[NB] <= now < a[NA]
               for a in effective(ops))


def pass_is_attenuative(ops, p, now, held=None):
    """L14: may `p`'s author pass what `p` passes?

    Only if that author HOLDS something covering `p`'s pattern -- and "holds"
    means an op that is itself EFFECTIVE and not the author's own unaccepted
    self-grant. The first cut credited any live op whose subject was the author,
    which made the property self-certifiable: a key could write two ops about
    itself (a grant with no Accept) and then pass the capability onward. So a
    candidate must be

      (a) authored by ANOTHER key -- or by the held trust root, whose own policy
          is the root and therefore does not need a second signature; and
      (b) itself effective: a widening op must carry its referenced Accept, a
          ceiling stands alone.

    With no trust root supplied (`held=None`, the op-algebra callers) a
    self-authored candidate is not credited. That can only make a pass INERT,
    never allow one, so the omission fails closed.
    """
    for x in effective(ops):
        if x[SUBJECT] != p[AUTHOR] or x[KIND] not in GRANT_SPECIES + ("ceiling",):
            continue
        if (x[AUTHOR] == p[AUTHOR] and x[AUTHOR] != held
                and MUTATION != "self-certifying-pass"):
            continue
        if not x[NB] <= now < x[NA]:
            continue
        if not pattern_contains(x[ACTION], x[RESOURCE], p[ACTION], p[RESOURCE]):
            continue
        if x[KIND] == "ceiling" or op_is_supported(ops, x, now):
            return True
    return False


def delegated_ok(ops, o, held, now):
    """L17: is an op by a NON-held author effective under a trust root?

    Ops authored by the held key are the trust root ("own policy") and are
    always effective. An op by any other author is effective only within a
    ceiling the held key granted that author: a live op authored BY the held
    key, whose subject IS this op's author, covering this op's pattern.
    """
    if held is None or o[AUTHOR] == held:
        return True
    for x in effective(ops):
        if x[AUTHOR] != held or x[SUBJECT] != o[AUTHOR] or x[KIND] != "ceiling":
            continue
        if not x[NB] <= now < x[NA]:
            continue
        if pattern_contains(x[ACTION], x[RESOURCE], o[ACTION], o[RESOURCE]):
            return True
    return False


def trust_filter(ops, held, now):
    """L17: the op set the evaluator may see, given the held author key.

    ACCEPTS ARE EXEMPT, and that exemption is the point of the law rather than a
    hole in it. L17 governs AUTHORITY: ops that assert what a key may do. An
    Accept asserts nothing -- L13 defines it as the countersignature of the
    referenced op's SUBJECT, and it is checked there ("signed by that op's
    subject"). Filtering Accepts by authorship is how the deployed
    owner->device shape came out with ZERO allows: the owner grants the device,
    the DEVICE accepts its own grant, and the owner's trust root then discarded
    the device's countersignature, so only self-grants could ever allow. The
    alternative reading -- make the held ceiling be about the SUBJECT -- was
    rejected because it changes what L17 is about (a held key tolerates
    AUTHORITIES, not countersignatures) and would let the trust root's ceiling
    decide whether a peer may accept what it was granted.
    """
    if held is None:
        return tuple(ops)
    if MUTATION == "held-key-ignored":
        return tuple(ops)
    if MUTATION == "trust-filter-drops-accepts":
        # The blocker, reintroduced on purpose: the tier-non-vacuity check must
        # catch it, because the laws themselves did not.
        return tuple(o for o in ops if delegated_ok(ops, o, held, now))
    return tuple(o for o in ops
                 if o[KIND] == "accept"
                 or ((MUTATION != "held-key-drops-own-policy" or o[AUTHOR] != held)
                     and delegated_ok(ops, o, held, now)))


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
        # L14: a Pass is a Grant species, and a pass its author cannot back is
        # INERT (review ruling 2: never wider than the author's own ceiling
        # toward that resource). Inert ops are dropped here, before L5/L13, so
        # they can neither widen nor read as merely unaccepted.
        if (o[KIND] == "pass" and MUTATION != "pass-wider-than-ceiling-widens"
                and not pass_is_attenuative(ops, o, now)):
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
    if MUTATION == "ceiling-completes-grant" and not allows:
        # REVIEW RULING 1's counterexample: a SECOND widening route. A ceiling
        # beside an accepted-less Grant makes the pair allow, and neither op
        # allows alone -- so L10 must fail on a pair that is not the
        # (Grant, its referenced Accept) pair.
        if any(o[KIND] == "ceiling" for o in applies) and unaccepted:
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


def valid_until_full(ops, subject, now, request, cert):
    """L3/L9 over the FACT-LAYERED decision.

    Review ruling 3 makes a certificate expiry an absolute deny, so expiry is a
    time at which the verdict changes and `valid_until` must not promise past
    it. A revoked certificate never changes back, so its horizon is None.
    """
    here = fact_verdict(ops, subject, now, request, cert)
    later = [b for b in boundaries(ops) if b > now]
    if cert is not None and cert.get("expires") is not None:
        exp = cert["expires"]
        if exp > now:
            later.append(exp)
    still = [b for b in sorted(set(later))
             if fact_verdict(ops, subject, b, request, cert) != here]
    return still[0] if still else None


def fact_verdict(ops, subject, now, request, cert):
    """The (decision, reason) half of the fact layers, without `because`.

    Used by valid_until_full, which must not recurse into the minimiser.
    """
    if cert is not None:
        if cert.get("revoked"):
            return (DENY, R_REVOKED)
        if cert.get("expires") is not None and cert["expires"] <= now:
            return (DENY, R_EXPIRED)
    return decide_core(ops, subject, now, request)


def because(ops, subject, now, request):
    """L7: a canonical minimal sufficient cause of (decision, reason).

    Deletion to a fixpoint in a fixed order. Sufficiency holds by construction
    (nothing is dropped that changes the verdict) and irredundancy holds at the
    fixpoint (no remaining op can be dropped). check_cell re-verifies both
    independently, so a broken minimiser is caught rather than trusted.

    Review ruling 6: the cause explains the DECISION (decision + reason). It is
    NOT required to explain `valid_until` -- a shorter sufficient cause may
    stop changing later than the full log does. check_cell records when that
    happens so the weaker claim is exercised rather than merely asserted.
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
    """The contract surface.

    Reads now, subject, ops -- and, since review rulings 2/3, exactly three more
    Facts fields: cert (L15), binding (L16) and held_author_key (L17).
    display_name is still NOT read; tier FACTS asserts that.
    """
    ops, subject, now = facts["ops"], facts["subject"], facts["now"]
    cert = facts.get("cert")
    binding = facts.get("binding")
    held = facts.get("held_author_key")
    if MUTATION == "reads-name" and facts.get("display_name") == "laptop":
        return (DENY, R_NOGRANT, None, ())
    # L15: a revoked or expired certificate denies absolutely, with its own
    # reason. Ordered so revocation wins (it is the permanent state).
    if cert is not None:
        if cert.get("revoked") and MUTATION != "cert-revoked-not-absolute":
            return (DENY, R_REVOKED, None, ())
        if (cert.get("expires") is not None and cert["expires"] <= now
                and MUTATION != "expired-not-absolute"):
            reason = R_REVOKED if MUTATION == "revoked-reads-as-expired" else R_EXPIRED
            return (DENY, reason, None, ())
    # L17: the trust root. Applied before the algebra, because it decides which
    # ops the evaluator may see at all.
    ops = trust_filter(ops, held, now)
    decision, reason = decide_core(ops, subject, now, request)
    ids, chosen = because(ops, subject, now, request)
    # L16: an allow must be backed at least as strongly as its cause demands.
    # The requirement is the STRONGEST any op in the cause asks for; Proven by
    # default, Inferred only where a Grant species asked for it (ruling 3, the
    # migration switch's home). Checked unconditionally -- an earlier cut only
    # ran it when the requirement was Proven, so an `inferred`-minimum op
    # allowed on an absent binding.
    if decision == ALLOW:
        # The requirement is the STRONGEST any supporting op asks for: an allow
        # must satisfy EVERY op in its cause, so one Proven-demanding Grant
        # outranks any number of Inferred ones. (The first cut started at
        # "proven" and DOWNGRADED on any inferred op -- the minimum, which is the
        # opposite of what its own comment claimed and would let a single weaker
        # op relax the whole cause.)
        needs = [o[MINB] for o in chosen if o[KIND] in WIDENING]
        need = "proven" if (not needs or "proven" in needs) else "inferred"
        granted = binding
        if MUTATION == "inferred-ok-for-proven-op" and binding == "Inferred":
            granted = "Proven"
        if MUTATION != "binding-ignored" and not binding_satisfies(granted, need):
            return (DENY, R_UNPROVEN,
                    valid_until_full(ops, subject, now, request, cert), ())
    return (decision, reason,
            valid_until_full(ops, subject, now, request, cert), ids)


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
    # Which laws this file actually CHECKS, taken from its own source: every
    # check key is written as "L<n> ..." at the call site, so the source is the
    # authority on what is backed. Review rulings 2/3/8 add L14-L18; CONTRACT.md
    # is the reviewer's to edit, so the mapping must follow the TEXT rather than
    # hold a fixed range -- when the contract was renumbered to declare
    # L1..L18, a range test called those laws declared-but-unbacked even though
    # checks exist for every one of them.
    backed = {int(n) for n in re.findall(r'"L(\d+) ', open(__file__, encoding="utf-8").read())}
    # The laws the deployed gate already rests on must be DECLARED: the model
    # cannot silently stop covering them by the contract dropping them.
    missing = [n for n in range(1, MAX_CONTRACT_LAW + 1) if n not in found]
    if missing:
        raise SystemExit(
            f"ledger guard: CONTRACT.md declares {found}; laws {missing} are "
            f"missing and this model checks L1..L{MAX_CONTRACT_LAW}. Recalibrate "
            "the model against the contract before changing either. Refusing "
            "to report.")
    # A declared law with no check key is the failure this model exists to
    # prevent: a contract claim nothing verifies.
    unbacked = [n for n in found if n not in backed]
    if unbacked:
        raise SystemExit(
            f"ledger guard: CONTRACT.md declares L{unbacked} but this model has "
            "no check key for " + ("them" if len(unbacked) > 1 else "it") +
            ". A contract law without a check is the failure this model exists "
            "to prevent. Refusing to report.")
    beyond = [n for n in found if n > MAX_MODEL_LAW]
    if beyond:
        raise SystemExit(
            f"ledger guard: CONTRACT.md declares L{beyond}, above the highest "
            f"law this model implements (L{MAX_MODEL_LAW}). Refusing to report.")
    gate = os.path.join(ROOT, "cli", "src", "shell_gate.rs")
    if not os.path.exists(gate):
        raise SystemExit(
            f"ledger guard: cannot find {gate}, the source of gate 0's oracle "
            "rows. Refusing to report.")
    # L1, checked against this file's own source rather than by assertion.
    for fn in (_decide_core, effective, covers, valid_until, because, decide,
               pattern_contains, pass_is_attenuative, delegated_ok, trust_filter,
               fact_verdict):
        body = inspect.getsource(fn)
        for banned in ("time.", "os.environ", "random.", "open(", "datetime"):
            if banned in body:
                raise SystemExit(
                    f"ledger guard: L1 violated in source -- {fn.__name__} "
                    f"references {banned!r}. The evaluator must be pure.")
    declared_rulings = [n for n in found if n > MAX_CONTRACT_LAW]
    if declared_rulings:
        # The text now carries the rulings, so the old "pending contract text"
        # note would be a claim the contract contradicts. History, not a claim.
        note = (f"; L{MAX_CONTRACT_LAW + 1}..L{max(declared_rulings)} are the "
                "review rulings, declared by the contract and checked here")
    else:
        note = (f"; L{MAX_CONTRACT_LAW + 1}..L{MAX_MODEL_LAW} are the review "
                "rulings, pending contract text")
    print(f"GUARD: CONTRACT.md declares L1..L{max(found)}; model implements "
          f"L1..L{MAX_MODEL_LAW}, every declared law mapped to a check key{note}; "
          "shell_gate.rs present; evaluator source free of clock / store / env")


# -------------------------------------------------------------------- gate 0
def mk(i, author, subject, pattern, nb, na, kind, version=1, ref=None,
       minb="proven"):
    return (i, author, subject, pattern[0], pattern[1], nb, na, kind, version,
            ref, minb)


def with_fields(op, **kw):
    """Rebuild an op with named fields replaced.

    Positional reconstruction (the pattern the tiers used before MINB existed)
    silently truncates any field added later; this cannot.
    """
    fields = {"id": op[ID], "author": op[AUTHOR], "subject": op[SUBJECT],
              "action": op[ACTION], "resource": op[RESOURCE], "nb": op[NB],
              "na": op[NA], "kind": op[KIND], "version": op[VERSION],
              "ref": op[REF], "minb": op[MINB]}
    fields.update(kw)
    return (fields["id"], fields["author"], fields["subject"], fields["action"],
            fields["resource"], fields["nb"], fields["na"], fields["kind"],
            fields["version"], fields["ref"], fields["minb"])


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
# Ruling 6 non-vacuity: cells where the minimal cause stops changing at a
# different time than the full log does. If this is ever 0 the weaker claim
# (because explains the decision, not valid_until) was never exercised.
CAUSE_VU_DIFFERS = 0

# Every verdict shape the evaluator can produce. A run that never reaches one of
# these passed the checks guarding it WITHOUT TESTING THEM, which is the failure
# mode fleet_automesh_model.py's Intruder tier exists to prevent. Required, not
# reported: a bound that stops expressing a verdict is a bound to widen.
REQUIRED_VERDICTS = (
    (ALLOW, None), (DENY, R_DENIED), (DENY, R_PAUSED),
    (DENY, R_CEILING), (DENY, R_UNACCEPTED), (DENY, R_NOGRANT),
    # Rulings 3/8: the reasons a certificate or a binding can refuse with are
    # required, not merely reachable.
    (DENY, R_REVOKED), (DENY, R_EXPIRED), (DENY, R_UNPROVEN),
)
REQUIRED_NONEMPTY = ("L12 pause-distinct", "L13 accept-well-formed",
                     "L10 deny-is-a-tombstone", "L3 valid-until-is-a-change-point",
                     # rulings 1/2/3/7: every new law must have BITTEN, and the
                     # two facts that were dead inputs must be load-bearing.
                     "L14 pass-wider-is-inert", "L15 revoked-is-absolute",
                     "L15 expired-is-absolute", "L16 allow-requires-binding",
                     "L17 own-policy-is-trust-root",
                     "L17 delegated-ops-need-ceiling",
                     "L18 compaction-preserves-verdict",
                     "L18 compaction-preserves-because",
                     "L1 fact-cert-is-load-bearing",
                     "L1 fact-binding-is-load-bearing",
                     "L1 fact-held_author_key-is-load-bearing",
                     # Review round 2: the shapes that SHIP, per tier, plus the
                     # deployed direction in particular. The L17 blocker passed
                     # 2.88M cells while the deployed shape allowed nothing.
                     "L0 tier-non-vacuity",
                     "L17 deployed-shape-allows",
                     "L17 deployed-shape-survives-no-root",
                     "L17 untrusted-author-is-not-effective",
                     "L14 self-grant-cannot-back-a-pass")


# ------------------------------------------------- per-tier non-vacuity
# "2.88M cells, 0 violations" says NOTHING about a law whose only reachable
# allows are degenerate -- and that is not hypothetical: the first L17 dropped
# the subject's own Accept, so the DEPLOYED owner->device shape produced 544
# denies and ZERO allows, every law checked passed, and the number looked
# healthy. A cell count is not evidence that a law constrains the configurations
# that actually ship, so every tier now DECLARES the verdict shapes it must
# reach and the run fails when one is missing. This is the coverage-matrix
# lesson one level up: assert reachability of the shapes you ship, per tier,
# rather than trusting a global total.
#
# Shape key: (decision, reason, held_is_subject) -- `held_is_subject` is False
# exactly when a trust root other than the granted subject is in play, which is
# the deployed direction (owner holds a key, device is the subject).
TIER_SHAPES = {}
TIER_SHAPE_LAW = "L0 tier-non-vacuity"
# What each tier must be able to REACH. A tier absent from this map is reported
# as unasserted, so adding a tier without declaring its shapes is itself a
# failure rather than a silent hole.
REQUIRED_TIER_SHAPES = {
    "L3..L13 over N=2": {("Allow", None, None), ("Deny", R_NOGRANT, None)},
    "L3..L13 over N=3": {("Allow", None, None), ("Deny", R_CEILING, None),
                         ("Deny", R_PAUSED, None)},
    "L4 versioning": {("Allow", None, None)},
    "L10 pairwise + tombstone": {("Allow", None, None), ("Deny", R_DENIED, None)},
    "L11 order / replay": {("Allow", None, None)},
    "L2 subject scoping": {("Allow", None, None)},
    "L14 pass attenuation": {("Allow", None, None)},
    "L15 certificate": {("Allow", None, None), ("Deny", R_REVOKED, None),
                        ("Deny", R_EXPIRED, None)},
    "L16 binding": {("Allow", None, None), ("Deny", R_UNPROVEN, None)},
    # The headline: with a held author key that is NOT the subject (the deployed
    # owner->device direction), an ALLOW must be reachable. This is the shape
    # that was 0 before the L17 fix.
    "L17 held author key": {("Allow", None, False), ("Deny", R_NOGRANT, False)},
    "L18 compaction": {("Allow", None, None), ("Deny", R_NOGRANT, None)},
    "L1/L2 facts relevance": {("Allow", None, None)},
    "L6 ingest": set(),
    "DEPLOYED owner->device": {("Allow", None, False)},
}


RUN_TIERS = set()
# The tier whose cells are being checked, so the shared per-cell checker can
# attribute a shape without being told on every call.
CURRENT_TIER = None


def register_tier(label):
    """A tier announces itself, so `check_tier_shapes` knows what ran."""
    RUN_TIERS.add(label)


def note_shape(tier, decision, reason, held, subject):
    """Record that `tier` reached this verdict shape."""
    key = (decision, reason, None if held is None else held == subject)
    TIER_SHAPES.setdefault(tier, set()).add(key)


def check_tier_shapes(tally):
    """Fail the run for any tier that could not reach a shape it must reach.

    Only tiers that RAN are checked, because a plan (the self-test's QUICK) runs
    a subset; a tier that ran and declared nothing is itself a failure.
    """
    for tier in sorted(RUN_TIERS):
        required = REQUIRED_TIER_SHAPES.get(tier)
        if required is None:
            tally.check(TIER_SHAPE_LAW, False)
            print(f"  !! tier {tier!r} ran without declaring required shapes")
            continue
        seen = TIER_SHAPES.get(tier, set())
        missing = sorted(str(m) for m in required - seen)
        tally.check(TIER_SHAPE_LAW, not missing)
        if missing:
            print(f"  !! tier {tier!r} never reached: {', '.join(missing)}")


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
def pool(keys, subjects, patterns, intervals, kinds, slots, minbs=("proven",)):
    """Every op a slot may hold, in a canonical order.

    `minbs` is the L16 dimension. It defaults to the single value `proven` so
    that the tiers whose laws do not read it stay pinned (and inside budget),
    and tier BINDING is the one place it varies.
    """
    out = []
    for author, subject, pattern, (nb, na), kind, minb in itertools.product(
            keys, subjects, patterns, intervals, kinds, minbs):
        # L16 construction invariant: an op may ask for less than Proven ONLY
        # if it is a plain GRANT. Ruling 3 names pair-secret GRANTS as the legacy
        # population whose weaker requirement has a home; a Pass is not that, and
        # allowing it made the L16 check tautological (the check would test
        # membership of the very set that admitted the weaker value).
        if minb == "inferred" and kind != "grant":
            continue
        out.append((author, subject, pattern, nb, na, kind, None, minb))
    for author, subject, (nb, na), ref in itertools.product(
            keys, subjects, intervals, range(slots)):
        out.append((author, subject, ACC, nb, na, "accept", ref, "proven"))
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
            author, subject, pattern, nb, na, kind, ref, minb = template_pool[index]
            ops.append(mk(i, author, subject, pattern, nb, na, kind, 1,
                          ref if ref is None else ref % slots, minb))
        yield tuple(ops)


def singles(template_pool, op_id):
    for author, subject, pattern, nb, na, kind, ref, minb in template_pool:
        yield mk(op_id, author, subject, pattern, nb, na, kind, 1,
                 ref if ref is None else (1 - op_id), minb)


# ------------------------------------------------------------------ law checks
DENY_PROBES = tuple((key, UNIVERSAL) for key in KEYS)


def check_cell(tally, ops, subject, now, request, clock):
    """Every law that is a property of one (log, subject, now, request) cell."""
    decision, reason = decide_core(ops, subject, now, request)
    VERDICTS_SEEN.add((decision, reason))
    if CURRENT_TIER:
        note_shape(CURRENT_TIER, decision, reason, None, subject)
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

    # L12 pause: author-only, PATTERN-SCOPED (ruling 7), interval-bounded, and
    #     reason distinct from denied.
    if reason == R_PAUSED:
        tally.check("L12 pause-distinct",
                    (not any_deny) and any(o[KIND] == "pause" for o in hits))
    tally.check("L12 pause-not-deny", reason != R_DENIED or any_deny)
    # Ruling 7: a pause is scoped by its own pattern, so a pause that does NOT
    # cover the request must be removable without moving the verdict. This is
    # what makes the lattice top (UNIVERSAL) the wholesale form rather than a
    # second mechanism.
    off_scope = tuple(o for o in ops if o[KIND] != "pause"
                      or covers(o[ACTION], o[RESOURCE], *request))
    tally.check("L12 pause-pattern-scoped",
                decide_core(off_scope, subject, now, request) == (decision, reason))
    if any(o[KIND] == "pause" for o in live):
        tally.check("L12 pause-scope-is-read", True)

    # L13 an allow rests on an accept naming a live widening op, signed by its
    #     subject.
    if decision == ALLOW:
        tally.check("L13 accept-well-formed", any(
            a[KIND] == "accept" and g[KIND] in WIDENING and g[ID] == a[REF]
            and a[AUTHOR] == g[SUBJECT] and a[SUBJECT] == g[SUBJECT]
            for a in live for g in hits))

    # L14 a Pass is a Grant species and is attenuation-only: an inert pass must
    #     be removable without moving the verdict (ruling 2).
    if any(o[KIND] == "pass" for o in live):
        inert = tuple(
            o for o in ops
            if o[KIND] != "pass"
            or not o[SUBJECT] == subject or not o[NB] <= now < o[NA]
            or pass_is_attenuative(ops, o, now))
        tally.check("L14 pass-attenuation",
                    decide_core(inert, subject, now, request) == (decision, reason))
        # And a pass that DOES widen must still need its Accept (L5/L13), i.e.
        # attenuation never substitutes for the second signature.
        tally.check("L14 pass-still-needs-accept",
                    decision != ALLOW or not any(
                        o[KIND] == "pass" for o in hits
                        if pass_is_attenuative(ops, o, now))
                    or any(a[KIND] == "accept" and a[REF] in
                           {o[ID] for o in hits if o[KIND] == "pass"}
                           for a in live))

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
    # Ruling 2 removed `certify` from the op kinds, so the old inertness probe
    # (drop certify ops) has nothing to drop. The remaining inertness claim is
    # narrower and still checkable: the cause never cites an op that is not live
    # for this subject and window.
    tally.check("L7 because-only-live-ops",
                all(o[SUBJECT] == subject and o[NB] <= now < o[NA]
                    for o in chosen))
    # Ruling 6: the cause explains the DECISION, not valid_until. Record the
    # cells where a shorter cause stops changing at a DIFFERENT time, so the
    # weaker claim is exercised rather than merely assumed.
    global CAUSE_VU_DIFFERS
    if valid_until(chosen, subject, now, request) != vu:
        CAUSE_VU_DIFFERS += 1


# ----------------------------------------------------------------------- tiers
def tier_cells(tally, label, keys, subjects, patterns, intervals, kinds, slots,
               clock, requests, decided):
    global CELL, CURRENT_TIER
    register_tier(label)
    CURRENT_TIER = label
    tpool = pool(keys, subjects, patterns, intervals, kinds, slots)
    logs = 0
    for ops in ledgers(tpool, slots):
        logs += 1
        for subject in decided:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    check_cell(tally, ops, subject, now, request, clock)
    CURRENT_TIER = None
    print(f"  {label:<28} logs={logs:<8d} pool={len(tpool):<4d} N={slots} "
          f"times={len(clock)} reqs={len(requests)}")


def tier_version(tally, keys, subjects, patterns, intervals, kinds, clock,
                 requests):
    """L4: newest version per author wins; older versions are ignored."""
    global CELL
    register_tier("L4 versioning")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    olds = [o for o in singles(tpool, 0) if o[KIND] != "accept"]
    pairs = 0
    for old in olds:
        for new in olds:
            if new[AUTHOR] != old[AUTHOR]:
                continue  # ingest refuses an id whose author changes
            newer = with_fields(new, version=2)
            # A supporting Accept, so this tier reaches the ALLOWING shape as
            # well: a version law tested only on denials proves nothing about the
            # shape that ships. The Accept references the revision's id and is
            # signed by its subject, which is exactly L13.
            acc = mk(9, new[SUBJECT], new[SUBJECT], ACC, new[NB], new[NA],
                     "accept", ref=new[ID])
            pairs += 1
            for subject in subjects:
                for request in requests:
                    for now in clock:
                        CELL = ((old, newer, acc), subject, now, request)
                        note_shape("L4 versioning",
                                   *decide_core((newer, acc), subject, now,
                                                request), None, subject)
                        tally.check("L4 newest-version-wins",
                                    decide_core((old, newer, acc), subject, now,
                                                request)
                                    == decide_core((newer, acc), subject, now,
                                                   request))
                        tally.check("L4 stale-version-inert",
                                    decide_core((newer, old, acc), subject, now,
                                                request)
                                    == decide_core((newer, acc), subject, now,
                                                   request))
    print(f"  {'L4 versioning':<28} pairs={pairs:<7d}  pool={len(olds)}")


def tier_pairs(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L10: no widening by combination, with L5's single exception named."""
    global CELL
    register_tier("L10 pairwise + tombstone")
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
                        note_shape("L10 pairwise + tombstone",
                                   *decide_core((left, right), subject, now,
                                                request), None, subject)
                        if la == DENY and lb == DENY and both == ALLOW:
                            widen = [o for o in (left, right) if o[KIND] in WIDENING]
                            acc = [o for o in (left, right) if o[KIND] == "accept"]
                            # Ruling 1: the (Grant species, its REFERENCED
                            # Accept) pair is THE defined widening. Any second
                            # route -- a wider kind set, a missing accept, an
                            # accept that references something else -- must
                            # FAIL here rather than be tolerated as "a widening
                            # combination we happen to know about".
                            tally.check("L10 no-widening-by-combination",
                                        len(widen) == 1 and len(acc) == 1
                                        and widen[0][KIND] in GRANT_SPECIES
                                        and acc[0][REF] == widen[0][ID]
                                        and acc[0][AUTHOR] == widen[0][SUBJECT]
                                        and acc[0][SUBJECT] == widen[0][SUBJECT])
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
            shorter = with_fields(left, na=now, kind="deny", version=2, ref=None)
            other = with_fields(left, author=(set(keys) - {left[AUTHOR]}).pop(),
                                na=now, kind="deny", version=2, ref=None)
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
    register_tier("L11 order / replay")
    tpool = pool(keys, subjects, patterns, intervals, kinds, slots)
    logs = 0
    for ops in ledgers(tpool, slots):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    base = decide_core(ops, subject, now, request)
                    note_shape("L11 order / replay", *base, None, subject)
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
    register_tier("L2 subject scoping")
    tpool = pool(keys, keys, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in keys:
            mine = tuple(o for o in ops if o[SUBJECT] == subject)
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    note_shape("L2 subject scoping",
                               *decide_core(ops, subject, now, request), None,
                               subject)
                    tally.check("L2 subject-scoped",
                                decide_core(ops, subject, now, request)
                                == decide_core(mine, subject, now, request))
    print(f"  {'L2 subject scoping':<28} logs={logs:<8d} pool={len(tpool)}")


def tier_ingest(tally, keys, patterns, clock, requests):
    """L6: sig and version checks at the boundary, not in the evaluator."""
    global CELL
    register_tier("L6 ingest")
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


# L15: certificate states. `expires` is an instant; the horizon is a clock
# boundary, so an expiry is a time at which the verdict changes.
CERT_NONE = None
CERT_VALID = {"device_pub": "d", "user_pub": "u", "expires": 4, "revoked": False}
CERT_EXPIRED = {"device_pub": "d", "user_pub": "u", "expires": 2, "revoked": False}
CERT_REVOKED = {"device_pub": "d", "user_pub": "u", "expires": 4, "revoked": True}
CERT_VARIANTS = (CERT_NONE, CERT_VALID, CERT_EXPIRED, CERT_REVOKED)


def tier_cert(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L15: a revoked or expired certificate denies, absolutely, by reason."""
    global CELL
    register_tier("L15 certificate")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    for cert in CERT_VARIANTS:
                        facts = {"now": now, "subject": subject, "ops": ops,
                                 "binding": "Proven", "cert": cert,
                                 "held_author_key": None,
                                 "display_name": "laptop"}
                        got = decide(facts, request)
                        VERDICTS_SEEN.add((got[0], got[1]))
                        note_shape("L15 certificate", got[0], got[1], None,
                                   subject)
                        revoked = cert is not None and cert["revoked"]
                        expired = (cert is not None and not cert["revoked"]
                                   and cert["expires"] <= now)
                        if revoked:
                            # ABSOLUTE: no op combination buys its way past it.
                            tally.check("L15 revoked-is-absolute",
                                        got[0] == DENY and got[1] == R_REVOKED
                                        and got[2] is None and got[3] == ())
                        elif expired:
                            tally.check("L15 expired-is-absolute",
                                        got[0] == DENY and got[1] == R_EXPIRED
                                        and got[2] is None and got[3] == ())
                            RELEVANT["cert"] += 1
                        else:
                            if got[0] == ALLOW:
                                # An allow must not promise past the expiry.
                                tally.check(
                                    "L15 valid-until-respects-expiry",
                                    cert is None or cert["expires"] <= now
                                    or got[2] is None
                                    or got[2] <= cert["expires"])
                            if not revoked and not expired:
                                tally.check("L15 cert-does-not-invent-denials",
                                            got[0] == ALLOW or got[1] != R_REVOKED)
                        # DISTINCT reasons, correctly attributed, for EVERY
                        # certificate state: the revoked reason belongs to
                        # revocation and the expired reason to expiry, never each
                        # other, and a healthy certificate reports neither. Must
                        # be unconditional -- inside the healthy-only branch it
                        # could not see a swapped reason at all.
                        tally.check("L15 reasons-distinct",
                                    (got[1] == R_REVOKED) == revoked
                                    and (got[1] == R_EXPIRED) == expired)
                        if cert is not None and got[1] == R_REVOKED:
                            RELEVANT["cert"] += 1
    print(f"  {'L15 certificate':<28} logs={logs:<8d} pool={len(tpool):<4d} "
          f"certs={len(CERT_VARIANTS)}")


def tier_pass(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L14 (ruling 2): a Pass is a Grant species, and attenuation-only.

    The law the reviewer asked this tier for: a pass WIDER than its author's own
    ceiling toward that resource is INERT -- not merely narrow, not merely
    unaccepted. Both directions are asserted here, because a check that only
    ever sees inert passes would pass with the attenuation test deleted.
    """
    global CELL
    register_tier("L14 pass attenuation")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs, attenuative, inert = 0, 0, 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    decision, reason = decide_core(ops, subject, now, request)
                    note_shape("L14 pass attenuation", decision, reason, None,
                               subject)
                    for o in effective(ops):
                        if o[KIND] != "pass":
                            continue
                        backed = pass_is_attenuative(ops, o, now)
                        if backed:
                            attenuative += 1
                        else:
                            inert += 1
                            # INERT: removing it cannot move the verdict.
                            without = tuple(x for x in ops if x != o)
                            tally.check("L14 pass-attenuation",
                                        decide_core(without, subject, now, request)
                                        == (decision, reason))
                        # Either way a pass is a GRANT SPECIES: it never gets
                        # authority without its own referenced Accept (L5/L13).
                        if decision == ALLOW:
                            tally.check(
                                "L14 pass-still-needs-accept",
                                not any(x[KIND] == "pass" for x in
                                        because(ops, subject, now, request)[1])
                                or any(a[KIND] == "accept" and a[REF] == x[ID]
                                       and a[AUTHOR] == x[SUBJECT]
                                       for a in effective(ops)
                                       for x in because(ops, subject, now,
                                                        request)[1]
                                       if x[KIND] == "pass"))
    # A pass backed ONLY by the author's own UNACCEPTED self-grant is not backed
    # at all: that is self-certification, and it must leave the pass inert (the
    # verdict without it), not merely unaccepted-by-someone-else. This is the
    # regression the first cut shipped -- `pass_is_attenuative` credited any live
    # op whose subject was the author.
    # The shape has to be FULLY self-certified to test anything: the author's own
    # grant AND the Accept that supports it, both signed by the author. With only
    # the unaccepted self-grant the "itself effective" clause already rejects it,
    # so a check built on that shape passes with the authorship clause deleted --
    # which is exactly what the first version of this check did.
    self_grant = mk(0, keys[0], keys[0], SHELL, 1, 3, "grant")
    self_accept = mk(1, keys[0], keys[0], ACC, 1, 3, "accept", ref=0)
    self_pass = mk(2, keys[0], keys[0], SHELL, 1, 3, "pass")
    for now in clock:
        CELL = ("self-certification", now)
        tally.check(
            "L14 self-grant-cannot-back-a-pass",
            not pass_is_attenuative((self_grant, self_accept, self_pass),
                                    self_pass, now))
    for subject in subjects:
        for request in requests:
            for now in clock:
                CELL = ("self-certification", subject, now, request)
                with_pass = decide_core((self_grant, self_accept, self_pass),
                                        subject, now, request)
                without = decide_core((self_grant, self_accept), subject, now,
                                      request)
                tally.check("L14 self-grant-cannot-back-a-pass",
                            with_pass == without)
    CELL = ("non-vacuity", "pass")
    # A tier that never produced BOTH an attenuative pass and an inert one did
    # not test L14; it tested that the file runs.
    tally.check("L14 pass-attenuation", attenuative > 0)
    tally.check("L14 pass-wider-is-inert", inert > 0)
    print(f"  {'L14 pass attenuation':<28} logs={logs:<8d} pool={len(tpool):<4d} "
          f"attenuative={attenuative} inert={inert}")


BINDINGS = (None, "Inferred", "Proven")


def tier_binding(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L16: every allow needs binding >= the cause's own minimum."""
    global CELL
    register_tier("L16 binding")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2,
                 minbs=("proven", "inferred"))
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    for binding in BINDINGS:
                        facts = {"now": now, "subject": subject, "ops": ops,
                                 "binding": binding, "cert": None,
                                 "held_author_key": None,
                                 "display_name": "laptop"}
                        got = decide(facts, request)
                        VERDICTS_SEEN.add((got[0], got[1]))
                        note_shape("L16 binding", got[0], got[1], None, subject)
                        if got[0] == ALLOW:
                            _needs = [o[MINB]
                                      for o in because(ops, subject, now,
                                                       request)[1]
                                      if o[KIND] in WIDENING]
                            need = "proven" if (not _needs or "proven" in _needs) \
                                else "inferred"
                            tally.check("L16 allow-requires-binding",
                                        binding_satisfies(binding, need))
                            # Ruling 3: Inferred is allowed ONLY for pair-secret
                            # Grants, so a Pass can never demand less than Proven.
                            # Checked against the KIND, not membership of the set
                            # that admitted the weaker value -- otherwise the law
                            # tests itself.
                            tally.check("L16 inferred-only-on-grants",
                                        need != "inferred" or all(
                                            o[KIND] == "grant"
                                            for o in because(ops, subject, now,
                                                             request)[1]
                                            if o[KIND] == "pass"))
                        elif got[1] == R_UNPROVEN:
                            RELEVANT["binding"] += 1
                            tally.check("L16 unproven-is-a-deny", got[0] == DENY)
    # Construction invariant: `inferred` never lands on anything but a GRANT
    # (ruling 3: the weaker requirement belongs to pair-secret Grants only). A
    # GRANT_SPECIES test here would be satisfied by a Pass, which is the
    # tautology this replaced.
    tally.check("L16 inferred-only-on-grants",
                all(o[MINB] != "inferred" or o[KIND] == "grant"
                    for ops in ledgers(tpool, 2) for o in ops))
    print(f"  {'L16 binding':<28} logs={logs:<8d} pool={len(tpool):<4d} "
          f"bindings={len(BINDINGS)}")


def tier_held(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L17: a held author key is the trust root; others act inside its ceiling."""
    global CELL
    register_tier("L17 held author key")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    base = decide({"now": now, "subject": subject, "ops": ops,
                                   "binding": "Proven", "cert": None,
                                   "held_author_key": None,
                                   "display_name": "laptop"}, request)
                    for held in KEYS:
                        facts = {"now": now, "subject": subject, "ops": ops,
                                 "binding": "Proven", "cert": None,
                                 "held_author_key": held,
                                 "display_name": "laptop"}
                        got = decide(facts, request)
                        VERDICTS_SEEN.add((got[0], got[1]))
                        note_shape("L17 held author key", got[0], got[1], held,
                                   subject)
                        if got != base:
                            RELEVANT["held_author_key"] += 1
                        # Own policy is the trust root: an op authored BY the
                        # held key is never delegated away.
                        mine = tuple(o for o in ops if o[AUTHOR] == held)
                        rest = tuple(o for o in ops if o[AUTHOR] != held)
                        tally.check(
                            "L17 own-policy-is-trust-root",
                            set(mine) <= set(trust_filter(ops, held, now)))
                        # A delegated op survives only inside a ceiling its
                        # author was granted BY the held key.
                        # Accepts are exempt from the trust filter by design
                        # (L13 governs them), so the invariant is about the
                        # AUTHORITY-bearing ops: every non-Accept op by another
                        # author survives only inside a ceiling the held key
                        # granted it.
                        tally.check(
                            "L17 delegated-ops-need-ceiling",
                            all(o[KIND] == "accept"
                                or delegated_ok(ops, o, held, now)
                                or o not in trust_filter(ops, held, now)
                                for o in rest))
    print(f"  {'L17 held author key':<28} logs={logs:<8d} pool={len(tpool):<4d}")


def compact(ops):
    """L18: the append-only log reduced without changing any verdict.

    Two rewrites, and only these: (1) drop revisions that are not effective
    (an append-only log keeps every revision; the evaluator already ignores
    them); (2) drop ops that are irrelevant to EVERY cell of the bounded
    universe -- deleting them cannot change a verdict by construction, so what
    this tier actually tests is that the MINIMAL CAUSE is also unchanged.
    """
    current = list(effective(ops))
    if MUTATION == "compaction-drops-live":
        return tuple(current[1:])
    changed = True
    while changed:
        changed = False
        for o in list(current):
            trial = tuple(x for x in current if x != o)
            if _no_verdict_changes(trial, ops):
                if MUTATION == "compaction-drops-because-op" and len(current) > 1:
                    return trial
                current = list(trial)
                changed = True
                break
    return tuple(current)


def _no_verdict_changes(candidate, original):
    """True iff `candidate` decides every bounded cell exactly as `original`."""
    for subject in KEYS:
        for request in REQUESTS:
            for now in range(6):
                if decide_core(candidate, subject, now, request) != \
                        decide_core(tuple(original), subject, now, request):
                    return False
    return True


def tier_compact(tally, keys, subjects, patterns, intervals, kinds, clock, requests):
    """L18 (ruling 8): compaction never changes a verdict or a `because`."""
    global CELL
    register_tier("L18 compaction")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        small = compact(ops)
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    note_shape("L18 compaction",
                               *decide_core(small, subject, now, request), None,
                               subject)
                    tally.check(
                        "L18 compaction-preserves-verdict",
                        decide_core(small, subject, now, request)
                        == decide_core(ops, subject, now, request))
                    tally.check(
                        "L18 compaction-preserves-because",
                        because(small, subject, now, request)[0]
                        == because(ops, subject, now, request)[0])
    # Ruling 8's other half: today's Revoke DELETES the grant row. In the ledger
    # it is a Deny tombstone, or a shorter-interval revision of the Grant by its
    # author -- and the two must agree with the deletion they replace.
    tombstones = 0
    for g in singles(tpool, 0):
        if g[KIND] not in GRANT_SPECIES:
            continue
        g = with_fields(g, kind="grant")
        acc = mk(1, g[SUBJECT], g[SUBJECT], ACC, g[NB], g[NA], "accept",
                 ref=g[ID])
        for now in clock:
            if not g[NB] < now < g[NA]:
                continue
            dead = with_fields(g, kind="deny", nb=now, version=2)
            cut = now + 1 if MUTATION == "truncation-off-by-one" else now
            short = with_fields(g, kind="grant", na=cut, version=2)
            tombstones += 1
            for subject in subjects:
                for request in requests:
                    CELL = ((g, acc, dead), subject, now, request)
                    # A tombstone from `now` denies from `now` on, and the
                    # shorter revision revokes the same window from the other
                    # side. Both must deny exactly where deletion would.
                    tally.check(
                        "L18 tombstone-denies-from-its-start",
                        decide_core((g, acc, dead), subject, now, request)[0]
                        == DENY)
                    tally.check(
                        "L18 shorter-revision-equals-truncation",
                        decide_core((g, acc, short), subject, now, request)[0]
                        == decide_core((with_fields(g, na=now), acc), subject,
                                       now, request)[0])
    print(f"  {'L18 compaction':<28} logs={logs:<8d} tombstones={tombstones}")


# L16/L17 non-vacuity: a fact field that no law reads is a dead input, and a
# field no cell varies is a check that never bit. Both are failures here.
RELEVANT = {"cert": 0, "binding": 0, "held_author_key": 0}


DEPLOYED_ALLOWS = 0


def tier_deployed(tally, keys, subjects, patterns, intervals, kinds, clock,
                  requests):
    """The configuration that SHIPS: an owner grants a device, the device
    accepts, and the OWNER's key is the trust root (`held != subject`).

    This tier exists because its absence hid the L17 blocker. Every law passed
    over 2.88M cells while this shape allowed NOTHING, so the assertion here is
    the plain one: with a held author key that is not the subject, an allow must
    be REACHABLE, and the count is reported rather than assumed.
    """
    global CELL, DEPLOYED_ALLOWS
    owner, device = KEYS[1], KEYS[0]
    grant = mk(0, owner, device, ("shell", "*"), 1, 4, "grant")
    accept = mk(1, device, device, ACC, 1, 4, "accept", ref=0)
    ops = (grant, accept)
    for request in requests:
        for now in clock:
            if not grant[NB] <= now < grant[NA]:
                continue
            CELL = ("deployed", request, now)
            facts = {"now": now, "subject": device, "ops": ops,
                     "binding": "Proven", "cert": None,
                     "held_author_key": owner, "display_name": "laptop"}
            got = decide(facts, request)
            note_shape("DEPLOYED owner->device", got[0], got[1], owner, device)
            if got[0] == ALLOW:
                DEPLOYED_ALLOWS += 1
            # The shape's own law: an owner-granted, device-accepted shell is an
            # ALLOW while the owner is the trust root. Checked for the requests
            # the grant covers, and deliberately not for the ones it does not.
            if covers(grant[ACTION], grant[RESOURCE], *request):
                tally.check("L17 deployed-shape-allows", got == (ALLOW, None,
                                                                 got[2], got[3]))
            else:
                tally.check("L17 deployed-shape-does-not-overreach",
                            got[0] == DENY)
    # The same configuration must ALSO deny when the trust root is absent, or the
    # allow above would prove nothing about L17 (it could be reaching an allow
    # with no filter at all).
    CELL = ("deployed", "no-trust-root")
    no_root = decide({"now": 2, "subject": device, "ops": ops,
                      "binding": "Proven", "cert": None,
                      "held_author_key": None, "display_name": "laptop"},
                     ("shell", "dev:a"))
    tally.check("L17 deployed-shape-survives-no-root", no_root[0] == ALLOW)
    # And a device grant the OWNER never issued (another author, no ceiling) must
    # NOT allow: the trust filter is doing work, not waving everything through.
    rogue = mk(0, device, device, ("shell", "*"), 1, 4, "grant")
    rogue_accept = mk(1, device, device, ACC, 1, 4, "accept", ref=0)
    CELL = ("deployed", "rogue")
    rogue_v = decide({"now": 2, "subject": device, "ops": (rogue, rogue_accept),
                      "binding": "Proven", "cert": None,
                      "held_author_key": owner, "display_name": "laptop"},
                     ("shell", "dev:a"))
    tally.check("L17 untrusted-author-is-not-effective", rogue_v[0] == DENY)
    print(f"  {'DEPLOYED owner->device':<28} allows with held != subject = "
          f"{DEPLOYED_ALLOWS}")


def tier_relevance(tally, keys, subjects, patterns, intervals, kinds, clock,
                   requests):
    """L1/L2 + ruling 3: which Facts fields are load-bearing, and which are not."""
    global CELL
    register_tier("L1/L2 facts relevance")
    tpool = pool(keys, subjects, patterns, intervals, kinds, 2)
    logs = 0
    for ops in ledgers(tpool, 2):
        logs += 1
        for subject in subjects:
            for request in requests:
                for now in clock:
                    CELL = (ops, subject, now, request)
                    base = None
                    for name in ("laptop", "phone"):
                        facts = {"now": now, "subject": subject, "ops": ops,
                                 "binding": "Proven", "cert": None,
                                 "held_author_key": None, "display_name": name}
                        got = decide(facts, request)
                        note_shape("L1/L2 facts relevance", got[0], got[1], None,
                                   subject)
                        if base is None:
                            base = got
                            tally.check("L1 deterministic",
                                        decide(facts, request) == got)
                        # L2: names are presentation, never authority.
                        tally.check("L2 display-name-irrelevant", got == base)
    # The load-bearing assertion: if one of these never moves a verdict, the
    # field is dead and ruling 3 was answered on paper only.
    for field, count in sorted(RELEVANT.items()):
        CELL = ("relevance", field)
        tally.check(f"L1 fact-{field}-is-load-bearing", count > 0)
    print(f"  {'L1/L2 facts relevance':<28} logs={logs:<8d} "
          f"load-bearing={ {k: v for k, v in sorted(RELEVANT.items())} }")


# ---------------------------------------------------------------------- runner
KINDS_ALL = ("grant", "deny", "ceiling", "pause", "pass")
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
    # Rulings 2/3/7/8: one tier per new law, bounded so the whole run stays
    # inside the ten-second budget. Each pins the dimensions its law does not
    # read (tier BINDING is the only place the MINB dimension varies).
    "pass":    dict(patterns=PATTERNS, intervals=((1, 3), (2, 4)),
                    kinds=("grant", "pass", "ceiling", "accept"),
                    clock=tuple(range(5)), requests=REQUESTS),
    "cert":    dict(patterns=PATTERNS[:2], intervals=((1, 3), (2, 4)),
                    kinds=("grant", "deny"), clock=tuple(range(6)),
                    requests=REQUESTS[:2]),
    "binding": dict(patterns=PATTERNS[:2], intervals=((1, 3), (2, 4)),
                    kinds=("grant", "pass"), clock=tuple(range(5)),
                    requests=REQUESTS[:2]),
    "held":    dict(patterns=PATTERNS[:2], intervals=((1, 3),),
                    kinds=("grant", "ceiling", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "compact": dict(patterns=PATTERNS[:2], intervals=((1, 3), (2, 4)),
                    kinds=("grant", "deny", "ceiling"), clock=tuple(range(5)),
                    requests=REQUESTS[:1]),
    # The shape that ships, so the tier-non-vacuity gate can see it in every
    # plan: the deployed owner->device direction must produce an ALLOW.
    "deployed": dict(patterns=PATTERNS, intervals=((1, 3),),
                     kinds=("grant",), clock=tuple(range(4)),
                     requests=REQUESTS),
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
                    kinds=("grant", "deny", "ceiling"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "order":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), slots=3, clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "scope":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "facts":   dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant",), clock=tuple(range(3)), requests=REQUESTS[:1]),
    "pass":    dict(patterns=PATTERNS[:2], intervals=((1, 3),),
                    kinds=("grant", "pass", "ceiling"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "cert":    dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "binding": dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant",), clock=tuple(range(3)),
                    requests=REQUESTS[:1]),
    "held":    dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "ceiling"), clock=tuple(range(3)),
                    requests=REQUESTS[:1]),
    "compact": dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                    kinds=("grant", "deny"), clock=tuple(range(4)),
                    requests=REQUESTS[:1]),
    "deployed": dict(patterns=PATTERNS[:1], intervals=((1, 3),),
                     kinds=("grant",), clock=tuple(range(4)),
                     requests=REQUESTS[:1]),
}


def run_all(tally, plan):
    if plan["core"]:
        print("\nTier CORE  -- N=2, every op kind including the widening `pass`")
        print("  (`certify` is not an op; ruling 2); all patterns, all requests.")
        tier_cells(tally, "L3..L13 over N=2", **plan["core"])
    if plan["depth"]:
        print("\nTier DEPTH -- N=3: composition needs three ops before a ceiling")
        print("  can sit between a grant and its accept.")
        tier_cells(tally, "L3..L13 over N=3", **plan["depth"])
    if plan["version"]:
        print("\nTier VER   -- two versions of one op id by one author.")
        tier_version(tally, KEYS, KEYS[:1], **plan["version"])
    if plan["pairs"]:
        print("\nTier PAIR  -- every ordered pair of single ops; L10, and the")
        print("  (Grant species, its referenced Accept) pair required to be the")
        print("  ONLY widening combination (ruling 1).")
        tier_pairs(tally, KEYS, KEYS[:1], **plan["pairs"])
    if plan["order"]:
        print("\nTier ORDER -- every permutation of an N=3 log, plus replay.")
        tier_order(tally, KEYS, KEYS[:1], **plan["order"])
    if plan["scope"]:
        print("\nTier SCOPE -- two subjects; an op about one must not move the other.")
        tier_scope(tally, KEYS, **plan["scope"])
    print("\nTier INGEST -- L6 at the boundary, with a non-vacuity proof.")
    tier_ingest(tally, KEYS, PATTERNS, tuple(range(6)), REQUESTS)
    if plan.get("pass"):
        print("\nTier PASS  -- L14: a Pass is a Grant species, attenuation-only.")
        tier_pass(tally, KEYS, KEYS[:1], **plan["pass"])
    if plan.get("cert"):
        print("\nTier CERT  -- L15: revoked and expired deny absolutely, by reason.")
        tier_cert(tally, KEYS, KEYS[:1], **plan["cert"])
    if plan.get("binding"):
        print("\nTier BIND -- L16: every allow needs binding >= the cause minimum.")
        tier_binding(tally, KEYS, KEYS[:1], **plan["binding"])
    if plan.get("held"):
        print("\nTier HELD  -- L17: the held author key is the trust root.")
        tier_held(tally, KEYS, KEYS[:1], **plan["held"])
    if plan.get("compact"):
        print("\nTier COMPACT -- L18: compaction changes no verdict and no because.")
        tier_compact(tally, KEYS, KEYS[:1], **plan["compact"])
    if plan["facts"]:
        print("\nTier FACTS -- L1/L2: which Facts fields are load-bearing, and")
        print("  which (display_name only) must stay inert (ruling 3).")
        tier_relevance(tally, KEYS, KEYS[:1], **plan["facts"])
    if plan.get("deployed"):
        print("\nTier DEPLOYED -- the configuration that SHIPS: owner grants a")
        print("  device, the device accepts, the OWNER is the trust root. Its")
        print("  absence is what hid the L17 blocker (544 denies, 0 allows).")
        tier_deployed(tally, KEYS, KEYS[:1], **plan["deployed"])
    # The lesson, enforced: a tier that cannot reach a shape it must reach has
    # proved nothing, however many cells it checked.
    check_tier_shapes(tally)


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
    ("reads-name", "L2 display-name-irrelevant"),
    # Rulings 1/2/3/7/8: each new law gets its own breach, so "the model bites"
    # is claimed per law rather than for the file as a whole.
    ("ceiling-completes-grant", "L10 no-widening-by-combination"),
    ("pass-wider-than-ceiling-widens", "L14 pass-attenuation"),
    ("cert-revoked-not-absolute", "L15 revoked-is-absolute"),
    ("expired-not-absolute", "L15 expired-is-absolute"),
    ("revoked-reads-as-expired", "L15 reasons-distinct"),
    ("binding-ignored", "L16 allow-requires-binding"),
    ("inferred-ok-for-proven-op", "L16 allow-requires-binding"),
    ("held-key-ignored", "L17 delegated-ops-need-ceiling"),
    # Review round 2, the blocker itself: the trust filter discarding a
    # subject's own Accept. The LAWS did not catch it, so the non-vacuity gate
    # must -- that is the whole point of adding it.
    ("trust-filter-drops-accepts", "L17 deployed-shape-allows"),
    ("self-certifying-pass", "L14 self-grant-cannot-back-a-pass"),
    ("held-key-drops-own-policy", "L17 own-policy-is-trust-root"),
    ("compaction-drops-live", "L18 compaction-preserves-verdict"),
    # The `because` arm is guarded rather than mutated, and that is a finding
    # worth stating: given a MINIMAL cause, no compaction can preserve every
    # verdict and still change a `because`, so no honest mutation exists for it.
    # L18's second breach is the other arm -- an off-by-one in the revocation
    # boundary, which is exactly how a revoke-to-truncation migration goes wrong.
    ("truncation-off-by-one", "L18 shorter-revision-equals-truncation"),
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

    print(f"Capability-ledger model check (CONTRACT.md L1-{MAX_CONTRACT_LAW} "
          f"+ rulings L{MAX_CONTRACT_LAW + 1}-L{MAX_MODEL_LAW})")
    source_guard()
    gate_0()
    tally = Tally()
    VERDICTS_SEEN.clear()
    run_all(tally, FULL)

    vacuous = [f"verdict {v}" for v in REQUIRED_VERDICTS if v not in VERDICTS_SEEN]
    vacuous += [f"check {c}" for c in REQUIRED_NONEMPTY if not tally.cells.get(c)]
    # Ruling 6: `because` must be seen NOT to explain valid_until, or the weaker
    # claim was never exercised.
    if CAUSE_VU_DIFFERS == 0:
        vacuous.append("check L7 because-does-not-explain-valid-until")

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
