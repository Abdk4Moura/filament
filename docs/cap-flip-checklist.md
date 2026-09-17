# Capability authoritative-flip checklist

> **FLIP REVERTED — 0.7.1.** The 0.7.0 default-on throw was premature. Real
> same-owner fleets show `flip_ready=false`: paired daemons aren't provisioned,
> so authoritative-by-default denied the owner's OWN ssh/transfer/mount until
> every capability was granted by hand. `cap_authoritative()` now defaults to
> OFF (legacy shadow gating) again; authoritative enforcement is **opt-in** via
> `FILAMENT_CAP_AUTHORITATIVE=1` (or `true`). Any other value, or leaving it
> unset, keeps shadow gating. Everything else the flip added (self-genesis
> header, restrictive gates, shell-key reconciler) stays; only the default
> changed. Re-throwing the default-on flip is gated on same-owner fleet-trust
> (auto-provision paired same-owner daemons so `flip_ready` holds on a real
> fleet), not just the single-node evidence below.
>
> **Prior throw (2026-07-29, 0.7.0, now reverted).** `cap_authoritative()`
> defaulted to ON. The single-node prerequisite checklist below was satisfied
> per the "Validation status" evidence trail (enforcement matrix proven
> cross-machine 2026-07-28: grant->allow, revoke->deny+key-removed,
> deny-by-default, real reasons, rollback, trust-floor, sandbox-contained
> reconciler) — but that evidence did not cover an unprovisioned multi-device
> same-owner fleet, which is what broke. History retained below.

Prerequisites for setting `FILAMENT_CAP_AUTHORITATIVE=1` (making the capability
layer the live gate instead of shadow). Do NOT flip until every item holds. The
first week after a flip is exactly when someone reads the denial logs to work out
what broke, so the diagnosability items matter as much as the correctness ones.

Owner: whoever writes the flip commit. Cite the evidence in that commit.

## Hard gate (ShadowCounts::flip_ready)

- [ ] `la_authorized > 0`: a real, meaningful sample of legacy-ALLOWED opens was
      observed on real traffic (not a token count, not a legacy-DENIED-only sample).
- [ ] `la_denied == 0`: no header that EXISTS disagreed with a legacy-allowed open
      (no BREAKAGE). Any `CAP-SHADOW CRITICAL` line is a blocker; fix the grant or
      the header, do not reinterpret the criterion.
- [ ] `la_no_header == 0`: every resource EXERCISED in the window was provisioned.
      Caveat: this proves it for resources exercised, not all resources. Tight today
      (all gates pass "self", one resource); becomes a sampled claim when resources
      multiply, revisit then.
- [ ] `la_narrowed` reviewed (informational, not a gate, and NOT part of
      `flip_ready`): opens legacy allowed and the layer refuses because the
      subject is not covered by any ceiling or grant. This is the flip CLOSING a
      legacy hole (pairing alone used to suffice) -- intended. A NONZERO value
      is expected on any fleet that has ever had a peer try to claim another
      device's name; enumerate the population before the flip so the number is
      explained rather than surprising. Its verdict text is
      `CAP-SHADOW cap-narrows-legacy` at Info, never CRITICAL.
- [ ] `ceiling_admitted` reviewed (informational, not a gate): opens allowed
      by fleet auto-trust WITHOUT an explicit grant (enrolment-ceiling
      admission). Widening is reviewed, not gated -- cite the count alongside
      the `ld_authorized` numbers and enumerate which opens it names before
      the flip, same as any other newly-permitted population.

Read these from the running daemon via the shadow-status surface (task #16), since
the counters are process-global and a fresh CLI invocation reads zeros.

## FLIP BLOCKER: fleet devices cannot re-prove identity after an owner restart

Measured on `cli/tests/fleet-cert-gates.sh` gate AUTH-A (currently KNOWN-RED,
https://github.com/Abdk4Moura/filament/issues/312): after the owner daemon
restarts, the possession challenge does not reach the peer on the link that is
carrying its traffic, so a covered shell-class open is refused under
authoritative mode until the peer reconnects cleanly. The defect is in the link,
not in the authz layer: a primary transport can go writable-but-deaf because its
reader exits silently on a QUIC `FinishedEarly` without marking the link dead
(`crates/filament-transport/src/direct.rs:1410`, `:1436`). Shadow mode masks it
entirely (legacy decides), which is why it went unnoticed.

Consequence for the flip: in shadow this is invisible; under authoritative it
locks out every fleet device that is mid-reconnect after an owner restart. Do NOT
flip until #312 is fixed and AUTH-A is green first-try.

## Mandatory review citation (not a boolean)

- [ ] Cite `ld_authorized`, the WIDENING count: opens legacy REFUSED that cap
      AUTHORIZES, which the flip will newly PERMIT. If nonzero, enumerate the
      distinct `(action, resource, device)` triples from the `CAP-SHADOW WIDENING`
      log and justify each: why should this access, absent before, exist now? This
      is the direction access appears silently; a migration to deny-by-default must
      not grant new access unseen.

## Diagnosability (fix before flip, correct in shadow so not shipped yet)

- [ ] Gate-level denial strings must defer to the cap outcome under authoritative.
      All five are currently worded for the LEGACY cause (l2-open "device not granted
      shell"; shell-bootstrap / pty "no shell cap / untrusted"; file-offer daemon
      "unverified peer"; mount "not authorized (mount capability required)"). Under
      authoritative these can be flatly false: a peer refused because the resource is
      UNPROVISIONED gets told "unverified peer", pointing the debugger at trust when
      the fix is to provision a header. A confidently wrong diagnostic is worse than
      silence. Fix: have `cap_gate_effective` hand back the reason it already computes
      (Denied vs Unprovisioned) so each gate says what actually happened rather than
      what usually does. The bool return currently discards that string.

## Performance

- [x] `load_cap_store` cache with invalidation. DONE (#27): nanosecond-mtime cache,
      explicitly invalidated inside `save_cap_store` (the single write funnel; all
      persists go through `save_and_list_revoked` -> `save_cap_store`). Nanosecond (not
      seconds) mtime so a sub-second direct rewrite can't serve stale data. Known
      follow-up (non-blocking): `save_cap_store` still uses `std::fs::write` (non-atomic),
      unlike the devices.json path made atomic in #23; deferred under the clean-slate call.

## Correctness corroboration (owed by capability.rs owner)

- [ ] Self genesis header is trusted local state: its signature is decorative (not
      verified on the authorize path). The header's sig is over the self-certifying
      resource id (SHA-256(owner_pub||nonce)), but the stored header has
      resource="self" after signing. cap_authorize/evaluate never calls
      verify_genesis/verify_sig on it (those run only on the grant-creation path).
      Consistent with Cmd::Grant which does the same. `la_no_header == 0` on a
      provisioned node corroborates this empirically, but confirm it structurally too.

## Authoritative-only restrictive gates (added, all purely restrictive)

Under `FILAMENT_CAP_AUTHORITATIVE` the effective decision is composed from the cap
outcome plus these gates, each of which can only downgrade Authorized -> Denied,
never widen. All are no-ops in shadow. Each has a both-branches CI test.

- [x] #21 binding-strength: a cap-authorized open with binding != `Proven` (identity
      not device_priv-proven) is denied. `cap_authorize_proven`.
- [x] #22 cert-expiry: re-checked per authorize (not only at resolve); expired or
      unknown-expiry (None) fails closed. `cap_authorize_expired`.
- [x] #26 trust floor: for gates whose legacy check is trust-based (transfer, mount),
      an untrusted link (not pair-proven) is denied even if cap-authorized. Prevents the
      flip from silently swapping the trust basis from pair-proof to device-key.
      `cap_trust_floor`. Shell is exempt (its legacy check is capability-equivalent).

### Caveat: shadow counters are BLIND to these gates

The shadow counters (and therefore `flip_ready`) bucket the raw cap-STORE outcome.
The restrictive gates above are no-ops in shadow, so `flip_ready == true` means
"the cap store agrees with legacy", NOT "the full authoritative gate agrees with
legacy." A peer that is la_authorized in shadow can still be denied at the flip by a
restrictive gate (e.g. an Inferred-binding, shell-granted peer). Do NOT read
`flip_ready` as "nothing breaks at the flip." If a breakage-accurate sample is ever
needed, the counters must apply the restrictive gates as-if-authoritative for the
COUNTING (separate from the returned decision).

## Migration (#25): RESOLVED — no migration, clean slate

Owner decision (2026-07-27): there is no install base to preserve, so the flip
simply reconciles away any device that is legacy-shell-authorized but has no cap
grant (hard cutover). No preview command, no auto-migrate. The blast-radius
enumeration exists if ever needed (`devices_with_shell_revoked` / the `CAP-SHADOW
RECONCILE: WOULD remove` log lines), but is not a gating concern for this flip.

## Validation status (as of this session)

- [x] Cap gate LOGIC: proven by unit tests (feat 054f41d, full binary suite green,
      incl. both-branches tests for every restrictive gate).
- [x] Shadow SAMPLING on real traffic: proven (la_authorized=3, shell+mount coverage,
      zero disagreement, single stable daemon PID). Instrument proven by the six-bucket
      detector-proof.
- [x] Authoritative grant / evaluate / cap-status display: confirmed working under
      `FILAMENT_CAP_AUTHORITATIVE=1`.
- [~] Live-traffic authoritative ENFORCEMENT: PARTIAL, proven cross-machine (do-vm <->
      4-days-late/other-do over Tailscale, same DC, 2026-07-28). The same-box rig could
      not establish transport (a same-box/loopback limitation, NOT a cap issue); the
      cross-machine rig works. Demonstrated on real cross-machine traffic:
        * transport + file transfer establish and complete cross-machine;
        * the cap gate FIRES on real traffic (counters move, coverage matrix records);
        * DENY-BY-DEFAULT enforced: an unprovisioned transfer that legacy ALLOWS (delivered
          in shadow) is DECLINED under FILAMENT_CAP_AUTHORITATIVE=1;
        * #19 real reason surfaced: "resource unprovisioned (no capability header); run
          filament grant/init" (the true cap cause, not a legacy assertion);
        * ROLLBACK: unsetting the flag returns to legacy gating, the transfer delivers again;
        * SANDBOX HELD: the live destructive reconciler ran under sandboxed HOME; do-vm's
          real ~/.ssh/authorized_keys byte-identical before/after.
      GRANTED->ALLOW now VERIFIED (2026-07-28, after #29 + #30): a granted peer's FIRST
      transfer under authoritative DELIVERS (cap-status transfer la_ok=1, "identity proven"
      logged), ungranted/unproven still denied. Required #29 (pairing exchanges deviceCert)
      AND #30 (in-session possession-sig sets binding=Proven: challenge fires after resolve,
      the async send is awaited, the sender answers via a shared responder, and the offer
      honors the pending_proven hold). So allow + deny + rollback + deny-by-default + real
      reasons are all proven on live cross-machine traffic.
      REVOKED->DENY+SSH-KEY-REMOVED now VERIFIED too (2026-07-28, commit 4b1fa91): grant shell ->
      first ssh ALLOWED + managed key installed; revoke -> real authoritative removal ("shell-key
      reconcile (revoke): removing..."), caps.json 0 grants, next ssh DENIED "not authorized", key
      NOT re-installed, authorized_keys byte-identical (sandbox). Closing this surfaced a real bug:
      Cmd::Revoke never emitted a Revoke cap_op (only legacy device_set_cap), so under authoritative
      the gate stayed Authorized and re-installed the key on the next open (widen=1) and the #24
      reconciler never fired — now revoke emits an owner-signed Revoke op + reconciles. The shell path
      also needed the same #30 Proven fixes transfer got (ssh initiator answers the challenge; receiver
      shell-bootstrap honors the pending_proven hold). So the FULL enforcement matrix is proven on live
      cross-machine traffic: grant->allow, revoke->deny+key-removed, deny-by-default, real reasons,
      rollback, trust-floor, sandbox-contained reconciler — both allow and deny directions.
      STILL nice-to-have before a production flip: a broader multi-device / multi-action sample and
      the load_cap_store cache under real concurrency, but the enforcement itself is end-to-end proven.

## Rollback

The flag is the rollback: unset `FILAMENT_CAP_AUTHORITATIVE` to return to legacy
gating instantly. Counters keep accumulating in both modes, so post-flip evidence
is not lost.
