//! The single shell gate shared by pty-open, exec-open, and ssh-sign.
//!
//! Both paths resolve the same inputs (link trust, device naming, legacy
//! store checks, capability inputs) and then the same verdict: the
//! capability engine's `granted.allowed()`, unconditionally -- no shadow /
//! authoritative split, no legacy fallback. Under the old split a revoked
//! certificate was still allowed whenever legacy checks passed, so exec
//! could be MORE permissive than a shell; the engine itself already denies
//! revoked certs absolutely (both modes), the split only hid it.
//!
//! `exec_gate_decision` and `pty_gate_decision` are deliberately separate
//! one-line entry points over one core: the cross-path equivalence test
//! calls both for every matrix cell, so any future per-path divergence
//! (the exact regression that motivated this module) turns red instead of
//! shipping silently.

use crate::capability::{BindingStrength, CAP_SHELL, CapOutcome, GateDecision};
use crate::conn::Conn;

/// Gathered gate inputs: link-derived + store-derived + policy, pre-decision.
/// Plain data (no Conn), so the matrix test can fabricate every cell.
pub(crate) struct ShellGateInputs {
    pub trusted: bool,
    pub denied: bool,
    pub policy_allows: bool,
    pub store_allows: bool,
    pub outcome: CapOutcome,
    pub idev: Option<[u8; 32]>,
    pub iusr: Option<[u8; 32]>,
    pub binding: BindingStrength,
    pub expires: Option<u64>,
    pub ak_caps: Option<Vec<String>>,
    pub own_user: Option<[u8; 32]>,
    pub has_grant: bool,
    pub cert_revoked: bool,
    /// The gated action, threaded from gather through decide so no shell
    /// literal can drift between callers. All current callers pass CAP_SHELL.
    pub action: String,
    /// Whether the peer's persisted, owner-signed enrolment ceiling covers
    /// the gated action. Gathered fresh (never cached) via
    /// `ceiling_covers_action`, keyed by verified device identity.
    pub ceiling_covers: bool,
}

/// Gather from live state. Both call sites use this; nothing gate-relevant
/// is resolved anywhere else, so the three paths cannot drift in inputs.
pub(crate) fn gather_shell_gate_inputs(
    conn: &mut Conn,
    pid: &str,
    shell_policy: &crate::ShellPolicy,
    action: &str,
) -> (Option<String>, ShellGateInputs) {
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let dev = conn.link(pid).and_then(|l| l.verified_name.clone());
    let (denied, policy_allows, store_allows) = match dev.as_deref() {
        Some(n) => (
            crate::device_capability_denied(n, action),
            shell_policy.auto_allows(n),
            crate::device_allows(n, action),
        ),
        None => (false, false, false),
    };
    let az = crate::peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let outcome = crate::capability::cap_authorize(
        &crate::settings::config_dir(),
        "self",
        action,
        idev,
        iusr,
        ak_caps,
    );
    let ceiling_covers = crate::identity_state::ceiling_covers_action(idev, action);
    let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
        &crate::settings::config_dir(),
        "self",
        action,
        idev,
        iusr,
        ak_caps,
    );
    let inputs = ShellGateInputs {
        trusted,
        denied,
        policy_allows,
        store_allows,
        outcome,
        idev: idev.copied(),
        iusr: iusr.copied(),
        binding,
        expires,
        ak_caps: ak_caps.map(|s| s.to_vec()),
        own_user,
        has_grant,
        cert_revoked,
        ceiling_covers,
        action: action.to_string(),
    };
    (dev, inputs)
}

/// Shared verdict core: legacy folds trust the same way for both paths, then
/// the capability verdict decides alone. Returns the engine's cap reason
/// when it names one; each call site applies its own fallback wording for
/// the reason-less case (pty and exec historically differ there, preserved).
fn decide(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    decide_with_legacy(
        inputs,
        inputs.trusted && !inputs.denied && (inputs.policy_allows || inputs.store_allows),
    )
}

/// Verdict core with a caller-supplied legacy fold. exec/pty/ssh-sign use
/// the shell fold above; the forward path passes its own blanket fold
/// (blanket L2 mode admits trusted peers with no shell policy behind it,
/// which the shell fold cannot express -- dropping it would newly deny
/// default setups in shadow). Same engine, same inputs otherwise.
fn decide_with_legacy(inputs: &ShellGateInputs, legacy_ok: bool) -> Result<(), Option<String>> {
    // The enrolment-ceiling substitution is an AUTHORITATIVE-mode behavior
    // only: in shadow the gate decides exactly as before this change (the
    // flip is the moment covered-without-grant opens become allows, never
    // before). Gating here rather than in the engine keeps every other
    // caller (transfer, forward) on its existing mode behavior.
    let scoped = inputs.ceiling_covers && crate::capability::cap_authoritative();
    let granted = crate::capability::cap_gate_effective(
        legacy_ok,
        &inputs.outcome,
        &inputs.action,
        "self",
        inputs.idev.as_ref(),
        inputs.iusr.as_ref(),
        inputs.binding,
        inputs.expires,
        inputs.ak_caps.as_deref(),
        inputs.own_user.as_ref(),
        scoped,
        inputs.has_grant,
        inputs.cert_revoked,
        inputs.denied,
    );
    match granted {
        GateDecision::Allow => Ok(()),
        GateDecision::Deny { cap_reason } => Err(cap_reason),
    }
}

/// Exec-open's entry point: delegates to the shared core (no local logic).
pub(crate) fn exec_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    decide(inputs)
}

/// Pty-open's entry point: delegates to the shared core (no local logic).
pub(crate) fn pty_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    decide(inputs)
}

/// Forward-open's entry point: same shared core, but the caller supplies
/// the legacy fold (see above) and overrides `ceiling_covers` with its
/// expose.json bound before calling. A forward --stdio to an exposed sshd
/// is shell-equivalent in reach.
pub(crate) fn forward_gate_decision(
    inputs: &ShellGateInputs,
    legacy_ok: bool,
) -> Result<(), Option<String>> {
    decide_with_legacy(inputs, legacy_ok)
}

/// SSH-sign's entry point: the certificate signer asks the same gate before
/// signing (a cert is B's statement about A, so the shell grant gates it
/// like any shell-class open). Delegates to the shared core (no local logic).
pub(crate) fn ssh_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    decide(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapOutcome;

    /// Cross-path equivalence: exec's decision == pty-open's for every cell
    /// of trusted x has_grant x cert_revoked x delegated-ceiling x
    /// ceiling-covers x denied x authoritative(on/off), calling all three
    /// entry points. Fabricated inputs
    /// mirror production gathering (store_allows tracks the grant, outcome
    /// tracks it the way cap_authorize's grant dependence does, legacy folds
    /// trust with store fixed grant-leaning); authoritative toggles via env
    /// under the config lock because the engine reads it globally.
    #[test]
    fn exec_matches_pty_across_gate_matrix() {
        let _guard = crate::tests::lock_test_config();
        let prior = std::env::var("FILAMENT_CAP_AUTHORITATIVE").ok();
        for authoritative in [false, true] {
            unsafe {
                std::env::set_var(
                    "FILAMENT_CAP_AUTHORITATIVE",
                    if authoritative { "1" } else { "0" },
                );
            }
            for trusted in [false, true] {
                for has_grant in [false, true] {
                    for cert_revoked in [false, true] {
                        for ceiling_allows in [false, true] {
                            for ceiling_covers in [false, true] {
                                for denied in [false, true] {
                                    let outcome = if has_grant {
                                        CapOutcome::Authorized
                                    } else {
                                        CapOutcome::Denied("test: no grant".into())
                                    };
                                    let ak_caps = if ceiling_allows {
                                        None
                                    } else {
                                        Some(vec!["transfer".to_string()])
                                    };
                                    let inputs = ShellGateInputs {
                                        trusted,
                                        denied,
                                        policy_allows: false,
                                        store_allows: has_grant,
                                        outcome,
                                        idev: Some([0x42u8; 32]),
                                        iusr: Some([0x11u8; 32]),
                                        binding: BindingStrength::Proven,
                                        // Fixed far-future expiry (not an axis): None
                                        // fail-closes under authoritative, which would
                                        // deny every allow-cell for a reason outside
                                        // the matrix.
                                        expires: Some(9_999_999_999u64),
                                        ak_caps,
                                        // Same user key as iusr: these cells model the
                                        // same-owner fleet population the ceiling branch
                                        // exists for (without it same_owner is false
                                        // and no covered cell could ever allow).
                                        own_user: Some([0x11u8; 32]),
                                        has_grant,
                                        cert_revoked,
                                        ceiling_covers,
                                        action: CAP_SHELL.to_string(),
                                    };
                                    let e = exec_gate_decision(&inputs);
                                    let p = pty_gate_decision(&inputs);
                                    let s = ssh_gate_decision(&inputs);
                                    let f = forward_gate_decision(
                                        &inputs,
                                        inputs.trusted
                                            && !inputs.denied
                                            && (inputs.policy_allows || inputs.store_allows),
                                    );
                                    assert_eq!(
                                        e, p,
                                        "exec vs pty disagree: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                    );
                                    // Blanket axis: the forward caller computes its legacy
                                    // fold through l2_open_allowed (blanket mode), not
                                    // the shell fold -- mirror that composition here so
                                    // the pin tests the real path, not an unreachable
                                    // forced-legacy input. Denied must deny even
                                    // blanketed -- N4 pins the l2_open_allowed rule.
                                    let f_blanket = forward_gate_decision(
                                        &inputs,
                                        crate::l2_policy::l2_open_allowed(
                                            true,
                                            inputs.store_allows,
                                            inputs.denied,
                                        ),
                                    );
                                    if denied {
                                        assert!(
                                            f_blanket.is_err(),
                                            "denied device opens nothing even blanketed: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                        );
                                    }
                                    assert_eq!(
                                        f, e,
                                        "forward vs exec disagree on shared inputs: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} denied={denied} auth={authoritative}"
                                    );
                                    assert_eq!(
                                        e, s,
                                        "exec vs ssh-sign disagree: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                    );
                                    // Oracle pins (not just equality): absolutes deny in
                                    // every cell, and the two canonical allows hold in
                                    // every cell. A core regression either way fails
                                    // here even if both wrappers still agree.
                                    if cert_revoked {
                                        assert!(
                                            e.is_err(),
                                            "revoked cert must deny: trusted={trusted} grant={has_grant} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                        );
                                    }
                                    if !ceiling_allows {
                                        assert!(
                                            e.is_err(),
                                            "narrow ceiling must deny: trusted={trusted} grant={has_grant} revoked={cert_revoked} covers={ceiling_covers} auth={authoritative}"
                                        );
                                    }
                                    if trusted
                                        && has_grant
                                        && !cert_revoked
                                        && ceiling_allows
                                        && !denied
                                    {
                                        assert!(
                                            e.is_ok(),
                                            "trusted+granted must allow: ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                        );
                                    }
                                    // Shadow follows the legacy fold EXACTLY where the
                                    // unconditional auth-key ceiling check passes (in this
                                    // matrix policy=false and store=grant, so legacy is
                                    // trusted && !denied && grant): the ceiling
                                    // substitution is authoritative-only, so those shadow
                                    // cells are a literal golden table of pre-change
                                    // behavior. ak-narrow cells deny in both modes via
                                    // the unconditional ceiling check, independent of
                                    // legacy -- that predates this change.
                                    // (cert-revoked cells excluded: the legacy fold has
                                    // no revocation term, but the gate denies revoked
                                    // absolutely in both modes -- that predates this
                                    // change.)
                                    if !authoritative && ceiling_allows && !cert_revoked {
                                        assert_eq!(
                                            e.is_ok(),
                                            trusted && !denied && has_grant,
                                            "shadow must follow the legacy fold exactly: trusted={trusted} grant={has_grant} denied={denied}"
                                        );
                                    }
                                    // An explicit deny short-circuits everything including
                                    // fleet auto-trust (#244 class): denied denies in
                                    // every cell, both modes, all paths.
                                    if denied {
                                        assert!(
                                            e.is_err(),
                                            "explicit deny must deny: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                        );
                                    }
                                    // covers=false is the pre-change behavior (scoped_in_bounds
                                    // was hardcoded false): authoritative deliberate-tier cells
                                    // without a grant must still deny, pinning the flip
                                    // blocker exactly where it was.
                                    if !ceiling_covers && authoritative && !has_grant {
                                        assert!(
                                            e.is_err(),
                                            "uncovered deliberate action must deny under authoritative: trusted={trusted} revoked={cert_revoked} ceiling={ceiling_allows} auth={authoritative}"
                                        );
                                    }
                                    // covers=true opens exactly one new door: authoritative,
                                    // trusted, Proven, unrevoked, grantless, covered,
                                    // UNDENIED (an explicit deny outranks coverage).
                                    if ceiling_covers
                                        && authoritative
                                        && trusted
                                        && !has_grant
                                        && !cert_revoked
                                        && ceiling_allows
                                        && !denied
                                    {
                                        assert!(
                                            e.is_ok(),
                                            "covered enrolment ceiling must allow under authoritative: ceiling={ceiling_allows} auth={authoritative}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        match prior {
            Some(v) => unsafe { std::env::set_var("FILAMENT_CAP_AUTHORITATIVE", v) },
            None => unsafe { std::env::remove_var("FILAMENT_CAP_AUTHORITATIVE") },
        }
    }

    // The revoked cells above are fabricated inputs, which is all a unit test
    // can reach: a secret-paired link resolves no identity, so `cert_revoked`
    // is false in every such harness whatever the product does. That was
    // recorded as verdict debt behind an ignored placeholder here. The debt is
    // paid LIVE instead, by `cli/tests/fleet-cert-gates.sh`, which enrols a
    // real certified device (`add --for` / `join`), revokes its CERTIFICATE
    // (`revoke <device> --certificate`) and asserts all three paths -- exec,
    // pty and ssh-sign -- refuse it, with a restore control so a broken link
    // cannot pass as a revocation. Keep that gate and this matrix together:
    // the matrix pins the decision, the gate pins that the decision is reached
    // with the real input.
}
