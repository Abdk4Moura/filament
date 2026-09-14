//! The single shell gate shared by pty-open and exec-open.
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

use crate::capability::{BindingStrength, CapOutcome, GateDecision, CAP_SHELL};
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
}

/// Gather from live state. Both call sites use this; nothing gate-relevant
/// is resolved anywhere else, so the two paths cannot drift in inputs.
pub(crate) fn gather_shell_gate_inputs(
    conn: &mut Conn,
    pid: &str,
    shell_policy: &crate::ShellPolicy,
) -> (Option<String>, ShellGateInputs) {
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let dev = conn.link(pid).and_then(|l| l.verified_name.clone());
    let (denied, policy_allows, store_allows) = match dev.as_deref() {
        Some(n) => (
            crate::device_capability_denied(n, "shell"),
            shell_policy.auto_allows(n),
            crate::device_allows(n, "shell"),
        ),
        None => (false, false, false),
    };
    let az = crate::peer_authz(conn, pid);
    let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
    let outcome = crate::capability::cap_authorize(
        &crate::settings::config_dir(),
        "self",
        CAP_SHELL,
        idev,
        iusr,
        ak_caps,
    );
    let (own_user, has_grant) = crate::capability::cap_fleet_inputs(
        &crate::settings::config_dir(),
        "self",
        CAP_SHELL,
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
    };
    (dev, inputs)
}

/// Shared verdict core: legacy folds trust the same way for both paths, then
/// the capability verdict decides alone. Returns the engine's cap reason
/// when it names one; each call site applies its own fallback wording for
/// the reason-less case (pty and exec historically differ there, preserved).
fn decide(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    let legacy_ok =
        inputs.trusted && !inputs.denied && (inputs.policy_allows || inputs.store_allows);
    let granted = crate::capability::cap_gate_effective(
        legacy_ok,
        &inputs.outcome,
        CAP_SHELL,
        "self",
        inputs.idev.as_ref(),
        inputs.iusr.as_ref(),
        inputs.binding,
        inputs.expires,
        inputs.ak_caps.as_deref(),
        inputs.own_user.as_ref(),
        false,
        inputs.has_grant,
        inputs.cert_revoked,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapOutcome;

    /// Cross-path equivalence: exec's decision == pty-open's for every cell
    /// of trusted x has_grant x cert_revoked x delegated-ceiling x
    /// authoritative(on/off), calling both entry points. Fabricated inputs
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
                                denied: false,
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
                                own_user: None,
                                has_grant,
                                cert_revoked,
                            };
                            let e = exec_gate_decision(&inputs);
                            let p = pty_gate_decision(&inputs);
                            assert_eq!(
                                e, p,
                                "exec vs pty disagree: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} auth={authoritative}"
                            );
                            // Oracle pins (not just equality): absolutes deny in
                            // every cell, and the two canonical allows hold in
                            // every cell. A core regression either way fails
                            // here even if both wrappers still agree.
                            if cert_revoked {
                                assert!(
                                    e.is_err(),
                                    "revoked cert must deny: trusted={trusted} grant={has_grant} ceiling={ceiling_allows} auth={authoritative}"
                                );
                            }
                            if !ceiling_allows {
                                assert!(
                                    e.is_err(),
                                    "narrow ceiling must deny: trusted={trusted} grant={has_grant} revoked={cert_revoked} auth={authoritative}"
                                );
                            }
                            if trusted && has_grant && !cert_revoked && ceiling_allows {
                                assert!(
                                    e.is_ok(),
                                    "trusted+granted must allow: ceiling={ceiling_allows} auth={authoritative}"
                                );
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

    /// The live cert-revoked e2e gate needs fleet enrollment in the harness
    /// (secret-paired links never resolve an identity, so cert_revoked is
    /// always false there); tracked in verdict_debt. Revoked cells ARE
    /// covered unit-level by the matrix above.
    #[test]
    #[ignore = "requires fleet enrollment in the e2e harness (see verdict_debt)"]
    fn cert_revoked_live_gate_requires_fleet_enrollment() {}
}
