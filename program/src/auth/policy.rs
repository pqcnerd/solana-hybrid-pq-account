//! Authorization policy evaluation.
//!
//! For [`AuthorizationPolicy::HybridAnd`], BOTH signatures must verify.
//! Never silently fall back to a single-scheme success.

use dualkey_core::{AuthorizationPolicy, DualKeyError};

/// Result of individual scheme checks before policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureValidity {
    pub ed25519_valid: bool,
    pub falcon_valid: bool,
}

/// Evaluate whether `sigs` satisfies `policy`.
///
/// Milestone 0: returns [`DualKeyError::Unimplemented`] for all policies so
/// no authorization path can succeed early. Milestone 5 implements
/// Ed25519Only / FalconOnly / HybridAnd.
pub fn evaluate_policy(
    policy: AuthorizationPolicy,
    _sigs: SignatureValidity,
) -> Result<(), DualKeyError> {
    if !policy.is_implemented() {
        return Err(DualKeyError::PolicyNotImplemented);
    }
    Err(DualKeyError::Unimplemented)
}
