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
/// Implemented modes:
/// * [`AuthorizationPolicy::Ed25519Only`] — requires `ed25519_valid`
/// * [`AuthorizationPolicy::FalconOnly`] — requires `falcon_valid`
/// * [`AuthorizationPolicy::HybridAnd`] — requires **both**; never falls back
///
/// Unimplemented modes return [`DualKeyError::PolicyNotImplemented`].
pub fn evaluate_policy(
    policy: AuthorizationPolicy,
    sigs: SignatureValidity,
) -> Result<(), DualKeyError> {
    if !policy.is_implemented() {
        return Err(DualKeyError::PolicyNotImplemented);
    }

    match policy {
        AuthorizationPolicy::Ed25519Only => {
            if sigs.ed25519_valid {
                Ok(())
            } else {
                Err(DualKeyError::InvalidEd25519)
            }
        }
        AuthorizationPolicy::FalconOnly => {
            if sigs.falcon_valid {
                Ok(())
            } else {
                Err(DualKeyError::InvalidFalcon)
            }
        }
        AuthorizationPolicy::HybridAnd => {
            // Both required. Report the first failure so logs name a scheme;
            // never return Ok when only one half verifies.
            if !sigs.ed25519_valid {
                return Err(DualKeyError::InvalidEd25519);
            }
            if !sigs.falcon_valid {
                return Err(DualKeyError::InvalidFalcon);
            }
            Ok(())
        }
        AuthorizationPolicy::HybridOr
        | AuthorizationPolicy::FalconForPrivileged
        | AuthorizationPolicy::FalconAboveThreshold => Err(DualKeyError::PolicyNotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_and_never_falls_back() {
        assert!(evaluate_policy(
            AuthorizationPolicy::HybridAnd,
            SignatureValidity {
                ed25519_valid: true,
                falcon_valid: true,
            },
        )
        .is_ok());
        assert_eq!(
            evaluate_policy(
                AuthorizationPolicy::HybridAnd,
                SignatureValidity {
                    ed25519_valid: true,
                    falcon_valid: false,
                },
            ),
            Err(DualKeyError::InvalidFalcon)
        );
        assert_eq!(
            evaluate_policy(
                AuthorizationPolicy::HybridAnd,
                SignatureValidity {
                    ed25519_valid: false,
                    falcon_valid: true,
                },
            ),
            Err(DualKeyError::InvalidEd25519)
        );
        assert_eq!(
            evaluate_policy(
                AuthorizationPolicy::HybridAnd,
                SignatureValidity {
                    ed25519_valid: false,
                    falcon_valid: false,
                },
            ),
            Err(DualKeyError::InvalidEd25519)
        );
    }

    #[test]
    fn single_scheme_policies() {
        assert!(evaluate_policy(
            AuthorizationPolicy::Ed25519Only,
            SignatureValidity {
                ed25519_valid: true,
                falcon_valid: false,
            },
        )
        .is_ok());
        assert!(evaluate_policy(
            AuthorizationPolicy::FalconOnly,
            SignatureValidity {
                ed25519_valid: false,
                falcon_valid: true,
            },
        )
        .is_ok());
    }
}
