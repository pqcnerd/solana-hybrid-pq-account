//! Authorization policy evaluation.
//!
//! For [`AuthorizationPolicy::HybridAnd`] / [`SignatureRequirement::Both`],
//! BOTH signatures must verify. Never silently fall back to a single-scheme
//! success.

use dualkey_core::{AuthorizationPolicy, DualKeyError, SignatureRequirement};

/// Result of individual scheme checks before policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureValidity {
    pub ed25519_valid: bool,
    pub falcon_valid: bool,
}

/// Evaluate whether `sigs` satisfies a concrete [`SignatureRequirement`].
pub fn evaluate_requirement(
    req: SignatureRequirement,
    sigs: SignatureValidity,
) -> Result<(), DualKeyError> {
    match req {
        SignatureRequirement::Ed25519 => {
            if sigs.ed25519_valid {
                Ok(())
            } else {
                Err(DualKeyError::InvalidEd25519)
            }
        }
        SignatureRequirement::Falcon => {
            if sigs.falcon_valid {
                Ok(())
            } else {
                Err(DualKeyError::InvalidFalcon)
            }
        }
        SignatureRequirement::Both => {
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
        SignatureRequirement::Either => {
            if sigs.ed25519_valid || sigs.falcon_valid {
                Ok(())
            } else {
                Err(DualKeyError::PolicyRejected)
            }
        }
    }
}

/// Evaluate whether `sigs` satisfies `policy` for a **context-free** check.
///
/// Context-sensitive modes ([`AuthorizationPolicy::FalconForPrivileged`],
/// [`AuthorizationPolicy::FalconAboveThreshold`]) cannot be evaluated from
/// signature bits alone; callers must use
/// [`AuthorizationPolicy::signature_requirement`] + [`evaluate_requirement`].
/// Passing those modes here returns [`DualKeyError::PolicyRejected`] only when
/// neither signature is valid would be wrong — instead we reject with
/// [`DualKeyError::PolicyNotImplemented`] to force the action-aware path.
pub fn evaluate_policy(
    policy: AuthorizationPolicy,
    sigs: SignatureValidity,
) -> Result<(), DualKeyError> {
    let req = match policy {
        AuthorizationPolicy::Ed25519Only => SignatureRequirement::Ed25519,
        AuthorizationPolicy::FalconOnly => SignatureRequirement::Falcon,
        AuthorizationPolicy::HybridAnd => SignatureRequirement::Both,
        AuthorizationPolicy::HybridOr => SignatureRequirement::Either,
        AuthorizationPolicy::FalconForPrivileged | AuthorizationPolicy::FalconAboveThreshold => {
            return Err(DualKeyError::PolicyNotImplemented);
        }
    };
    evaluate_requirement(req, sigs)
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
    }

    #[test]
    fn hybrid_or_accepts_either() {
        assert!(evaluate_policy(
            AuthorizationPolicy::HybridOr,
            SignatureValidity {
                ed25519_valid: true,
                falcon_valid: false,
            },
        )
        .is_ok());
        assert!(evaluate_policy(
            AuthorizationPolicy::HybridOr,
            SignatureValidity {
                ed25519_valid: false,
                falcon_valid: true,
            },
        )
        .is_ok());
        assert_eq!(
            evaluate_policy(
                AuthorizationPolicy::HybridOr,
                SignatureValidity {
                    ed25519_valid: false,
                    falcon_valid: false,
                },
            ),
            Err(DualKeyError::PolicyRejected)
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
