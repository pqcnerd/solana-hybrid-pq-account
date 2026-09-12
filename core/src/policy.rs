//! Authorization policy enumeration and signature-requirement lattice.
//!
//! All six modes are implemented as of Milestone 10. Context-sensitive modes
//! ([`AuthorizationPolicy::FalconForPrivileged`],
//! [`AuthorizationPolicy::FalconAboveThreshold`]) need the action (and, for the
//! threshold mode, the stored threshold) to decide which schemes are required.

use crate::intent::Action;

/// Configurable authorization policy for a DualKey account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorizationPolicy {
    /// Require a valid Ed25519 signature over the intent digest.
    Ed25519Only = 0,
    /// Require a valid Falcon-512 signature over the intent digest.
    FalconOnly = 1,
    /// Require BOTH Ed25519 AND Falcon-512 (defense in depth). Never falls back.
    HybridAnd = 2,
    /// Accept either Ed25519 OR Falcon-512.
    HybridOr = 3,
    /// Falcon required for privileged actions; Ed25519 for normal transfers.
    FalconForPrivileged = 4,
    /// Falcon required when transfer lamports exceed the account threshold.
    FalconAboveThreshold = 5,
}

/// Which signature scheme(s) must verify for an authorization attempt.
///
/// Ordered by strength for [`SignatureRequirement::meet`]: `Both` is strictest,
/// `Either` is weakest. Used by `ChangePolicy` so downgrades must satisfy the
/// **stricter** of current and target requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureRequirement {
    /// Ed25519 **or** Falcon is enough.
    Either,
    /// Ed25519 required (Falcon ignored).
    Ed25519,
    /// Falcon required (Ed25519 ignored).
    Falcon,
    /// Both schemes required (never falls back).
    Both,
}

impl SignatureRequirement {
    /// Lattice meet: the stricter of two requirements.
    ///
    /// `Ed25519` meet `Falcon` = `Both`. Anything meet `Both` = `Both`.
    pub const fn meet(self, other: Self) -> Self {
        use SignatureRequirement::*;
        match (self, other) {
            (Both, _) | (_, Both) => Both,
            (Ed25519, Falcon) | (Falcon, Ed25519) => Both,
            (Ed25519, Ed25519) | (Ed25519, Either) | (Either, Ed25519) => Ed25519,
            (Falcon, Falcon) | (Falcon, Either) | (Either, Falcon) => Falcon,
            (Either, Either) => Either,
        }
    }
}

impl AuthorizationPolicy {
    /// Parse a policy byte from account data.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ed25519Only),
            1 => Some(Self::FalconOnly),
            2 => Some(Self::HybridAnd),
            3 => Some(Self::HybridOr),
            4 => Some(Self::FalconForPrivileged),
            5 => Some(Self::FalconAboveThreshold),
            _ => None,
        }
    }

    /// Encode as the account-data policy byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this policy mode is implemented for the current milestone set.
    ///
    /// All six declared modes are reachable as of Milestone 10.
    pub const fn is_implemented(self) -> bool {
        matches!(
            self,
            Self::Ed25519Only
                | Self::FalconOnly
                | Self::HybridAnd
                | Self::HybridOr
                | Self::FalconForPrivileged
                | Self::FalconAboveThreshold
        )
    }

    /// Stable kebab-case name, used by the CLI and in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519Only => "ed25519-only",
            Self::FalconOnly => "falcon-only",
            Self::HybridAnd => "hybrid-and",
            Self::HybridOr => "hybrid-or",
            Self::FalconForPrivileged => "falcon-for-privileged",
            Self::FalconAboveThreshold => "falcon-above-threshold",
        }
    }

    /// Parse a [`AuthorizationPolicy::name`].
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Ed25519Only,
            Self::FalconOnly,
            Self::HybridAnd,
            Self::HybridOr,
            Self::FalconForPrivileged,
            Self::FalconAboveThreshold,
        ]
        .into_iter()
        .find(|p| p.name() == name)
    }

    /// Signature schemes required to authorize `action` under this policy.
    ///
    /// `threshold` is the account's `falcon_required_above` when set. If the
    /// policy is [`Self::FalconAboveThreshold`] and the flag is unset, the
    /// threshold is treated as `0` (any positive transfer needs Falcon).
    pub fn signature_requirement(
        self,
        action: &Action,
        threshold: Option<u64>,
    ) -> SignatureRequirement {
        match self {
            Self::Ed25519Only => SignatureRequirement::Ed25519,
            Self::FalconOnly => SignatureRequirement::Falcon,
            Self::HybridAnd => SignatureRequirement::Both,
            Self::HybridOr => SignatureRequirement::Either,
            Self::FalconForPrivileged => {
                if action.is_privileged() {
                    SignatureRequirement::Falcon
                } else {
                    SignatureRequirement::Ed25519
                }
            }
            Self::FalconAboveThreshold => match action {
                Action::TransferSol { lamports, .. } => {
                    let thr = threshold.unwrap_or(0);
                    if *lamports > thr {
                        SignatureRequirement::Falcon
                    } else {
                        SignatureRequirement::Ed25519
                    }
                }
                // Rotations and policy changes always require Falcon under this mode.
                _ => SignatureRequirement::Falcon,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_policies() {
        for p in [
            AuthorizationPolicy::Ed25519Only,
            AuthorizationPolicy::FalconOnly,
            AuthorizationPolicy::HybridAnd,
            AuthorizationPolicy::HybridOr,
            AuthorizationPolicy::FalconForPrivileged,
            AuthorizationPolicy::FalconAboveThreshold,
        ] {
            assert!(p.is_implemented());
            assert_eq!(AuthorizationPolicy::from_u8(p.as_u8()), Some(p));
        }
    }

    #[test]
    fn meet_is_stricter() {
        use SignatureRequirement::*;
        assert_eq!(Both.meet(Ed25519), Both);
        assert_eq!(Ed25519.meet(Falcon), Both);
        assert_eq!(Either.meet(Falcon), Falcon);
        assert_eq!(Either.meet(Ed25519), Ed25519);
        assert_eq!(Either.meet(Either), Either);
    }

    #[test]
    fn hybrid_and_to_ed25519_only_requires_both() {
        let transfer = Action::TransferSol {
            recipient: [0u8; 32],
            lamports: 1,
        };
        let change = Action::ChangePolicy {
            new_policy: AuthorizationPolicy::Ed25519Only.as_u8(),
            threshold: 0,
        };
        let current = AuthorizationPolicy::HybridAnd.signature_requirement(&change, None);
        let target = AuthorizationPolicy::Ed25519Only.signature_requirement(&change, None);
        assert_eq!(current.meet(target), SignatureRequirement::Both);
        // Sanity: ordinary transfer under HybridAnd still needs both.
        assert_eq!(
            AuthorizationPolicy::HybridAnd.signature_requirement(&transfer, None),
            SignatureRequirement::Both
        );
    }

    #[test]
    fn falcon_for_privileged_splits_actions() {
        let transfer = Action::TransferSol {
            recipient: [0u8; 32],
            lamports: 100,
        };
        let rotate = Action::RotateEd25519Key {
            new_pubkey: [1u8; 32],
        };
        assert_eq!(
            AuthorizationPolicy::FalconForPrivileged.signature_requirement(&transfer, None),
            SignatureRequirement::Ed25519
        );
        assert_eq!(
            AuthorizationPolicy::FalconForPrivileged.signature_requirement(&rotate, None),
            SignatureRequirement::Falcon
        );
    }

    #[test]
    fn falcon_above_threshold_uses_lamports() {
        let below = Action::TransferSol {
            recipient: [0u8; 32],
            lamports: 100,
        };
        let above = Action::TransferSol {
            recipient: [0u8; 32],
            lamports: 1_000_001,
        };
        let p = AuthorizationPolicy::FalconAboveThreshold;
        assert_eq!(
            p.signature_requirement(&below, Some(1_000_000)),
            SignatureRequirement::Ed25519
        );
        assert_eq!(
            p.signature_requirement(&above, Some(1_000_000)),
            SignatureRequirement::Falcon
        );
    }
}
