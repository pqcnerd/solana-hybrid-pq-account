//! Authorization policy enumeration.
//!
//! All planned modes are declared for forward compatibility. Only
//! [`AuthorizationPolicy::Ed25519Only`], [`AuthorizationPolicy::FalconOnly`],
//! and [`AuthorizationPolicy::HybridAnd`] are reachable in early milestones.

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
    /// Accept either Ed25519 OR Falcon-512 (Milestone 10).
    HybridOr = 3,
    /// Falcon required for privileged actions; Ed25519 for normal (Milestone 10).
    FalconForPrivileged = 4,
    /// Falcon required when transfer value exceeds threshold (Milestone 10).
    FalconAboveThreshold = 5,
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
    /// Unreachable modes must return [`crate::DualKeyError::PolicyNotImplemented`]
    /// rather than silently falling back.
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::Ed25519Only | Self::FalconOnly | Self::HybridAnd)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_implemented_policies() {
        for p in [
            AuthorizationPolicy::Ed25519Only,
            AuthorizationPolicy::FalconOnly,
            AuthorizationPolicy::HybridAnd,
        ] {
            assert!(p.is_implemented());
            assert_eq!(AuthorizationPolicy::from_u8(p.as_u8()), Some(p));
        }
    }

    #[test]
    fn future_policies_declared_but_not_implemented() {
        assert!(!AuthorizationPolicy::HybridOr.is_implemented());
        assert!(!AuthorizationPolicy::FalconForPrivileged.is_implemented());
        assert!(!AuthorizationPolicy::FalconAboveThreshold.is_implemented());
    }
}
