//! Shared DualKey error codes.
//!
//! Mapped to `ProgramError::Custom(u32)` on-chain in `program::error`.
//! Numeric values are stable; do not renumber without a version bump.

/// Errors returned by DualKey authorization and account logic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DualKeyError {
    /// Instruction or feature not yet implemented for this milestone.
    Unimplemented = 0,
    /// Account data length or layout is invalid.
    InvalidAccountData = 1,
    /// PDA derivation or bump does not match.
    InvalidPda = 2,
    /// Intent version is unsupported.
    UnsupportedVersion = 3,
    /// Intent nonce does not equal account nonce.
    InvalidNonce = 4,
    /// Current slot is past intent expiry.
    IntentExpired = 5,
    /// Ed25519 signature / precompile introspection failed.
    InvalidEd25519 = 6,
    /// Falcon-512 signature verification failed.
    InvalidFalcon = 7,
    /// Authorization policy rejected the provided signature set.
    PolicyRejected = 8,
    /// Malformed Falcon signature or pubkey bytes.
    MalformedFalcon = 9,
    /// Malformed Ed25519 precompile instruction.
    MalformedEd25519Precompile = 10,
    /// Action type is not supported.
    UnsupportedAction = 11,
    /// Chain domain / network identifier mismatch.
    ChainDomainMismatch = 12,
    /// Authorization policy variant is not yet enabled.
    PolicyNotImplemented = 13,
    /// Arithmetic overflow / underflow.
    MathOverflow = 14,
    /// Insufficient lamports for the requested transfer.
    InsufficientFunds = 15,
}

impl DualKeyError {
    /// Stable numeric code for on-chain `ProgramError::Custom`.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl core::fmt::Display for DualKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unimplemented => write!(f, "unimplemented"),
            Self::InvalidAccountData => write!(f, "invalid account data"),
            Self::InvalidPda => write!(f, "invalid PDA"),
            Self::UnsupportedVersion => write!(f, "unsupported version"),
            Self::InvalidNonce => write!(f, "invalid nonce"),
            Self::IntentExpired => write!(f, "intent expired"),
            Self::InvalidEd25519 => write!(f, "invalid Ed25519 signature"),
            Self::InvalidFalcon => write!(f, "invalid Falcon signature"),
            Self::PolicyRejected => write!(f, "authorization policy rejected"),
            Self::MalformedFalcon => write!(f, "malformed Falcon material"),
            Self::MalformedEd25519Precompile => write!(f, "malformed Ed25519 precompile"),
            Self::UnsupportedAction => write!(f, "unsupported action"),
            Self::ChainDomainMismatch => write!(f, "chain domain mismatch"),
            Self::PolicyNotImplemented => write!(f, "policy not implemented"),
            Self::MathOverflow => write!(f, "math overflow"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
        }
    }
}
