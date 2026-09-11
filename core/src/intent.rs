//! Authorization intent and action types.
//!
//! Both signature schemes sign the SHA-256 digest of the canonical preimage
//! of [`AuthorizationIntent`]. See `docs/canonical-intent.md`.

use crate::canonical::INTENT_VERSION;

/// Action discriminator for `TransferSol` (Milestone 7).
pub const ACTION_TAG_TRANSFER_SOL: u8 = 1;

/// Reserved tags for later milestones (declared for forward compatibility).
pub const ACTION_TAG_TRANSFER_SPL: u8 = 2;
pub const ACTION_TAG_ROTATE_ED25519: u8 = 3;
pub const ACTION_TAG_ROTATE_FALCON: u8 = 4;
pub const ACTION_TAG_CHANGE_POLICY: u8 = 5;
pub const ACTION_TAG_RECOVER_ACCOUNT: u8 = 6;

/// Authorized action encoded inside an intent.
///
/// Only [`Action::TransferSol`] is in scope for early milestones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Transfer lamports from the DualKey PDA to `recipient`.
    TransferSol {
        /// Destination account.
        recipient: [u8; 32],
        /// Amount in lamports.
        lamports: u64,
    },
}

impl Action {
    /// Stable action tag byte written into the canonical preimage.
    pub const fn tag(self) -> u8 {
        match self {
            Self::TransferSol { .. } => ACTION_TAG_TRANSFER_SOL,
        }
    }
}

/// Canonical authorization intent signed by both schemes.
///
/// On the wire (instruction data), only `expiry_slot` and `action` are
/// transmitted. The program reconstructs `chain_domain`, `program_id`,
/// `account`, and `nonce` from trusted context. Clients MUST populate all
/// fields when building the signing preimage so both sides match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationIntent {
    /// Intent schema version ([`INTENT_VERSION`]).
    pub version: u8,
    /// Network / cluster domain separator (compile-time constant on-chain).
    pub chain_domain: [u8; 32],
    /// DualKey program id.
    pub program_id: [u8; 32],
    /// HybridAccount PDA address.
    pub account: [u8; 32],
    /// Expected account nonce (must equal `HybridAccount.nonce`).
    pub nonce: u64,
    /// Last slot at which this intent is valid (inclusive).
    pub expiry_slot: u64,
    /// Action to execute if authorization succeeds.
    pub action: Action,
}

impl AuthorizationIntent {
    /// Construct an intent with the current schema version.
    pub const fn new(
        chain_domain: [u8; 32],
        program_id: [u8; 32],
        account: [u8; 32],
        nonce: u64,
        expiry_slot: u64,
        action: Action,
    ) -> Self {
        Self {
            version: INTENT_VERSION,
            chain_domain,
            program_id,
            account,
            nonce,
            expiry_slot,
            action,
        }
    }
}
