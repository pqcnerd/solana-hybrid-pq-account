//! Authorization intent and action types.
//!
//! Both signature schemes sign the SHA-256 digest of the canonical preimage
//! of [`AuthorizationIntent`]. See `docs/canonical-intent.md`.

use crate::canonical::INTENT_VERSION;

/// Action discriminator for `TransferSol` (Milestone 7).
pub const ACTION_TAG_TRANSFER_SOL: u8 = 1;
/// Action discriminator for `TransferSpl` (Milestone 11 — reserved).
pub const ACTION_TAG_TRANSFER_SPL: u8 = 2;
/// Action discriminator for `RotateEd25519Key` (Milestone 9).
pub const ACTION_TAG_ROTATE_ED25519: u8 = 3;
/// Action discriminator for `RotateFalconKey` (Milestone 9).
pub const ACTION_TAG_ROTATE_FALCON: u8 = 4;
/// Action discriminator for `ChangePolicy` (Milestone 10).
pub const ACTION_TAG_CHANGE_POLICY: u8 = 5;
/// Action discriminator for `RecoverAccount` (reserved; not yet wired).
pub const ACTION_TAG_RECOVER_ACCOUNT: u8 = 6;

/// Authorized action encoded inside an intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Transfer lamports from the DualKey PDA to `recipient`.
    TransferSol {
        /// Destination account.
        recipient: [u8; 32],
        /// Amount in lamports.
        lamports: u64,
    },
    /// Replace the Ed25519 owner key (Milestone 9).
    ///
    /// Authorized under the **current** policy. The new pubkey is bound into
    /// the signed digest; a separate proof-of-possession is not required
    /// (anyone who can authorize can already drain the vault).
    RotateEd25519Key {
        /// Replacement Ed25519 owner public key.
        new_pubkey: [u8; 32],
    },
    /// Replace the Falcon-512 public key (Milestone 9).
    ///
    /// `new_pubkey_hash` is `SHA256(wire_pubkey)` for the 897-byte key that
    /// accompanies the `RotateFalconKey` instruction. The instruction also
    /// requires a Falcon proof-of-possession over the same digest under the
    /// **new** key so a bogus registration cannot brick HybridAnd accounts.
    RotateFalconKey {
        /// SHA-256 of the new 897-byte Falcon wire public key.
        new_pubkey_hash: [u8; 32],
    },
    /// Replace the authorization policy (Milestone 10).
    ///
    /// Authorized under the **stricter** of the current and target policies'
    /// signature requirements for this action, so a stolen Ed25519 key alone
    /// cannot disable Falcon on a HybridAnd account.
    ///
    /// Wire body: `new_policy[1] ‖ pad[7] ‖ threshold_u64_le[8] ‖ reserved[24]`.
    /// `threshold` is stored when the target is [`crate::AuthorizationPolicy::FalconAboveThreshold`];
    /// otherwise it is ignored and the threshold flag is cleared.
    ChangePolicy {
        /// Target [`crate::AuthorizationPolicy`] as a `u8`.
        new_policy: u8,
        /// Lamport threshold for `FalconAboveThreshold` (meaningful only then).
        threshold: u64,
    },
}

impl Action {
    /// Stable action tag byte written into the canonical preimage.
    pub const fn tag(self) -> u8 {
        match self {
            Self::TransferSol { .. } => ACTION_TAG_TRANSFER_SOL,
            Self::RotateEd25519Key { .. } => ACTION_TAG_ROTATE_ED25519,
            Self::RotateFalconKey { .. } => ACTION_TAG_ROTATE_FALCON,
            Self::ChangePolicy { .. } => ACTION_TAG_CHANGE_POLICY,
        }
    }

    /// Whether this action is "privileged" for [`crate::AuthorizationPolicy::FalconForPrivileged`].
    ///
    /// Transfers are normal; key rotation and policy changes are privileged.
    pub const fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::RotateEd25519Key { .. }
                | Self::RotateFalconKey { .. }
                | Self::ChangePolicy { .. }
        )
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
