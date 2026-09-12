//! DualKey instruction discriminators.
//!
//! Discriminators 0–9 are the live account instructions (Initialize through
//! CancelSocialRecovery).
//!
//! Discriminators 240–243 are the Milestone 2–4 verification / reconstruction
//! harness. They exist to prove Falcon-512 verification and the canonical
//! digest actually run under SBF and to measure their compute cost. They are
//! deliberately numbered far away from the real instruction set so they can be
//! deleted without renumbering anything.
//!
//! The harness instructions authorize nothing: they own no account, move no
//! lamports, and mutate no state. They are pure verification oracles whose only
//! observable effect is success or failure and the compute units consumed.

/// Instruction discriminators (first byte of instruction data).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DualKeyInstruction {
    /// Initialize a HybridAccount PDA (Milestone 3).
    Initialize = 0,
    /// Execute an authorized intent (Milestone 5–7).
    Execute = 1,
    /// Rotate Ed25519 owner key (Milestone 9).
    RotateEd25519Key = 2,
    /// Rotate Falcon public key (Milestone 9).
    RotateFalconKey = 3,
    /// Change authorization policy (Milestone 10).
    ChangePolicy = 4,
    /// Recovery enable/disable / Falcon-only Ed25519 rotate.
    RecoverAccount = 5,
    /// Set / replace social-recovery guardian + delay (Milestone 15).
    SetRecoveryConfig = 6,
    /// Guardian initiates a pending Ed25519 owner change (Milestone 15).
    InitiateSocialRecovery = 7,
    /// Finalize pending social recovery after the timelock (Milestone 15).
    FinalizeSocialRecovery = 8,
    /// Cancel pending social recovery under DualKey policy (Milestone 15).
    CancelSocialRecovery = 9,

    /// Milestone 2 harness: verify a Falcon-512 signature against the prepared
    /// public key held in the first account's data.
    ///
    /// Accounts:
    /// * `[0]` readonly — data begins with a [`PREPARED_FALCON_PUBKEY_LEN`]
    ///   prepared public key. Solana guarantees 8-byte-aligned account data.
    ///
    /// Instruction data: `[240] ‖ signature(666) ‖ message(..)`
    ///
    /// [`PREPARED_FALCON_PUBKEY_LEN`]: crate::auth::falcon::PREPARED_FALCON_PUBKEY_LEN
    VerifyFalconPrepared = 240,

    /// Milestone 2 harness: verify a Falcon-512 signature against a raw
    /// 897-byte wire public key supplied in instruction data, decoding and
    /// running the forward NTT in-instruction.
    ///
    /// Instruction data: `[241] ‖ signature(666) ‖ pubkey(897) ‖ message(..)`
    VerifyFalconRaw = 241,

    /// Milestone 2 harness: recompute a canonical digest with `sol_sha256` and
    /// compare it to an expected digest, proving the on-chain hash agrees with
    /// the client's `sha2` digest over identical preimage bytes.
    ///
    /// Instruction data: `[242] ‖ preimage(172) ‖ expected_digest(32)`
    VerifyCanonicalDigest = 242,

    /// Milestone 4 harness: reconstruct a canonical intent from HybridAccount
    /// context + wire fields, hash with `sol_sha256`, and compare to an expected
    /// digest. Proves on-chain reconstruction agrees with the client without
    /// implementing authorization.
    ///
    /// Accounts:
    /// * `[0]` readonly — HybridAccount (address + nonce enter the digest)
    ///
    /// Instruction data:
    /// `[243] ‖ expiry(8) ‖ action_tag(1) ‖ action_body(40) ‖ expected_digest(32)`
    ReconstructCanonicalDigest = 243,
}

impl DualKeyInstruction {
    /// Parse the discriminator byte. Unknown values yield `None`.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Initialize),
            1 => Some(Self::Execute),
            2 => Some(Self::RotateEd25519Key),
            3 => Some(Self::RotateFalconKey),
            4 => Some(Self::ChangePolicy),
            5 => Some(Self::RecoverAccount),
            6 => Some(Self::SetRecoveryConfig),
            7 => Some(Self::InitiateSocialRecovery),
            8 => Some(Self::FinalizeSocialRecovery),
            9 => Some(Self::CancelSocialRecovery),
            240 => Some(Self::VerifyFalconPrepared),
            241 => Some(Self::VerifyFalconRaw),
            242 => Some(Self::VerifyCanonicalDigest),
            243 => Some(Self::ReconstructCanonicalDigest),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this is a verification/reconstruction harness instruction.
    pub const fn is_verification_harness(self) -> bool {
        matches!(
            self,
            Self::VerifyFalconPrepared
                | Self::VerifyFalconRaw
                | Self::VerifyCanonicalDigest
                | Self::ReconstructCanonicalDigest
        )
    }
}
