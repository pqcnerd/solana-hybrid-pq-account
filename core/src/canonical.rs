//! Canonical authorization-intent preimage constants.
//!
//! Both Ed25519 and Falcon-512 MUST sign `SHA256(canonical_preimage(intent))`.
//! The preimage is a fixed-width binary layout (no JSON, no variable strings).
//!
//! Full byte-level specification: `docs/canonical-intent.md`.
//! Encoding function `canonical_preimage` lands in Milestone 4.

/// Domain separation tag ASCII bytes (without the length prefix byte).
pub const DOMAIN_TAG: &[u8] = b"DUALKEY_SOLANA_V1";

/// Length of [`DOMAIN_TAG`] (17). Prefixed on the wire by `0x11`.
pub const DOMAIN_TAG_LEN: usize = 17;

/// Intent schema version encoded in the preimage.
pub const INTENT_VERSION: u8 = 1;

/// Fixed action body width (TransferSol: recipient[32] || lamports u64 LE).
pub const ACTION_BODY_LEN: usize = 40;

/// Digest length produced by SHA-256 over the preimage.
pub const DIGEST_LEN: usize = 32;

/// Total preimage length:
/// ```text
/// 1 (tag len) + 17 (tag) + 1 (version) + 32 (chain_domain)
/// + 32 (program_id) + 32 (account) + 8 (nonce) + 8 (expiry)
/// + 1 (action_tag) + 40 (action_body) = 172
/// ```
pub const CANONICAL_PREIMAGE_LEN: usize = 172;

/// Offsets into the 172-byte preimage (for documentation and future encoders).
pub mod offsets {
    pub const DOMAIN_LEN: usize = 0;
    pub const DOMAIN_TAG: usize = 1;
    pub const VERSION: usize = 18;
    pub const CHAIN_DOMAIN: usize = 19;
    pub const PROGRAM_ID: usize = 51;
    pub const ACCOUNT: usize = 83;
    pub const NONCE: usize = 115;
    pub const EXPIRY_SLOT: usize = 123;
    pub const ACTION_TAG: usize = 131;
    pub const ACTION_BODY: usize = 132;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_length_matches_constant() {
        assert_eq!(DOMAIN_TAG.len(), DOMAIN_TAG_LEN);
        assert_eq!(DOMAIN_TAG_LEN, 0x11);
    }

    #[test]
    fn preimage_length_is_172() {
        assert_eq!(CANONICAL_PREIMAGE_LEN, 1 + DOMAIN_TAG_LEN + 1 + 32 + 32 + 32 + 8 + 8 + 1 + ACTION_BODY_LEN);
        assert_eq!(offsets::ACTION_BODY + ACTION_BODY_LEN, CANONICAL_PREIMAGE_LEN);
    }
}
