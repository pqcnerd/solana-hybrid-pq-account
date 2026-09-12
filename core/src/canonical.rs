//! Canonical authorization-intent encoding.
//!
//! Both Ed25519 and Falcon-512 MUST sign `SHA256(canonical_preimage(intent))`.
//!
//! Domain separation is *inside* the preimage: the first 18 bytes are
//! `0x11 || "DUALKEY_SOLANA_V1"`. Therefore
//!
//! ```text
//! digest = SHA256(preimage)
//!        = SHA256(0x11 || "DUALKEY_SOLANA_V1" || intent fields)
//! ```
//!
//! The tag is never applied twice. Full specification:
//! `docs/canonical-intent.md`.

use crate::intent::{Action, AuthorizationIntent};

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

/// Offsets into the 172-byte preimage.
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

// Layout is load-bearing for cross-layer signature agreement.
const _: () = assert!(DOMAIN_TAG_LEN == 0x11);
const _: () = assert!(offsets::ACTION_BODY + ACTION_BODY_LEN == CANONICAL_PREIMAGE_LEN);

/// Build the canonical, fixed-width signing preimage for `intent`.
///
/// Deterministic and allocation-free. Every field is fixed width, so no two
/// distinct intents can produce the same preimage.
pub fn canonical_preimage(intent: &AuthorizationIntent) -> [u8; CANONICAL_PREIMAGE_LEN] {
    let mut out = [0u8; CANONICAL_PREIMAGE_LEN];

    out[offsets::DOMAIN_LEN] = DOMAIN_TAG_LEN as u8;
    out[offsets::DOMAIN_TAG..offsets::DOMAIN_TAG + DOMAIN_TAG_LEN].copy_from_slice(DOMAIN_TAG);
    out[offsets::VERSION] = intent.version;
    out[offsets::CHAIN_DOMAIN..offsets::CHAIN_DOMAIN + 32].copy_from_slice(&intent.chain_domain);
    out[offsets::PROGRAM_ID..offsets::PROGRAM_ID + 32].copy_from_slice(&intent.program_id);
    out[offsets::ACCOUNT..offsets::ACCOUNT + 32].copy_from_slice(&intent.account);
    out[offsets::NONCE..offsets::NONCE + 8].copy_from_slice(&intent.nonce.to_le_bytes());
    out[offsets::EXPIRY_SLOT..offsets::EXPIRY_SLOT + 8]
        .copy_from_slice(&intent.expiry_slot.to_le_bytes());
    out[offsets::ACTION_TAG] = intent.action.tag();

    match intent.action {
        Action::TransferSol {
            recipient,
            lamports,
        } => {
            let body = offsets::ACTION_BODY;
            out[body..body + 32].copy_from_slice(&recipient);
            out[body + 32..body + 40].copy_from_slice(&lamports.to_le_bytes());
        }
        Action::RotateEd25519Key { new_pubkey } => {
            let body = offsets::ACTION_BODY;
            out[body..body + 32].copy_from_slice(&new_pubkey);
            // Remaining 8 bytes stay zero (reserved).
        }
        Action::RotateFalconKey { new_pubkey_hash } => {
            let body = offsets::ACTION_BODY;
            out[body..body + 32].copy_from_slice(&new_pubkey_hash);
            // Remaining 8 bytes stay zero (reserved).
        }
        Action::ChangePolicy {
            new_policy,
            threshold,
        } => {
            let body = offsets::ACTION_BODY;
            out[body] = new_policy;
            // bytes [1..8] stay zero (pad)
            out[body + 8..body + 16].copy_from_slice(&threshold.to_le_bytes());
            // Remaining 24 bytes stay zero (reserved).
        }
    }

    out
}

/// Compute the 32-byte signing digest from an already-built preimage.
///
/// Host-only (requires the `sha2` feature). The on-chain program hashes the
/// identical preimage bytes with the `sol_sha256` syscall instead.
#[cfg(feature = "sha2")]
pub fn digest_preimage(preimage: &[u8; CANONICAL_PREIMAGE_LEN]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Build the preimage and return the single 32-byte digest both schemes sign.
#[cfg(feature = "sha2")]
pub fn canonical_digest(intent: &AuthorizationIntent) -> [u8; DIGEST_LEN] {
    digest_preimage(&canonical_preimage(intent))
}

// ---------------------------------------------------------------------------
// Cross-layer known-answer vectors.
//
// Exposed publicly (not test-only) so the client, and later the program, can
// each assert that their own hasher reproduces the same digest from the same
// fixture. Changing any of these values is a breaking protocol change.
// ---------------------------------------------------------------------------

/// First 19 bytes of the [`test_vector_intent`] preimage: the length-prefixed
/// domain tag followed by the intent version.
pub const TEST_VECTOR_PREIMAGE_PREFIX: [u8; 19] = [
    0x11,
    b'D',
    b'U',
    b'A',
    b'L',
    b'K',
    b'E',
    b'Y',
    b'_',
    b'S',
    b'O',
    b'L',
    b'A',
    b'N',
    b'A',
    b'_',
    b'V',
    b'1',
    INTENT_VERSION,
];

/// SHA-256 of the full 172-byte [`test_vector_intent`] preimage.
///
/// `6182ba27c082b3e8110e47a2af27e0ece6f5eee8fcea6e7927e40707f8deb5ec`
pub const TEST_VECTOR_DIGEST: [u8; DIGEST_LEN] = [
    0x61, 0x82, 0xba, 0x27, 0xc0, 0x82, 0xb3, 0xe8, 0x11, 0x0e, 0x47, 0xa2, 0xaf, 0x27, 0xe0, 0xec,
    0xe6, 0xf5, 0xee, 0xe8, 0xfc, 0xea, 0x6e, 0x79, 0x27, 0xe4, 0x07, 0x07, 0xf8, 0xde, 0xb5, 0xec,
];

/// Deterministic test intent used for cross-layer known-answer vectors.
///
/// Available to all consumers so client and program can assert agreement on
/// the same fixture without duplicating it.
pub fn test_vector_intent() -> AuthorizationIntent {
    AuthorizationIntent {
        version: INTENT_VERSION,
        chain_domain: [0x11; 32],
        program_id: [0x22; 32],
        account: [0x33; 32],
        nonce: 7,
        expiry_slot: 1_234_567,
        action: Action::TransferSol {
            recipient: [0x44; 32],
            lamports: 5_000_000_000,
        },
    }
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
        assert_eq!(
            CANONICAL_PREIMAGE_LEN,
            1 + DOMAIN_TAG_LEN + 1 + 32 + 32 + 32 + 8 + 8 + 1 + ACTION_BODY_LEN
        );
        assert_eq!(
            offsets::ACTION_BODY + ACTION_BODY_LEN,
            CANONICAL_PREIMAGE_LEN
        );
    }

    #[test]
    fn preimage_starts_with_length_prefixed_domain_tag() {
        let p = canonical_preimage(&test_vector_intent());
        assert_eq!(p[0], 0x11);
        assert_eq!(&p[1..18], DOMAIN_TAG);
    }

    #[test]
    fn preimage_encodes_every_field_at_its_offset() {
        let intent = test_vector_intent();
        let p = canonical_preimage(&intent);

        assert_eq!(p[offsets::VERSION], INTENT_VERSION);
        assert_eq!(
            &p[offsets::CHAIN_DOMAIN..offsets::CHAIN_DOMAIN + 32],
            &[0x11; 32]
        );
        assert_eq!(
            &p[offsets::PROGRAM_ID..offsets::PROGRAM_ID + 32],
            &[0x22; 32]
        );
        assert_eq!(&p[offsets::ACCOUNT..offsets::ACCOUNT + 32], &[0x33; 32]);
        assert_eq!(&p[offsets::NONCE..offsets::NONCE + 8], &7u64.to_le_bytes());
        assert_eq!(
            &p[offsets::EXPIRY_SLOT..offsets::EXPIRY_SLOT + 8],
            &1_234_567u64.to_le_bytes()
        );
        assert_eq!(
            p[offsets::ACTION_TAG],
            crate::intent::ACTION_TAG_TRANSFER_SOL
        );
        assert_eq!(
            &p[offsets::ACTION_BODY..offsets::ACTION_BODY + 32],
            &[0x44; 32]
        );
        assert_eq!(
            &p[offsets::ACTION_BODY + 32..CANONICAL_PREIMAGE_LEN],
            &5_000_000_000u64.to_le_bytes()
        );
    }

    #[test]
    fn distinct_fields_produce_distinct_preimages() {
        let base = test_vector_intent();
        let p0 = canonical_preimage(&base);

        let mut nonce_changed = base;
        nonce_changed.nonce = 8;
        assert_ne!(canonical_preimage(&nonce_changed), p0);

        let mut amount_changed = base;
        amount_changed.action = Action::TransferSol {
            recipient: [0x44; 32],
            lamports: 5_000_000_001,
        };
        assert_ne!(canonical_preimage(&amount_changed), p0);

        let mut recipient_changed = base;
        recipient_changed.action = Action::TransferSol {
            recipient: [0x45; 32],
            lamports: 5_000_000_000,
        };
        assert_ne!(canonical_preimage(&recipient_changed), p0);

        let mut program_changed = base;
        program_changed.program_id = [0x23; 32];
        assert_ne!(canonical_preimage(&program_changed), p0);

        let mut account_changed = base;
        account_changed.account = [0x34; 32];
        assert_ne!(canonical_preimage(&account_changed), p0);

        let mut chain_changed = base;
        chain_changed.chain_domain = [0x12; 32];
        assert_ne!(canonical_preimage(&chain_changed), p0);
    }

    #[test]
    fn known_answer_preimage_prefix_is_stable() {
        let p = canonical_preimage(&test_vector_intent());
        assert_eq!(&p[..19], &TEST_VECTOR_PREIMAGE_PREFIX);
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn known_answer_digest_is_stable() {
        let digest = canonical_digest(&test_vector_intent());
        assert_eq!(
            digest, TEST_VECTOR_DIGEST,
            "canonical digest changed; update docs/canonical-intent.md deliberately"
        );
    }
}
