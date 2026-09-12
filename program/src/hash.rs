//! On-chain canonical digest computation.
//!
//! `dualkey-core` owns the canonical serialization
//! ([`dualkey_core::canonical_preimage`]) but is deliberately hasher-agnostic:
//! it has no dependencies, so it cannot reach either `sha2` or the Solana
//! syscalls. Each layer supplies its own SHA-256:
//!
//! * the off-chain client enables `dualkey-core`'s optional `sha2` feature,
//! * this program hashes the identical bytes with `sol_sha256`.
//!
//! Because both hash the same `canonical_preimage` output, the digests are
//! equal by construction. That equality is a cross-layer invariant rather than
//! an assumption, so it is asserted against the shared known-answer vector
//! [`dualkey_core::TEST_VECTOR_DIGEST`] in the Milestone 2 SBF tests.

use dualkey_core::{DualKeyError, CANONICAL_PREIMAGE_LEN, DIGEST_LEN};
use solana_sha256_hasher::hashv;

/// SHA-256 arbitrary bytes using the `sol_sha256` syscall.
pub fn sha256(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    hashv(&[bytes]).to_bytes()
}

/// SHA-256 a canonical authorization preimage using the `sol_sha256` syscall.
///
/// Rejects any length other than [`CANONICAL_PREIMAGE_LEN`] so a truncated or
/// extended preimage can never hash to a digest the client would also produce.
pub fn digest_canonical_preimage(preimage: &[u8]) -> Result<[u8; DIGEST_LEN], DualKeyError> {
    if preimage.len() != CANONICAL_PREIMAGE_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }
    Ok(sha256(preimage))
}
