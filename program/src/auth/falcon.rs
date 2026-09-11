//! Falcon-512 on-chain verification.
//!
//! Uses [`solana_falcon512`] for prepared-pubkey verification.
//! Key generation and signing are NEVER performed on-chain.
//!
//! Milestone 2 introduces a minimal verify instruction; Milestone 5 wires
//! this into HybridAnd authorization.

use dualkey_core::DualKeyError;

// Re-export lengths used by instruction parsing (Milestone 2+).
pub use dualkey_core::state::{FALCON_SIGNATURE_LEN, PREPARED_FALCON_PUBKEY_LEN};

/// Verify a Falcon-512 compressed signature against a prepared public key.
///
/// Milestone 0: not implemented. Returns [`DualKeyError::Unimplemented`].
/// Never returns `Ok(())` until `solana_falcon512` verification is called.
///
/// Intended Milestone 2+ body (do not invent APIs — call the crate):
/// ```ignore
/// let prepared = Falcon512PreparedPubkey::try_from_slice(prepared_pubkey)
///     .map_err(|_| DualKeyError::MalformedFalcon)?;
/// let signature = Falcon512Signature::try_from_slice(signature)
///     .map_err(|_| DualKeyError::MalformedFalcon)?;
/// if !signature.verify_with_prepared(message, prepared) {
///     return Err(DualKeyError::InvalidFalcon);
/// }
/// Ok(())
/// ```
pub fn verify_falcon_prepared(
    _prepared_pubkey: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), DualKeyError> {
    // Keep the dependency linked so SBF build regressions surface early once
    // the toolchain is installed, without calling verify yet.
    let _ = core::mem::size_of::<solana_falcon512::Falcon512Signature>();
    Err(DualKeyError::Unimplemented)
}
