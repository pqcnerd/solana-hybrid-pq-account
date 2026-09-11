//! Ed25519 verification via the Solana Ed25519 precompile + instructions sysvar.
//!
//! Planned procedure (Milestone 5; see `docs/architecture.md`):
//! 1. Pin instructions sysvar by key.
//! 2. Load the Ed25519 precompile instruction.
//! 3. Assert program id is `Ed25519SigVerify111111111111111111111111111`.
//! 4. Assert exactly one signature; bounds-check offsets.
//! 5. Assert pubkey == account owner AND message == reconstructed digest.
//!
//! A bare "did an Ed25519 ix run?" check is insufficient and exploitable.

use dualkey_core::DualKeyError;

/// Verify that the Ed25519 precompile authorized `expected_digest` under
/// `expected_pubkey`.
///
/// Milestone 0: not implemented. Returns [`DualKeyError::Unimplemented`].
/// Never returns `Ok(())` until real introspection is complete.
pub fn verify_ed25519_precompile(
    _instructions_sysvar_data: &[u8],
    _expected_pubkey: &[u8; 32],
    _expected_digest: &[u8; 32],
) -> Result<(), DualKeyError> {
    Err(DualKeyError::Unimplemented)
}
