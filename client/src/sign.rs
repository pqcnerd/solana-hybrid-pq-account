//! Dual-scheme signing and local verification (Milestone 1).
//!
//! Both schemes MUST sign the same SHA-256 digest of the canonical preimage.
//! Falcon verification on the host should use `solana-falcon512` (cross-check),
//! not only `pqcrypto-falcon`.

use std::path::Path;

use crate::error::{ClientError, Result};

/// Sign an intent file with Ed25519 and Falcon-512.
pub fn run(intent_path: &Path, keys_dir: &Path) -> Result<()> {
    let _ = (intent_path, keys_dir);
    Err(ClientError::Unimplemented(
        "sign — implement in Milestone 1",
    ))
}

/// Verify a signature bundle locally.
pub fn verify(input_path: &Path) -> Result<()> {
    let _ = input_path;
    Err(ClientError::Unimplemented(
        "verify — implement in Milestone 1",
    ))
}
