//! Key generation (Milestone 1).
//!
//! Will generate:
//! - Ed25519 keypair (Solana-compatible id.json)
//! - Falcon-512 keypair via `pqcrypto_falcon::falcon512`
//!
//! Falcon secret key material NEVER goes on-chain.

use std::path::Path;

use crate::error::{ClientError, Result};

/// Generate Ed25519 + Falcon-512 keypairs into `out_dir`.
pub fn run(out_dir: &Path) -> Result<()> {
    let _ = out_dir;
    // Keep Falcon crate linked for Milestone 0 so missing-C-compiler issues
    // surface early without performing keygen yet.
    let _ = pqcrypto_falcon::falcon512::public_key_bytes();
    Err(ClientError::Unimplemented(
        "keygen — implement in Milestone 1",
    ))
}
