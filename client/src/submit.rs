//! Transaction submission (Milestones 3 / 7).
//!
//! Builds the Ed25519 precompile instruction by hand (144 bytes) plus the
//! DualKey execute instruction. Does not use SDK helpers that re-sign.

use std::path::Path;

use crate::error::{ClientError, Result};

/// Initialize a HybridAccount PDA.
pub fn init(keys_dir: &Path, account_index: u32) -> Result<()> {
    let _ = (keys_dir, account_index);
    Err(ClientError::Unimplemented(
        "init — implement in Milestone 3",
    ))
}

/// Submit a hybrid-authorized SOL transfer.
pub fn transfer(keys_dir: &Path, recipient: &str, lamports: u64) -> Result<()> {
    let _ = (keys_dir, recipient, lamports);
    Err(ClientError::Unimplemented(
        "transfer — implement in Milestone 7",
    ))
}
