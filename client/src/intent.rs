//! Intent construction helpers (Milestone 1 / 4).
//!
//! Builds [`dualkey_core::AuthorizationIntent`] values for signing.

#![allow(dead_code)] // Wired in Milestone 1.

use crate::error::{ClientError, Result};

/// Placeholder for loading / building an authorization intent.
pub fn load_intent_placeholder() -> Result<()> {
    Err(ClientError::Unimplemented(
        "intent construction — implement in Milestone 1",
    ))
}
