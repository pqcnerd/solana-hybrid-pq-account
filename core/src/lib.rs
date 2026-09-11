//! DualKey shared types and layout constants.
//!
//! This crate is intentionally dependency-free. Client and program both
//! construct the same [`crate::canonical`] preimage bytes, then hash with
//! their own SHA-256 (`sha2` off-chain, `sol_sha256` on-chain).
//!
//! Encoding of the preimage body is implemented in Milestone 4; this crate
//! currently exposes the length constants and type definitions that both
//! sides will share.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod canonical;
pub mod error;
pub mod intent;
pub mod policy;
pub mod state;

pub use canonical::{
    ACTION_BODY_LEN, CANONICAL_PREIMAGE_LEN, DOMAIN_TAG, DOMAIN_TAG_LEN, INTENT_VERSION,
};
pub use error::DualKeyError;
pub use intent::{Action, AuthorizationIntent, ACTION_TAG_TRANSFER_SOL};
pub use policy::AuthorizationPolicy;
pub use state::{
    HybridAccount, ACCOUNT_DATA_LEN, FLAG_FALCON_THRESHOLD_SET, FLAG_RECOVERY_ENABLED,
    PREPARED_FALCON_PUBKEY_LEN, PDA_SEED,
};
