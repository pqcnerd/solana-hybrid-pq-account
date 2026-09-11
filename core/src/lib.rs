//! DualKey shared types, canonical encoding, and account layout.
//!
//! Client and program both build the same [`canonical::canonical_preimage`]
//! bytes, then hash with their own SHA-256 (`sha2` off-chain via the `sha2`
//! feature, `sol_sha256` on-chain). This makes "both schemes sign the exact
//! same canonical intent" true by construction rather than by convention.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod canonical;
pub mod error;
pub mod intent;
pub mod policy;
pub mod state;

pub use canonical::{
    canonical_preimage, test_vector_intent, ACTION_BODY_LEN, CANONICAL_PREIMAGE_LEN, DIGEST_LEN,
    DOMAIN_TAG, DOMAIN_TAG_LEN, INTENT_VERSION, TEST_VECTOR_DIGEST, TEST_VECTOR_PREIMAGE_PREFIX,
};
#[cfg(feature = "sha2")]
pub use canonical::{canonical_digest, digest_preimage};
pub use error::DualKeyError;
pub use intent::{Action, AuthorizationIntent, ACTION_TAG_TRANSFER_SOL};
pub use policy::AuthorizationPolicy;
pub use state::{
    HybridAccount, ACCOUNT_DATA_LEN, FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN,
    FLAG_FALCON_THRESHOLD_SET, FLAG_RECOVERY_ENABLED, PDA_SEED, PREPARED_FALCON_PUBKEY_LEN,
};
