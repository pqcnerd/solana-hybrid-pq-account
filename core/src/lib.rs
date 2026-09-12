//! DualKey shared types, canonical encoding, and account layout.
//!
//! Client and program both build the same [`canonical::canonical_preimage`]
//! bytes, then hash with their own SHA-256 (`sha2` off-chain via the `sha2`
//! feature, `sol_sha256` on-chain). This makes "both schemes sign the exact
//! same canonical intent" true by construction rather than by convention.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod canonical;
pub mod chain_domain;
pub mod error;
pub mod intent;
pub mod policy;
pub mod state;
pub mod wire;

#[cfg(feature = "sha2")]
pub use canonical::{canonical_digest, digest_preimage};
pub use canonical::{
    canonical_preimage, test_vector_intent, ACTION_BODY_LEN, CANONICAL_PREIMAGE_LEN, DIGEST_LEN,
    DOMAIN_TAG, DOMAIN_TAG_LEN, INTENT_VERSION, TEST_VECTOR_DIGEST, TEST_VECTOR_PREIMAGE_PREFIX,
};
pub use chain_domain::{CHAIN_DOMAIN_DEVNET, CHAIN_DOMAIN_LOCALNET, CHAIN_DOMAIN_MAINNET};
pub use error::DualKeyError;
pub use intent::{
    Action, AuthorizationIntent, ACTION_TAG_CHANGE_POLICY, ACTION_TAG_ROTATE_ED25519,
    ACTION_TAG_ROTATE_FALCON, ACTION_TAG_TRANSFER_SOL,
};
pub use policy::{AuthorizationPolicy, SignatureRequirement};
pub use state::{
    pda_seeds, HybridAccount, ACCOUNT_DATA_LEN, ACCOUNT_INDEX_LEN, ACCOUNT_VERSION,
    FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN, FLAG_FALCON_THRESHOLD_SET, FLAG_RECOVERY_ENABLED,
    PDA_SEED, PDA_SEED_COUNT, PREPARED_FALCON_PUBKEY_LEN,
};
pub use wire::{
    reconstruct_intent, ExecuteIntentWire, IntentContext, EXECUTE_INTENT_DERIVED_LEN,
    EXECUTE_INTENT_WIRE_LEN,
};
