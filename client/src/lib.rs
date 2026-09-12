//! DualKey off-chain client library.
//!
//! Host-side key generation, dual-scheme signing, and verification. All
//! canonical serialization and hashing comes from [`dualkey_core`]; this crate
//! never reimplements either.
//!
//! Falcon secret key material is never written into anything destined for
//! on-chain account data and is never printed.

pub mod error;
pub mod falcon_interop;
pub mod intent;
pub mod keygen;
pub mod keys;
pub mod onchain;
pub mod sign;
pub mod submit;

pub use error::{ClientError, Result};
