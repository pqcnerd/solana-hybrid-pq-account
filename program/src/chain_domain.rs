//! Compile-time `chain_domain` selected by Cargo feature.
//!
//! Exactly one of `mainnet`, `devnet`, or `localnet` may be enabled. When none
//! is selected the research default is `localnet`, so host tests and unmarked
//! SBF builds still produce a defined domain.

#[cfg(all(feature = "mainnet", feature = "devnet"))]
compile_error!("enable at most one of dualkey-program features: mainnet, devnet, localnet");
#[cfg(all(feature = "mainnet", feature = "localnet"))]
compile_error!("enable at most one of dualkey-program features: mainnet, devnet, localnet");
#[cfg(all(feature = "devnet", feature = "localnet"))]
compile_error!("enable at most one of dualkey-program features: mainnet, devnet, localnet");

/// Cluster domain embedded in every reconstructed authorization intent.
///
/// Selected at compile time — see the crate features and
/// `docs/canonical-intent.md`.
#[cfg(feature = "mainnet")]
pub const CHAIN_DOMAIN: [u8; 32] = dualkey_core::CHAIN_DOMAIN_MAINNET;

#[cfg(all(feature = "devnet", not(feature = "mainnet")))]
pub const CHAIN_DOMAIN: [u8; 32] = dualkey_core::CHAIN_DOMAIN_DEVNET;

#[cfg(all(not(feature = "mainnet"), not(feature = "devnet")))]
pub const CHAIN_DOMAIN: [u8; 32] = dualkey_core::CHAIN_DOMAIN_LOCALNET;
