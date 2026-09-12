//! Compile-time cluster domain separators.
//!
//! Solana programs cannot read the cluster genesis hash at runtime, so a
//! user-supplied domain at initialization would be attacker-chosen and would
//! not bind the intent to a network. DualKey therefore embeds a **compile-time**
//! [`chain_domain`](crate::AuthorizationIntent::chain_domain) chosen by Cargo
//! features on the program crate (`mainnet` / `devnet` / `localnet`).
//!
//! Cross-network replay resistance therefore holds only between binaries built
//! with different features — stated plainly in `docs/threat-model.md`.
//!
//! Local validators mint a fresh genesis hash per start, so `localnet` uses a
//! fixed research label rather than pretending to track genesis.

/// `chain_domain` for mainnet-beta builds.
///
/// ASCII `dualkey:mainnet`, zero-padded to 32 bytes.
pub const CHAIN_DOMAIN_MAINNET: [u8; 32] = *b"dualkey:mainnet\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// `chain_domain` for Solana Devnet builds.
///
/// ASCII `dualkey:devnet`, zero-padded to 32 bytes.
pub const CHAIN_DOMAIN_DEVNET: [u8; 32] = *b"dualkey:devnet\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// `chain_domain` for local / research builds.
///
/// ASCII `dualkey:localnet`, zero-padded to 32 bytes. Not a genesis hash: local
/// validators rotate genesis on every restart, so a fixed research label is the
/// honest choice.
pub const CHAIN_DOMAIN_LOCALNET: [u8; 32] = *b"dualkey:localnet\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_distinct() {
        assert_ne!(CHAIN_DOMAIN_MAINNET, CHAIN_DOMAIN_DEVNET);
        assert_ne!(CHAIN_DOMAIN_MAINNET, CHAIN_DOMAIN_LOCALNET);
        assert_ne!(CHAIN_DOMAIN_DEVNET, CHAIN_DOMAIN_LOCALNET);
    }

    #[test]
    fn domains_start_with_documented_labels() {
        assert!(CHAIN_DOMAIN_MAINNET.starts_with(b"dualkey:mainnet"));
        assert!(CHAIN_DOMAIN_DEVNET.starts_with(b"dualkey:devnet"));
        assert!(CHAIN_DOMAIN_LOCALNET.starts_with(b"dualkey:localnet"));
    }
}
