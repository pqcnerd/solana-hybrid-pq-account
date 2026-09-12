//! Falcon-512 on-chain verification.
//!
//! Uses [`solana_falcon512`] for verification only. Falcon key generation and
//! Falcon signing are performed exclusively off-chain by the client; neither
//! appears anywhere in this crate's dependency graph.
//!
//! Two verification paths are exposed:
//!
//! * [`verify_falcon_prepared`] — takes the 1024-byte NTT-form ("prepared")
//!   public key. This is the production path: from Milestone 3 the prepared key
//!   lives in the HybridAccount PDA at an 8-byte-aligned offset and is borrowed
//!   zero-copy, skipping the wire decode and forward NTT on every call.
//! * [`verify_falcon_raw`] — takes the 897-byte wire public key and performs
//!   the decode plus forward NTT in-instruction. Kept for comparison so the
//!   cost of the prepared representation is measured rather than assumed.
//!
//! Both return `Err` on every failure path and never panic on caller-supplied
//! bytes: length, header, alignment and compression failures are all mapped to
//! errors by the underlying crate's checked constructors and its
//! `verify*` methods, which are documented to return `false` rather than panic.

use dualkey_core::DualKeyError;
use solana_falcon512::{Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature};

// Re-export lengths used by instruction parsing.
pub use dualkey_core::state::{
    FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN, PREPARED_FALCON_PUBKEY_LEN,
};

// `dualkey-core` is deliberately dependency-free so it can be shared with the
// off-chain client, which means it re-declares the Falcon lengths rather than
// importing them. Pin the two definitions together at compile time so they can
// never drift apart silently.
const _: () = assert!(
    FALCON_SIGNATURE_LEN == solana_falcon512::FALCON_512_SIGNATURE_LEN,
    "dualkey-core FALCON_SIGNATURE_LEN disagrees with solana-falcon512"
);
const _: () = assert!(
    FALCON_WIRE_PUBKEY_LEN == solana_falcon512::FALCON_512_PUBKEY_LEN,
    "dualkey-core FALCON_WIRE_PUBKEY_LEN disagrees with solana-falcon512"
);
const _: () = assert!(
    PREPARED_FALCON_PUBKEY_LEN == solana_falcon512::FALCON_512_PREPARED_PUBKEY_LEN,
    "dualkey-core PREPARED_FALCON_PUBKEY_LEN disagrees with solana-falcon512"
);

/// Verify a Falcon-512 compressed signature against a prepared (NTT-form)
/// public key.
///
/// `prepared_pubkey` must be exactly [`PREPARED_FALCON_PUBKEY_LEN`] bytes and
/// at least 2-byte aligned, because the verifier reinterprets it as
/// `[u16; 512]`. Solana guarantees account data is 8-byte aligned, and the
/// HybridAccount layout places the prepared key at offset 96 (a compile-time
/// assertion in `dualkey_core::state`), so the production caller always
/// satisfies this. A misaligned slice yields
/// [`DualKeyError::MalformedFalcon`] rather than undefined behaviour.
///
/// `signature` must be exactly [`FALCON_SIGNATURE_LEN`] bytes: the compressed
/// encoding right-zero-padded to 666. The padded (`0x49`) and constant-time
/// formats are not accepted.
pub fn verify_falcon_prepared(
    prepared_pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DualKeyError> {
    let prepared = Falcon512PreparedPubkey::try_from_slice(prepared_pubkey)
        .map_err(|_| DualKeyError::MalformedFalcon)?;
    let signature =
        Falcon512Signature::try_from_slice(signature).map_err(|_| DualKeyError::MalformedFalcon)?;

    if !signature.verify_with_prepared(message, prepared) {
        return Err(DualKeyError::InvalidFalcon);
    }
    Ok(())
}

/// Verify a Falcon-512 compressed signature against a raw 897-byte wire
/// public key, decoding and running the forward NTT in-instruction.
///
/// Provided for benchmarking against [`verify_falcon_prepared`]; the vault
/// path uses the prepared form.
pub fn verify_falcon_raw(
    pubkey_wire: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DualKeyError> {
    let pubkey =
        Falcon512Pubkey::try_from_slice(pubkey_wire).map_err(|_| DualKeyError::MalformedFalcon)?;
    let signature =
        Falcon512Signature::try_from_slice(signature).map_err(|_| DualKeyError::MalformedFalcon)?;

    if !signature.verify(message, pubkey) {
        return Err(DualKeyError::InvalidFalcon);
    }
    Ok(())
}
