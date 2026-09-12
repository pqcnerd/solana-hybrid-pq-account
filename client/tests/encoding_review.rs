//! Encoding review tests (added while auditing Milestone 1).
//!
//! These pin down two properties that the `WireSignature` design depends on:
//!
//! 1. Whether the trailing-zero stripping used to recover `encoded_len` can
//!    ever remove a byte that was genuinely part of the encoding.
//! 2. Whether PQClean's own verifier accepts the 666-byte zero-padded buffer
//!    directly, which would remove the need for length recovery entirely.
//!
//! PQClean's `do_verify` contains:
//!
//! ```c
//! v = comp_decode(sig, 9, sigbuf, sigbuflen);
//! if (v == 0) return -1;
//! if (v != sigbuflen) {
//!     if (sigbuflen == FALCONPADDED512_CRYPTO_BYTES - NONCELEN - 1) {  // 625
//!         while (v < sigbuflen) { if (sigbuf[v++] != 0) return -1; }
//!     } else { return -1; }
//! }
//! ```
//!
//! so a 666-byte signature (sigbuflen = 666 - 40 - 1 = 625) takes the
//! zero-padded branch and is accepted.

use dualkey_client::falcon_interop::{self, WireSignature};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

const MESSAGE: &[u8] = b"encoding review";

/// The final byte of a `comp_encode` output carries the last coefficient's
/// unary terminator bit, so it should never be zero. If this ever fails, the
/// trailing-zero length recovery in `from_wire_bytes` is unsound.
#[test]
fn last_byte_of_compressed_signature_is_never_zero() {
    let mut checked = 0usize;
    for k in 0..8 {
        let (_pk, sk) = falcon512::keypair();
        for i in 0..250 {
            let msg = format!("terminator-{k}-{i}");
            let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
            let bytes = sig.as_bytes();
            let last = *bytes.last().unwrap();
            assert_ne!(
                last,
                0,
                "signature {k}/{i} (len={}) ended in a zero byte; \
                 trailing-zero length recovery would corrupt it",
                bytes.len()
            );
            checked += 1;
        }
    }
    println!("checked {checked} signatures; no zero terminal byte");
}

/// Consequence of the above: padding to 666 and stripping back recovers the
/// exact original length and bytes.
#[test]
fn wire_round_trip_recovers_exact_encoded_length() {
    for k in 0..10 {
        let (_pk, sk) = falcon512::keypair();
        for i in 0..50 {
            let msg = format!("roundtrip-{k}-{i}");
            let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
            let true_len = sig.as_bytes().len();

            let wire = WireSignature::from_pqclean(&sig).expect("pad");
            let reloaded = WireSignature::from_wire_bytes(wire.as_wire_bytes()).expect("reload");

            assert_eq!(
                reloaded.encoded_len(),
                true_len,
                "length recovery mismatch at {k}/{i}"
            );
            assert_eq!(reloaded.encoded_bytes(), sig.as_bytes());
        }
    }
}

/// PQClean accepts the full 666-byte zero-padded buffer, so verification does
/// not need to depend on recovering the encoded length at all.
#[test]
fn pqclean_verifies_the_666_byte_padded_buffer_directly() {
    for k in 0..10 {
        let (pk, sk) = falcon512::keypair();
        let msg = format!("padded-direct-{k}");
        let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
        let wire = WireSignature::from_pqclean(&sig).expect("pad");

        // Build a DetachedSignature from all 666 padded bytes.
        let padded = falcon512::DetachedSignature::from_bytes(wire.as_wire_bytes())
            .expect("PQClean must accept a 666-byte buffer");
        assert_eq!(padded.as_bytes().len(), 666);

        assert!(
            falcon_interop::verify_pqclean(&padded, msg.as_bytes(), &pk),
            "PQClean must verify the zero-padded 666-byte form (round {k})"
        );
    }
}

/// The padded form must still be rejected when the padding is not zero, which
/// is what makes the padded branch safe.
#[test]
fn pqclean_rejects_padded_buffer_with_non_zero_padding() {
    let (pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(MESSAGE, &sk);
    let wire = WireSignature::from_pqclean(&sig).expect("pad");
    assert!(wire.padding_len() > 0, "need padding for this test");

    let mut bytes = *wire.as_wire_bytes();
    bytes[665] = 0x01;

    let padded = falcon512::DetachedSignature::from_bytes(&bytes).expect("accepts 666 bytes");
    assert!(
        !falcon_interop::verify_pqclean(&padded, MESSAGE, &pk),
        "non-zero padding must be rejected by PQClean too"
    );
}

/// The high-level helper must verify via the padded buffer, so it agrees with
/// the on-chain verifier on exactly the same 666 bytes.
#[test]
fn verify_pqclean_wire_matches_the_on_chain_bytes() {
    for k in 0..10 {
        let (pk, sk) = falcon512::keypair();
        let msg = format!("agreement-{k}");
        let (_sig, wire) = falcon_interop::sign_to_wire(msg.as_bytes(), &sk).expect("sign");
        let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");

        // Same 666 bytes, three verifiers, all must agree.
        assert!(falcon_interop::verify_pqclean_wire(
            &wire,
            msg.as_bytes(),
            pk.as_bytes()
        ));
        assert!(falcon_interop::verify_solana_raw(
            &wire,
            msg.as_bytes(),
            pk.as_bytes()
        ));
        assert!(falcon_interop::verify_solana_prepared(
            &wire,
            msg.as_bytes(),
            &prepared
        ));
    }
}

/// A truncated signature must be rejected, not silently accepted via the
/// padded branch.
#[test]
fn truncated_signature_is_rejected_by_pqclean() {
    let (pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(MESSAGE, &sk);
    let bytes = sig.as_bytes();

    for cut in [1usize, 2, 5, 20] {
        let truncated = &bytes[..bytes.len() - cut];
        if let Ok(s) = falcon512::DetachedSignature::from_bytes(truncated) {
            assert!(
                !falcon_interop::verify_pqclean(&s, MESSAGE, &pk),
                "truncating {cut} bytes must not verify"
            );
        }
    }
}
