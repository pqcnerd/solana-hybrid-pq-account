//! GROUP C (signature mutation): flipping one bit of either signature must
//! cause verification failure, and malformed Falcon signatures must fail
//! safely with no panic.

use dualkey_client::falcon_interop::{self, WireSignature};
use dualkey_client::keys::{Ed25519Keypair, FalconKeypair};
use dualkey_client::sign::{self, signing_material};
use dualkey_core::{Action, AuthorizationIntent};
use ed25519_dalek::Signer;

fn digest() -> [u8; 32] {
    signing_material(AuthorizationIntent::new(
        [0x0A; 32],
        [0x0B; 32],
        [0x0C; 32],
        5,
        50_000,
        Action::TransferSol {
            recipient: [0x0D; 32],
            lamports: 42,
        },
    ))
    .digest
}

#[test]
fn ed25519_signature_bit_flip_fails() {
    let ed = Ed25519Keypair::generate();
    let d = digest();
    let sig = ed.signing_key().sign(&d).to_bytes();

    assert!(sign::verify_ed25519(&ed.public_bytes(), &sig, &d));

    for byte in 0..64usize {
        for bit in 0..8u32 {
            let mut m = sig;
            m[byte] ^= 1 << bit;
            assert!(
                !sign::verify_ed25519(&ed.public_bytes(), &m, &d),
                "Ed25519 accepted signature mutation at byte {byte} bit {bit}"
            );
        }
    }
}

#[test]
fn falcon_signature_bit_flip_fails_under_both_verifiers() {
    let falcon = FalconKeypair::generate();
    let d = digest();
    let (pq_sig, wire) = falcon_interop::sign_to_wire(&d, falcon.secret()).expect("sign");
    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");

    assert!(falcon_interop::verify_pqclean(&pq_sig, &d, falcon.public()));
    assert!(falcon_interop::verify_solana_prepared(&wire, &d, &prepared));

    // Sample bit positions across the header, nonce, and encoded s2 region.
    let positions: [usize; 8] = [0, 1, 20, 40, 41, 100, 400, wire.encoded_len() - 1];
    for &byte in &positions {
        for bit in [0u32, 3, 7] {
            let mut bytes = *wire.as_wire_bytes();
            bytes[byte] ^= 1 << bit;
            let mutated = WireSignature::from_wire_bytes(&bytes).expect("reload");

            assert!(
                !falcon_interop::verify_solana_prepared(&mutated, &d, &prepared),
                "solana-falcon512 accepted signature mutation at byte {byte} bit {bit}"
            );
            assert!(
                !falcon_interop::verify_solana_raw(&mutated, &d, falcon.public_bytes()),
                "solana-falcon512 (raw) accepted mutation at byte {byte} bit {bit}"
            );

            // PQClean path: rebuilding may fail outright, which also counts as
            // rejection. If it rebuilds, it must not verify.
            if let Ok(pq) = mutated.to_pqclean() {
                assert!(
                    !falcon_interop::verify_pqclean(&pq, &d, falcon.public()),
                    "PQClean accepted signature mutation at byte {byte} bit {bit}"
                );
            }
        }
    }
}

/// Mutating the zero padding must be rejected: `solana-falcon512` requires all
/// trailing bytes past the encoded signature to be zero.
#[test]
fn non_zero_padding_is_rejected() {
    let falcon = FalconKeypair::generate();
    let d = digest();
    let (_pq_sig, wire) = falcon_interop::sign_to_wire(&d, falcon.secret()).expect("sign");
    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");

    assert!(
        wire.padding_len() > 0,
        "need at least one padding byte for this test (encoded_len={})",
        wire.encoded_len()
    );

    let mut bytes = *wire.as_wire_bytes();
    bytes[665] = 0x01; // last byte is always padding here
    let mutated = WireSignature::from_wire_bytes(&bytes).expect("reload");

    assert!(
        !falcon_interop::verify_solana_prepared(&mutated, &d, &prepared),
        "non-zero trailing padding must be rejected"
    );
}

/// Malformed / adversarial Falcon signature buffers must fail safely and never
/// panic. `solana-falcon512` documents that verify never panics; this asserts
/// it for our own call paths too.
#[test]
fn malformed_falcon_signatures_fail_safely_without_panic() {
    let falcon = FalconKeypair::generate();
    let d = digest();
    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("all zeros", vec![0u8; 666]),
        ("all 0xFF", vec![0xFFu8; 666]),
        ("wrong header 0x00", {
            let mut v = vec![0u8; 666];
            v[0] = 0x00;
            v
        }),
        ("padded header 0x49", {
            let mut v = vec![0u8; 666];
            v[0] = 0x49;
            v
        }),
        ("header only", {
            let mut v = vec![0u8; 666];
            v[0] = 0x39;
            v
        }),
        ("random-ish body", {
            let mut v = vec![0u8; 666];
            v[0] = 0x39;
            for (i, b) in v.iter_mut().enumerate().skip(1) {
                *b = (i as u8).wrapping_mul(37).wrapping_add(11);
            }
            v
        }),
    ];

    for (name, bytes) in cases {
        let wire = WireSignature::from_wire_bytes(&bytes)
            .unwrap_or_else(|e| panic!("case {name} should still parse as 666 bytes: {e}"));
        assert!(
            !falcon_interop::verify_solana_prepared(&wire, &d, &prepared),
            "case {name}: malformed signature must not verify"
        );
        assert!(
            !falcon_interop::verify_solana_raw(&wire, &d, falcon.public_bytes()),
            "case {name}: malformed signature must not verify (raw)"
        );
    }
}

/// Wrong-length signature buffers are rejected at the boundary, not truncated
/// or zero-extended into something that might verify.
#[test]
fn wrong_length_signature_buffers_are_rejected() {
    for len in [0usize, 1, 40, 41, 665, 667, 752, 1024] {
        let bytes = vec![0x39u8; len];
        let result = WireSignature::from_wire_bytes(&bytes);
        assert!(
            result.is_err(),
            "a {len}-byte buffer must not be accepted as a 666-byte wire signature"
        );
    }
    // Exactly 666 is the only accepted width.
    assert!(WireSignature::from_wire_bytes(&vec![0u8; 666]).is_ok());
}

/// Malformed Ed25519 signature and key material must fail safely.
#[test]
fn malformed_ed25519_material_fails_safely() {
    let d = digest();
    assert!(!sign::verify_ed25519(&[], &[], &d));
    assert!(!sign::verify_ed25519(&[0u8; 32], &[0u8; 64], &d));
    assert!(!sign::verify_ed25519(&[0xFFu8; 32], &[0xFFu8; 64], &d));
    assert!(!sign::verify_ed25519(&[0u8; 31], &[0u8; 64], &d));
    assert!(!sign::verify_ed25519(&[0u8; 32], &[0u8; 63], &d));
}
