//! GROUP D (wrong keys): a correct signature must not verify under the wrong
//! public key, for either scheme.

use dualkey_client::falcon_interop;
use dualkey_client::keys::{Ed25519Keypair, FalconKeypair};
use dualkey_client::sign::{self, sign_intent, signing_material, verify_bundle};
use dualkey_core::{Action, AuthorizationIntent};
use ed25519_dalek::Signer;

fn intent() -> AuthorizationIntent {
    AuthorizationIntent::new(
        [0x21; 32],
        [0x22; 32],
        [0x23; 32],
        3,
        30_000,
        Action::TransferSol {
            recipient: [0x24; 32],
            lamports: 999,
        },
    )
}

#[test]
fn correct_ed25519_signature_fails_under_wrong_public_key() {
    let signer = Ed25519Keypair::generate();
    let other = Ed25519Keypair::generate();
    let d = signing_material(intent()).digest;

    let sig = signer.signing_key().sign(&d).to_bytes();

    assert!(sign::verify_ed25519(&signer.public_bytes(), &sig, &d));
    assert_ne!(signer.public_bytes(), other.public_bytes());
    assert!(
        !sign::verify_ed25519(&other.public_bytes(), &sig, &d),
        "Ed25519 signature must not verify under an unrelated public key"
    );
}

#[test]
fn correct_falcon_signature_fails_under_wrong_public_key() {
    let signer = FalconKeypair::generate();
    let other = FalconKeypair::generate();
    let d = signing_material(intent()).digest;

    let (pq_sig, wire) = falcon_interop::sign_to_wire(&d, signer.secret()).expect("sign");

    // Correct key verifies in all paths.
    assert!(falcon_interop::verify_pqclean(&pq_sig, &d, signer.public()));
    assert!(falcon_interop::verify_solana_raw(
        &wire,
        &d,
        signer.public_bytes()
    ));

    assert_ne!(signer.public_bytes(), other.public_bytes());

    // Wrong key fails in all paths.
    assert!(
        !falcon_interop::verify_pqclean(&pq_sig, &d, other.public()),
        "PQClean must reject an unrelated public key"
    );
    assert!(
        !falcon_interop::verify_solana_raw(&wire, &d, other.public_bytes()),
        "solana-falcon512 (raw) must reject an unrelated public key"
    );
    let other_prepared = falcon_interop::prepare_pubkey(other.public_bytes()).expect("prepare");
    assert!(
        !falcon_interop::verify_solana_prepared(&wire, &d, &other_prepared),
        "solana-falcon512 (prepared) must reject an unrelated public key"
    );
}

/// A one-bit change to a Falcon public key must not verify. It may also fail
/// wire parsing or NTT preparation, which is equally a rejection.
#[test]
fn falcon_public_key_bit_flip_does_not_verify() {
    let signer = FalconKeypair::generate();
    let d = signing_material(intent()).digest;
    let (_pq_sig, wire) = falcon_interop::sign_to_wire(&d, signer.secret()).expect("sign");

    for byte in [1usize, 10, 400, 896] {
        let mut pk = signer.public_bytes().to_vec();
        pk[byte] ^= 1;

        assert!(
            !falcon_interop::verify_solana_raw(&wire, &d, &pk),
            "mutated public key at byte {byte} must not verify (raw)"
        );
        if let Ok(prepared) = falcon_interop::prepare_pubkey(&pk) {
            assert!(
                !falcon_interop::verify_solana_prepared(&wire, &d, &prepared),
                "mutated public key at byte {byte} must not verify (prepared)"
            );
        }
    }
}

/// Swapping either public key in a signed bundle must break that scheme's
/// verification while leaving the other intact, proving the two checks are
/// independent (a HybridAnd prerequisite).
#[test]
fn bundle_with_substituted_public_keys_fails_per_scheme() {
    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();
    let other_ed = Ed25519Keypair::generate();
    let other_falcon = FalconKeypair::generate();

    let bundle = sign_intent(intent(), &ed, &falcon).expect("sign");
    assert!(verify_bundle(&bundle).expect("verify").all_valid());

    // Wrong Ed25519 key: Ed25519 fails, Falcon still valid.
    let mut swapped_ed = bundle.clone();
    swapped_ed.ed25519_public_key = hex::encode(other_ed.public_bytes());
    let r = verify_bundle(&swapped_ed).expect("verify");
    assert!(!r.ed25519_valid, "Ed25519 should fail with a swapped key");
    assert!(r.falcon_solana_valid, "Falcon should be unaffected");
    assert!(!r.all_valid());

    // Wrong Falcon key: Falcon fails, Ed25519 still valid.
    let mut swapped_falcon = bundle.clone();
    swapped_falcon.falcon512_public_key = hex::encode(other_falcon.public_bytes());
    let r = verify_bundle(&swapped_falcon).expect("verify");
    assert!(r.ed25519_valid, "Ed25519 should be unaffected");
    assert!(
        !r.falcon_pqclean_valid && !r.falcon_solana_valid && !r.falcon_solana_prepared_valid,
        "Falcon should fail with a swapped key"
    );
    assert!(!r.all_valid());
}

/// Tampering with the intent inside a signed bundle must break both schemes
/// and be reported as a digest mismatch.
#[test]
fn bundle_with_tampered_intent_fails_both_schemes() {
    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();
    let bundle = sign_intent(intent(), &ed, &falcon).expect("sign");

    // Change the transfer amount after signing.
    let mut tampered = bundle.clone();
    tampered.intent.action = dualkey_client::intent::ActionSpec::TransferSol {
        recipient: hex::encode([0x24u8; 32]),
        lamports: 1_000_000,
    };

    let r = verify_bundle(&tampered).expect("verify");
    assert!(!r.ed25519_valid, "amount change must break Ed25519");
    assert!(!r.falcon_solana_valid, "amount change must break Falcon");
    assert!(!r.shared_digest, "stored digest must no longer match");
    assert!(!r.all_valid());

    // Change the recipient after signing.
    let mut tampered = bundle.clone();
    tampered.intent.action = dualkey_client::intent::ActionSpec::TransferSol {
        recipient: hex::encode([0x99u8; 32]),
        lamports: 999,
    };
    let r = verify_bundle(&tampered).expect("verify");
    assert!(!r.ed25519_valid && !r.falcon_solana_valid && !r.shared_digest);

    // Change the nonce after signing.
    let mut tampered = bundle.clone();
    tampered.intent.nonce = 4;
    let r = verify_bundle(&tampered).expect("verify");
    assert!(!r.ed25519_valid && !r.falcon_solana_valid && !r.shared_digest);
}
