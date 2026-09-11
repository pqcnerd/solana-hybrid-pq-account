//! GROUP B (digest mutation): flipping one bit of the 32-byte digest must
//! invalidate the Ed25519 signature and the Falcon signature under BOTH
//! Falcon verifiers.

use dualkey_client::falcon_interop;
use dualkey_client::keys::{Ed25519Keypair, FalconKeypair};
use dualkey_client::sign::{self, signing_material};
use dualkey_core::{Action, AuthorizationIntent};
use ed25519_dalek::Signer;

fn intent() -> AuthorizationIntent {
    AuthorizationIntent::new(
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        1,
        1_000,
        Action::TransferSol {
            recipient: [0x04; 32],
            lamports: 7_000_000,
        },
    )
}

/// Flip bit `bit` of byte `byte` in a digest copy.
fn flip(digest: &[u8; 32], byte: usize, bit: u32) -> [u8; 32] {
    let mut d = *digest;
    d[byte] ^= 1 << bit;
    d
}

#[test]
fn original_ed25519_signature_fails_on_mutated_digest() {
    let ed = Ed25519Keypair::generate();
    let digest = signing_material(intent()).digest;
    let sig = ed.signing_key().sign(&digest);

    // Sanity: valid over the true digest.
    assert!(sign::verify_ed25519(
        &ed.public_bytes(),
        &sig.to_bytes(),
        &digest
    ));

    let mutated = flip(&digest, 0, 0);
    assert_ne!(mutated, digest);
    assert!(
        !sign::verify_ed25519(&ed.public_bytes(), &sig.to_bytes(), &mutated),
        "Ed25519 must reject a one-bit-mutated digest"
    );
}

#[test]
fn original_falcon_signature_fails_on_mutated_digest_under_both_verifiers() {
    let falcon = FalconKeypair::generate();
    let digest = signing_material(intent()).digest;
    let (pq_sig, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret()).expect("sign");
    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");

    // Sanity: valid over the true digest in all three paths.
    assert!(falcon_interop::verify_pqclean(
        &pq_sig,
        &digest,
        falcon.public()
    ));
    assert!(falcon_interop::verify_solana_raw(
        &wire,
        &digest,
        falcon.public_bytes()
    ));
    assert!(falcon_interop::verify_solana_prepared(
        &wire, &digest, &prepared
    ));

    let mutated = flip(&digest, 31, 7);
    assert_ne!(mutated, digest);

    assert!(
        !falcon_interop::verify_pqclean(&pq_sig, &mutated, falcon.public()),
        "PQClean must reject a mutated digest"
    );
    assert!(
        !falcon_interop::verify_solana_raw(&wire, &mutated, falcon.public_bytes()),
        "solana-falcon512 (raw) must reject a mutated digest"
    );
    assert!(
        !falcon_interop::verify_solana_prepared(&wire, &mutated, &prepared),
        "solana-falcon512 (prepared) must reject a mutated digest"
    );
}

/// Sweep every bit position of the digest, not just one, so a positional
/// weakness cannot hide.
#[test]
fn every_single_bit_flip_of_the_digest_is_rejected() {
    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();
    let digest = signing_material(intent()).digest;

    let ed_sig = ed.signing_key().sign(&digest);
    let (pq_sig, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret()).expect("sign");
    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");

    for byte in 0..32usize {
        for bit in 0..8u32 {
            let mutated = flip(&digest, byte, bit);
            assert!(
                !sign::verify_ed25519(&ed.public_bytes(), &ed_sig.to_bytes(), &mutated),
                "Ed25519 accepted digest mutation at byte {byte} bit {bit}"
            );
            assert!(
                !falcon_interop::verify_pqclean(&pq_sig, &mutated, falcon.public()),
                "PQClean accepted digest mutation at byte {byte} bit {bit}"
            );
            assert!(
                !falcon_interop::verify_solana_prepared(&wire, &mutated, &prepared),
                "solana-falcon512 accepted digest mutation at byte {byte} bit {bit}"
            );
        }
    }
}

/// A one-bit change anywhere in the intent changes the digest, which is what
/// makes the mutation tests above meaningful at the protocol level.
#[test]
fn intent_field_changes_produce_different_digests() {
    let base = intent();
    let base_digest = signing_material(base).digest;

    let mut nonce = base;
    nonce.nonce += 1;
    assert_ne!(signing_material(nonce).digest, base_digest);

    let mut expiry = base;
    expiry.expiry_slot += 1;
    assert_ne!(signing_material(expiry).digest, base_digest);

    let mut amount = base;
    amount.action = Action::TransferSol {
        recipient: [0x04; 32],
        lamports: 7_000_001,
    };
    assert_ne!(signing_material(amount).digest, base_digest);

    let mut recipient = base;
    let mut r = [0x04u8; 32];
    r[0] ^= 1;
    recipient.action = Action::TransferSol {
        recipient: r,
        lamports: 7_000_000,
    };
    assert_ne!(signing_material(recipient).digest, base_digest);

    let mut account = base;
    account.account[0] ^= 1;
    assert_ne!(signing_material(account).digest, base_digest);

    let mut program = base;
    program.program_id[0] ^= 1;
    assert_ne!(signing_material(program).digest, base_digest);

    let mut chain = base;
    chain.chain_domain[0] ^= 1;
    assert_ne!(signing_material(chain).digest, base_digest);
}
