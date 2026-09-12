//! GROUP A (positive): keygen, signing, verification, shared digest, and
//! agreement with the shared core test vectors.

use dualkey_client::falcon_interop::{self, WireSignature};
use dualkey_client::keys::{Ed25519Keypair, FalconKeypair};
use dualkey_client::sign::{self, sign_intent, signing_material, verify_bundle};
use dualkey_core::{Action, AuthorizationIntent, INTENT_VERSION};
use ed25519_dalek::Signer;
use pqcrypto_traits::sign::DetachedSignature as _;

fn sample_intent() -> AuthorizationIntent {
    AuthorizationIntent::new(
        [0xA1; 32],
        [0xB2; 32],
        [0xC3; 32],
        42,
        99_999,
        Action::TransferSol {
            recipient: [0xD4; 32],
            lamports: 1_234_567_890,
        },
    )
}

#[test]
fn ed25519_keygen_sign_verify_succeeds() {
    let ed = Ed25519Keypair::generate();
    let message = b"dualkey ed25519 positive path";
    let sig = ed.signing_key().sign(message);

    assert!(sign::verify_ed25519(
        &ed.public_bytes(),
        &sig.to_bytes(),
        message
    ));
    assert_eq!(ed.public_bytes().len(), 32);
    assert_eq!(sig.to_bytes().len(), 64);
}

#[test]
fn falcon_keygen_sign_verify_succeeds_with_pqclean() {
    let falcon = FalconKeypair::generate();
    let message = b"dualkey falcon positive path";
    let (pq_sig, _wire) = falcon_interop::sign_to_wire(message, falcon.secret()).expect("sign");

    assert!(falcon_interop::verify_pqclean(
        &pq_sig,
        message,
        falcon.public()
    ));
    assert_eq!(falcon.public_bytes().len(), 897);
}

#[test]
fn same_falcon_signature_verifies_under_solana_implementation() {
    let falcon = FalconKeypair::generate();
    let message = b"dualkey falcon cross-implementation";
    let (pq_sig, wire) = falcon_interop::sign_to_wire(message, falcon.secret()).expect("sign");

    // PQClean accepts it.
    assert!(falcon_interop::verify_pqclean(
        &pq_sig,
        message,
        falcon.public()
    ));
    // The very same signature bytes verify on the on-chain implementation.
    assert_eq!(wire.encoded_bytes(), pq_sig.as_bytes());
    assert!(falcon_interop::verify_solana_raw(
        &wire,
        message,
        falcon.public_bytes()
    ));

    let prepared = falcon_interop::prepare_pubkey(falcon.public_bytes()).expect("prepare");
    assert!(falcon_interop::verify_solana_prepared(
        &wire, message, &prepared
    ));
}

/// The core Milestone 1 property: one digest, signed by both schemes.
#[test]
fn both_schemes_sign_exactly_the_same_digest() {
    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();
    let intent = sample_intent();

    let material = signing_material(intent);
    assert_eq!(material.digest.len(), 32);
    assert_eq!(material.preimage.len(), 172);

    let bundle = sign_intent(intent, &ed, &falcon).expect("sign");

    // The bundle's digest is the one produced by dualkey-core.
    assert_eq!(bundle.digest, hex::encode(material.digest));

    // Ed25519 verifies against that digest and nothing else.
    let ed_sig = hex::decode(&bundle.ed25519_signature).unwrap();
    assert!(
        sign::verify_ed25519(&ed.public_bytes(), &ed_sig, &material.digest),
        "Ed25519 must verify over the 32-byte digest"
    );
    assert!(
        !sign::verify_ed25519(&ed.public_bytes(), &ed_sig, &material.preimage),
        "Ed25519 must NOT verify over the 172-byte preimage"
    );

    // Falcon verifies against that same digest and nothing else.
    let wire_bytes = hex::decode(&bundle.falcon512_signature_wire).unwrap();
    let wire = WireSignature::from_wire_bytes(&wire_bytes).unwrap();
    assert!(
        falcon_interop::verify_solana_raw(&wire, &material.digest, falcon.public_bytes()),
        "Falcon must verify over the 32-byte digest"
    );
    assert!(
        !falcon_interop::verify_solana_raw(&wire, &material.preimage, falcon.public_bytes()),
        "Falcon must NOT verify over the 172-byte preimage"
    );

    // End-to-end bundle verification reports the shared digest.
    let report = verify_bundle(&bundle).expect("verify");
    assert!(report.shared_digest);
    assert!(report.all_valid(), "{}", report.render());
}

#[test]
fn falcon_signature_serialization_round_trips() {
    let falcon = FalconKeypair::generate();
    let message = b"round trip";
    let (pq_sig, wire) = falcon_interop::sign_to_wire(message, falcon.secret()).expect("sign");

    // wire -> hex -> wire
    let hexed = hex::encode(wire.as_wire_bytes());
    let decoded = hex::decode(&hexed).unwrap();
    let reloaded = WireSignature::from_wire_bytes(&decoded).expect("reload");

    assert_eq!(reloaded.as_wire_bytes(), wire.as_wire_bytes());
    assert_eq!(reloaded.encoded_len(), wire.encoded_len());
    assert_eq!(reloaded.encoded_bytes(), pq_sig.as_bytes());

    // Still verifies under both implementations after the round trip.
    assert!(falcon_interop::verify_solana_raw(
        &reloaded,
        message,
        falcon.public_bytes()
    ));
    let rebuilt = reloaded.to_pqclean().expect("to pqclean");
    assert!(falcon_interop::verify_pqclean(
        &rebuilt,
        message,
        falcon.public()
    ));
}

/// The client's SHA-256 must reproduce the shared core known-answer vectors.
#[test]
fn client_sha256_agrees_with_core_test_vectors() {
    let intent = dualkey_core::test_vector_intent();
    let preimage = dualkey_core::canonical_preimage(&intent);

    // Prefix (length-prefixed domain tag + version) matches the shared vector.
    assert_eq!(
        &preimage[..19],
        &dualkey_core::TEST_VECTOR_PREIMAGE_PREFIX,
        "domain separation prefix drifted"
    );

    // Core's own digest matches the published vector.
    let core_digest = dualkey_core::canonical_digest(&intent);
    assert_eq!(core_digest, dualkey_core::TEST_VECTOR_DIGEST);

    // An independent SHA-256 in the client produces the identical digest,
    // confirming the client adds no extra transform.
    let independent: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(preimage);
        h.finalize().into()
    };
    assert_eq!(independent, dualkey_core::TEST_VECTOR_DIGEST);

    // And the client signing path uses exactly that digest.
    assert_eq!(
        signing_material(intent).digest,
        dualkey_core::TEST_VECTOR_DIGEST
    );
}

#[test]
fn digest_is_domain_separated_and_not_a_bare_field_hash() {
    let intent = sample_intent();
    let digest = signing_material(intent).digest;

    // Hashing only the action (amount + recipient) must not match.
    let naive: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([0xD4; 32]);
        h.update(1_234_567_890u64.to_le_bytes());
        h.finalize().into()
    };
    assert_ne!(digest, naive);

    // Version is covered.
    let mut other = intent;
    other.version = INTENT_VERSION + 1;
    assert_ne!(signing_material(other).digest, digest);
}

#[test]
fn signed_bundle_contains_no_secret_material() {
    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();
    let bundle = sign_intent(sample_intent(), &ed, &falcon).expect("sign");

    let json = serde_json::to_string(&bundle).unwrap();
    let ed_secret = hex::encode(ed.signing_key().to_bytes());
    let falcon_secret = hex::encode(pqcrypto_traits::sign::SecretKey::as_bytes(falcon.secret()));

    assert!(
        !json.contains(&ed_secret),
        "bundle leaked the Ed25519 secret key"
    );
    assert!(
        !json.contains(&falcon_secret),
        "bundle leaked the Falcon secret key"
    );
}
