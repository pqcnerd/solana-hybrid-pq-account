//! GROUP E (file safety): private-key files must be mode 0600 on Unix, and no
//! CLI/report output may contain secret-key bytes.

use dualkey_client::keygen;
use dualkey_client::keys::{
    self, Ed25519Keypair, FalconKeypair, KeyPaths, KeySet, ED25519_ID_FILE, ED25519_PK_FILE,
    ED25519_SK_FILE, FALCON_PK_FILE, FALCON_PREPARED_FILE, FALCON_SK_FILE, SECRET_FILES,
};
use pqcrypto_traits::sign::SecretKey as _;

#[test]
#[cfg(unix)]
fn private_key_files_have_mode_0600() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    for (name, path) in [
        (ED25519_SK_FILE, paths.ed25519_sk()),
        (ED25519_ID_FILE, paths.ed25519_id()),
        (FALCON_SK_FILE, paths.falcon_sk()),
    ] {
        let mode = keys::file_mode(&path).expect("mode");
        assert_eq!(mode, 0o600, "{name} must be mode 0600, found {mode:o}");
    }

    // The declared secret-file list must cover exactly what we checked.
    assert_eq!(SECRET_FILES.len(), 3);
    assert!(SECRET_FILES.contains(&ED25519_SK_FILE));
    assert!(SECRET_FILES.contains(&ED25519_ID_FILE));
    assert!(SECRET_FILES.contains(&FALCON_SK_FILE));
}

#[test]
#[cfg(unix)]
fn no_secret_file_is_group_or_world_readable() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    for path in [paths.ed25519_sk(), paths.ed25519_id(), paths.falcon_sk()] {
        let mode = keys::file_mode(&path).expect("mode");
        assert_eq!(
            mode & 0o077,
            0,
            "{} exposes group/world bits: {mode:o}",
            path.display()
        );
    }
}

#[test]
#[cfg(unix)]
fn public_files_exist_and_have_expected_sizes() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    let cases = [
        (ED25519_PK_FILE, paths.ed25519_pk(), 32usize),
        (FALCON_PK_FILE, paths.falcon_pk(), 897),
        (FALCON_PREPARED_FILE, paths.falcon_prepared(), 1024),
    ];
    for (name, path, expected) in cases {
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes.len(), expected, "{name} size");
    }

    // Secret key sizes, read back through the loader.
    assert_eq!(std::fs::read(paths.ed25519_sk()).unwrap().len(), 32);
    assert_eq!(std::fs::read(paths.falcon_sk()).unwrap().len(), 1281);
}

/// The prepared public key written for on-chain account data must contain no
/// secret material. It is derived only from the public key, so it must be
/// exactly reproducible from `falcon512.pk` alone.
#[test]
fn prepared_account_data_contains_no_secret_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    let falcon = FalconKeypair::load(&paths).expect("load falcon");
    let secret = falcon.secret().as_bytes();
    let prepared = std::fs::read(paths.falcon_prepared()).expect("read prepared");

    // Reproducible from the public key alone.
    let pk = std::fs::read(paths.falcon_pk()).expect("read pk");
    let recomputed =
        dualkey_client::falcon_interop::prepare_pubkey(&pk).expect("prepare from public key");
    assert_eq!(prepared.as_slice(), recomputed.as_bytes().as_slice());

    // No 16-byte window of the secret key appears in the prepared data.
    for window in secret.windows(16) {
        assert!(
            !prepared.windows(16).any(|w| w == window),
            "prepared account data contains secret key material"
        );
    }
}

/// The `Initialize` instruction is the first thing DualKey sends on-chain, so it
/// is the most consequential place for a leak. It must carry both public keys and
/// no byte of either secret key.
#[test]
fn initialize_instruction_contains_no_secret_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    let public = keys::PublicKeys::load(&paths).expect("load public keys");
    let data = dualkey_client::onchain::initialize_data(
        0,
        public.ed25519(),
        dualkey_core::AuthorizationPolicy::HybridAnd,
        public.falcon_wire(),
    )
    .expect("build instruction data");

    // Both public keys must be present, or the program could not store them.
    assert!(
        data.windows(32).any(|w| w == public.ed25519()),
        "Ed25519 owner public key must be in the instruction"
    );
    assert!(
        data.windows(public.falcon_wire().len())
            .any(|w| w == public.falcon_wire()),
        "Falcon wire public key must be in the instruction"
    );

    // Neither secret key may appear, in whole or in part.
    let falcon_secret = FalconKeypair::load(&paths)
        .expect("load falcon")
        .secret()
        .as_bytes()
        .to_vec();
    let ed_secret = std::fs::read(paths.ed25519_sk()).expect("read ed25519 sk");
    for (name, secret) in [
        (FALCON_SK_FILE, falcon_secret.as_slice()),
        (ED25519_SK_FILE, ed_secret.as_slice()),
    ] {
        for window in secret.windows(16) {
            assert!(
                !data.windows(16).any(|w| w == window),
                "Initialize instruction contains {name} material"
            );
        }
    }
}

#[test]
fn keygen_report_output_contains_no_secret_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = keygen::generate(dir.path()).expect("keygen");
    let rendered = report.render();
    let debug = format!("{report:?}");
    let paths = KeyPaths::new(dir.path());

    let ed = Ed25519Keypair::load(&paths).expect("load ed");
    let falcon = FalconKeypair::load(&paths).expect("load falcon");

    let ed_secret_hex = hex::encode(ed.signing_key().to_bytes());
    let falcon_secret_hex = hex::encode(falcon.secret().as_bytes());

    for (label, haystack) in [("render", &rendered), ("debug", &debug)] {
        assert!(
            !haystack.contains(&ed_secret_hex),
            "{label} output leaked the Ed25519 secret key"
        );
        assert!(
            !haystack.contains(&falcon_secret_hex),
            "{label} output leaked the Falcon secret key"
        );
    }

    // Spot-check raw byte sequences too, in case of a non-hex encoding.
    for window in falcon.secret().as_bytes().windows(16) {
        let hexed = hex::encode(window);
        assert!(
            !rendered.contains(&hexed),
            "keygen output leaked a Falcon secret key window"
        );
    }

    // The report should still contain the useful public material.
    assert!(rendered.contains(&report.ed25519_public_key));
    assert!(rendered.contains("1281 bytes (not shown)"));
}

#[test]
fn keyset_manifest_contains_no_secret_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    let raw = std::fs::read_to_string(paths.keyset()).expect("read keyset");
    let keyset = KeySet::load(&paths).expect("parse keyset");

    let ed = Ed25519Keypair::load(&paths).expect("load ed");
    let falcon = FalconKeypair::load(&paths).expect("load falcon");

    assert!(!raw.contains(&hex::encode(ed.signing_key().to_bytes())));
    assert!(!raw.contains(&hex::encode(falcon.secret().as_bytes())));

    // Public fields are present and correct.
    assert_eq!(keyset.ed25519_public_key, hex::encode(ed.public_bytes()));
    assert_eq!(
        keyset.falcon512_public_key_sha256,
        hex::encode(keys::sha256(falcon.public_bytes()))
    );
    assert_eq!(keyset.falcon512_prepared_public_key_len, 1024);
}

#[test]
fn error_messages_contain_no_secret_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());
    let falcon = FalconKeypair::load(&paths).expect("load falcon");

    // Truncate the Falcon secret key to force a length error, then confirm the
    // error text reports only lengths and paths.
    let bad = dir.path().join("bad-keys");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("falcon512.sk"), [0u8; 10]).unwrap();
    std::fs::write(bad.join("falcon512.pk"), [0u8; 897]).unwrap();

    // `FalconKeypair` deliberately has no `Debug` impl, so `unwrap_err` is not
    // available; match instead.
    let text = match FalconKeypair::load(&KeyPaths::new(&bad)) {
        Ok(_) => panic!("a 10-byte secret key must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(text.contains("1281") && text.contains("10"), "{text}");
    assert!(!text.contains(&hex::encode(falcon.secret().as_bytes())));
}

/// Keys round-trip from disk and still produce verifying signatures, proving
/// the 0600 files are genuinely usable and not corrupted by the write path.
#[test]
fn keys_round_trip_from_disk_and_still_verify() {
    let dir = tempfile::tempdir().expect("tempdir");
    keygen::generate(dir.path()).expect("keygen");
    let paths = KeyPaths::new(dir.path());

    let ed = Ed25519Keypair::load(&paths).expect("load ed");
    let falcon = FalconKeypair::load(&paths).expect("load falcon");

    let intent = dualkey_core::test_vector_intent();
    let bundle = dualkey_client::sign::sign_intent(intent, &ed, &falcon).expect("sign");
    let report = dualkey_client::sign::verify_bundle(&bundle).expect("verify");

    assert!(report.all_valid(), "{}", report.render());
    assert_eq!(bundle.digest, hex::encode(dualkey_core::TEST_VECTOR_DIGEST));
}
