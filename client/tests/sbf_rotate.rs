//! Milestone 9: key rotation under Solana SBF.
//!
//! `RotateEd25519Key` and `RotateFalconKey` are authorized under the account's
//! **current** policy. Falcon rotation additionally requires a proof-of-possession
//! signature from the **new** Falcon key over the same digest.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN,
    FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN,
};
use ed25519_dalek::Signer;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const PROGRAM_NAME: &str = "dualkey_program";
const RENT_EXEMPT_LAMPORTS: u64 = 8_686_080;

fn program_id() -> Pubkey {
    Pubkey::new_from_array([7u8; 32])
}

fn mollusk() -> Mollusk {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/deploy")
        .join(format!("{PROGRAM_NAME}.so"));
    let elf = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nrun: cargo-build-sbf --manifest-path program/Cargo.toml",
            path.display()
        )
    });
    let mut mollusk = Mollusk::default();
    mollusk.add_program_with_loader_and_elf(&program_id(), &loader_keys::LOADER_V3, &elf);
    mollusk
}

fn custom(err: DualKeyError) -> Check<'static> {
    Check::err(ProgramError::Custom(err.code()))
}

struct Fixture {
    ed: Ed25519Keypair,
    falcon_secret: falcon512::SecretKey,
    falcon_hash: [u8; 32],
    account: Pubkey,
    account_data: Vec<u8>,
    nonce: u64,
}

fn fixture(policy: AuthorizationPolicy, nonce: u64) -> Fixture {
    let ed = Ed25519Keypair::generate();
    let (pk, sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
    let falcon_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pk.as_bytes());
        h.finalize().into()
    };

    let account = Pubkey::new_from_array([0x55; 32]);
    let mut data = vec![0u8; ACCOUNT_DATA_LEN];
    {
        let mut acct = HybridAccount::initialize(
            &mut data,
            255,
            0,
            &ed.public_bytes(),
            &falcon_hash,
            prepared.as_bytes(),
            policy,
        )
        .expect("init");
        acct.set_nonce(nonce);
    }

    Fixture {
        ed,
        falcon_secret: sk,
        falcon_hash,
        account,
        account_data: data,
        nonce,
    }
}

fn hybrid_account(f: &Fixture) -> (Pubkey, Account) {
    (
        f.account,
        Account {
            lamports: RENT_EXEMPT_LAMPORTS + 2_000_000,
            data: f.account_data.clone(),
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn empty_recovery_config(hybrid: &Pubkey) -> (Pubkey, Account) {
    let (addr, _) = onchain::derive_recovery_config(&program_id(), hybrid).unwrap();
    (
        addr,
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn recovery_pda(hybrid: &Pubkey) -> Pubkey {
    onchain::derive_recovery_config(&program_id(), hybrid)
        .unwrap()
        .0
}

fn payer() -> (Pubkey, Account) {
    (
        Pubkey::new_from_array([0x01; 32]),
        Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn run_tx(
    mollusk: &Mollusk,
    instructions: &[Instruction],
    accounts: &[(Pubkey, Account)],
    checks: &[Check],
) {
    let (payer_key, payer_acct) = payer();
    let mut all = vec![(payer_key, payer_acct)];
    all.extend_from_slice(accounts);
    mollusk.process_and_validate_transaction_instructions(
        instructions,
        &all,
        checks,
        Some(&payer_key),
    );
}

fn run_tx_result(
    mollusk: &Mollusk,
    instructions: &[Instruction],
    accounts: &[(Pubkey, Account)],
    checks: &[Check],
) -> Account {
    let (payer_key, payer_acct) = payer();
    let mut all = vec![(payer_key, payer_acct)];
    all.extend_from_slice(accounts);
    let hybrid_key = accounts[0].0;
    let result = mollusk.process_and_validate_transaction_instructions(
        instructions,
        &all,
        checks,
        Some(&payer_key),
    );
    result.get_account(&hybrid_key).unwrap().clone()
}

fn falcon_sig(digest: &[u8; 32], sk: &falcon512::SecretKey) -> [u8; FALCON_SIGNATURE_LEN] {
    let (_d, wire) = falcon_interop::sign_to_wire(digest, sk).expect("sign");
    let mut out = [0u8; FALCON_SIGNATURE_LEN];
    out.copy_from_slice(wire.as_wire_bytes());
    out
}

#[test]
fn rotate_ed25519_under_hybrid_and_updates_owner() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 3);
    let new_ed = Ed25519Keypair::generate();
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateEd25519Key {
            new_pubkey: new_ed.public_bytes(),
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let rot_ix = onchain::rotate_ed25519_instruction(
        &program_id(),
        &f.account,
        &recovery_pda(&f.account),
        &intent,
        &falcon,
    )
    .unwrap();
    assert_eq!(rot_ix.data.len(), onchain::EXECUTE_DATA_LEN);
    assert_eq!(rot_ix.data[0], onchain::ROTATE_ED25519_DISCRIMINATOR);

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, rot_ix],
        &[hybrid_account(&f), empty_recovery_config(&f.account)],
        &[Check::success()],
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 4);
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&after.data).unwrap(),
        new_ed.public_bytes()
    );
    // Falcon material unchanged.
    assert_eq!(
        HybridAccount::falcon_public_key_hash_from_slice(&after.data).unwrap(),
        f.falcon_hash
    );
}

#[test]
fn rotate_ed25519_rejects_same_pubkey() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 0);
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateEd25519Key {
            new_pubkey: f.ed.public_bytes(),
        },
    );
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let rot_ix = onchain::rotate_ed25519_instruction(
        &program_id(),
        &f.account,
        &recovery_pda(&f.account),
        &intent,
        &falcon,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f), empty_recovery_config(&f.account)],
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn rotate_ed25519_requires_current_policy_auth() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 1);
    let new_ed = Ed25519Keypair::generate();
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateEd25519Key {
            new_pubkey: new_ed.public_bytes(),
        },
    );
    let digest = canonical_digest(&intent);
    // Only Falcon — HybridAnd must not fall back.
    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let rot_ix = onchain::rotate_ed25519_instruction(
        &program_id(),
        &f.account,
        &recovery_pda(&f.account),
        &intent,
        &falcon,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f), empty_recovery_config(&f.account)],
        &[custom(DualKeyError::MalformedEd25519Precompile)],
    );
}

#[test]
fn rotate_falcon_under_hybrid_and_with_pop() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 5);
    let (new_pk, new_sk) = falcon512::keypair();
    let new_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(new_pk.as_bytes());
        h.finalize().into()
    };
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateFalconKey {
            new_pubkey_hash: new_hash,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let auth = falcon_sig(&digest, &f.falcon_secret);
    let pop = falcon_sig(&digest, &new_sk);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let rot_ix = onchain::rotate_falcon_instruction(
        &program_id(),
        &f.account,
        &intent,
        &auth,
        new_pk.as_bytes(),
        &pop,
    )
    .unwrap();
    assert_eq!(rot_ix.data.len(), onchain::ROTATE_FALCON_DATA_LEN);

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, rot_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 6);
    assert_eq!(
        HybridAccount::falcon_public_key_hash_from_slice(&after.data).unwrap(),
        new_hash
    );
    // Owner Ed25519 unchanged.
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&after.data).unwrap(),
        f.ed.public_bytes()
    );

    // Prepared key matches on-chain prepare of the new wire key.
    let expected_prepared = falcon_interop::prepare_pubkey(new_pk.as_bytes()).unwrap();
    let stored = HybridAccount::prepared_falcon_public_key_from_slice(&after.data).unwrap();
    assert_eq!(stored.as_slice(), expected_prepared.as_bytes());
}

#[test]
fn rotate_falcon_rejects_missing_pop() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 2);
    let (new_pk, _new_sk) = falcon512::keypair();
    let new_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(new_pk.as_bytes());
        h.finalize().into()
    };
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateFalconKey {
            new_pubkey_hash: new_hash,
        },
    );
    let digest = canonical_digest(&intent);
    let auth = falcon_sig(&digest, &f.falcon_secret);
    // PoP is zeros — verification fails under the new key.
    let pop = [0u8; FALCON_SIGNATURE_LEN];
    let rot_ix = onchain::rotate_falcon_instruction(
        &program_id(),
        &f.account,
        &intent,
        &auth,
        new_pk.as_bytes(),
        &pop,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn rotate_falcon_rejects_hash_mismatch() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 0);
    let (new_pk, new_sk) = falcon512::keypair();
    let wrong_hash = [0x11u8; 32];
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateFalconKey {
            new_pubkey_hash: wrong_hash,
        },
    );
    let digest = canonical_digest(&intent);
    let auth = falcon_sig(&digest, &f.falcon_secret);
    let pop = falcon_sig(&digest, &new_sk);
    let rot_ix = onchain::rotate_falcon_instruction(
        &program_id(),
        &f.account,
        &intent,
        &auth,
        new_pk.as_bytes(),
        &pop,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn rotate_falcon_rejects_pop_under_old_key() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 1);
    let (new_pk, _new_sk) = falcon512::keypair();
    let new_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(new_pk.as_bytes());
        h.finalize().into()
    };
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateFalconKey {
            new_pubkey_hash: new_hash,
        },
    );
    let digest = canonical_digest(&intent);
    let auth = falcon_sig(&digest, &f.falcon_secret);
    // PoP signed by the *old* key — verifies under old key but not new wire key.
    let pop = falcon_sig(&digest, &f.falcon_secret);
    let rot_ix = onchain::rotate_falcon_instruction(
        &program_id(),
        &f.account,
        &intent,
        &auth,
        new_pk.as_bytes(),
        &pop,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn after_ed25519_rotation_old_key_cannot_authorize_transfer() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::Ed25519Only, 0);
    let new_ed = Ed25519Keypair::generate();
    let rotate_intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RotateEd25519Key {
            new_pubkey: new_ed.public_bytes(),
        },
    );
    let digest = canonical_digest(&rotate_intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = [0xABu8; FALCON_SIGNATURE_LEN];
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let rot_ix = onchain::rotate_ed25519_instruction(
        &program_id(),
        &f.account,
        &recovery_pda(&f.account),
        &rotate_intent,
        &falcon,
    )
    .unwrap();

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, rot_ix],
        &[hybrid_account(&f), empty_recovery_config(&f.account)],
        &[Check::success()],
    );

    // Attempt transfer signed by the *old* Ed25519 key against the rotated account.
    let transfer = onchain::signing_intent(
        &program_id(),
        &f.account,
        1,
        50_000_000,
        Action::TransferSol {
            recipient: [0x44; 32],
            lamports: 1,
        },
    );
    let tdigest = canonical_digest(&transfer);
    let old_sig = f.ed.signing_key().sign(&tdigest).to_bytes();
    let old_ed_ix =
        onchain::ed25519_precompile_instruction(&tdigest, &old_sig, &f.ed.public_bytes());
    let exec = onchain::execute_instruction(
        &program_id(),
        &f.account,
        &transfer,
        &[0u8; FALCON_SIGNATURE_LEN],
    )
    .unwrap();
    let recipient = (
        Pubkey::new_from_array([0x44; 32]),
        Account {
            lamports: 0,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    let (payer_key, payer_acct) = payer();
    mollusk.process_and_validate_transaction_instructions(
        &[old_ed_ix, exec],
        &[(payer_key, payer_acct), (f.account, after), recipient],
        &[custom(DualKeyError::InvalidEd25519)],
        Some(&payer_key),
    );
}

#[test]
fn rotate_falcon_data_length_is_2279() {
    assert_eq!(onchain::ROTATE_FALCON_DATA_LEN, 2279);
    assert_eq!(
        1 + dualkey_core::EXECUTE_INTENT_WIRE_LEN
            + FALCON_SIGNATURE_LEN
            + FALCON_WIRE_PUBKEY_LEN
            + FALCON_SIGNATURE_LEN,
        2279
    );
}
