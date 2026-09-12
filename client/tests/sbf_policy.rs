//! Milestone 10: richer policies and `ChangePolicy` under Solana SBF.
//!
//! Covers HybridOr, FalconForPrivileged, FalconAboveThreshold, and the
//! stricter-of authorization rule for policy changes.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN,
    FALCON_SIGNATURE_LEN,
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
const TRANSFER_LAMPORTS: u64 = 1_000_000;
const THRESHOLD: u64 = 500_000;

fn program_id() -> Pubkey {
    Pubkey::new_from_array([7u8; 32])
}

fn recipient_pubkey() -> Pubkey {
    Pubkey::new_from_array([0x44; 32])
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
    account: Pubkey,
    account_data: Vec<u8>,
    nonce: u64,
}

fn fixture(policy: AuthorizationPolicy, nonce: u64) -> Fixture {
    fixture_with_threshold(policy, nonce, None)
}

fn fixture_with_threshold(
    policy: AuthorizationPolicy,
    nonce: u64,
    threshold: Option<u64>,
) -> Fixture {
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
            &ed.public_bytes(),
            &falcon_hash,
            prepared.as_bytes(),
            policy,
        )
        .expect("init");
        acct.set_nonce(nonce);
        acct.set_falcon_required_above(threshold);
    }

    Fixture {
        ed,
        falcon_secret: sk,
        account,
        account_data: data,
        nonce,
    }
}

fn hybrid_account(f: &Fixture) -> (Pubkey, Account) {
    (
        f.account,
        Account {
            lamports: RENT_EXEMPT_LAMPORTS + 5_000_000,
            data: f.account_data.clone(),
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn recipient_account() -> (Pubkey, Account) {
    (
        recipient_pubkey(),
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
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

fn transfer_intent(f: &Fixture, lamports: u64) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::TransferSol {
            recipient: recipient_pubkey().to_bytes(),
            lamports,
        },
    )
}

fn zero_falcon() -> [u8; FALCON_SIGNATURE_LEN] {
    [0u8; FALCON_SIGNATURE_LEN]
}

#[test]
fn hybrid_or_accepts_ed25519_alone() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridOr, 1);
    let intent = transfer_intent(&f, TRANSFER_LAMPORTS);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 2);
}

#[test]
fn hybrid_or_accepts_falcon_alone() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridOr, 2);
    let intent = transfer_intent(&f, TRANSFER_LAMPORTS);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ex_ix = onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();

    let after = run_tx_result(
        &mollusk,
        &[ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 3);
}

#[test]
fn hybrid_or_rejects_neither() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridOr, 0);
    let intent = transfer_intent(&f, TRANSFER_LAMPORTS);
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    run_tx(
        &mollusk,
        &[ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[custom(DualKeyError::PolicyRejected)],
    );
}

#[test]
fn falcon_for_privileged_transfer_uses_ed25519() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconForPrivileged, 1);
    let intent = transfer_intent(&f, TRANSFER_LAMPORTS);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
}

#[test]
fn falcon_for_privileged_rotate_rejects_ed25519_alone() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconForPrivileged, 1);
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

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let rot_ix =
        onchain::rotate_ed25519_instruction(&program_id(), &f.account, &intent, &zero_falcon())
            .unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, rot_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn falcon_for_privileged_rotate_with_falcon() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconForPrivileged, 1);
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
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let rot_ix =
        onchain::rotate_ed25519_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();

    let after = run_tx_result(
        &mollusk,
        &[rot_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&after.data).unwrap(),
        new_ed.public_bytes()
    );
}

#[test]
fn falcon_above_threshold_below_uses_ed25519() {
    let mollusk = mollusk();
    let f = fixture_with_threshold(
        AuthorizationPolicy::FalconAboveThreshold,
        1,
        Some(THRESHOLD),
    );
    let intent = transfer_intent(&f, THRESHOLD); // equal → not above → Ed25519
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
}

#[test]
fn falcon_above_threshold_above_requires_falcon() {
    let mollusk = mollusk();
    let f = fixture_with_threshold(
        AuthorizationPolicy::FalconAboveThreshold,
        1,
        Some(THRESHOLD),
    );
    let intent = transfer_intent(&f, THRESHOLD + 1);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[custom(DualKeyError::InvalidFalcon)],
    );

    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let ex_ok = onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    run_tx(
        &mollusk,
        &[ex_ok],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
}

#[test]
fn change_policy_hybrid_and_to_ed25519_requires_both() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 5);
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::ChangePolicy {
            new_policy: AuthorizationPolicy::Ed25519Only.as_u8(),
            threshold: 0,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let cp_ix =
        onchain::change_policy_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    assert_eq!(cp_ix.data.len(), onchain::EXECUTE_DATA_LEN);
    assert_eq!(cp_ix.data[0], onchain::CHANGE_POLICY_DISCRIMINATOR);

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, cp_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    assert_eq!(
        HybridAccount::policy_from_slice(&after.data).unwrap(),
        AuthorizationPolicy::Ed25519Only
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 6);
}

#[test]
fn change_policy_hybrid_and_to_ed25519_rejects_ed_alone() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 5);
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::ChangePolicy {
            new_policy: AuthorizationPolicy::Ed25519Only.as_u8(),
            threshold: 0,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let cp_ix =
        onchain::change_policy_instruction(&program_id(), &f.account, &intent, &zero_falcon())
            .unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, cp_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn change_policy_sets_falcon_above_threshold() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 1);
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::ChangePolicy {
            new_policy: AuthorizationPolicy::FalconAboveThreshold.as_u8(),
            threshold: THRESHOLD,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let cp_ix =
        onchain::change_policy_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, cp_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    assert_eq!(
        HybridAccount::policy_from_slice(&after.data).unwrap(),
        AuthorizationPolicy::FalconAboveThreshold
    );
    assert_eq!(
        HybridAccount::falcon_required_above_from_slice(&after.data).unwrap(),
        Some(THRESHOLD)
    );
}

#[test]
fn change_policy_noop_is_rejected() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 1);
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::ChangePolicy {
            new_policy: AuthorizationPolicy::HybridAnd.as_u8(),
            threshold: 0,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let cp_ix =
        onchain::change_policy_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, cp_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn after_downgrade_ed25519_only_authorizes_transfer() {
    let mollusk = mollusk();
    let mut f = fixture(AuthorizationPolicy::HybridAnd, 1);
    let change = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::ChangePolicy {
            new_policy: AuthorizationPolicy::Ed25519Only.as_u8(),
            threshold: 0,
        },
    );
    let digest = canonical_digest(&change);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let cp_ix =
        onchain::change_policy_instruction(&program_id(), &f.account, &change, &falcon).unwrap();

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, cp_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    f.account_data = after.data;
    f.nonce = 2;

    let intent = transfer_intent(&f, TRANSFER_LAMPORTS);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &zero_falcon()).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, ex_ix],
        &[hybrid_account(&f), recipient_account()],
        &[Check::success()],
    );
}
