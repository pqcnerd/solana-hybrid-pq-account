//! Project completion: `RecoverAccount` under Solana SBF.
//!
//! Enable/disable the recovery flag under the current policy; with the flag
//! set, Falcon alone can rotate the Ed25519 owner (lost-key escape hatch).

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, RecoveryOp,
    ACCOUNT_DATA_LEN, FALCON_SIGNATURE_LEN,
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
    account: Pubkey,
    account_data: Vec<u8>,
    nonce: u64,
}

fn fixture(policy: AuthorizationPolicy, nonce: u64, recovery: bool) -> Fixture {
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
        acct.set_recovery_enabled(recovery);
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
            lamports: RENT_EXEMPT_LAMPORTS,
            data: f.account_data.clone(),
            owner: program_id(),
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

fn recover_intent(
    f: &Fixture,
    op: RecoveryOp,
    new_ed25519: [u8; 32],
) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RecoverAccount { op, new_ed25519 },
    )
}

#[test]
fn enable_recovery_under_hybrid_and() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 1, false);
    let intent = recover_intent(&f, RecoveryOp::Enable, [0u8; 32]);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ix =
        onchain::recover_account_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    assert_eq!(ix.data[0], onchain::RECOVER_ACCOUNT_DISCRIMINATOR);

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
    assert!(HybridAccount::recovery_enabled_from_slice(&after.data).unwrap());
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 2);
}

#[test]
fn rotate_ed25519_without_recovery_flag_is_rejected() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 0, false);
    let new_ed = Ed25519Keypair::generate();
    let intent = recover_intent(&f, RecoveryOp::RotateEd25519, new_ed.public_bytes());
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ix =
        onchain::recover_account_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    run_tx(
        &mollusk,
        &[ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn falcon_alone_recovers_ed25519_when_flag_set() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 3, true);
    let new_ed = Ed25519Keypair::generate();
    let intent = recover_intent(&f, RecoveryOp::RotateEd25519, new_ed.public_bytes());
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    // No Ed25519 precompile — Falcon alone must succeed.
    let ix =
        onchain::recover_account_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    let after = run_tx_result(&mollusk, &[ix], &[hybrid_account(&f)], &[Check::success()]);
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&after.data).unwrap(),
        new_ed.public_bytes()
    );
    assert_eq!(HybridAccount::nonce_from_slice(&after.data).unwrap(), 4);
}

#[test]
fn recovery_rotate_rejects_ed25519_alone_even_with_flag() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 0, true);
    let new_ed = Ed25519Keypair::generate();
    let intent = recover_intent(&f, RecoveryOp::RotateEd25519, new_ed.public_bytes());
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ix = onchain::recover_account_instruction(
        &program_id(),
        &f.account,
        &intent,
        &[0u8; FALCON_SIGNATURE_LEN],
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn disable_recovery_clears_flag() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 1, true);
    let intent = recover_intent(&f, RecoveryOp::Disable, [0u8; 32]);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ix =
        onchain::recover_account_instruction(&program_id(), &f.account, &intent, &falcon).unwrap();
    let after = run_tx_result(&mollusk, &[ix], &[hybrid_account(&f)], &[Check::success()]);
    assert!(!HybridAccount::recovery_enabled_from_slice(&after.data).unwrap());
}
