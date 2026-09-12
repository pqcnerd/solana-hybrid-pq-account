//! Milestone 5: HybridAnd authorization under Solana SBF.
//!
//! Builds a real two-instruction transaction (Ed25519 precompile + DualKey
//! `Execute`) and runs it through Mollusk with the `precompiles` feature so the
//! runtime actually verifies the Ed25519 signature. Falcon is verified by the
//! DualKey program against the prepared key stored in the HybridAccount.
//!
//! Milestone 5 authorizes only: no nonce consumption, no lamport transfer.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN,
    FALCON_SIGNATURE_LEN,
};
use dualkey_program::instruction::DualKeyInstruction;
use ed25519_dalek::Signer;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const PROGRAM_NAME: &str = "dualkey_program";

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
        account,
        account_data: data,
        nonce,
    }
}

fn intent_for(f: &Fixture) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::TransferSol {
            recipient: [0x44; 32],
            lamports: 1_000_000,
        },
    )
}

fn sign_both(
    f: &Fixture,
    intent: &dualkey_core::AuthorizationIntent,
) -> ([u8; 64], [u8; FALCON_SIGNATURE_LEN]) {
    let digest = canonical_digest(intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let (_d, wire) = falcon_interop::sign_to_wire(&digest, &f.falcon_secret).expect("falcon sign");
    let mut falcon = [0u8; FALCON_SIGNATURE_LEN];
    falcon.copy_from_slice(wire.as_wire_bytes());
    (ed_sig, falcon)
}

fn hybrid_account(f: &Fixture) -> (Pubkey, Account) {
    (
        f.account,
        Account {
            lamports: 10_000_000,
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

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn hybrid_and_succeeds_with_both_signatures() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 7);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (ed_sig, falcon_sig) = sign_both(&f, &intent);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    assert_eq!(ed_ix.data.len(), 144);
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();
    assert_eq!(exec_ix.data.len(), onchain::EXECUTE_DATA_LEN);
    assert_eq!(exec_ix.data[0], DualKeyInstruction::Execute.as_u8());

    let result = {
        let (payer_key, payer_acct) = payer();
        let accounts = vec![payer_key, hybrid_account(&f).0];
        let keyed = vec![(payer_key, payer_acct), hybrid_account(&f)];
        let _ = accounts;
        mollusk.process_and_validate_transaction_instructions(
            &[ed_ix, exec_ix],
            &keyed,
            &[Check::success()],
            Some(&payer_key),
        )
    };

    println!(
        "HybridAnd Execute: {} CU (tx total)",
        result.compute_units_consumed
    );
    // Account unchanged: Milestone 5 does not consume the nonce.
    let after = result.get_account(&f.account).expect("account");
    assert_eq!(after.data, f.account_data);
}

#[test]
fn ed25519_only_succeeds_without_valid_falcon() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::Ed25519Only, 1);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    // Garbage Falcon signature — must be ignored under Ed25519Only.
    let falcon_sig = [0xABu8; FALCON_SIGNATURE_LEN];

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, exec_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
}

#[test]
fn falcon_only_succeeds_without_ed25519_precompile() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 2);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (_d, wire) = falcon_interop::sign_to_wire(&digest, &f.falcon_secret).unwrap();

    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, wire.as_wire_bytes())
            .unwrap();

    // Single-instruction transaction — no Ed25519 predecessor.
    run_tx(
        &mollusk,
        &[exec_ix],
        &[hybrid_account(&f)],
        &[Check::success()],
    );
}

// ---------------------------------------------------------------------------
// HybridAnd never falls back
// ---------------------------------------------------------------------------

#[test]
fn hybrid_and_rejects_ed25519_without_falcon() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 3);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon_sig = [0u8; FALCON_SIGNATURE_LEN]; // invalid

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn hybrid_and_rejects_falcon_without_ed25519() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 4);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (_d, wire) = falcon_interop::sign_to_wire(&digest, &f.falcon_secret).unwrap();
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, wire.as_wire_bytes())
            .unwrap();

    // No Ed25519 predecessor — HybridAnd must not fall back to Falcon-only.
    run_tx(
        &mollusk,
        &[exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::MalformedEd25519Precompile)],
    );
}

#[test]
fn hybrid_and_rejects_ed25519_over_wrong_digest() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 5);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (ed_sig, falcon_sig) = sign_both(&f, &intent);

    // Valid Ed25519 signature, but over a different message.
    let wrong_msg = [0xFFu8; 32];
    let wrong_sig = f.ed.signing_key().sign(&wrong_msg).to_bytes();
    let ed_ix =
        onchain::ed25519_precompile_instruction(&wrong_msg, &wrong_sig, &f.ed.public_bytes());
    let _ = ed_sig;
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidEd25519)],
    );
    let _ = digest;
}

#[test]
fn hybrid_and_rejects_wrong_ed25519_pubkey() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 6);
    let other = Ed25519Keypair::generate();
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (_ed_sig, falcon_sig) = sign_both(&f, &intent);

    // Precompile verifies under `other`, which is not the account owner.
    let other_sig = other.signing_key().sign(&digest).to_bytes();
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &other_sig, &other.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidEd25519)],
    );
}

#[test]
fn hybrid_and_rejects_tampered_falcon_signature() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 8);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (ed_sig, mut falcon_sig) = sign_both(&f, &intent);
    falcon_sig[40] ^= 0x01;

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[ed_ix, exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn unrelated_earlier_ed25519_is_not_accepted() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 9);
    let intent = intent_for(&f);
    let digest = canonical_digest(&intent);
    let (ed_sig, falcon_sig) = sign_both(&f, &intent);

    // Valid owner signature over the digest, then another valid Ed25519 over a
    // different 32-byte message immediately before Execute. Relative -1 binds
    // to the decoy → InvalidEd25519 (message ≠ reconstructed digest).
    let good_ed = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let decoy_msg = [0xDEu8; 32];
    let decoy_sig = f.ed.signing_key().sign(&decoy_msg).to_bytes();
    let decoy =
        onchain::ed25519_precompile_instruction(&decoy_msg, &decoy_sig, &f.ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();

    run_tx(
        &mollusk,
        &[good_ed, decoy, exec_ix],
        &[hybrid_account(&f)],
        &[custom(DualKeyError::InvalidEd25519)],
    );
}

#[test]
fn wrong_nonce_in_intent_fails_digest_binding() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 10);
    // Sign as if nonce were 11 while account stores 10.
    let mut intent = intent_for(&f);
    intent.nonce = 11;
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let (_d, wire) = falcon_interop::sign_to_wire(&digest, &f.falcon_secret).unwrap();

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id(), &f.account, &intent, wire.as_wire_bytes())
            .unwrap();

    // Reconstruction uses account nonce 10 → digest mismatch vs signatures over 11.
    // Falcon verify fails (or Ed25519 message mismatch). Either is a hard reject.
    let result = {
        let (payer_key, payer_acct) = payer();
        mollusk.process_transaction_instructions(
            &[ed_ix, exec_ix],
            &[(payer_key, payer_acct), hybrid_account(&f)],
            Some(&payer_key),
        )
    };
    assert!(result.raw_result.is_err(), "wrong nonce must not authorize");
}

#[test]
fn execute_data_length_is_716() {
    assert_eq!(onchain::EXECUTE_DATA_LEN, 716);
    assert_eq!(
        1 + dualkey_core::EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN,
        716
    );
}
