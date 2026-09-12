//! Milestone 4: on-chain intent reconstruction under Solana SBF.
//!
//! Proves the program rebuilds the same canonical digest the client signs, using
//! only trusted context (program id, account address, stored nonce, compile-time
//! chain domain) plus the 49-byte wire fragment. Authorization is not tested
//! here — `Execute` remains unimplemented.

use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN,
    CHAIN_DOMAIN_LOCALNET, EXECUTE_INTENT_DERIVED_LEN, EXECUTE_INTENT_WIRE_LEN,
    PREPARED_FALCON_PUBKEY_LEN,
};
use dualkey_program::chain_domain::CHAIN_DOMAIN;
use dualkey_program::instruction::DualKeyInstruction;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use solana_account::Account;
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

/// A HybridAccount with a chosen nonce, owned by the test program.
fn account_with_nonce(address: Pubkey, nonce: u64) -> (Pubkey, Account) {
    let mut data = vec![0u8; ACCOUNT_DATA_LEN];
    {
        let mut acct = HybridAccount::initialize(
            &mut data,
            255,
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; PREPARED_FALCON_PUBKEY_LEN],
            AuthorizationPolicy::HybridAnd,
        )
        .expect("initialize buffer");
        acct.set_nonce(nonce);
    }
    (
        address,
        Account {
            lamports: 10_000_000,
            data,
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn sample_intent(account: &Pubkey, nonce: u64) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        account,
        nonce,
        9_999_999,
        Action::TransferSol {
            recipient: [0x44; 32],
            lamports: 1_000_000,
        },
    )
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

#[test]
fn program_default_chain_domain_is_localnet() {
    assert_eq!(
        CHAIN_DOMAIN, CHAIN_DOMAIN_LOCALNET,
        "unmarked SBF builds must use the localnet research domain"
    );
    assert_eq!(onchain::default_chain_domain(), CHAIN_DOMAIN_LOCALNET);
}

#[test]
fn reconstructed_digest_matches_client_sha2() {
    let mollusk = mollusk();
    let account_key = Pubkey::new_from_array([0x55; 32]);
    let nonce = 7u64;
    let (pda, account) = account_with_nonce(account_key, nonce);
    let intent = sample_intent(&pda, nonce);
    let expected = canonical_digest(&intent);

    assert_eq!(intent.chain_domain, CHAIN_DOMAIN);
    assert_eq!(intent.program_id, program_id().to_bytes());
    assert_eq!(intent.account, pda.to_bytes());
    assert_eq!(intent.nonce, nonce);

    let ix = onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected);
    assert_eq!(ix.data.len(), 1 + EXECUTE_INTENT_WIRE_LEN + 32);
    assert_eq!(
        ix.data[0],
        DualKeyInstruction::ReconstructCanonicalDigest.as_u8()
    );

    let result =
        mollusk.process_and_validate_instruction(&ix, &[(pda, account)], &[Check::success()]);
    println!(
        "ReconstructCanonicalDigest: {} CU",
        result.compute_units_consumed
    );
}

#[test]
fn wire_fragment_is_exactly_49_bytes_and_saves_105() {
    let account = Pubkey::new_from_array([0x55; 32]);
    let intent = sample_intent(&account, 0);
    let wire = onchain::encode_execute_intent_wire(&intent);
    assert_eq!(wire.len(), EXECUTE_INTENT_WIRE_LEN);
    assert_eq!(EXECUTE_INTENT_WIRE_LEN, 49);
    assert_eq!(EXECUTE_INTENT_DERIVED_LEN, 105);

    // Full execute instruction body estimate (M5): disc + wire + falcon sig.
    let execute_ix_estimate = 1 + EXECUTE_INTENT_WIRE_LEN + 666;
    assert_eq!(execute_ix_estimate, 716);
    // Putting the derived fields on the wire would add 105 bytes and blow the
    // legacy transaction budget once Ed25519 precompile data is included.
    assert!(execute_ix_estimate + EXECUTE_INTENT_DERIVED_LEN > 800);
}

// ---------------------------------------------------------------------------
// Negative paths — wrong trusted context or wire must not match
// ---------------------------------------------------------------------------

#[test]
fn wrong_expected_digest_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 3);
    let intent = sample_intent(&pda, 3);
    let mut bad = canonical_digest(&intent);
    bad[0] ^= 1;

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &bad),
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn wrong_account_nonce_changes_digest() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    // Account stores nonce 10; client signs as if nonce were 11.
    let (pda, account) = account_with_nonce(pda, 10);
    let intent = sample_intent(&pda, 11);
    let expected = canonical_digest(&intent);

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn wrong_account_address_changes_digest() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let other = Pubkey::new_from_array([0x66; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    // Client signed for `other`, but the instruction points at `pda`.
    let intent = sample_intent(&other, 1);
    let expected = canonical_digest(&intent);

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn wrong_program_id_in_intent_changes_digest() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    let mut intent = sample_intent(&pda, 1);
    intent.program_id = [0xAB; 32];
    let expected = canonical_digest(&intent);

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn wrong_chain_domain_in_intent_changes_digest() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    let mut intent = sample_intent(&pda, 1);
    intent.chain_domain = dualkey_core::CHAIN_DOMAIN_MAINNET;
    let expected = canonical_digest(&intent);

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn flipped_wire_expiry_fails_without_matching_client_digest() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);

    let mut ix = onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected);
    // Flip a bit in expiry_slot (bytes 1..9 of instruction data).
    ix.data[1] ^= 1;

    mollusk.process_and_validate_instruction(
        &ix,
        &[(pda, account)],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

#[test]
fn unsupported_action_tag_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);

    let mut ix = onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected);
    // action_tag sits at offset 1 (disc) + 8 (expiry) = 9.
    ix.data[9] = 99;

    mollusk.process_and_validate_instruction(
        &ix,
        &[(pda, account)],
        &[custom(DualKeyError::UnsupportedAction)],
    );
}

#[test]
fn malformed_payload_length_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, account) = account_with_nonce(pda, 1);
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);
    let good = onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected);

    for len in [1usize, 50, good.data.len() - 1, good.data.len() + 1] {
        let mut ix = good.clone();
        ix.data.resize(len, 0);
        if len > 0 {
            ix.data[0] = DualKeyInstruction::ReconstructCanonicalDigest.as_u8();
        }
        mollusk.process_and_validate_instruction(
            &ix,
            &[(pda, account.clone())],
            &[custom(DualKeyError::MalformedInstructionData)],
        );
    }
}

#[test]
fn wrong_owner_account_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);

    let mut foreign = account_with_nonce(pda, 1).1;
    foreign.owner = onchain::system_program_id();

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, foreign)],
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn unsupported_account_version_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let (pda, mut account) = account_with_nonce(pda, 1);
    account.data[0] = 99; // version byte
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);

    mollusk.process_and_validate_instruction(
        &onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected),
        &[(pda, account)],
        &[custom(DualKeyError::UnsupportedVersion)],
    );
}

/// `Execute` is implemented in Milestone 5; reconstruction harness still works.
#[test]
fn execute_remains_authorization_only_until_transfer_milestone() {
    // Kept as a documentation anchor: M5 authorizes, M7 transfers.
    // Behavioural coverage lives in `sbf_hybrid.rs`.
    assert_eq!(DualKeyInstruction::Execute.as_u8(), 1);
}

#[test]
fn missing_account_is_rejected() {
    let mollusk = mollusk();
    let pda = Pubkey::new_from_array([0x55; 32]);
    let intent = sample_intent(&pda, 1);
    let expected = canonical_digest(&intent);
    let mut ix = onchain::reconstruct_digest_instruction(&program_id(), &pda, &intent, &expected);
    ix.accounts.clear();

    mollusk.process_and_validate_instruction(
        &ix,
        &[],
        &[custom(DualKeyError::MalformedInstructionData)],
    );
}
