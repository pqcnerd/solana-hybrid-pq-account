//! Milestone 15: guardian + timelock social recovery under Solana SBF.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, social_recover_digest, Action, AuthorizationPolicy, DualKeyError,
    HybridAccount, RecoveryConfig, RecoveryOp, ACCOUNT_DATA_LEN, CHAIN_DOMAIN_LOCALNET,
    FALCON_SIGNATURE_LEN, RECOVERY_CONFIG_LEN,
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
const DELAY_SLOTS: u64 = 10;

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
    guardian: Ed25519Keypair,
    creator: Pubkey,
    account: Pubkey,
    recovery_config: Pubkey,
    account_data: Vec<u8>,
    nonce: u64,
}

fn fixture(nonce: u64, recovery_enabled: bool) -> Fixture {
    let ed = Ed25519Keypair::generate();
    let guardian = Ed25519Keypair::generate();
    let (pk, sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
    let falcon_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pk.as_bytes());
        h.finalize().into()
    };

    let creator = Pubkey::new_from_array([0xC1; 32]);
    let (account, _bump) = onchain::derive_hybrid_account(&program_id(), &creator, 0).unwrap();
    let (recovery_config, _) = onchain::derive_recovery_config(&program_id(), &account).unwrap();

    let mut data = vec![0u8; ACCOUNT_DATA_LEN];
    {
        let mut acct = HybridAccount::initialize(
            &mut data,
            255,
            0,
            &ed.public_bytes(),
            &falcon_hash,
            prepared.as_bytes(),
            AuthorizationPolicy::HybridAnd,
        )
        .expect("init");
        acct.set_nonce(nonce);
        acct.set_recovery_enabled(recovery_enabled);
    }

    Fixture {
        ed,
        falcon_secret: sk,
        guardian,
        creator,
        account,
        recovery_config,
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
            lamports: 10_000_000_000,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn falcon_sig(digest: &[u8; 32], sk: &falcon512::SecretKey) -> [u8; FALCON_SIGNATURE_LEN] {
    let (_d, wire) = falcon_interop::sign_to_wire(digest, sk).expect("sign");
    let mut out = [0u8; FALCON_SIGNATURE_LEN];
    out.copy_from_slice(wire.as_wire_bytes());
    out
}

fn run_tx(
    mollusk: &Mollusk,
    instructions: &[Instruction],
    accounts: &[(Pubkey, Account)],
    checks: &[Check],
) -> Vec<(Pubkey, Account)> {
    let (payer_key, payer_acct) = payer();
    let mut all = vec![(payer_key, payer_acct)];
    all.extend_from_slice(accounts);
    let result = mollusk.process_and_validate_transaction_instructions(
        instructions,
        &all,
        checks,
        Some(&payer_key),
    );
    accounts
        .iter()
        .map(|(k, _)| {
            (
                *k,
                result
                    .get_account(k)
                    .cloned()
                    .unwrap_or_else(|| all.iter().find(|(pk, _)| pk == k).unwrap().1.clone()),
            )
        })
        .collect()
}

fn set_config(f: &Fixture) -> (Instruction, Instruction) {
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::SetRecoveryConfig {
            guardian_ed25519: f.guardian.public_bytes(),
            delay_slots: DELAY_SLOTS,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let (payer_key, _) = payer();
    let ix = onchain::set_recovery_config_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &payer_key,
        &intent,
        &falcon,
    )
    .unwrap();
    (ed_ix, ix)
}

fn base_accounts(f: &Fixture) -> Vec<(Pubkey, Account)> {
    vec![
        hybrid_account(f),
        (
            f.recovery_config,
            Account {
                lamports: 0,
                data: vec![],
                owner: onchain::system_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        ),
        (
            f.creator,
            Account {
                lamports: 1_000_000,
                data: vec![],
                owner: onchain::system_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        ),
        mollusk_svm::program::keyed_account_for_system_program(),
    ]
}

#[test]
fn social_recovery_set_initiate_finalize_flow() {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(100);
    let f = fixture(1, true);
    let (ed_ix, set_ix) = set_config(&f);

    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );
    let cfg = after_set
        .iter()
        .find(|(k, _)| *k == f.recovery_config)
        .unwrap();
    assert_eq!(cfg.1.data.len(), RECOVERY_CONFIG_LEN);
    assert_eq!(
        RecoveryConfig::guardian_from_slice(&cfg.1.data).unwrap(),
        f.guardian.public_bytes()
    );
    let hybrid = after_set.iter().find(|(k, _)| *k == f.account).unwrap();
    assert_eq!(HybridAccount::nonce_from_slice(&hybrid.1.data).unwrap(), 2);

    let new_owner = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &new_owner.public_bytes(),
        2, // nonce after set
    );
    let g_sig = f.guardian.signing_key().sign(&digest).to_bytes();
    let g_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &f.guardian.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &new_owner.public_bytes(),
    );

    let accounts_after_set: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();

    let after_init = run_tx(
        &mollusk,
        &[g_ix, init_ix],
        &accounts_after_set,
        &[Check::success()],
    );
    let cfg = after_init
        .iter()
        .find(|(k, _)| *k == f.recovery_config)
        .unwrap();
    let mut cfg_data = cfg.1.data.clone();
    let view = RecoveryConfig::try_from_bytes(&mut cfg_data).unwrap();
    assert!(view.has_pending());
    assert_eq!(view.pending_ready_slot(), 100 + DELAY_SLOTS);

    // Too early
    let fin = onchain::finalize_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
    );
    run_tx(
        &mollusk,
        std::slice::from_ref(&fin),
        &after_init,
        &[custom(DualKeyError::IntentExpired)],
    );

    mollusk.warp_to_slot(100 + DELAY_SLOTS);
    let after_fin = run_tx(
        &mollusk,
        std::slice::from_ref(&fin),
        &after_init,
        &[Check::success()],
    );
    let hybrid = after_fin.iter().find(|(k, _)| *k == f.account).unwrap();
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&hybrid.1.data).unwrap(),
        new_owner.public_bytes()
    );
    assert_eq!(HybridAccount::nonce_from_slice(&hybrid.1.data).unwrap(), 3);
}

#[test]
fn social_recovery_cancel_clears_pending() {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(50);
    let f = fixture(0, true);
    let (ed_ix, set_ix) = set_config(&f);
    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );

    let new_owner = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &new_owner.public_bytes(),
        1,
    );
    let g_sig = f.guardian.signing_key().sign(&digest).to_bytes();
    let g_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &f.guardian.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &new_owner.public_bytes(),
    );
    let accounts: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();
    let after_init = run_tx(&mollusk, &[g_ix, init_ix], &accounts, &[Check::success()]);

    let cancel_intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        1,
        50_000_000,
        Action::CancelSocialRecovery,
    );
    let c_digest = canonical_digest(&cancel_intent);
    let ed_sig = f.ed.signing_key().sign(&c_digest).to_bytes();
    let falcon = falcon_sig(&c_digest, &f.falcon_secret);
    let ed_ix = onchain::ed25519_precompile_instruction(&c_digest, &ed_sig, &f.ed.public_bytes());
    let cancel_ix = onchain::cancel_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &cancel_intent,
        &falcon,
    )
    .unwrap();

    let after = run_tx(
        &mollusk,
        &[ed_ix, cancel_ix],
        &after_init,
        &[Check::success()],
    );
    let cfg = after.iter().find(|(k, _)| *k == f.recovery_config).unwrap();
    let mut cfg_data = cfg.1.data.clone();
    assert!(!RecoveryConfig::try_from_bytes(&mut cfg_data)
        .unwrap()
        .has_pending());
}

#[test]
fn social_recovery_rejects_reinitiate_while_pending() {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(50);
    let f = fixture(0, true);
    let (ed_ix, set_ix) = set_config(&f);
    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );

    let new_owner = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &new_owner.public_bytes(),
        1,
    );
    let g_sig = f.guardian.signing_key().sign(&digest).to_bytes();
    let g_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &f.guardian.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &new_owner.public_bytes(),
    );
    let accounts: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();
    let after_init = run_tx(
        &mollusk,
        &[g_ix.clone(), init_ix.clone()],
        &accounts,
        &[Check::success()],
    );

    // Same guardian digest still valid (nonce unchanged); must not reset ready_slot.
    mollusk.warp_to_slot(55);
    run_tx(
        &mollusk,
        &[g_ix, init_ix],
        &after_init,
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn social_recovery_rejects_wrong_guardian() {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(1);
    let f = fixture(0, true);
    let (ed_ix, set_ix) = set_config(&f);
    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );

    let impostor = Ed25519Keypair::generate();
    let new_owner = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &new_owner.public_bytes(),
        1,
    );
    let bad_sig = impostor.signing_key().sign(&digest).to_bytes();
    let bad_ix =
        onchain::ed25519_precompile_instruction(&digest, &bad_sig, &impostor.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &new_owner.public_bytes(),
    );
    let accounts: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();
    run_tx(
        &mollusk,
        &[bad_ix, init_ix],
        &accounts,
        &[custom(DualKeyError::InvalidEd25519)],
    );
}

#[test]
fn social_recovery_initiate_requires_recovery_flag() {
    let mollusk = mollusk();
    // Flag off: set config still works; initiate must fail.
    let f = fixture(0, false);
    let (ed_ix, set_ix) = set_config(&f);
    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );

    let new_owner = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &new_owner.public_bytes(),
        1,
    );
    let g_sig = f.guardian.signing_key().sign(&digest).to_bytes();
    let g_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &f.guardian.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &new_owner.public_bytes(),
    );
    let accounts: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();
    run_tx(
        &mollusk,
        &[g_ix, init_ix],
        &accounts,
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn falcon_only_recover_still_works_without_social_config() {
    // Sanity: M12 path is independent of RecoveryConfig contents.
    let mollusk = mollusk();
    let f = fixture(3, true);
    let new_ed = Ed25519Keypair::generate();
    let intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::RecoverAccount {
            op: RecoveryOp::RotateEd25519,
            new_ed25519: new_ed.public_bytes(),
        },
    );
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);
    let ix = onchain::recover_account_instruction(
        &program_id(),
        &f.account,
        &intent,
        &falcon,
        Some(&f.recovery_config),
    )
    .unwrap();
    let after = run_tx(&mollusk, &[ix], &base_accounts(&f), &[Check::success()]);
    let hybrid = after.iter().find(|(k, _)| *k == f.account).unwrap();
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&hybrid.1.data).unwrap(),
        new_ed.public_bytes()
    );
}

#[test]
fn falcon_recover_clears_social_pending_so_finalize_cannot_overwrite() {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(100);
    let f = fixture(1, true);
    let (ed_ix, set_ix) = set_config(&f);
    let after_set = run_tx(
        &mollusk,
        &[ed_ix, set_ix],
        &base_accounts(&f),
        &[Check::success()],
    );

    let guardian_choice = Ed25519Keypair::generate();
    let digest = social_recover_digest(
        &CHAIN_DOMAIN_LOCALNET,
        &program_id().to_bytes(),
        &f.account.to_bytes(),
        &guardian_choice.public_bytes(),
        2,
    );
    let g_sig = f.guardian.signing_key().sign(&digest).to_bytes();
    let g_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &f.guardian.public_bytes());
    let init_ix = onchain::initiate_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
        &guardian_choice.public_bytes(),
    );
    let accounts_after_set: Vec<_> = after_set
        .iter()
        .cloned()
        .chain(std::iter::once(
            mollusk_svm::program::keyed_account_for_system_program(),
        ))
        .collect();
    let after_init = run_tx(
        &mollusk,
        &[g_ix, init_ix],
        &accounts_after_set,
        &[Check::success()],
    );

    let recovered = Ed25519Keypair::generate();
    let recover_intent = onchain::signing_intent(
        &program_id(),
        &f.account,
        2,
        50_000_000,
        Action::RecoverAccount {
            op: RecoveryOp::RotateEd25519,
            new_ed25519: recovered.public_bytes(),
        },
    );
    let r_digest = canonical_digest(&recover_intent);
    let falcon = falcon_sig(&r_digest, &f.falcon_secret);
    let recover_ix = onchain::recover_account_instruction(
        &program_id(),
        &f.account,
        &recover_intent,
        &falcon,
        Some(&f.recovery_config),
    )
    .unwrap();
    let after_recover = run_tx(&mollusk, &[recover_ix], &after_init, &[Check::success()]);

    let cfg = after_recover
        .iter()
        .find(|(k, _)| *k == f.recovery_config)
        .unwrap();
    let mut cfg_data = cfg.1.data.clone();
    assert!(!RecoveryConfig::try_from_bytes(&mut cfg_data)
        .unwrap()
        .has_pending());

    let hybrid = after_recover.iter().find(|(k, _)| *k == f.account).unwrap();
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&hybrid.1.data).unwrap(),
        recovered.public_bytes()
    );

    mollusk.warp_to_slot(100 + DELAY_SLOTS);
    let fin = onchain::finalize_social_recovery_instruction(
        &program_id(),
        &f.account,
        &f.recovery_config,
    );
    run_tx(
        &mollusk,
        std::slice::from_ref(&fin),
        &after_recover,
        &[custom(DualKeyError::InvalidAccountData)],
    );

    let hybrid = after_recover.iter().find(|(k, _)| *k == f.account).unwrap();
    assert_eq!(
        HybridAccount::owner_ed25519_from_slice(&hybrid.1.data).unwrap(),
        recovered.public_bytes()
    );
}
