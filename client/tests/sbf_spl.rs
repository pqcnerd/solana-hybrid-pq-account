//! Milestone 11: hybrid-authorized SPL Token transfer under Solana SBF.
//!
//! The HybridAccount PDA signs an SPL `TransferChecked` CPI. Source token
//! accounts must be owned by the PDA; the destination is bound into the signed
//! intent body.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN,
    FALCON_SIGNATURE_LEN,
};
use ed25519_dalek::Signer;
use mollusk_svm::program::loader_keys;
use mollusk_svm::result::Check;
use mollusk_svm::Mollusk;
use mollusk_svm_programs_token::token as mollusk_token;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use spl_token_interface::state::{Account as TokenAccount, AccountState, Mint};

const PROGRAM_NAME: &str = "dualkey_program";
const RENT_EXEMPT_LAMPORTS: u64 = 8_686_080;
const ACCOUNT_INDEX: u32 = 7;
const TRANSFER_AMOUNT: u64 = 1_000;
const SOURCE_BALANCE: u64 = 5_000;

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
    mollusk_token::add_program(&mut mollusk);
    mollusk
}

fn custom(err: DualKeyError) -> Check<'static> {
    Check::err(ProgramError::Custom(err.code()))
}

struct Fixture {
    ed: Ed25519Keypair,
    falcon_secret: falcon512::SecretKey,
    creator: Pubkey,
    account: Pubkey,
    bump: u8,
    account_data: Vec<u8>,
    nonce: u64,
    mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    mint_account: Account,
    source_account: Account,
    destination_account: Account,
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

    let creator = Pubkey::new_from_array([0xC1; 32]);
    let (account, bump) =
        onchain::derive_hybrid_account(&program_id(), &creator, ACCOUNT_INDEX).unwrap();

    let mut data = vec![0u8; ACCOUNT_DATA_LEN];
    {
        let mut acct = HybridAccount::initialize(
            &mut data,
            bump,
            ACCOUNT_INDEX,
            &ed.public_bytes(),
            &falcon_hash,
            prepared.as_bytes(),
            policy,
        )
        .expect("init");
        acct.set_nonce(nonce);
    }

    let mint = Pubkey::new_from_array([0xB1; 32]);
    let source = Pubkey::new_from_array([0xA1; 32]);
    let destination = Pubkey::new_from_array([0xA2; 32]);

    let mint_account = mollusk_token::create_account_for_mint(Mint {
        mint_authority: COption::None,
        supply: SOURCE_BALANCE,
        decimals: 6,
        is_initialized: true,
        freeze_authority: COption::None,
    });

    let source_account = mollusk_token::create_account_for_token_account(TokenAccount {
        mint,
        owner: account,
        amount: SOURCE_BALANCE,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    });

    let destination_account = mollusk_token::create_account_for_token_account(TokenAccount {
        mint,
        owner: Pubkey::new_from_array([0xD0; 32]),
        amount: 0,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    });

    Fixture {
        ed,
        falcon_secret: sk,
        creator,
        account,
        bump,
        account_data: data,
        nonce,
        mint,
        source,
        destination,
        mint_account,
        source_account,
        destination_account,
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

fn token_program_keyed() -> (Pubkey, Account) {
    mollusk_token::keyed_account()
}

fn all_accounts(f: &Fixture) -> Vec<(Pubkey, Account)> {
    vec![
        hybrid_account(f),
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
        (f.source, f.source_account.clone()),
        (f.mint, f.mint_account.clone()),
        (f.destination, f.destination_account.clone()),
        token_program_keyed(),
    ]
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
        .map(|(k, _)| (*k, result.get_account(k).unwrap().clone()))
        .collect()
}

fn falcon_sig(digest: &[u8; 32], sk: &falcon512::SecretKey) -> [u8; FALCON_SIGNATURE_LEN] {
    let (_d, wire) = falcon_interop::sign_to_wire(digest, sk).expect("sign");
    let mut out = [0u8; FALCON_SIGNATURE_LEN];
    out.copy_from_slice(wire.as_wire_bytes());
    out
}

fn intent_for(f: &Fixture, amount: u64) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        &f.account,
        f.nonce,
        50_000_000,
        Action::TransferSpl {
            destination: f.destination.to_bytes(),
            amount,
        },
    )
}

fn token_amount(data: &[u8]) -> u64 {
    TokenAccount::unpack(data).unwrap().amount
}

#[test]
fn transfer_spl_under_hybrid_and_moves_tokens() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::HybridAnd, 2);
    let intent = intent_for(&f, TRANSFER_AMOUNT);
    let digest = canonical_digest(&intent);
    let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
    let ex_ix = onchain::execute_transfer_spl_instruction(
        &program_id(),
        &f.account,
        &f.creator,
        &f.source,
        &f.mint,
        &intent,
        &falcon,
    )
    .unwrap();
    assert_eq!(ex_ix.accounts.len(), 7);
    assert_eq!(ex_ix.data.len(), onchain::EXECUTE_DATA_LEN);

    let after = run_tx_result(
        &mollusk,
        &[ed_ix, ex_ix],
        &all_accounts(&f),
        &[Check::success()],
    );
    let hybrid = after.iter().find(|(k, _)| *k == f.account).unwrap();
    let source = after.iter().find(|(k, _)| *k == f.source).unwrap();
    let dest = after.iter().find(|(k, _)| *k == f.destination).unwrap();

    assert_eq!(HybridAccount::nonce_from_slice(&hybrid.1.data).unwrap(), 3);
    assert_eq!(
        HybridAccount::account_index_from_slice(&hybrid.1.data).unwrap(),
        ACCOUNT_INDEX
    );
    assert_eq!(hybrid.1.data[dualkey_core::account_offsets::BUMP], f.bump);
    assert_eq!(
        token_amount(&source.1.data),
        SOURCE_BALANCE - TRANSFER_AMOUNT
    );
    assert_eq!(token_amount(&dest.1.data), TRANSFER_AMOUNT);
}

#[test]
fn transfer_spl_rejects_wrong_destination_account() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 0);
    let intent = intent_for(&f, TRANSFER_AMOUNT);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let mut ex_ix = onchain::execute_transfer_spl_instruction(
        &program_id(),
        &f.account,
        &f.creator,
        &f.source,
        &f.mint,
        &intent,
        &falcon,
    )
    .unwrap();
    // Swap the destination account meta to a different pubkey while keeping
    // the signed body pointing at f.destination.
    let other = Pubkey::new_from_array([0xEE; 32]);
    ex_ix.accounts[4].pubkey = other;

    let mut accounts = all_accounts(&f);
    accounts.push((
        other,
        mollusk_token::create_account_for_token_account(TokenAccount {
            mint: f.mint,
            owner: Pubkey::new_from_array([0xD1; 32]),
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }),
    ));

    run_tx(
        &mollusk,
        &[ex_ix],
        &accounts,
        &[custom(DualKeyError::InvalidAccountData)],
    );
}

#[test]
fn transfer_spl_rejects_wrong_creator_seed() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 1);
    let intent = intent_for(&f, TRANSFER_AMOUNT);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let wrong_creator = Pubkey::new_from_array([0xBD; 32]);
    let ex_ix = onchain::execute_transfer_spl_instruction(
        &program_id(),
        &f.account,
        &wrong_creator,
        &f.source,
        &f.mint,
        &intent,
        &falcon,
    )
    .unwrap();

    let mut accounts = all_accounts(&f);
    accounts[1] = (
        wrong_creator,
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    run_tx(
        &mollusk,
        &[ex_ix],
        &accounts,
        &[custom(DualKeyError::InvalidPda)],
    );
}

#[test]
fn transfer_spl_rejects_insufficient_token_balance() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 0);
    let intent = intent_for(&f, SOURCE_BALANCE + 1);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ex_ix = onchain::execute_transfer_spl_instruction(
        &program_id(),
        &f.account,
        &f.creator,
        &f.source,
        &f.mint,
        &intent,
        &falcon,
    )
    .unwrap();

    run_tx(
        &mollusk,
        &[ex_ix],
        &all_accounts(&f),
        &[custom(DualKeyError::InsufficientFunds)],
    );
}

#[test]
fn transfer_spl_zero_amount_consumes_nonce_only() {
    let mollusk = mollusk();
    let f = fixture(AuthorizationPolicy::FalconOnly, 4);
    let intent = intent_for(&f, 0);
    let digest = canonical_digest(&intent);
    let falcon = falcon_sig(&digest, &f.falcon_secret);

    let ex_ix = onchain::execute_transfer_spl_instruction(
        &program_id(),
        &f.account,
        &f.creator,
        &f.source,
        &f.mint,
        &intent,
        &falcon,
    )
    .unwrap();

    let after = run_tx_result(&mollusk, &[ex_ix], &all_accounts(&f), &[Check::success()]);
    let hybrid = after.iter().find(|(k, _)| *k == f.account).unwrap();
    let source = after.iter().find(|(k, _)| *k == f.source).unwrap();
    let dest = after.iter().find(|(k, _)| *k == f.destination).unwrap();
    assert_eq!(HybridAccount::nonce_from_slice(&hybrid.1.data).unwrap(), 5);
    assert_eq!(token_amount(&source.1.data), SOURCE_BALANCE);
    assert_eq!(token_amount(&dest.1.data), 0);
}

#[test]
fn initialize_stores_account_index_for_pda_signing() {
    // Spot-check that the M11 layout field is populated by Initialize.
    let mollusk = mollusk();
    let owner = Ed25519Keypair::generate();
    let (pk, _sk) = falcon512::keypair();
    let creator = Pubkey::new_from_array([0x11; 32]);
    let (ix, pda, bump) = onchain::initialize_instruction(
        &program_id(),
        &creator,
        42,
        &owner.public_bytes(),
        AuthorizationPolicy::Ed25519Only,
        pk.as_bytes(),
    )
    .unwrap();

    let creator_acct = Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: onchain::system_program_id(),
        executable: false,
        rent_epoch: 0,
    };
    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct),
            (
                pda,
                Account {
                    lamports: 0,
                    data: vec![],
                    owner: onchain::system_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            ),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );
    let data = &result.get_account(&pda).unwrap().data;
    assert_eq!(HybridAccount::account_index_from_slice(data).unwrap(), 42);
    assert_eq!(data[dualkey_core::account_offsets::BUMP], bump);
}
