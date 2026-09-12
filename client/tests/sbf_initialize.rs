//! Milestone 3: HybridAccount PDA initialization under Solana SBF.
//!
//! Executes the compiled `dualkey_program.so` inside Mollusk. The instruction is
//! built by the real client code path (`dualkey_client::onchain`), so these tests
//! also check that the client and program agree on seeds, account order and
//! instruction encoding.
//!
//! No authorized value movement is involved: the only lamport flow is the
//! creator funding the new account's rent-exempt minimum.

use dualkey_client::falcon_interop;
use dualkey_client::onchain;
use dualkey_core::{
    AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN, ACCOUNT_VERSION,
    FALCON_WIRE_PUBKEY_LEN, PREPARED_FALCON_PUBKEY_LEN,
};
use dualkey_program::instruction::DualKeyInstruction;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// An off-chain Falcon keypair plus the Ed25519 owner key an account is created
/// with.
struct Owner {
    ed25519: [u8; 32],
    falcon_wire: [u8; FALCON_WIRE_PUBKEY_LEN],
    falcon_secret: falcon512::SecretKey,
}

fn owner() -> Owner {
    let (pk, sk) = falcon512::keypair();
    Owner {
        ed25519: [0x11; 32],
        falcon_wire: pk.as_bytes().try_into().expect("897 bytes"),
        falcon_secret: sk,
    }
}

fn creator_account(lamports: u64) -> (Pubkey, Account) {
    (
        Pubkey::new_from_array([3u8; 32]),
        Account {
            lamports,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

/// An uninitialized PDA account, as the runtime presents it before creation.
fn empty_pda_account(pda: Pubkey) -> (Pubkey, Account) {
    (
        pda,
        Account {
            lamports: 0,
            data: vec![],
            owner: onchain::system_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

/// Build the `Initialize` instruction through the client's own code path.
fn init_ix(
    creator: &Pubkey,
    account_index: u32,
    owner: &Owner,
    policy: AuthorizationPolicy,
) -> (Instruction, Pubkey, u8) {
    onchain::initialize_instruction(
        &program_id(),
        creator,
        account_index,
        &owner.ed25519,
        policy,
        &owner.falcon_wire,
    )
    .expect("client builds Initialize")
}

/// Run `Initialize` and return the resulting account data.
fn initialize(
    mollusk: &Mollusk,
    owner: &Owner,
    account_index: u32,
    policy: AuthorizationPolicy,
) -> (Pubkey, u8, Vec<u8>, u64) {
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, bump) = init_ix(&creator, account_index, owner, policy);

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct),
            empty_pda_account(pda),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let account = result
        .get_account(&pda)
        .expect("PDA must exist after Initialize")
        .clone();
    assert_eq!(account.owner, program_id(), "PDA must be program-owned");
    (pda, bump, account.data, result.compute_units_consumed)
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

#[test]
fn initialize_writes_every_field_of_the_account() {
    let mollusk = mollusk();
    let owner = owner();
    let (_pda, bump, mut data, cu) =
        initialize(&mollusk, &owner, 0, AuthorizationPolicy::HybridAnd);

    assert_eq!(data.len(), ACCOUNT_DATA_LEN, "fixed 1120-byte layout");

    let account = HybridAccount::try_from_bytes(&mut data).expect("parses");
    assert_eq!(account.version(), ACCOUNT_VERSION);
    assert_eq!(account.bump(), bump);
    assert_eq!(account.policy().unwrap(), AuthorizationPolicy::HybridAnd);
    assert_eq!(account.owner_ed25519(), owner.ed25519);
    assert_eq!(
        account.falcon_public_key_hash(),
        sha256(&owner.falcon_wire),
        "stored hash must bind the Falcon wire public key"
    );
    assert_eq!(
        account.nonce(),
        0,
        "nonce starts at zero for replay control"
    );
    assert_eq!(account.falcon_required_above(), None);
    assert!(!account.recovery_enabled());

    println!("Initialize: {cu} CU");
}

/// The prepared key is computed on-chain from the 897-byte wire key. It must
/// equal what the off-chain preparation produces, byte for byte.
#[test]
fn on_chain_preparation_matches_off_chain_preparation() {
    let mollusk = mollusk();
    let owner = owner();
    let (_pda, _bump, mut data, _cu) =
        initialize(&mollusk, &owner, 0, AuthorizationPolicy::HybridAnd);

    let expected = falcon_interop::prepare_pubkey(&owner.falcon_wire).expect("prepare off-chain");
    let account = HybridAccount::try_from_bytes(&mut data).expect("parses");
    assert_eq!(
        account.prepared_falcon_public_key().as_slice(),
        expected.as_bytes().as_slice(),
        "on-chain try_prepare_pubkey must match off-chain preparation"
    );
}

/// End-to-end: the key stored by `Initialize` must actually verify a real
/// Falcon signature through the on-chain verifier. This is what makes the
/// stored prepared key meaningful rather than merely well-formed bytes.
#[test]
fn signature_verifies_against_the_key_stored_by_initialize() {
    let mollusk = mollusk();
    let owner = owner();
    let (_pda, _bump, mut data, _cu) =
        initialize(&mollusk, &owner, 0, AuthorizationPolicy::HybridAnd);

    let message = [0x5Au8; 32];
    let (_d, sig) = falcon_interop::sign_to_wire(&message, &owner.falcon_secret).expect("sign");

    // The Milestone 2 harness is layout-agnostic: it reads a prepared key from
    // offset 0 of its account. A real HybridAccount stores it at offset 96, so
    // lift the stored region out and hand the harness exactly those bytes.
    let stored_key = *HybridAccount::try_from_bytes(&mut data)
        .expect("parses")
        .prepared_falcon_public_key();
    let pda = Pubkey::new_from_array([9u8; 32]);
    let initialized = Account {
        lamports: 10_000_000,
        data: stored_key.to_vec(),
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    };

    let mut ix_data = vec![DualKeyInstruction::VerifyFalconPrepared.as_u8()];
    ix_data.extend_from_slice(sig.as_wire_bytes());
    ix_data.extend_from_slice(&message);

    let result = mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![AccountMeta::new_readonly(pda, false)],
            data: ix_data,
        },
        &[(pda, initialized.clone())],
        &[Check::success()],
    );
    println!(
        "verify against initialized account: {} CU",
        result.compute_units_consumed
    );

    // ...and a signature over a different message must not verify against it.
    let mut bad = vec![DualKeyInstruction::VerifyFalconPrepared.as_u8()];
    bad.extend_from_slice(sig.as_wire_bytes());
    bad.extend_from_slice(b"different message");
    mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![AccountMeta::new_readonly(pda, false)],
            data: bad,
        },
        &[(pda, initialized)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

/// Each `account_index` must yield a distinct vault for the same creator, so a
/// creator can hold several.
#[test]
fn distinct_account_indices_yield_distinct_accounts() {
    let mollusk = mollusk();
    let owner = owner();
    let mut seen = std::collections::BTreeSet::new();

    for index in [0u32, 1, 2, 7, u32::MAX] {
        let (pda, bump, mut data, _cu) =
            initialize(&mollusk, &owner, index, AuthorizationPolicy::HybridAnd);
        assert!(seen.insert(pda), "account_index {index} reused an address");

        // The stored bump must be the one that derives this very address.
        let account = HybridAccount::try_from_bytes(&mut data).unwrap();
        assert_eq!(account.bump(), bump);
    }
}

/// Different creators must not collide, even at the same index.
#[test]
fn distinct_creators_yield_distinct_accounts() {
    let a = Pubkey::new_from_array([3u8; 32]);
    let b = Pubkey::new_from_array([4u8; 32]);
    let pda_a = onchain::derive_hybrid_account(&program_id(), &a, 0)
        .unwrap()
        .0;
    let pda_b = onchain::derive_hybrid_account(&program_id(), &b, 0)
        .unwrap()
        .0;
    assert_ne!(pda_a, pda_b);
}

/// The client and the program must derive the same address and bump. If these
/// ever disagree the client would send funds to an address the program refuses.
#[test]
fn client_and_program_derive_identical_addresses() {
    for index in [0u32, 1, 9, 12345, u32::MAX] {
        for seed in [3u8, 42, 200] {
            let creator = Pubkey::new_from_array([seed; 32]);
            let from_client =
                onchain::derive_hybrid_account(&program_id(), &creator, index).unwrap();
            let from_program =
                dualkey_program::pda::derive(&program_id(), &creator, index).unwrap();
            assert_eq!(from_client, from_program);
        }
    }
}

#[test]
fn every_implemented_policy_is_accepted() {
    let mollusk = mollusk();
    let owner = owner();
    for policy in [
        AuthorizationPolicy::Ed25519Only,
        AuthorizationPolicy::FalconOnly,
        AuthorizationPolicy::HybridAnd,
    ] {
        let (_pda, _bump, mut data, _cu) = initialize(&mollusk, &owner, 0, policy);
        let account = HybridAccount::try_from_bytes(&mut data).unwrap();
        assert_eq!(account.policy().unwrap(), policy);
    }
}

// ---------------------------------------------------------------------------
// Negative paths
// ---------------------------------------------------------------------------

/// A wrong PDA must be rejected. Without this the program would happily
/// initialize an attacker-chosen address.
#[test]
fn wrong_pda_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, correct_pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    // The PDA for a different index, an unrelated address, and the PDA of a
    // different creator: all must fail against instruction data claiming index 0.
    let other_index = onchain::derive_hybrid_account(&program_id(), &creator, 1)
        .unwrap()
        .0;
    let other_creator =
        onchain::derive_hybrid_account(&program_id(), &Pubkey::new_from_array([9u8; 32]), 0)
            .unwrap()
            .0;
    let unrelated = Pubkey::new_from_array([123u8; 32]);

    for wrong in [other_index, other_creator, unrelated] {
        assert_ne!(wrong, correct_pda);
        let mut ix = ix.clone();
        ix.accounts[1] = AccountMeta::new(wrong, false);
        mollusk.process_and_validate_instruction(
            &ix,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(wrong),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
            &[custom(DualKeyError::InvalidPda)],
        );
    }
}

/// The creator is a PDA seed and chooses the stored owner key, so its signature
/// is mandatory. Without this check anyone could create accounts seeded by
/// another address.
#[test]
fn unsigned_creator_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (mut ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    ix.accounts[0] = AccountMeta::new(creator, false); // drop the signer flag

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct),
            empty_pda_account(pda),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[custom(DualKeyError::MissingSigner)],
    );
}

/// A substituted "system program" must be rejected before any CPI is attempted.
#[test]
fn wrong_system_program_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (mut ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    let impostor = Pubkey::new_from_array([200u8; 32]);
    ix.accounts[2] = AccountMeta::new_readonly(impostor, false);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct),
            empty_pda_account(pda),
            (
                impostor,
                Account {
                    lamports: 1,
                    data: vec![],
                    owner: onchain::system_program_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            ),
        ],
        &[custom(DualKeyError::InvalidProgramAccount)],
    );
}

/// An already-initialized account must never be re-initialized: doing so would
/// reset the nonce and let previously-used intents replay, and would let a
/// caller swap the stored keys.
#[test]
fn already_initialized_account_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (pda, _bump, data, _cu) = initialize(&mollusk, &owner, 0, AuthorizationPolicy::HybridAnd);

    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, _pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    let existing = Account {
        lamports: 10_000_000,
        data,
        owner: program_id(),
        executable: false,
        rent_epoch: 0,
    };
    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct),
            (pda, existing),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[custom(DualKeyError::AccountAlreadyInitialized)],
    );
}

/// Declared-but-unimplemented policies must be refused, not stored. Storing one
/// would create an account whose policy this program cannot evaluate.
#[test]
fn unimplemented_policy_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    for policy_byte in [
        AuthorizationPolicy::HybridOr.as_u8(),
        AuthorizationPolicy::FalconForPrivileged.as_u8(),
        AuthorizationPolicy::FalconAboveThreshold.as_u8(),
    ] {
        let mut ix = ix.clone();
        ix.data[37] = policy_byte;
        mollusk.process_and_validate_instruction(
            &ix,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(pda),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
            &[custom(DualKeyError::PolicyNotImplemented)],
        );
    }
}

/// An unknown policy byte is a distinct failure from a known-but-unimplemented
/// one, and must not be silently coerced to a default.
#[test]
fn unknown_policy_byte_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    for policy_byte in [6u8, 7, 100, 255] {
        let mut ix = ix.clone();
        ix.data[37] = policy_byte;
        mollusk.process_and_validate_instruction(
            &ix,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(pda),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
            &[custom(DualKeyError::PolicyRejected)],
        );
    }
}

/// A malformed Falcon wire public key must be rejected rather than stored. The
/// prepared form is unvalidated by construction, which is exactly why the
/// program derives it from the validated wire encoding.
#[test]
fn malformed_falcon_public_key_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    // Wrong header byte, all-zero, all-ones, and a flipped coefficient region.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    let mut bad_header = owner.falcon_wire.to_vec();
    bad_header[0] ^= 0xFF;
    cases.push(bad_header);
    cases.push(vec![0u8; FALCON_WIRE_PUBKEY_LEN]);
    cases.push(vec![0xFFu8; FALCON_WIRE_PUBKEY_LEN]);

    for bad in cases {
        let mut ix = ix.clone();
        ix.data[38..38 + FALCON_WIRE_PUBKEY_LEN].copy_from_slice(&bad);
        let result = mollusk.process_instruction(
            &ix,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(pda),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
        );
        assert!(
            result.program_result.is_err(),
            "malformed Falcon public key must not be stored"
        );
    }
}

/// Framing errors must produce a clean error, never a panic (which would surface
/// as `ProgramFailedToComplete`) and never a success.
#[test]
fn malformed_instruction_data_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    let full_len = ix.data.len();
    for len in [1usize, 2, 37, 38, full_len - 1] {
        let mut short = ix.clone();
        short.data.truncate(len);
        mollusk.process_and_validate_instruction(
            &short,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(pda),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
            &[custom(DualKeyError::MalformedInstructionData)],
        );
    }

    // Too long by one byte.
    let mut long = ix.clone();
    long.data.push(0);
    mollusk.process_and_validate_instruction(
        &long,
        &[
            (creator, creator_acct.clone()),
            empty_pda_account(pda),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[custom(DualKeyError::MalformedInstructionData)],
    );
}

/// Missing or extra accounts must be rejected by exact match, not ignored.
#[test]
fn wrong_account_count_is_rejected() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);
    let system = mollusk_svm::program::keyed_account_for_system_program();

    // Two accounts instead of three.
    let mut short = ix.clone();
    short.accounts.truncate(2);
    mollusk.process_and_validate_instruction(
        &short,
        &[(creator, creator_acct.clone()), empty_pda_account(pda)],
        &[custom(DualKeyError::MalformedInstructionData)],
    );

    // Four accounts.
    let mut long = ix.clone();
    long.accounts.push(AccountMeta::new_readonly(
        Pubkey::new_from_array([88u8; 32]),
        false,
    ));
    mollusk.process_and_validate_instruction(
        &long,
        &[
            (creator, creator_acct),
            empty_pda_account(pda),
            system,
            empty_pda_account(Pubkey::new_from_array([88u8; 32])),
        ],
        &[custom(DualKeyError::MalformedInstructionData)],
    );
}

/// Anyone can compute a vault's future address, so anyone can send lamports to
/// it before it exists. `create_account` would then refuse forever ("account
/// already in use"), permanently blocking that `(creator, account_index)` pair
/// for the price of one lamport. Initialization must survive that.
#[test]
fn prefunded_pda_can_still_be_initialized() {
    let mollusk = mollusk();
    let owner = owner();
    let (ix, pda, bump) = {
        let (creator, _) = creator_account(0);
        init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd)
    };

    // One lamport, and a griefer generous enough to overshoot the rent minimum.
    for prefund in [1u64, 1_000, 8_686_079, 8_686_080, 500_000_000] {
        let (creator, creator_acct) = creator_account(10_000_000_000);
        let mut prefunded = empty_pda_account(pda);
        prefunded.1.lamports = prefund;

        let result = mollusk.process_and_validate_instruction(
            &ix,
            &[
                (creator, creator_acct.clone()),
                prefunded,
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
            &[Check::success()],
        );

        let account = result
            .get_account(&pda)
            .expect("created despite prefunding");
        assert_eq!(account.data.len(), ACCOUNT_DATA_LEN);
        assert_eq!(account.owner, program_id());
        assert!(
            account.lamports >= 8_686_080,
            "prefund {prefund}: account must end up rent-exempt"
        );

        // The prefunded lamports are credited, not double-charged: the creator
        // pays only the shortfall.
        let spent = creator_acct.lamports - result.get_account(&creator).unwrap().lamports;
        assert_eq!(
            spent,
            8_686_080u64.saturating_sub(prefund),
            "prefund {prefund}: creator must pay only the shortfall"
        );

        let mut data = account.data.clone();
        let parsed = HybridAccount::try_from_bytes(&mut data).expect("parses");
        assert_eq!(parsed.bump(), bump);
        assert_eq!(parsed.nonce(), 0);
    }
}

/// A creator without enough lamports for the rent-exempt minimum must fail
/// cleanly in the System program CPI.
#[test]
fn underfunded_creator_fails_cleanly() {
    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(1_000); // far below rent
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    let result = mollusk.process_instruction(
        &ix,
        &[
            (creator, creator_acct),
            empty_pda_account(pda),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
    );
    assert!(
        result.program_result.is_err(),
        "an underfunded creator must not produce an account"
    );
}

// ---------------------------------------------------------------------------
// Compute units and rent
// ---------------------------------------------------------------------------

/// Record the real cost of `Initialize`, which includes the one-time
/// `try_prepare_pubkey` NTT that Milestone 0 estimated at ~99k CU.
#[test]
fn initialize_compute_units_and_rent() {
    const MAX_PER_INSTRUCTION: u64 = 1_400_000;

    let mollusk = mollusk();
    let owner = owner();
    let (creator, creator_acct) = creator_account(10_000_000_000);
    let (ix, pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, creator_acct.clone()),
            empty_pda_account(pda),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let cu = result.compute_units_consumed;
    let created = result.get_account(&pda).expect("created");
    let spent = creator_acct.lamports - result.get_account(&creator).unwrap().lamports;

    // Decompose the cost. A wire key with a corrupted header byte fails at the
    // start of `try_prepare_pubkey`, i.e. after parsing, PDA derivation and the
    // System CPI have all been paid for. The difference isolates the one-time
    // NTT that Milestone 0 estimated at ~99k CU.
    let mut bad_key = ix.clone();
    bad_key.data[38] ^= 0xFF;
    let without_ntt = mollusk
        .process_instruction(
            &bad_key,
            &[
                (creator, creator_acct.clone()),
                empty_pda_account(pda),
                mollusk_svm::program::keyed_account_for_system_program(),
            ],
        )
        .compute_units_consumed;

    // Two rejection paths that straddle the PDA derivation isolate the cost of
    // the `sol_try_find_program_address` syscall.
    let before_derive = {
        let mut ix = ix.clone();
        ix.accounts[2] = AccountMeta::new_readonly(Pubkey::new_from_array([200u8; 32]), false);
        mollusk
            .process_instruction(
                &ix,
                &[
                    (creator, creator_acct.clone()),
                    empty_pda_account(pda),
                    (
                        Pubkey::new_from_array([200u8; 32]),
                        Account {
                            lamports: 1,
                            data: vec![],
                            owner: onchain::system_program_id(),
                            executable: false,
                            rent_epoch: 0,
                        },
                    ),
                ],
            )
            .compute_units_consumed
    };
    let after_derive = {
        let wrong = Pubkey::new_from_array([123u8; 32]);
        let mut ix = ix.clone();
        ix.accounts[1] = AccountMeta::new(wrong, false);
        mollusk
            .process_instruction(
                &ix,
                &[
                    (creator, creator_acct.clone()),
                    empty_pda_account(wrong),
                    mollusk_svm::program::keyed_account_for_system_program(),
                ],
            )
            .compute_units_consumed
    };

    println!("\n=== Milestone 3: Initialize ===");
    println!("Compute units          : {cu:>9}");
    println!("  parse + PDA + CPI    : {without_ntt:>9}");
    println!(
        "  try_prepare_pubkey   : {:>9}  (NTT, one-time)",
        cu - without_ntt
    );
    println!("Rejection path costs:");
    println!("  before PDA derive    : {before_derive:>9}");
    println!("  after PDA derive     : {after_derive:>9}");
    println!(
        "  PDA derive syscall   : {:>9}",
        after_derive - before_derive
    );
    println!("Instruction data       : {:>9} bytes", ix.data.len());
    println!("Account data           : {:>9} bytes", created.data.len());
    println!("Rent-exempt lamports   : {:>9}", created.lamports);
    println!("Creator lamports spent : {spent:>9}");
    println!("Headroom to ceiling    : {:>9}\n", MAX_PER_INSTRUCTION - cu);

    assert_eq!(created.data.len(), ACCOUNT_DATA_LEN);
    assert_eq!(
        spent, created.lamports,
        "every lamport leaving the creator must land in the new account: \
         Initialize moves no value anywhere else"
    );
    assert!(
        cu < MAX_PER_INSTRUCTION,
        "Initialize must fit one instruction"
    );
}

/// The instruction carries the 897-byte wire key, not the 1024-byte prepared
/// form, and must leave room in a legacy transaction.
#[test]
fn initialize_instruction_fits_a_legacy_transaction() {
    const LEGACY_TX_LIMIT: usize = 1232;

    let owner = owner();
    let creator = Pubkey::new_from_array([3u8; 32]);
    let (ix, _pda, _bump) = init_ix(&creator, 0, &owner, AuthorizationPolicy::HybridAnd);

    assert_eq!(ix.data.len(), 935);
    assert_eq!(
        ix.data.len(),
        1 + 4 + 32 + 1 + FALCON_WIRE_PUBKEY_LEN,
        "discriminator + index + owner + policy + wire pubkey"
    );
    assert!(
        ix.data.len() < PREPARED_FALCON_PUBKEY_LEN + 38,
        "sending the wire key must be smaller than sending the prepared form"
    );

    // 1 signature (64) + message header/accounts. Deriving the prepared key
    // on-chain keeps 127 bytes off the wire.
    let overhead = 64 + 3 + 32 * 4 + 32 + 2;
    assert!(
        ix.data.len() + overhead < LEGACY_TX_LIMIT,
        "Initialize must fit a legacy transaction: {} + {overhead} >= {LEGACY_TX_LIMIT}",
        ix.data.len()
    );
    println!(
        "Initialize tx estimate: {} bytes of {LEGACY_TX_LIMIT}",
        ix.data.len() + overhead
    );
}
