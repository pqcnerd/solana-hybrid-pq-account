//! Milestone 8: CU + legacy transaction-size benchmarks under Solana SBF.
//!
//! ## Methodology
//!
//! - **Compute units:** Mollusk 0.15 with the `precompiles` feature, against
//!   the compiled `dualkey_program.so`. Multi-instruction transactions use
//!   `process_and_validate_transaction_instructions` so the Ed25519 precompile
//!   and DualKey `Execute` share one message (required for introspection).
//! - **Transaction size:** `bincode::serialized_size` of a legacy
//!   [`solana_transaction::Transaction`] with dummy fee-payer signatures.
//!   That is the same encoding the UDP packet budget uses (≤ 1232 bytes).
//!
//! Falcon verify cost varies with SHAKE rejection sampling (~10k CU steps).
//! Ranges are therefore min/max over several independent signatures; a single
//! sample is not meaningful for this primitive.
//!
//! Numbers are empirical research measurements, not a security proof.

use dualkey_client::falcon_interop;
use dualkey_client::keys::Ed25519Keypair;
use dualkey_client::onchain;
use dualkey_core::{
    canonical_digest, Action, AuthorizationPolicy, HybridAccount, ACCOUNT_DATA_LEN,
    FALCON_SIGNATURE_LEN,
};
use ed25519_dalek::Signer;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use std::fs;
use std::path::PathBuf;

const PROGRAM_NAME: &str = "dualkey_program";
const LEGACY_TX_LIMIT: usize = 1232;
const RENT_EXEMPT_LAMPORTS: u64 = 8_686_080;
const TRANSFER_LAMPORTS: u64 = 1_000_000;
const SAMPLES: usize = 9;

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

struct Fixture {
    ed: Ed25519Keypair,
    falcon_secret: falcon512::SecretKey,
    account: Pubkey,
    account_data: Vec<u8>,
}

fn fixture(policy: AuthorizationPolicy) -> Fixture {
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
    HybridAccount::initialize(
        &mut data,
        255,
        &ed.public_bytes(),
        &falcon_hash,
        prepared.as_bytes(),
        policy,
    )
    .expect("init");

    Fixture {
        ed,
        falcon_secret: sk,
        account,
        account_data: data,
    }
}

fn intent_for(f: &Fixture, nonce: u64) -> dualkey_core::AuthorizationIntent {
    onchain::signing_intent(
        &program_id(),
        &f.account,
        nonce,
        50_000_000,
        Action::TransferSol {
            recipient: recipient_pubkey().to_bytes(),
            lamports: TRANSFER_LAMPORTS,
        },
    )
}

fn hybrid_account(f: &Fixture) -> (Pubkey, Account) {
    (
        f.account,
        Account {
            lamports: RENT_EXEMPT_LAMPORTS + TRANSFER_LAMPORTS + 1_000_000,
            data: f.account_data.clone(),
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn recipient() -> (Pubkey, Account) {
    (
        recipient_pubkey(),
        Account {
            lamports: 0,
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

fn sign_policy(
    f: &Fixture,
    intent: &dualkey_core::AuthorizationIntent,
    policy: AuthorizationPolicy,
) -> (Option<Instruction>, Instruction) {
    let digest = canonical_digest(intent);
    let falcon_sig = match policy {
        AuthorizationPolicy::Ed25519Only => [0xABu8; FALCON_SIGNATURE_LEN],
        _ => {
            let (_d, wire) =
                falcon_interop::sign_to_wire(&digest, &f.falcon_secret).expect("falcon");
            let mut sig = [0u8; FALCON_SIGNATURE_LEN];
            sig.copy_from_slice(wire.as_wire_bytes());
            sig
        }
    };
    let exec =
        onchain::execute_instruction(&program_id(), &f.account, intent, &falcon_sig).unwrap();

    let ed_ix = match policy {
        AuthorizationPolicy::FalconOnly => None,
        _ => {
            let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
            Some(onchain::ed25519_precompile_instruction(
                &digest,
                &ed_sig,
                &f.ed.public_bytes(),
            ))
        }
    };
    (ed_ix, exec)
}

fn run_tx_cu(mollusk: &Mollusk, instructions: &[Instruction], f: &Fixture) -> u64 {
    let (payer_key, payer_acct) = payer();
    mollusk
        .process_and_validate_transaction_instructions(
            instructions,
            &[(payer_key, payer_acct), hybrid_account(f), recipient()],
            &[Check::success()],
            Some(&payer_key),
        )
        .compute_units_consumed
}

fn sample_policy_cu(mollusk: &Mollusk, policy: AuthorizationPolicy) -> (u64, u64, u64) {
    let mut samples = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        // Fresh keys each sample so Falcon rejection-sampling variance appears.
        let mut f = fixture(policy);
        {
            let mut acct = HybridAccount::try_from_bytes(&mut f.account_data).unwrap();
            acct.set_nonce(i as u64);
        }
        let intent = intent_for(&f, i as u64);
        let (ed_ix, exec) = sign_policy(&f, &intent, policy);
        let mut ixs = Vec::new();
        if let Some(ed) = ed_ix {
            ixs.push(ed);
        }
        ixs.push(exec);
        samples.push(run_tx_cu(mollusk, &ixs, &f));
    }
    samples.sort_unstable();
    (samples[0], samples[SAMPLES / 2], samples[SAMPLES - 1])
}

/// Bincode size of a legacy DualKey authorization transaction.
fn legacy_tx_size(policy: AuthorizationPolicy) -> usize {
    let f = fixture(policy);
    let intent = intent_for(&f, 0);
    let (ed_ix, exec) = sign_policy(&f, &intent, policy);
    let payer_key = Pubkey::new_from_array([0x01; 32]);

    let mut ixs = Vec::new();
    if let Some(ed) = ed_ix {
        ixs.push(ed);
    }
    ixs.push(exec);

    let mut tx = Transaction::new_with_payer(&ixs, Some(&payer_key));
    let n = tx.message.header.num_required_signatures as usize;
    tx.signatures = vec![Signature::default(); n];
    bincode::serialized_size(&tx).expect("serialize") as usize
}

fn write_bench_markdown(body: &str) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/benches");
    fs::create_dir_all(&dir).expect("mkdir benches");
    let path = dir.join("dualkey-milestone-8.md");
    fs::write(&path, body).expect("write bench md");
    println!("Wrote {}", path.display());
}

#[test]
fn legacy_hybrid_and_transfer_fits_without_alt() {
    let ed_only = legacy_tx_size(AuthorizationPolicy::Ed25519Only);
    let falcon_only = legacy_tx_size(AuthorizationPolicy::FalconOnly);
    let hybrid = legacy_tx_size(AuthorizationPolicy::HybridAnd);

    println!("\n=== Legacy transaction serialized size (bincode) ===");
    println!("{:>12}  {:>6}  {:>8}", "policy", "bytes", "headroom");
    for (name, size) in [
        ("Ed25519Only", ed_only),
        ("FalconOnly", falcon_only),
        ("HybridAnd", hybrid),
    ] {
        println!(
            "{name:>12}  {size:>6}  {:>8}",
            LEGACY_TX_LIMIT as isize - size as isize
        );
    }
    println!("Legacy limit: {LEGACY_TX_LIMIT}\n");

    assert!(
        hybrid <= LEGACY_TX_LIMIT,
        "HybridAnd transfer must fit a legacy tx without ALT: {hybrid} > {LEGACY_TX_LIMIT}"
    );
    assert!(
        falcon_only < hybrid,
        "FalconOnly should be smaller than HybridAnd (no Ed25519 precompile ix)"
    );
    // Execute always includes the 666-byte Falcon slot even under Ed25519Only,
    // so Ed25519Only and HybridAnd share the same instruction data length and
    // the same Ed25519 precompile — serialized sizes match.
    assert_eq!(
        ed_only, hybrid,
        "Ed25519Only and HybridAnd share Execute data + Ed25519 precompile"
    );
}

#[test]
fn compute_unit_matrix_for_authorization_policies() {
    let mollusk = mollusk();

    println!("\n=== DualKey Execute+TransferSol CU (Mollusk tx, {SAMPLES} samples) ===");
    println!(
        "{:>12}  {:>9}  {:>9}  {:>9}",
        "policy", "min", "median", "max"
    );

    let ed = sample_policy_cu(&mollusk, AuthorizationPolicy::Ed25519Only);
    println!(
        "{:>12}  {:>9}  {:>9}  {:>9}",
        "Ed25519Only", ed.0, ed.1, ed.2
    );

    let falcon = sample_policy_cu(&mollusk, AuthorizationPolicy::FalconOnly);
    println!(
        "{:>12}  {:>9}  {:>9}  {:>9}",
        "FalconOnly", falcon.0, falcon.1, falcon.2
    );

    let hybrid = sample_policy_cu(&mollusk, AuthorizationPolicy::HybridAnd);
    println!(
        "{:>12}  {:>9}  {:>9}  {:>9}",
        "HybridAnd", hybrid.0, hybrid.1, hybrid.2
    );

    // Invalid Falcon under HybridAnd — DoS surface. Use a *well-formed* but
    // wrong signature (bit-flip a real one). An all-zero buffer fails in decode
    // for ~2k CU and understates the cost of a crafted rejection.
    let mut reject_samples = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let mut f = fixture(AuthorizationPolicy::HybridAnd);
        {
            let mut acct = HybridAccount::try_from_bytes(&mut f.account_data).unwrap();
            acct.set_nonce(i as u64);
        }
        let intent = intent_for(&f, i as u64);
        let digest = canonical_digest(&intent);
        let ed_sig = f.ed.signing_key().sign(&digest).to_bytes();
        let (_d, wire) = falcon_interop::sign_to_wire(&digest, &f.falcon_secret).expect("falcon");
        let mut falcon_sig = [0u8; FALCON_SIGNATURE_LEN];
        falcon_sig.copy_from_slice(wire.as_wire_bytes());
        falcon_sig[40] ^= 0x01;
        let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &f.ed.public_bytes());
        let exec =
            onchain::execute_instruction(&program_id(), &f.account, &intent, &falcon_sig).unwrap();
        let (payer_key, payer_acct) = payer();
        let result = mollusk.process_and_validate_transaction_instructions(
            &[ed_ix, exec],
            &[(payer_key, payer_acct), hybrid_account(&f), recipient()],
            &[Check::err(solana_program_error::ProgramError::Custom(
                dualkey_core::DualKeyError::InvalidFalcon.code(),
            ))],
            Some(&payer_key),
        );
        reject_samples.push(result.compute_units_consumed);
    }
    reject_samples.sort_unstable();
    println!(
        "{:>12}  {:>9}  {:>9}  {:>9}",
        "Hybrid reject",
        reject_samples[0],
        reject_samples[SAMPLES / 2],
        reject_samples[SAMPLES - 1]
    );

    let hybrid_overhead = hybrid.1.saturating_sub(ed.1);
    let falcon_overhead = falcon.1.saturating_sub(ed.1);
    println!("\nMarginal median CU vs Ed25519Only:");
    println!("  FalconOnly:  {falcon_overhead}");
    println!("  HybridAnd:   {hybrid_overhead}");
    println!();

    // Sanity: HybridAnd ≥ FalconOnly ≥ Ed25519Only (medians).
    assert!(
        hybrid.1 >= falcon.1,
        "HybridAnd should cost at least FalconOnly"
    );
    assert!(
        falcon.1 > ed.1 + 50_000,
        "Falcon path should dominate Ed25519Only by >>50k CU"
    );
    // Rejection still burns Falcon-class CU (DoS surface).
    assert!(
        reject_samples[SAMPLES / 2] > 100_000,
        "invalid Falcon must still consume substantial CU"
    );

    let ed_size = legacy_tx_size(AuthorizationPolicy::Ed25519Only);
    let falcon_size = legacy_tx_size(AuthorizationPolicy::FalconOnly);
    let hybrid_size = legacy_tx_size(AuthorizationPolicy::HybridAnd);

    let md = format!(
        r#"# DualKey Milestone 8 — CU + transaction size

Generated by `client/tests/sbf_bench.rs`. Mollusk 0.15 (`precompiles`),
compiled `dualkey_program.so`, {SAMPLES} samples per policy (fresh keys each).

**Not a security proof** — empirical cost measurements only.

## Compute units (transaction total)

| Policy | min | median | max |
|--------|----:|-------:|----:|
| Ed25519Only | {} | {} | {} |
| FalconOnly | {} | {} | {} |
| HybridAnd | {} | {} | {} |
| HybridAnd invalid Falcon | {} | {} | {} |

Marginal median vs Ed25519Only: FalconOnly +{falcon_overhead} CU, HybridAnd +{hybrid_overhead} CU.

## Legacy transaction size (bincode)

| Policy | bytes | headroom to 1232 |
|--------|------:|-----------------:|
| Ed25519Only | {ed_size} | {} |
| FalconOnly | {falcon_size} | {} |
| HybridAnd | {hybrid_size} | {} |

**Verdict:** HybridAnd TransferSol fits a legacy transaction **without** an
Address Lookup Table ({hybrid_size} ≤ {LEGACY_TX_LIMIT}).
"#,
        ed.0,
        ed.1,
        ed.2,
        falcon.0,
        falcon.1,
        falcon.2,
        hybrid.0,
        hybrid.1,
        hybrid.2,
        reject_samples[0],
        reject_samples[SAMPLES / 2],
        reject_samples[SAMPLES - 1],
        LEGACY_TX_LIMIT - ed_size,
        LEGACY_TX_LIMIT - falcon_size,
        LEGACY_TX_LIMIT - hybrid_size,
    );
    write_bench_markdown(&md);
}
