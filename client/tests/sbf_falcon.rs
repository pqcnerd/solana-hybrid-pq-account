//! Milestone 2: Falcon-512 verification and the canonical digest running under
//! Solana SBF.
//!
//! These tests execute the **compiled SBF binary** (`dualkey_program.so`) inside
//! Mollusk, not host Rust. Signatures are produced here by the off-chain client
//! using PQClean, exactly as a real user would, and are then handed to the
//! on-chain verifier. That makes this the end-to-end interoperability test:
//! client signs -> program verifies, across two independent Falcon
//! implementations.
//!
//! Run `cargo-build-sbf --manifest-path program/Cargo.toml` first; Mollusk
//! resolves the ELF from `SBF_OUT_DIR` or `target/deploy`.
//!
//! No vault, no PDA and no authorization policy are involved. The harness
//! instructions verify and report; they authorize nothing.

use dualkey_client::falcon_interop::{self, WireSignature};
use dualkey_core::{
    canonical_preimage, test_vector_intent, DualKeyError, CANONICAL_PREIMAGE_LEN, DIGEST_LEN,
    TEST_VECTOR_DIGEST,
};
use dualkey_program::instruction::DualKeyInstruction;
use mollusk_svm::{program::loader_keys, result::Check, Mollusk};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const PROGRAM_NAME: &str = "dualkey_program";
const PREPARED_LEN: usize = 1024;
const SIGNATURE_LEN: usize = 666;
const WIRE_PUBKEY_LEN: usize = 897;

fn program_id() -> Pubkey {
    Pubkey::new_from_array([7u8; 32])
}

/// Load the compiled SBF ELF and register it directly.
///
/// Deliberately avoids `Mollusk::new`, which resolves the ELF through the
/// `SBF_OUT_DIR` environment variable: tests run in parallel by default, and
/// mutating the process environment from several threads is unsound. Reading the
/// path explicitly keeps each test independent.
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

/// A freshly generated Falcon keypair plus a signature over `message`.
struct Fixture {
    prepared: [u8; PREPARED_LEN],
    wire_pubkey: [u8; WIRE_PUBKEY_LEN],
    signature: WireSignature,
    message: Vec<u8>,
}

fn fixture(message: &[u8]) -> Fixture {
    let (pk, sk) = falcon512::keypair();
    let (_detached, signature) = falcon_interop::sign_to_wire(message, &sk).expect("sign");
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");

    // Sanity-check off-chain before asking the on-chain verifier, so a failure
    // on-chain is unambiguously an on-chain failure.
    assert!(
        falcon_interop::verify_pqclean_wire(&signature, message, pk.as_bytes()),
        "fixture must verify off-chain with PQClean"
    );

    Fixture {
        prepared: *prepared.as_bytes(),
        wire_pubkey: pk.as_bytes().try_into().expect("897 bytes"),
        signature,
        message: message.to_vec(),
    }
}

/// Account holding a prepared public key at offset 0, as Milestone 3's PDA will.
fn prepared_key_account(prepared: &[u8; PREPARED_LEN]) -> (Pubkey, Account) {
    (
        Pubkey::new_from_array([9u8; 32]),
        Account {
            lamports: 1_000_000_000,
            data: prepared.to_vec(),
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn prepared_ix(key_account: &Pubkey, signature: &[u8], message: &[u8]) -> Instruction {
    let mut data = Vec::with_capacity(1 + SIGNATURE_LEN + message.len());
    data.push(DualKeyInstruction::VerifyFalconPrepared.as_u8());
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction {
        program_id: program_id(),
        accounts: vec![AccountMeta::new_readonly(*key_account, false)],
        data,
    }
}

fn raw_ix(pubkey: &[u8], signature: &[u8], message: &[u8]) -> Instruction {
    let mut data = Vec::with_capacity(1 + SIGNATURE_LEN + WIRE_PUBKEY_LEN + message.len());
    data.push(DualKeyInstruction::VerifyFalconRaw.as_u8());
    data.extend_from_slice(signature);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(message);
    Instruction {
        program_id: program_id(),
        accounts: vec![],
        data,
    }
}

fn digest_ix(preimage: &[u8], expected: &[u8]) -> Instruction {
    let mut data = Vec::with_capacity(1 + CANONICAL_PREIMAGE_LEN + DIGEST_LEN);
    data.push(DualKeyInstruction::VerifyCanonicalDigest.as_u8());
    data.extend_from_slice(preimage);
    data.extend_from_slice(expected);
    Instruction {
        program_id: program_id(),
        accounts: vec![],
        data,
    }
}

fn custom(err: DualKeyError) -> Check<'static> {
    Check::err(ProgramError::Custom(err.code()))
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn falcon_verifies_on_chain_with_prepared_pubkey_from_account_data() {
    let mollusk = mollusk();
    let f = fixture(b"dualkey milestone 2 prepared");
    let (key, account) = prepared_key_account(&f.prepared);

    let result = mollusk.process_and_validate_instruction(
        &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
        &[(key, account)],
        &[Check::success()],
    );
    println!(
        "prepared-pubkey verify: {} CU",
        result.compute_units_consumed
    );
}

#[test]
fn falcon_verifies_on_chain_with_raw_wire_pubkey() {
    let mollusk = mollusk();
    let f = fixture(b"dualkey milestone 2 raw");

    let result = mollusk.process_and_validate_instruction(
        &raw_ix(&f.wire_pubkey, f.signature.as_wire_bytes(), &f.message),
        &[],
        &[Check::success()],
    );
    println!(
        "raw-pubkey verify:      {} CU",
        result.compute_units_consumed
    );
}

/// Independently generated keys and messages all verify, so success is not an
/// artifact of one lucky fixture.
#[test]
fn many_independent_signatures_verify_on_chain() {
    let mollusk = mollusk();
    for i in 0..12 {
        let message = format!("independent-{i}");
        let f = fixture(message.as_bytes());
        let (key, account) = prepared_key_account(&f.prepared);
        mollusk.process_and_validate_instruction(
            &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
            &[(key, account)],
            &[Check::success()],
        );
    }
}

/// Verification must be message-length agnostic: the vault will verify 32-byte
/// digests, but the primitive should not care.
#[test]
fn verifies_across_message_lengths_including_empty() {
    let mollusk = mollusk();
    for len in [0usize, 1, 32, 172, 500] {
        let message = vec![0xABu8; len];
        let f = fixture(&message);
        let (key, account) = prepared_key_account(&f.prepared);
        let result = mollusk.process_and_validate_instruction(
            &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
            &[(key, account)],
            &[Check::success()],
        );
        println!("message len {len:>4}: {} CU", result.compute_units_consumed);
    }
}

// ---------------------------------------------------------------------------
// Cross-layer digest invariant
// ---------------------------------------------------------------------------

/// The on-chain `sol_sha256` digest must equal the client's `sha2` digest over
/// identical canonical preimage bytes. Asserted against the shared
/// known-answer vector, closing the invariant across both layers.
#[test]
fn sol_sha256_reproduces_the_client_known_answer_digest() {
    let mollusk = mollusk();
    let preimage = canonical_preimage(&test_vector_intent());

    let result = mollusk.process_and_validate_instruction(
        &digest_ix(&preimage, &TEST_VECTOR_DIGEST),
        &[],
        &[Check::success()],
    );
    println!(
        "sol_sha256 canonical digest: {} CU",
        result.compute_units_consumed
    );
}

/// Same property over arbitrary intents, not just the pinned vector.
#[test]
fn sol_sha256_matches_client_digest_for_arbitrary_intents() {
    use dualkey_core::canonical_digest;

    let mollusk = mollusk();
    for nonce in 0..6u64 {
        let mut intent = test_vector_intent();
        intent.nonce = nonce;
        intent.expiry_slot = 1_000 + nonce;

        let preimage = canonical_preimage(&intent);
        let expected = canonical_digest(&intent);

        mollusk.process_and_validate_instruction(
            &digest_ix(&preimage, &expected),
            &[],
            &[Check::success()],
        );
    }
}

#[test]
fn wrong_expected_digest_is_rejected() {
    let mollusk = mollusk();
    let preimage = canonical_preimage(&test_vector_intent());
    let mut wrong = TEST_VECTOR_DIGEST;
    wrong[0] ^= 0x01;

    mollusk.process_and_validate_instruction(
        &digest_ix(&preimage, &wrong),
        &[],
        &[custom(DualKeyError::DigestMismatch)],
    );
}

/// A single flipped preimage bit must change the digest, so the on-chain hash
/// is genuinely binding on every field.
#[test]
fn preimage_bit_flip_changes_the_on_chain_digest() {
    let mollusk = mollusk();
    let base = canonical_preimage(&test_vector_intent());

    for byte in [0usize, 18, 51, 115, 131, CANONICAL_PREIMAGE_LEN - 1] {
        let mut preimage = base;
        preimage[byte] ^= 0x01;
        mollusk.process_and_validate_instruction(
            &digest_ix(&preimage, &TEST_VECTOR_DIGEST),
            &[],
            &[custom(DualKeyError::DigestMismatch)],
        );
    }
}

// ---------------------------------------------------------------------------
// Negative paths: verification must fail, and fail safely
// ---------------------------------------------------------------------------

#[test]
fn tampered_message_fails_on_chain() {
    let mollusk = mollusk();
    let f = fixture(b"authentic message");
    let (key, account) = prepared_key_account(&f.prepared);

    mollusk.process_and_validate_instruction(
        &prepared_ix(&key, f.signature.as_wire_bytes(), b"tampered message"),
        &[(key, account)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

#[test]
fn signature_bit_flip_fails_on_chain() {
    let mollusk = mollusk();
    let f = fixture(b"bit flip target");
    let (key, account) = prepared_key_account(&f.prepared);

    // Header, nonce, and compressed-body regions.
    for index in [0usize, 1, 20, 41, 100, 400] {
        let mut sig = *f.signature.as_wire_bytes();
        sig[index] ^= 0x01;
        mollusk.process_and_validate_instruction(
            &prepared_ix(&key, &sig, &f.message),
            &[(key, account.clone())],
            &[custom(DualKeyError::InvalidFalcon)],
        );
    }
}

/// A signature valid under one key must not verify under another.
#[test]
fn signature_under_wrong_public_key_fails_on_chain() {
    let mollusk = mollusk();
    let f = fixture(b"key substitution");
    let other = fixture(b"unrelated");
    let (key, account) = prepared_key_account(&other.prepared);

    mollusk.process_and_validate_instruction(
        &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
        &[(key, account)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

/// Non-zero trailing padding must be rejected rather than ignored, matching the
/// off-chain verifier. Otherwise the 666-byte encoding would be malleable.
#[test]
fn non_zero_padding_fails_on_chain() {
    let mollusk = mollusk();
    let f = fixture(b"padding malleability");
    assert!(
        f.signature.padding_len() > 0,
        "fixture needs padding for this test"
    );
    let (key, account) = prepared_key_account(&f.prepared);

    let mut sig = *f.signature.as_wire_bytes();
    sig[SIGNATURE_LEN - 1] = 0x01;

    mollusk.process_and_validate_instruction(
        &prepared_ix(&key, &sig, &f.message),
        &[(key, account)],
        &[custom(DualKeyError::InvalidFalcon)],
    );
}

/// Malformed instruction data must produce a clean error, never a panic and
/// never a success. A panic would surface as `ProgramFailedToComplete`.
#[test]
fn malformed_instruction_data_is_rejected_without_panicking() {
    let mollusk = mollusk();
    let f = fixture(b"malformed framing");
    let (key, account) = prepared_key_account(&f.prepared);

    // Empty instruction data (no discriminator).
    mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![],
            data: vec![],
        },
        &[],
        &[custom(DualKeyError::MalformedInstructionData)],
    );

    // Unknown discriminator.
    mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![],
            data: vec![99],
        },
        &[],
        &[custom(DualKeyError::MalformedInstructionData)],
    );

    // Signature field shorter than 666 bytes.
    for short in [0usize, 1, 665] {
        let mut data = vec![DualKeyInstruction::VerifyFalconPrepared.as_u8()];
        data.extend_from_slice(&f.signature.as_wire_bytes()[..short]);
        mollusk.process_and_validate_instruction(
            &Instruction {
                program_id: program_id(),
                accounts: vec![AccountMeta::new_readonly(key, false)],
                data,
            },
            &[(key, account.clone())],
            &[custom(DualKeyError::MalformedInstructionData)],
        );
    }

    // Raw path with a truncated public key.
    let mut data = vec![DualKeyInstruction::VerifyFalconRaw.as_u8()];
    data.extend_from_slice(f.signature.as_wire_bytes());
    data.extend_from_slice(&f.wire_pubkey[..800]);
    mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![],
            data,
        },
        &[],
        &[custom(DualKeyError::MalformedInstructionData)],
    );

    // Digest path with a wrong-length payload.
    for len in [0usize, 171, 203, 205] {
        let mut data = vec![DualKeyInstruction::VerifyCanonicalDigest.as_u8()];
        data.extend_from_slice(&vec![0u8; len]);
        mollusk.process_and_validate_instruction(
            &Instruction {
                program_id: program_id(),
                accounts: vec![],
                data,
            },
            &[],
            &[custom(DualKeyError::MalformedInstructionData)],
        );
    }
}

/// A prepared-key account whose data is shorter than 1024 bytes must be
/// rejected, not read out of bounds.
#[test]
fn undersized_prepared_key_account_is_rejected() {
    let mollusk = mollusk();
    let f = fixture(b"short account");
    let key = Pubkey::new_from_array([9u8; 32]);

    for len in [0usize, 1, 1023] {
        let account = Account {
            lamports: 1_000_000_000,
            data: f.prepared[..len].to_vec(),
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        };
        mollusk.process_and_validate_instruction(
            &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
            &[(key, account)],
            &[custom(DualKeyError::InvalidAccountData)],
        );
    }
}

/// Garbage in the prepared-key region must fail verification cleanly. The
/// prepared form is unvalidated by construction (any 1024 bytes decode to some
/// polynomial), so this must fail the norm check rather than error out.
#[test]
fn garbage_prepared_key_fails_verification_without_panicking() {
    let mollusk = mollusk();
    let f = fixture(b"garbage key");
    let key = Pubkey::new_from_array([9u8; 32]);

    for fill in [0x00u8, 0xFF, 0xA5] {
        let account = Account {
            lamports: 1_000_000_000,
            data: vec![fill; PREPARED_LEN],
            owner: program_id(),
            executable: false,
            rent_epoch: 0,
        };
        let result = mollusk.process_instruction(
            &prepared_ix(&key, f.signature.as_wire_bytes(), &f.message),
            &[(key, account)],
        );
        assert!(
            result.program_result.is_err(),
            "garbage prepared key (fill {fill:#04x}) must not verify"
        );
        assert!(
            result.raw_result.is_ok() || !format!("{:?}", result.raw_result).contains("Failed"),
            "must fail as a clean error, not a VM abort: {:?}",
            result.raw_result
        );
    }
}

/// `ChangePolicy` is implemented in Milestone 10 (`sbf_policy`).
/// A bare discriminator without the 715-byte payload is malformed.
#[test]
fn change_policy_requires_full_payload() {
    let mollusk = mollusk();
    mollusk.process_and_validate_instruction(
        &Instruction {
            program_id: program_id(),
            accounts: vec![],
            data: vec![DualKeyInstruction::ChangePolicy.as_u8()],
        },
        &[],
        &[custom(DualKeyError::MalformedInstructionData)],
    );
}

// ---------------------------------------------------------------------------
// Compute-unit budget
// ---------------------------------------------------------------------------

/// Record the real compute cost of both verification paths and assert the
/// prepared path stays inside the budget the architecture assumes.
///
/// Cost is **not** deterministic for a fixed message length. `hash_to_point`
/// rejection-samples SHAKE256 output, so the number of Keccak-f permutations
/// varies per signature, and each permutation costs ~10,150 CU on SBF. Measured
/// over a 32-byte digest the observed values cluster at ~172.6k / ~182.9k, with
/// a ~192.9k tail. The test therefore checks the median against the documented
/// budget and the worst case against one extra permutation, rather than pinning
/// a single number that would be flaky.
#[test]
fn compute_units_are_within_the_documented_budget() {
    /// Documented safe budget for the prepared path (architecture doc).
    const PREPARED_BUDGET: u64 = 195_000;
    /// One additional Keccak-f permutation above the budget, for the tail.
    const PREPARED_CEILING: u64 = 205_000;
    const MAX_PER_INSTRUCTION: u64 = 1_400_000;
    const SAMPLES: usize = 9;

    let mollusk = mollusk();
    // Verify over a 32-byte digest: the shape the vault will actually use.
    let (pk, sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
    let wire_pubkey: [u8; WIRE_PUBKEY_LEN] = pk.as_bytes().try_into().expect("897");
    let (key, account) = prepared_key_account(prepared.as_bytes());

    let mut prepared_cu = Vec::with_capacity(SAMPLES);
    let mut raw_cu = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let mut message = [0x5Au8; DIGEST_LEN];
        message[0] = i as u8;
        let (_d, sig) = falcon_interop::sign_to_wire(&message, &sk).expect("sign");

        prepared_cu.push(
            mollusk
                .process_and_validate_instruction(
                    &prepared_ix(&key, sig.as_wire_bytes(), &message),
                    &[(key, account.clone())],
                    &[Check::success()],
                )
                .compute_units_consumed,
        );
        raw_cu.push(
            mollusk
                .process_and_validate_instruction(
                    &raw_ix(&wire_pubkey, sig.as_wire_bytes(), &message),
                    &[],
                    &[Check::success()],
                )
                .compute_units_consumed,
        );
    }
    prepared_cu.sort_unstable();
    raw_cu.sort_unstable();
    let (prepared_med, prepared_max) = (prepared_cu[SAMPLES / 2], prepared_cu[SAMPLES - 1]);
    let raw_med = raw_cu[SAMPLES / 2];

    let digest_cu = mollusk
        .process_and_validate_instruction(
            &digest_ix(
                &canonical_preimage(&test_vector_intent()),
                &TEST_VECTOR_DIGEST,
            ),
            &[],
            &[Check::success()],
        )
        .compute_units_consumed;

    println!("\n=== Milestone 2 compute units (32-byte digest, {SAMPLES} samples) ===");
    println!(
        "Falcon-512 verify, prepared pubkey : median {prepared_med:>7}  max {prepared_max:>7} CU"
    );
    println!("Falcon-512 verify, raw wire pubkey : median {raw_med:>7} CU");
    println!("Canonical digest via sol_sha256    :        {digest_cu:>7} CU");
    println!(
        "Prepared saves                     :        {:>7} CU vs raw",
        raw_med.saturating_sub(prepared_med)
    );
    println!("Per-instruction ceiling            :      {MAX_PER_INSTRUCTION:>7} CU\n");

    assert!(
        prepared_med <= PREPARED_BUDGET,
        "median prepared verify used {prepared_med} CU, over the documented \
         {PREPARED_BUDGET} CU budget"
    );
    assert!(
        prepared_max <= PREPARED_CEILING,
        "worst-case prepared verify used {prepared_max} CU, above the \
         {PREPARED_CEILING} CU tail ceiling"
    );
    assert!(
        prepared_med < raw_med,
        "the prepared representation must be cheaper than decoding the wire key \
         (prepared {prepared_med}, raw {raw_med})"
    );
    // Headroom for Ed25519 introspection, state writes and the transfer CPI
    // that Milestones 5-7 add on top.
    assert!(
        prepared_max * 2 < MAX_PER_INSTRUCTION,
        "no headroom left for hybrid authorization: {prepared_max} CU"
    );
}

/// Controlled compute-unit measurement.
///
/// The per-test fixtures above each generate a fresh keypair, so their CU
/// figures mix three variables: message length, the signature's compressed
/// length (647-663 bytes), and the key itself. This holds the key fixed and
/// takes several samples per message length so the message-length relationship
/// can be read off without that confounding.
///
/// Ignored by default because it runs a few hundred SBF invocations. Run with:
/// `cargo test -p dualkey-client --release --test sbf_falcon -- --ignored --nocapture`
#[test]
#[ignore = "benchmark; run explicitly"]
fn compute_unit_profile_by_message_length() {
    const SAMPLES: usize = 12;

    let mollusk = mollusk();
    let (pk, sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
    let prepared_bytes = *prepared.as_bytes();
    let wire_pubkey: [u8; WIRE_PUBKEY_LEN] = pk.as_bytes().try_into().expect("897");
    let (key, account) = prepared_key_account(&prepared_bytes);

    println!("\n=== Falcon-512 verify: CU by message length (single key, {SAMPLES} samples) ===");
    println!(
        "{:>8}  {:>9}  {:>9}  {:>9}  {:>9}",
        "msg len", "min", "median", "max", "raw med"
    );

    for len in [0usize, 32, 64, 96, 128, 172, 256, 512] {
        let mut prepared_cu = Vec::with_capacity(SAMPLES);
        let mut raw_cu = Vec::with_capacity(SAMPLES);

        for i in 0..SAMPLES {
            // Vary content, not length, so each sample is a distinct signature.
            let mut message = vec![0u8; len];
            if len > 0 {
                message[i % len] = i as u8;
            }
            let (_d, sig) = falcon_interop::sign_to_wire(&message, &sk).expect("sign");

            prepared_cu.push(
                mollusk
                    .process_and_validate_instruction(
                        &prepared_ix(&key, sig.as_wire_bytes(), &message),
                        &[(key, account.clone())],
                        &[Check::success()],
                    )
                    .compute_units_consumed,
            );
            raw_cu.push(
                mollusk
                    .process_and_validate_instruction(
                        &raw_ix(&wire_pubkey, sig.as_wire_bytes(), &message),
                        &[],
                        &[Check::success()],
                    )
                    .compute_units_consumed,
            );
        }

        prepared_cu.sort_unstable();
        raw_cu.sort_unstable();
        println!(
            "{len:>8}  {:>9}  {:>9}  {:>9}  {:>9}",
            prepared_cu[0],
            prepared_cu[SAMPLES / 2],
            prepared_cu[SAMPLES - 1],
            raw_cu[SAMPLES / 2],
        );
    }
    println!();
}
