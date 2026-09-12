//! On-chain reconstruction of an [`AuthorizationIntent`].
//!
//! Milestone 4 proves that the program rebuilds the same 172-byte canonical
//! preimage the client signed, using trusted context for every field that must
//! not be attacker-chosen on the wire. Authorization (HybridAnd) is Milestone 5;
//! this module only reconstructs and digests.

use dualkey_core::{
    canonical_preimage, reconstruct_intent, DualKeyError, ExecuteIntentWire, HybridAccount,
    IntentContext, ACCOUNT_VERSION, DIGEST_LEN, EXECUTE_INTENT_WIRE_LEN,
};
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::chain_domain::CHAIN_DOMAIN;
use crate::hash::{digest_canonical_preimage, sha256};

/// Total harness payload after the discriminator: wire intent + expected digest.
pub const RECONSTRUCT_DIGEST_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + DIGEST_LEN;

const _: () = assert!(RECONSTRUCT_DIGEST_PAYLOAD_LEN == 81);

/// Rebuild an intent from a HybridAccount + wire fragment, then SHA-256 it.
///
/// `account_info` must be the HybridAccount PDA whose address and stored nonce
/// are bound into the digest. The account is not mutated.
pub fn reconstruct_and_digest(
    program_id: &Pubkey,
    account_info: &AccountInfo,
    wire: &ExecuteIntentWire,
) -> Result<([u8; DIGEST_LEN], IntentContext), DualKeyError> {
    if account_info.owner != program_id {
        return Err(DualKeyError::InvalidAccountData);
    }

    let data = account_info
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let version = HybridAccount::version_from_slice(&data)?;
    if version != ACCOUNT_VERSION {
        return Err(DualKeyError::UnsupportedVersion);
    }
    let nonce = HybridAccount::nonce_from_slice(&data)?;
    drop(data);

    let ctx = IntentContext {
        chain_domain: CHAIN_DOMAIN,
        program_id: program_id.to_bytes(),
        account: account_info.key.to_bytes(),
        nonce,
    };
    let intent = reconstruct_intent(&ctx, wire);
    let preimage = canonical_preimage(&intent);
    let digest = digest_canonical_preimage(&preimage)?;
    Ok((digest, ctx))
}

/// Milestone 4 harness: reconstruct from account context + wire fields, hash
/// with `sol_sha256`, and compare to an expected digest.
///
/// ```text
/// Accounts:
///   [0] HybridAccount (readonly) — supplies address + nonce
///
/// Instruction data:
///   [243] ‖ expiry(8) ‖ action_tag(1) ‖ action_body(40) ‖ expected_digest(32)
/// ```
///
/// Authorizes nothing: no policy check, no signature check, no state mutation.
pub fn process_reconstruct_canonical_digest(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != RECONSTRUCT_DIGEST_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let account_info = accounts
        .first()
        .ok_or(DualKeyError::MalformedInstructionData)?;

    let (wire_bytes, expected) = payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;
    let expected: [u8; DIGEST_LEN] = expected
        .try_into()
        .map_err(|_| DualKeyError::MalformedInstructionData)?;

    let (digest, _ctx) = reconstruct_and_digest(program_id, account_info, &wire)?;
    if digest != expected {
        return Err(DualKeyError::DigestMismatch);
    }
    msg!("Canonical reconstruct: MATCH");
    Ok(())
}

/// Hash the compile-time chain domain alone — used by tests to confirm which
/// cluster constant the binary was built with, without reconstructing an intent.
pub fn chain_domain_fingerprint() -> [u8; DIGEST_LEN] {
    sha256(&CHAIN_DOMAIN)
}
