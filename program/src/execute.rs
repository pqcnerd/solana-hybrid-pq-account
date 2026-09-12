//! `Execute` — authorize an intent under the account's policy.
//!
//! Milestone 5: Ed25519 / Falcon / HybridAnd verification.
//! Milestone 6: expiry against the Clock sysvar, and nonce consumption so a
//! signed intent cannot be replayed. Still does **not** transfer lamports
//! (Milestone 7).
//!
//! ## Instruction data (716 bytes)
//!
//! ```text
//! Offset  Size  Field
//! 0       1     discriminator (1)
//! 1       8     expiry_slot (u64 LE)
//! 9       1     action_tag
//! 10      40    action_body
//! 50      666   falcon signature (compressed, zero-padded)
//! 716           end
//! ```
//!
//! ## Accounts
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `hybrid_account` | **writable** — nonce is incremented on success |
//! | 1 | `instructions_sysvar` | readonly — for Ed25519 precompile introspection |
//!
//! The Ed25519 signature is **not** in this instruction. It must appear as the
//! immediately preceding Ed25519 precompile instruction in the same transaction,
//! over the 32-byte reconstructed digest.

use dualkey_core::{
    AuthorizationPolicy, DualKeyError, ExecuteIntentWire, HybridAccount, EXECUTE_INTENT_WIRE_LEN,
    FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_get_sysvar::GetSysvar;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::auth::ed25519::verify_ed25519_precompile;
use crate::auth::falcon::verify_falcon_prepared;
use crate::auth::policy::{evaluate_policy, SignatureValidity};
use crate::reconstruct::reconstruct_and_digest;

/// Payload length after the discriminator.
pub const EXECUTE_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full instruction data length including the discriminator.
pub const EXECUTE_DATA_LEN: usize = 1 + EXECUTE_PAYLOAD_LEN;

const _: () = assert!(EXECUTE_DATA_LEN == 716);

/// Authorize `payload` against the HybridAccount under its stored policy.
///
/// On success the account nonce is incremented. A second submission of the same
/// signatures then reconstructs a different digest (new nonce) and fails
/// verification — that is the replay defense. Expiry is checked against
/// `Clock::get().slot` before the expensive Falcon verify.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != EXECUTE_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let [hybrid_account, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    if !hybrid_account.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let (wire_bytes, falcon_sig) = payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    // Expiry before crypto: a stale intent should fail cheaply. Inclusive bound
    // (`<=`) matches the intent field docs ("last slot at which this intent is
    // valid").
    let clock = Clock::get().map_err(|_| DualKeyError::InvalidAccountData)?;
    if clock.slot > wire.expiry_slot {
        return Err(DualKeyError::IntentExpired);
    }

    // Reconstruct + digest before any crypto so both schemes bind the same
    // bytes. The reconstructed nonce is always the account's current nonce, so
    // a client that signed a different nonce gets a digest mismatch at verify
    // (see InvalidNonce note below).
    let (digest, ctx) = reconstruct_and_digest(program_id, hybrid_account, &wire)?;

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let policy = HybridAccount::policy_from_slice(&data)?;
    let owner_ed25519 = HybridAccount::owner_ed25519_from_slice(&data)?;
    let prepared = *HybridAccount::prepared_falcon_public_key_from_slice(&data)?;
    let account_nonce = HybridAccount::nonce_from_slice(&data)?;
    drop(data);

    // Redundant with reconstruction, but keeps InvalidNonce as an explicit
    // failure mode if those paths ever diverge, and documents the invariant
    // the architecture requires.
    if ctx.nonce != account_nonce {
        return Err(DualKeyError::InvalidNonce);
    }

    // Refuse to authorize when the next bump would overflow — otherwise a
    // successful verify could not be recorded and the intent would remain
    // forever replayable.
    let next_nonce = account_nonce
        .checked_add(1)
        .ok_or(DualKeyError::MathOverflow)?;

    let sigs = match policy {
        AuthorizationPolicy::Ed25519Only => {
            verify_ed25519_precompile(instructions_sysvar, &owner_ed25519, &digest)?;
            SignatureValidity {
                ed25519_valid: true,
                falcon_valid: false,
            }
        }
        AuthorizationPolicy::FalconOnly => {
            verify_falcon_prepared(prepared.as_slice(), &digest, falcon_sig)?;
            SignatureValidity {
                ed25519_valid: false,
                falcon_valid: true,
            }
        }
        AuthorizationPolicy::HybridAnd => {
            verify_ed25519_precompile(instructions_sysvar, &owner_ed25519, &digest)?;
            verify_falcon_prepared(prepared.as_slice(), &digest, falcon_sig)?;
            SignatureValidity {
                ed25519_valid: true,
                falcon_valid: true,
            }
        }
        AuthorizationPolicy::HybridOr
        | AuthorizationPolicy::FalconForPrivileged
        | AuthorizationPolicy::FalconAboveThreshold => {
            return Err(DualKeyError::PolicyNotImplemented);
        }
    };

    evaluate_policy(policy, sigs)?;

    // Auth succeeded — consume the nonce. Solana transaction atomicity means
    // this write reverts if anything later fails (Milestone 7 transfer).
    {
        let mut data = hybrid_account
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut account = HybridAccount::try_from_bytes(&mut data)?;
        account.set_nonce(next_nonce);
    }

    msg!(
        "DualKey: authorization VALID ({}); nonce {} -> {}",
        policy.name(),
        account_nonce,
        next_nonce
    );
    Ok(())
}
