//! `Execute` — authorize an intent under the account's policy, then act.
//!
//! Milestone 5: Ed25519 / Falcon / HybridAnd verification.
//! Milestone 6: expiry against the Clock sysvar, and nonce consumption so a
//! signed intent cannot be replayed.
//! Milestone 7: `TransferSol` — move lamports from the HybridAccount PDA to the
//! declared recipient while preserving the rent-exempt floor.
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
//! | 0 | `hybrid_account` | **writable** — nonce bump + lamport debit |
//! | 1 | `recipient` | **writable** — must equal the signed action recipient |
//! | 2 | `instructions_sysvar` | readonly — Ed25519 precompile introspection |
//!
//! The Ed25519 signature is **not** in this instruction. It must appear as the
//! immediately preceding Ed25519 precompile instruction in the same transaction,
//! over the 32-byte reconstructed digest.

use dualkey_core::{
    Action, AuthorizationPolicy, DualKeyError, ExecuteIntentWire, HybridAccount, ACCOUNT_DATA_LEN,
    EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_get_sysvar::GetSysvar;
use solana_msg::msg;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

use crate::auth::ed25519::verify_ed25519_precompile;
use crate::auth::falcon::verify_falcon_prepared;
use crate::auth::policy::{evaluate_policy, SignatureValidity};
use crate::reconstruct::reconstruct_and_digest;

/// Payload length after the discriminator.
pub const EXECUTE_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full instruction data length including the discriminator.
pub const EXECUTE_DATA_LEN: usize = 1 + EXECUTE_PAYLOAD_LEN;

const _: () = assert!(EXECUTE_DATA_LEN == 716);

/// Authorize `payload`, consume the nonce, then execute the signed action.
///
/// Replay defense is the nonce bump: a second submission of the same signatures
/// reconstructs a different digest and fails verification. Expiry is checked
/// against `Clock::get().slot` before the expensive Falcon verify. The transfer
/// runs only after a successful bump; Solana atomicity reverts both on failure.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != EXECUTE_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let [hybrid_account, recipient, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    if !hybrid_account.is_writable || !recipient.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let (wire_bytes, falcon_sig) = payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    let Action::TransferSol {
        recipient: expected_recipient,
        lamports,
    } = wire.action;
    if recipient.key.to_bytes() != expected_recipient {
        return Err(DualKeyError::InvalidAccountData);
    }
    if recipient.key == hybrid_account.key {
        return Err(DualKeyError::InvalidAccountData);
    }

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

    // Auth succeeded — consume the nonce before moving value. Transaction
    // atomicity reverts this write if the transfer below fails.
    {
        let mut data = hybrid_account
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut account = HybridAccount::try_from_bytes(&mut data)?;
        account.set_nonce(next_nonce);
    }

    transfer_sol(hybrid_account, recipient, lamports)?;

    msg!(
        "DualKey: TransferSol {} lamports OK ({}); nonce {} -> {}",
        lamports,
        policy.name(),
        account_nonce,
        next_nonce
    );
    Ok(())
}

/// Debit `amount` from the program-owned HybridAccount and credit `recipient`.
///
/// Keeps the vault at or above the rent-exempt minimum for its fixed data
/// length. Uses direct lamport mutation rather than a System CPI: the source is
/// DualKey-owned, so the System program's transfer instruction does not apply.
fn transfer_sol(
    hybrid_account: &AccountInfo,
    recipient: &AccountInfo,
    amount: u64,
) -> Result<(), DualKeyError> {
    if amount == 0 {
        return Ok(());
    }

    let rent_min = Rent::get()
        .map_err(|_| DualKeyError::InvalidAccountData)?
        .minimum_balance(ACCOUNT_DATA_LEN);

    let remaining = hybrid_account
        .lamports()
        .checked_sub(amount)
        .ok_or(DualKeyError::InsufficientFunds)?;
    if remaining < rent_min {
        return Err(DualKeyError::InsufficientFunds);
    }

    let mut from = hybrid_account
        .try_borrow_mut_lamports()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut to = recipient
        .try_borrow_mut_lamports()
        .map_err(|_| DualKeyError::InvalidAccountData)?;

    **from = remaining;
    **to = to.checked_add(amount).ok_or(DualKeyError::MathOverflow)?;
    Ok(())
}
