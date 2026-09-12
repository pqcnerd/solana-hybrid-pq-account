//! `Execute` — authorize an intent under the account's policy, then act.
//!
//! Milestone 5–6: Ed25519 / Falcon / HybridAnd verification, expiry, nonce.
//! Milestone 7: `TransferSol`.
//! Milestone 11: `TransferSpl` (classic SPL Token CPI via PDA signer).
//!
//! Key rotation and policy changes use dedicated instructions; this path only
//! accepts [`Action::TransferSol`] and [`Action::TransferSpl`].
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
//! ## Accounts — `TransferSol`
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `hybrid_account` | **writable** — nonce bump + lamport debit |
//! | 1 | `recipient` | **writable** — must equal the signed action recipient |
//! | 2 | `instructions_sysvar` | readonly — Ed25519 precompile introspection |
//!
//! ## Accounts — `TransferSpl`
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `hybrid_account` | **writable** — nonce bump; PDA authority |
//! | 1 | `creator` | readonly — PDA seed (must reconstruct address) |
//! | 2 | `source_token` | **writable** — owned by the HybridAccount PDA |
//! | 3 | `mint` | readonly |
//! | 4 | `destination_token` | **writable** — must equal the signed destination |
//! | 5 | `token_program` | readonly — classic SPL Token |
//! | 6 | `instructions_sysvar` | readonly |

use dualkey_core::{
    Action, DualKeyError, ExecuteIntentWire, HybridAccount, ACCOUNT_DATA_LEN,
    EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_get_sysvar::GetSysvar;
use solana_msg::msg;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

use crate::authorize;
use crate::spl_token;

/// Payload length after the discriminator.
pub const EXECUTE_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full instruction data length including the discriminator.
pub const EXECUTE_DATA_LEN: usize = 1 + EXECUTE_PAYLOAD_LEN;

const _: () = assert!(EXECUTE_DATA_LEN == 716);

/// Authorize `payload`, consume the nonce, then execute the signed transfer action.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != EXECUTE_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    match wire.action {
        Action::TransferSol {
            recipient: expected_recipient,
            lamports,
        } => process_transfer_sol(
            program_id,
            accounts,
            &wire,
            falcon_sig,
            expected_recipient,
            lamports,
        ),
        Action::TransferSpl {
            destination: expected_destination,
            amount,
        } => process_transfer_spl(
            program_id,
            accounts,
            &wire,
            falcon_sig,
            expected_destination,
            amount,
        ),
        _ => Err(DualKeyError::UnsupportedAction),
    }
}

fn process_transfer_sol(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    wire: &ExecuteIntentWire,
    falcon_sig: &[u8],
    expected_recipient: [u8; 32],
    lamports: u64,
) -> Result<(), DualKeyError> {
    let [hybrid_account, recipient, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    if !hybrid_account.is_writable || !recipient.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    if recipient.key.to_bytes() != expected_recipient {
        return Err(DualKeyError::InvalidAccountData);
    }
    if recipient.key == hybrid_account.key {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        wire,
        falcon_sig,
    )?;

    bump_nonce(hybrid_account, auth.next_nonce)?;
    transfer_sol(hybrid_account, recipient, lamports)?;

    msg!(
        "DualKey: TransferSol {} lamports OK ({}); nonce {} -> {}",
        lamports,
        auth.policy.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

fn process_transfer_spl(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    wire: &ExecuteIntentWire,
    falcon_sig: &[u8],
    expected_destination: [u8; 32],
    amount: u64,
) -> Result<(), DualKeyError> {
    let [hybrid_account, creator, source, mint, destination, token_program, instructions_sysvar] =
        accounts
    else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    if !hybrid_account.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        wire,
        falcon_sig,
    )?;

    bump_nonce(hybrid_account, auth.next_nonce)?;
    spl_token::transfer_spl(
        program_id,
        hybrid_account,
        creator,
        source,
        mint,
        destination,
        token_program,
        amount,
        &expected_destination,
    )?;

    msg!(
        "DualKey: TransferSpl {} tokens OK ({}); nonce {} -> {}",
        amount,
        auth.policy.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

fn bump_nonce(hybrid_account: &AccountInfo, next_nonce: u64) -> Result<(), DualKeyError> {
    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    account.set_nonce(next_nonce);
    Ok(())
}

/// Debit `amount` from the program-owned HybridAccount and credit `recipient`.
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
