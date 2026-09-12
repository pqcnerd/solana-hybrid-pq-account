//! `Execute` — authorize an intent under the account's policy, then act.
//!
//! Milestone 5–6: Ed25519 / Falcon / HybridAnd verification, expiry, nonce.
//! Milestone 7: `TransferSol`.
//!
//! Key rotation uses dedicated instructions (`RotateEd25519Key` /
//! `RotateFalconKey`); this path only accepts [`Action::TransferSol`].
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

/// Payload length after the discriminator.
pub const EXECUTE_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full instruction data length including the discriminator.
pub const EXECUTE_DATA_LEN: usize = 1 + EXECUTE_PAYLOAD_LEN;

const _: () = assert!(EXECUTE_DATA_LEN == 716);

/// Authorize `payload`, consume the nonce, then execute `TransferSol`.
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

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    let Action::TransferSol {
        recipient: expected_recipient,
        lamports,
    } = wire.action
    else {
        return Err(DualKeyError::UnsupportedAction);
    };
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
        &wire,
        falcon_sig,
    )?;

    {
        let mut data = hybrid_account
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut account = HybridAccount::try_from_bytes(&mut data)?;
        account.set_nonce(auth.next_nonce);
    }

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
