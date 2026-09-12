//! `RecoverAccount` — recovery flag and Falcon-only Ed25519 recovery rotate.
//!
//! Opt-in escape hatch for a lost Ed25519 key:
//!
//! 1. Owner enables recovery under the **current** policy (privileged).
//! 2. Later, Falcon alone can authorize `RotateEd25519` to install a new
//!    classical owner — without needing the lost Ed25519 key.
//!
//! Enabling recovery is a deliberate HybridAnd/policy tradeoff: once set,
//! compromise of Falcon alone can rotate the Ed25519 owner.
//!
//! ## Instruction data (716 bytes)
//!
//! Same shape as `Execute` / `ChangePolicy`:
//! ```text
//! [5] ‖ wire(49) ‖ falcon_sig(666)
//! ```
//!
//! Action body: `op[1] ‖ pad[7] ‖ new_ed25519[32]`.
//!
//! ## Accounts
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `hybrid_account` | writable |
//! | 1 | instructions sysvar | readonly |

use dualkey_core::{
    Action, DualKeyError, ExecuteIntentWire, HybridAccount, RecoveryOp, EXECUTE_INTENT_WIRE_LEN,
    FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::authorize::{self, Authorization};

/// Payload after discriminator (same as Execute).
pub const RECOVER_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full `RecoverAccount` instruction length.
pub const RECOVER_DATA_LEN: usize = 1 + RECOVER_PAYLOAD_LEN;

const _: () = assert!(RECOVER_DATA_LEN == 716);

/// Process recovery enable/disable or Falcon-only Ed25519 rotation.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != RECOVER_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let [hybrid_account, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    let Action::RecoverAccount { op, new_ed25519 } = wire.action else {
        return Err(DualKeyError::UnsupportedAction);
    };

    match op {
        RecoveryOp::Enable | RecoveryOp::Disable => {
            if new_ed25519 != [0u8; 32] {
                return Err(DualKeyError::InvalidAccountData);
            }
        }
        RecoveryOp::RotateEd25519 => {
            let data = hybrid_account
                .try_borrow_data()
                .map_err(|_| DualKeyError::InvalidAccountData)?;
            let current = HybridAccount::owner_ed25519_from_slice(&data)?;
            drop(data);
            if new_ed25519 == current || new_ed25519 == [0u8; 32] {
                return Err(DualKeyError::InvalidAccountData);
            }
        }
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_sig,
    )?;

    apply_recovery(hybrid_account, op, &new_ed25519, &auth)?;
    msg!(
        "DualKey: RecoverAccount {} OK ({}); nonce {} -> {}",
        op_name(op),
        auth.policy.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

fn op_name(op: RecoveryOp) -> &'static str {
    match op {
        RecoveryOp::Enable => "enable",
        RecoveryOp::Disable => "disable",
        RecoveryOp::RotateEd25519 => "rotate-ed25519",
    }
}

fn apply_recovery(
    hybrid_account: &AccountInfo,
    op: RecoveryOp,
    new_ed25519: &[u8; 32],
    auth: &Authorization,
) -> Result<(), DualKeyError> {
    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    account.set_nonce(auth.next_nonce);
    match op {
        RecoveryOp::Enable => {
            if account.recovery_enabled() {
                return Err(DualKeyError::InvalidAccountData);
            }
            account.set_recovery_enabled(true);
        }
        RecoveryOp::Disable => {
            if !account.recovery_enabled() {
                return Err(DualKeyError::InvalidAccountData);
            }
            account.set_recovery_enabled(false);
        }
        RecoveryOp::RotateEd25519 => {
            account.set_owner_ed25519(new_ed25519);
        }
    }
    Ok(())
}
