//! `ChangePolicy` — update the HybridAccount authorization policy.
//!
//! Authorized under the **stricter** of the current and target policies'
//! signature requirements (see [`dualkey_core::SignatureRequirement::meet`]),
//! so a stolen Ed25519 key alone cannot disable Falcon on a HybridAnd account.
//!
//! ## Instruction data (716 bytes)
//!
//! Same shape as `Execute` / `RotateEd25519Key`:
//! ```text
//! [4] ‖ wire(49) ‖ falcon_sig(666)
//! ```
//!
//! Action body: `new_policy[1] ‖ pad[7] ‖ threshold_u64_le[8] ‖ reserved[24]`.
//!
//! ## Accounts
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `hybrid_account` | writable |
//! | 1 | instructions sysvar | readonly |

use dualkey_core::{
    Action, AuthorizationPolicy, DualKeyError, ExecuteIntentWire, HybridAccount,
    EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::authorize::{self, Authorization};

/// Payload after discriminator (same as Execute).
pub const CHANGE_POLICY_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full `ChangePolicy` instruction length.
pub const CHANGE_POLICY_DATA_LEN: usize = 1 + CHANGE_POLICY_PAYLOAD_LEN;

const _: () = assert!(CHANGE_POLICY_DATA_LEN == 716);

/// Apply a signed policy change under the stricter-of authorization rule.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != CHANGE_POLICY_PAYLOAD_LEN {
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

    let Action::ChangePolicy {
        new_policy,
        threshold,
    } = wire.action
    else {
        return Err(DualKeyError::UnsupportedAction);
    };

    let target =
        AuthorizationPolicy::from_u8(new_policy).ok_or(DualKeyError::InvalidAccountData)?;
    if !target.is_implemented() {
        return Err(DualKeyError::PolicyNotImplemented);
    }

    let resulting_threshold = if target == AuthorizationPolicy::FalconAboveThreshold {
        Some(threshold)
    } else {
        None
    };

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let current = HybridAccount::policy_from_slice(&data)?;
    let current_threshold = HybridAccount::falcon_required_above_from_slice(&data)?;
    drop(data);

    if current == target && current_threshold == resulting_threshold {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_sig,
    )?;

    apply_policy_change(hybrid_account, target, resulting_threshold, &auth)?;
    msg!(
        "DualKey: ChangePolicy OK ({} -> {}); nonce {} -> {}",
        auth.policy.name(),
        target.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

fn apply_policy_change(
    hybrid_account: &AccountInfo,
    target: AuthorizationPolicy,
    threshold: Option<u64>,
    auth: &Authorization,
) -> Result<(), DualKeyError> {
    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    account.set_nonce(auth.next_nonce);
    account.set_policy(target);
    account.set_falcon_required_above(threshold);
    Ok(())
}
