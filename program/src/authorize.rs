//! Shared authorization for `Execute`, key-rotation, and `ChangePolicy`.
//!
//! Reconstructs the intent, checks expiry and nonce, verifies signatures under
//! the effective [`SignatureRequirement`], and returns the next nonce. Callers
//! bump the nonce and then perform their action; Solana atomicity reverts both
//! on failure.
//!
//! For `ChangePolicy`, the requirement is the **meet** (stricter) of the
//! current and target policies' requirements for that action.

use dualkey_core::{
    Action, AuthorizationPolicy, DualKeyError, ExecuteIntentWire, HybridAccount, RecoveryOp,
    SignatureRequirement, DIGEST_LEN, EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_get_sysvar::GetSysvar;
use solana_pubkey::Pubkey;

use crate::auth::ed25519::verify_ed25519_precompile;
use crate::auth::falcon::verify_falcon_prepared;
use crate::auth::policy::{evaluate_requirement, SignatureValidity};
use crate::reconstruct::reconstruct_and_digest;

/// Result of a successful authorization under the effective signature requirement.
pub struct Authorization {
    pub digest: [u8; DIGEST_LEN],
    pub policy: AuthorizationPolicy,
    pub account_nonce: u64,
    pub next_nonce: u64,
}

/// Authorize `wire` + `falcon_sig` against `hybrid_account`.
///
/// Does **not** mutate the account. The caller must bump the nonce and apply
/// the action after this returns.
pub fn authorize(
    program_id: &Pubkey,
    hybrid_account: &AccountInfo,
    instructions_sysvar: &AccountInfo,
    wire: &ExecuteIntentWire,
    falcon_sig: &[u8],
) -> Result<Authorization, DualKeyError> {
    if falcon_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let clock = Clock::get().map_err(|_| DualKeyError::InvalidAccountData)?;
    if clock.slot > wire.expiry_slot {
        return Err(DualKeyError::IntentExpired);
    }

    let (digest, ctx) = reconstruct_and_digest(program_id, hybrid_account, wire)?;

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let policy = HybridAccount::policy_from_slice(&data)?;
    let owner_ed25519 = HybridAccount::owner_ed25519_from_slice(&data)?;
    let prepared = *HybridAccount::prepared_falcon_public_key_from_slice(&data)?;
    let account_nonce = HybridAccount::nonce_from_slice(&data)?;
    let threshold = HybridAccount::falcon_required_above_from_slice(&data)?;
    let recovery_enabled = HybridAccount::recovery_enabled_from_slice(&data)?;
    drop(data);

    if ctx.nonce != account_nonce {
        return Err(DualKeyError::InvalidNonce);
    }

    let next_nonce = account_nonce
        .checked_add(1)
        .ok_or(DualKeyError::MathOverflow)?;

    let req = effective_requirement(policy, threshold, recovery_enabled, &wire.action)?;
    let sigs = collect_signatures(
        req,
        instructions_sysvar,
        &owner_ed25519,
        prepared.as_slice(),
        &digest,
        falcon_sig,
    )?;
    evaluate_requirement(req, sigs)?;

    Ok(Authorization {
        digest,
        policy,
        account_nonce,
        next_nonce,
    })
}

/// Compute the signature requirement for this authorization attempt.
///
/// Ordinary actions use the account's current policy. `ChangePolicy` uses the
/// stricter of current and target. `RecoverAccount::RotateEd25519` requires the
/// recovery flag and authorizes with **Falcon alone** (opt-in escape hatch).
fn effective_requirement(
    current: AuthorizationPolicy,
    current_threshold: Option<u64>,
    recovery_enabled: bool,
    action: &Action,
) -> Result<SignatureRequirement, DualKeyError> {
    if let Action::RecoverAccount { op, .. } = *action {
        if op == RecoveryOp::RotateEd25519 {
            if !recovery_enabled {
                return Err(DualKeyError::InvalidAccountData);
            }
            // Opted-in recovery: Falcon alone can replace a lost Ed25519 key.
            return Ok(SignatureRequirement::Falcon);
        }
    }

    let current_req = current.signature_requirement(action, current_threshold);

    let Action::ChangePolicy {
        new_policy,
        threshold: new_threshold,
    } = *action
    else {
        return Ok(current_req);
    };

    let target =
        AuthorizationPolicy::from_u8(new_policy).ok_or(DualKeyError::InvalidAccountData)?;
    if !target.is_implemented() {
        return Err(DualKeyError::PolicyNotImplemented);
    }

    let target_threshold = if target == AuthorizationPolicy::FalconAboveThreshold {
        Some(new_threshold)
    } else {
        None
    };
    let target_req = target.signature_requirement(action, target_threshold);
    Ok(current_req.meet(target_req))
}

/// Verify the schemes demanded by `req` and return their validity bits.
fn collect_signatures(
    req: SignatureRequirement,
    instructions_sysvar: &AccountInfo,
    owner_ed25519: &[u8; 32],
    prepared: &[u8],
    digest: &[u8; DIGEST_LEN],
    falcon_sig: &[u8],
) -> Result<SignatureValidity, DualKeyError> {
    let mut ed25519_valid = false;
    let mut falcon_valid = false;

    match req {
        SignatureRequirement::Ed25519 | SignatureRequirement::Both => {
            verify_ed25519_precompile(instructions_sysvar, owner_ed25519, digest)?;
            ed25519_valid = true;
        }
        SignatureRequirement::Either => {
            ed25519_valid =
                verify_ed25519_precompile(instructions_sysvar, owner_ed25519, digest).is_ok();
        }
        SignatureRequirement::Falcon => {}
    }

    match req {
        SignatureRequirement::Falcon | SignatureRequirement::Both => {
            verify_falcon_prepared(prepared, digest, falcon_sig)?;
            falcon_valid = true;
        }
        SignatureRequirement::Either => {
            falcon_valid = verify_falcon_prepared(prepared, digest, falcon_sig).is_ok();
        }
        SignatureRequirement::Ed25519 => {}
    }

    Ok(SignatureValidity {
        ed25519_valid,
        falcon_valid,
    })
}

/// Split a standard 715-byte post-discriminator payload into wire + Falcon sig.
pub fn split_wire_and_falcon(payload: &[u8]) -> Result<(&[u8], &[u8]), DualKeyError> {
    payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)
}
