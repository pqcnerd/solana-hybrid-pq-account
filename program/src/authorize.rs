//! Shared authorization for `Execute` and key-rotation instructions.
//!
//! Reconstructs the intent, checks expiry and nonce, verifies signatures under
//! the account's current policy, and returns the next nonce. Callers bump the
//! nonce and then perform their action; Solana atomicity reverts both on failure.

use dualkey_core::{
    AuthorizationPolicy, DualKeyError, ExecuteIntentWire, HybridAccount, DIGEST_LEN,
    EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_get_sysvar::GetSysvar;
use solana_pubkey::Pubkey;

use crate::auth::ed25519::verify_ed25519_precompile;
use crate::auth::falcon::verify_falcon_prepared;
use crate::auth::policy::{evaluate_policy, SignatureValidity};
use crate::reconstruct::reconstruct_and_digest;

/// Result of a successful authorization under the account's current policy.
pub struct Authorization {
    pub digest: [u8; DIGEST_LEN],
    pub policy: AuthorizationPolicy,
    pub account_nonce: u64,
    pub next_nonce: u64,
}

/// Authorize `wire` + `falcon_sig` against `hybrid_account` under its stored policy.
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
    drop(data);

    if ctx.nonce != account_nonce {
        return Err(DualKeyError::InvalidNonce);
    }

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

    Ok(Authorization {
        digest,
        policy,
        account_nonce,
        next_nonce,
    })
}

/// Split a standard 715-byte post-discriminator payload into wire + Falcon sig.
pub fn split_wire_and_falcon(payload: &[u8]) -> Result<(&[u8], &[u8]), DualKeyError> {
    payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)
}
