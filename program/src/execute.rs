//! `Execute` — authorize an intent under the account's policy (Milestone 5).
//!
//! Verifies signatures. Does **not** transfer lamports (Milestone 7) and does
//! **not** consume the nonce or check expiry against the clock (Milestone 6).
//! A successful `Execute` in this milestone is an authorization oracle: the
//! HybridAccount is unchanged.
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
//! | 0 | `hybrid_account` | readonly — vault state (keys, nonce, policy) |
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

    let (wire_bytes, falcon_sig) = payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    // Reconstruct + digest before any crypto so both schemes bind the same
    // bytes. Also validates program ownership and account version.
    let (digest, _ctx) = reconstruct_and_digest(program_id, hybrid_account, &wire)?;

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    // reconstruct_and_digest already checked version; re-read fields for auth.
    let _ = HybridAccount::version_from_slice(&data)?;
    let policy = HybridAccount::policy_from_slice(&data)?;
    let owner_ed25519 = HybridAccount::owner_ed25519_from_slice(&data)?;
    let prepared = *HybridAccount::prepared_falcon_public_key_from_slice(&data)?;
    drop(data);

    // Verify only what the policy requires. HybridAnd always verifies both and
    // never returns Ok if either half fails.
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

    // Milestone 5 stops here: authorization succeeded. No nonce bump, no
    // transfer. Those are Milestones 6 and 7.
    msg!("DualKey: authorization VALID ({})", policy.name());
    Ok(())
}
