//! Key rotation — `RotateEd25519Key` and `RotateFalconKey`.
//!
//! Both instructions are authorized under the account's **current** policy
//! (HybridAnd never falls back). Nonce is consumed on success.
//!
//! ## `RotateEd25519Key` (discriminator 2)
//!
//! Same 715-byte payload shape as `Execute` (wire intent + Falcon auth sig).
//! The action body carries the new 32-byte Ed25519 pubkey. No separate
//! proof-of-possession: anyone who can authorize under the current policy can
//! already move value.
//!
//! Accounts: HybridAccount (writable), RecoveryConfig PDA (writable; may be
//! empty), instructions sysvar (readonly). A successful rotate clears any
//! social-recovery pending so finalize cannot overwrite the new owner.
//!
//! ## `RotateFalconKey` (discriminator 3)
//!
//! ```text
//! [3] ‖ wire(49) ‖ falcon_auth(666) ‖ new_wire_pk(897) ‖ falcon_pop(666)
//! ```
//!
//! Action body carries `SHA256(new_wire_pk)`. After current-policy auth, the
//! program verifies `falcon_pop` against the **new** wire key over the same
//! digest (proof-of-possession), then prepares and stores the new key.
//!
//! HybridAnd + two Falcon signatures exceeds the legacy 1232-byte packet; this
//! path is intended for v0 transactions with an Address Lookup Table. Mollusk
//! tests exercise correctness without the packet limit.

use dualkey_core::{
    Action, DualKeyError, ExecuteIntentWire, HybridAccount, EXECUTE_INTENT_WIRE_LEN,
    FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN,
};
use solana_account_info::AccountInfo;
use solana_falcon512::Falcon512Pubkey;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::auth::falcon::verify_falcon_raw;
use crate::authorize::{self, Authorization};
use crate::hash::sha256;
use crate::social_recovery;

/// Payload after discriminator for `RotateEd25519Key` (same as Execute).
pub const ROTATE_ED25519_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

/// Full `RotateEd25519Key` instruction length.
pub const ROTATE_ED25519_DATA_LEN: usize = 1 + ROTATE_ED25519_PAYLOAD_LEN;

const _: () = assert!(ROTATE_ED25519_DATA_LEN == 716);

/// Payload after discriminator for `RotateFalconKey`.
pub const ROTATE_FALCON_PAYLOAD_LEN: usize =
    EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN + FALCON_WIRE_PUBKEY_LEN + FALCON_SIGNATURE_LEN;

/// Full `RotateFalconKey` instruction length.
pub const ROTATE_FALCON_DATA_LEN: usize = 1 + ROTATE_FALCON_PAYLOAD_LEN;

const _: () = assert!(ROTATE_FALCON_DATA_LEN == 2279);

/// Rotate the Ed25519 owner key under the current authorization policy.
pub fn process_rotate_ed25519(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != ROTATE_ED25519_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let [hybrid_account, recovery_config, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;

    let Action::RotateEd25519Key { new_pubkey } = wire.action else {
        return Err(DualKeyError::UnsupportedAction);
    };

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let current = HybridAccount::owner_ed25519_from_slice(&data)?;
    drop(data);
    if new_pubkey == current {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_sig,
    )?;

    apply_ed25519_rotation(hybrid_account, &new_pubkey, &auth)?;
    social_recovery::clear_pending_after_ed25519_owner_change(
        program_id,
        hybrid_account.key,
        recovery_config,
    )?;
    msg!(
        "DualKey: RotateEd25519 OK ({}); nonce {} -> {}",
        auth.policy.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

/// Rotate the Falcon public key under the current policy, with PoP on the new key.
pub fn process_rotate_falcon(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != ROTATE_FALCON_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let [hybrid_account, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let (wire_bytes, rest) = payload
        .split_at_checked(EXECUTE_INTENT_WIRE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let (falcon_auth, rest) = rest
        .split_at_checked(FALCON_SIGNATURE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let (new_wire_pk, falcon_pop) = rest
        .split_at_checked(FALCON_WIRE_PUBKEY_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    if falcon_pop.len() != FALCON_SIGNATURE_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let wire = ExecuteIntentWire::decode(wire_bytes)?;
    let Action::RotateFalconKey { new_pubkey_hash } = wire.action else {
        return Err(DualKeyError::UnsupportedAction);
    };

    let computed_hash = sha256(new_wire_pk);
    if computed_hash != new_pubkey_hash {
        return Err(DualKeyError::DigestMismatch);
    }

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let current_hash = HybridAccount::falcon_public_key_hash_from_slice(&data)?;
    drop(data);
    if new_pubkey_hash == current_hash {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_auth,
    )?;

    // Proof-of-possession: the *new* Falcon key must sign the same digest.
    verify_falcon_raw(new_wire_pk, &auth.digest, falcon_pop)?;

    apply_falcon_rotation(hybrid_account, new_wire_pk, &new_pubkey_hash, &auth)?;
    msg!(
        "DualKey: RotateFalcon OK ({}); nonce {} -> {}",
        auth.policy.name(),
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

fn apply_ed25519_rotation(
    hybrid_account: &AccountInfo,
    new_pubkey: &[u8; 32],
    auth: &Authorization,
) -> Result<(), DualKeyError> {
    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    account.set_nonce(auth.next_nonce);
    account.set_owner_ed25519(new_pubkey);
    Ok(())
}

/// Prepare and store the new Falcon key. `#[inline(never)]` keeps the 1024-byte
/// prepared value out of the caller's stack frame (SBF 4 KB limit).
#[inline(never)]
fn apply_falcon_rotation(
    hybrid_account: &AccountInfo,
    new_wire_pk: &[u8],
    new_pubkey_hash: &[u8; 32],
    auth: &Authorization,
) -> Result<(), DualKeyError> {
    let prepared = Falcon512Pubkey::try_from_slice(new_wire_pk)
        .map_err(|_| DualKeyError::MalformedFalcon)?
        .try_prepare_pubkey()
        .map_err(|_| DualKeyError::MalformedFalcon)?;

    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    account.set_nonce(auth.next_nonce);
    account.set_falcon_public_key_hash(new_pubkey_hash);
    account
        .prepared_falcon_public_key_mut()
        .copy_from_slice(prepared.as_bytes());
    Ok(())
}
