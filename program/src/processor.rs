//! Instruction processor.
//!
//! Milestone 2: verification harness (240–242).
//! Milestone 3: `Initialize` (0).
//! Milestone 4: reconstruction harness (243).
//! Milestone 5–7: `Execute` authorization, replay/expiry, and `TransferSol` (1).
//! Rotation / policy-change instructions still return
//! [`DualKeyError::Unimplemented`].

use dualkey_core::{DualKeyError, CANONICAL_PREIMAGE_LEN, DIGEST_LEN};
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::auth::falcon::{
    verify_falcon_prepared, verify_falcon_raw, FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN,
    PREPARED_FALCON_PUBKEY_LEN,
};
use crate::hash::digest_canonical_preimage;
use crate::instruction::DualKeyInstruction;

/// Dispatch DualKey instructions.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), DualKeyError> {
    let (&discriminator, payload) = instruction_data
        .split_first()
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let Some(ix) = DualKeyInstruction::from_u8(discriminator) else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    match ix {
        DualKeyInstruction::VerifyFalconPrepared => {
            process_verify_falcon_prepared(accounts, payload)
        }
        DualKeyInstruction::VerifyFalconRaw => process_verify_falcon_raw(payload),
        DualKeyInstruction::VerifyCanonicalDigest => process_verify_canonical_digest(payload),

        DualKeyInstruction::ReconstructCanonicalDigest => {
            crate::reconstruct::process_reconstruct_canonical_digest(program_id, accounts, payload)
        }

        DualKeyInstruction::Initialize => crate::initialize::process(program_id, accounts, payload),

        DualKeyInstruction::Execute => crate::execute::process(program_id, accounts, payload),

        DualKeyInstruction::RotateEd25519Key
        | DualKeyInstruction::RotateFalconKey
        | DualKeyInstruction::ChangePolicy => {
            msg!("DualKey: instruction {} not yet implemented", ix.as_u8());
            // Explicit rejection — never a silent success.
            Err(DualKeyError::Unimplemented)
        }
    }
}

/// `[240] ‖ signature(666) ‖ message(..)`, prepared pubkey from `accounts[0]`.
fn process_verify_falcon_prepared(
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    let account = accounts
        .first()
        .ok_or(DualKeyError::MalformedInstructionData)?;

    let (signature, message) = payload
        .split_at_checked(FALCON_SIGNATURE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;

    let data = account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let prepared = data
        .get(..PREPARED_FALCON_PUBKEY_LEN)
        .ok_or(DualKeyError::InvalidAccountData)?;

    verify_falcon_prepared(prepared, message, signature)?;
    msg!("Falcon-512 prepared: VALID");
    Ok(())
}

/// `[241] ‖ signature(666) ‖ pubkey(897) ‖ message(..)`
fn process_verify_falcon_raw(payload: &[u8]) -> Result<(), DualKeyError> {
    let (signature, rest) = payload
        .split_at_checked(FALCON_SIGNATURE_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;
    let (pubkey, message) = rest
        .split_at_checked(FALCON_WIRE_PUBKEY_LEN)
        .ok_or(DualKeyError::MalformedInstructionData)?;

    verify_falcon_raw(pubkey, message, signature)?;
    msg!("Falcon-512 raw: VALID");
    Ok(())
}

/// `[242] ‖ preimage(172) ‖ expected_digest(32)`
fn process_verify_canonical_digest(payload: &[u8]) -> Result<(), DualKeyError> {
    if payload.len() != CANONICAL_PREIMAGE_LEN + DIGEST_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let (preimage, expected) = payload.split_at(CANONICAL_PREIMAGE_LEN);

    let digest = digest_canonical_preimage(preimage)?;
    if digest.as_slice() != expected {
        return Err(DualKeyError::DigestMismatch);
    }
    msg!("Canonical digest: MATCH");
    Ok(())
}
