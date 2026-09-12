//! Ed25519 verification via the Solana Ed25519 precompile + instructions sysvar.
//!
//! Procedure (SOL-035 / architecture):
//! 1. Pin the instructions sysvar by key.
//! 2. Load the immediately preceding instruction (`get_instruction_relative(-1)`).
//! 3. Assert its program id is `Ed25519SigVerify111111111111111111111111111`.
//! 4. Assert exactly one signature; bounds-check offsets.
//! 5. Assert pubkey == account owner AND message == reconstructed digest.
//!
//! A bare "did an Ed25519 ix run somewhere in the tx?" check is insufficient
//! and exploitable. Binding to the previous instruction plus pubkey/message
//! equality is what makes the check meaningful.
//!
//! The precompile itself performs the cryptographic verify. This module only
//! introspects the instruction the runtime already accepted.

use dualkey_core::{DualKeyError, DIGEST_LEN};
use solana_account_info::AccountInfo;
use solana_instructions_sysvar::{self as instructions_sysvar, get_instruction_relative};
use solana_pubkey::Pubkey;

/// Serialized Ed25519 public key size in the precompile instruction.
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Serialized Ed25519 signature size in the precompile instruction.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Size of one `Ed25519SignatureOffsets` record.
pub const ED25519_OFFSETS_LEN: usize = 14;
/// Byte offset where the first offsets record begins (`num_signatures` + pad).
pub const ED25519_OFFSETS_START: usize = 2;
/// First byte after the header + one offsets record.
pub const ED25519_DATA_START: usize = ED25519_OFFSETS_START + ED25519_OFFSETS_LEN;

/// Single-signature Ed25519 precompile instruction size for a 32-byte message.
///
/// `2 + 14 + 32 + 64 + 32 = 144`.
pub const ED25519_SINGLE_DIGEST_IX_LEN: usize = 144;

const _: () = assert!(
    ED25519_SINGLE_DIGEST_IX_LEN
        == ED25519_DATA_START + ED25519_PUBKEY_LEN + ED25519_SIGNATURE_LEN + DIGEST_LEN
);

/// Offsets layout inside one signature record (all `u16` LE).
mod off {
    pub const SIGNATURE_OFFSET: usize = 0;
    pub const SIGNATURE_IX_INDEX: usize = 2;
    pub const PUBLIC_KEY_OFFSET: usize = 4;
    pub const PUBLIC_KEY_IX_INDEX: usize = 6;
    pub const MESSAGE_DATA_OFFSET: usize = 8;
    pub const MESSAGE_DATA_SIZE: usize = 10;
    pub const MESSAGE_IX_INDEX: usize = 12;
}

fn read_u16(data: &[u8], at: usize) -> Result<u16, DualKeyError> {
    let bytes = data
        .get(at..at + 2)
        .ok_or(DualKeyError::MalformedEd25519Precompile)?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| DualKeyError::MalformedEd25519Precompile)?,
    ))
}

fn slice_at(data: &[u8], offset: u16, len: usize) -> Result<&[u8], DualKeyError> {
    let start = offset as usize;
    data.get(start..start + len)
        .ok_or(DualKeyError::MalformedEd25519Precompile)
}

/// Verify that the Ed25519 precompile immediately before this instruction
/// authorized `expected_digest` under `expected_pubkey`.
///
/// The cryptographic check is the precompile's job (already enforced by the
/// runtime before this instruction runs). This function binds that check to
/// DualKey's owner key and reconstructed digest.
pub fn verify_ed25519_precompile(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &[u8; 32],
    expected_digest: &[u8; DIGEST_LEN],
) -> Result<(), DualKeyError> {
    if !instructions_sysvar::check_id(instructions_sysvar.key) {
        return Err(DualKeyError::InvalidProgramAccount);
    }

    // Bind to the previous instruction only. Scanning the whole transaction for
    // "any Ed25519 success" would accept unrelated signatures (SOL-035).
    let ix = get_instruction_relative(-1, instructions_sysvar).map_err(|_| {
        // Missing predecessor is a malformed authorization attempt, not a
        // sysvar plumbing error the caller can usefully distinguish.
        DualKeyError::MalformedEd25519Precompile
    })?;

    if ix.program_id != ed25519_program_id() {
        return Err(DualKeyError::MalformedEd25519Precompile);
    }

    let data = ix.data.as_slice();
    if data.len() < ED25519_DATA_START {
        return Err(DualKeyError::MalformedEd25519Precompile);
    }

    // `new_ed25519_instruction_with_signature` writes `num_signatures` as a u8
    // with a padding byte; reject anything other than exactly one signature.
    let num_signatures = data[0];
    if num_signatures != 1 || data[1] != 0 {
        return Err(DualKeyError::MalformedEd25519Precompile);
    }

    let offsets = &data[ED25519_OFFSETS_START..ED25519_DATA_START];
    let signature_offset = read_u16(offsets, off::SIGNATURE_OFFSET)?;
    let signature_ix_index = read_u16(offsets, off::SIGNATURE_IX_INDEX)?;
    let public_key_offset = read_u16(offsets, off::PUBLIC_KEY_OFFSET)?;
    let public_key_ix_index = read_u16(offsets, off::PUBLIC_KEY_IX_INDEX)?;
    let message_data_offset = read_u16(offsets, off::MESSAGE_DATA_OFFSET)?;
    let message_data_size = read_u16(offsets, off::MESSAGE_DATA_SIZE)?;
    let message_ix_index = read_u16(offsets, off::MESSAGE_IX_INDEX)?;

    // `u16::MAX` means "this instruction". DualKey requires pubkey, signature
    // and message to live in the precompile instruction itself — not pointed
    // into some other instruction's data.
    if signature_ix_index != u16::MAX
        || public_key_ix_index != u16::MAX
        || message_ix_index != u16::MAX
    {
        return Err(DualKeyError::MalformedEd25519Precompile);
    }

    if message_data_size as usize != DIGEST_LEN {
        return Err(DualKeyError::MalformedEd25519Precompile);
    }

    let pubkey = slice_at(data, public_key_offset, ED25519_PUBKEY_LEN)?;
    let _signature = slice_at(data, signature_offset, ED25519_SIGNATURE_LEN)?;
    let message = slice_at(data, message_data_offset, DIGEST_LEN)?;

    if pubkey != expected_pubkey.as_slice() {
        return Err(DualKeyError::InvalidEd25519);
    }
    if message != expected_digest.as_slice() {
        return Err(DualKeyError::InvalidEd25519);
    }

    Ok(())
}

/// The Ed25519 signature-verify native program id.
pub fn ed25519_program_id() -> Pubkey {
    Pubkey::from(solana_sdk_ids::ed25519_program::ID.to_bytes())
}
