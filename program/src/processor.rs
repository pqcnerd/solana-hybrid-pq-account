//! Instruction processor.
//!
//! Milestone 0 returns [`DualKeyError::Unimplemented`] for every instruction.
//! No placeholder crypto and no permissive verification stubs.

use dualkey_core::DualKeyError;
use solana_account_info::AccountInfo;
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::instruction::DualKeyInstruction;

/// Dispatch DualKey instructions.
pub fn process(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), DualKeyError> {
    let discriminator = instruction_data.first().copied().ok_or(DualKeyError::Unimplemented)?;
    let Some(ix) = DualKeyInstruction::from_u8(discriminator) else {
        return Err(DualKeyError::Unimplemented);
    };

    msg!("DualKey: {:?} not yet implemented (Milestone 0)", ix as u8);
    // Explicit rejection — never a silent success.
    Err(DualKeyError::Unimplemented)
}
