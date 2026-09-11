//! Map [`dualkey_core::DualKeyError`] onto `ProgramError`.

use dualkey_core::DualKeyError;
use solana_program_error::ProgramError;

/// Convert a DualKey error into a Solana program error.
pub fn to_program_error(err: DualKeyError) -> ProgramError {
    ProgramError::Custom(err.code())
}
