//! DualKey Solana program.
//!
//! Milestone 0: scaffolding only. All instructions return
//! [`dualkey_core::DualKeyError::Unimplemented`]. Cryptographic verification
//! is wired as dependencies and module stubs but is not invoked yet.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_pubkey::Pubkey;

pub mod auth;
pub mod error;
pub mod instruction;
pub mod processor;

pub use error::to_program_error;

entrypoint!(process_instruction);

/// Program entrypoint.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), solana_program_error::ProgramError> {
    processor::process(program_id, accounts, instruction_data).map_err(to_program_error)
}
