//! DualKey Solana program.
//!
//! Milestone 2 brought real Falcon-512 verification and the `sol_sha256`
//! canonical digest under SBF, via the verification-harness instructions
//! (discriminators 240–242).
//!
//! Milestone 3 adds `Initialize`, which creates the HybridAccount PDA holding
//! the Ed25519 owner key, the prepared Falcon public key, a nonce and a policy.
//! It still moves no value: the only lamport flow is rent funding for the new
//! account. `Execute` and the rotation instructions remain
//! [`dualkey_core::DualKeyError::Unimplemented`], so a HybridAccount cannot yet
//! authorize anything.
//!
//! Falcon key generation and Falcon signing never happen here; this crate
//! contains verification only, and `pqcrypto-falcon` is absent from its
//! dependency graph.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_pubkey::Pubkey;

pub mod auth;
pub mod error;
pub mod hash;
pub mod initialize;
pub mod instruction;
pub mod pda;
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
