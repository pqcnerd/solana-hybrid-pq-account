//! DualKey Solana program.
//!
//! Milestone 2 brought real Falcon-512 verification and the `sol_sha256`
//! canonical digest under SBF, via the verification-harness instructions
//! (discriminators 240–242).
//!
//! Milestone 3 adds `Initialize`, which creates the HybridAccount PDA holding
//! the Ed25519 owner key, the prepared Falcon public key, a nonce and a policy.
//!
//! Milestone 4 adds on-chain intent reconstruction (discriminator 243).
//!
//! Milestone 5 implements `Execute` authorization: reconstruct the intent,
//! verify Ed25519 (precompile introspection) and/or Falcon under the account
//! policy (HybridAnd requires both; never falls back).
//!
//! Milestone 6 adds expiry (Clock sysvar) and nonce consumption so a signed
//! intent cannot be replayed. Value movement is still Milestone 7.
//!
//! Falcon key generation and Falcon signing never happen here; this crate
//! contains verification only, and `pqcrypto-falcon` is absent from its
//! dependency graph.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_pubkey::Pubkey;

pub mod auth;
pub mod chain_domain;
pub mod error;
pub mod execute;
pub mod hash;
pub mod initialize;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod reconstruct;

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
