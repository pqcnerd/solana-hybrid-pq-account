//! Off-chain construction of DualKey on-chain instructions.
//!
//! Address derivation and instruction encoding are mirrored from the program,
//! but the shared pieces are not duplicated: seeds come from
//! [`dualkey_core::pda_seeds`] and lengths from `dualkey_core`, so the client and
//! program cannot drift apart.
//!
//! Nothing here signs or submits a transaction. It produces the instruction the
//! program expects; broadcasting needs an RPC endpoint and is out of scope until
//! the transfer milestone.

use dualkey_core::{pda_seeds, AuthorizationPolicy, ACCOUNT_INDEX_LEN, FALCON_WIRE_PUBKEY_LEN};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::error::{ClientError, Result};

/// `Initialize` discriminator, mirroring `DualKeyInstruction::Initialize`.
pub const INITIALIZE_DISCRIMINATOR: u8 = 0;

/// Total `Initialize` instruction data length.
pub const INITIALIZE_DATA_LEN: usize = 1 + ACCOUNT_INDEX_LEN + 32 + 1 + FALCON_WIRE_PUBKEY_LEN;

const _: () = assert!(INITIALIZE_DATA_LEN == 935);

/// The System program address, which `Initialize` requires as its third account.
pub fn system_program_id() -> Pubkey {
    Pubkey::from(solana_system_interface::program::ID.to_bytes())
}

/// Derive the HybridAccount address and its canonical bump.
///
/// Uses the same seeds as the program: `["dualkey", creator, account_index_le]`.
pub fn derive_hybrid_account(
    program_id: &Pubkey,
    creator: &Pubkey,
    account_index: u32,
) -> Result<(Pubkey, u8)> {
    let creator_bytes = creator.to_bytes();
    let index_le = account_index.to_le_bytes();
    let seeds = pda_seeds(&creator_bytes, &index_le);
    Pubkey::try_find_program_address(&seeds, program_id).ok_or(ClientError::PdaDerivation)
}

/// Encode `Initialize` instruction data.
///
/// Only the 897-byte Falcon **wire** public key is sent. The 1024-byte prepared
/// form is derived on-chain, so the client never has to be trusted to compute
/// the NTT correctly.
pub fn initialize_data(
    account_index: u32,
    owner_ed25519: &[u8; 32],
    policy: AuthorizationPolicy,
    falcon_wire_pubkey: &[u8],
) -> Result<Vec<u8>> {
    if falcon_wire_pubkey.len() != FALCON_WIRE_PUBKEY_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon512.pk".to_string(),
            expected: FALCON_WIRE_PUBKEY_LEN,
            actual: falcon_wire_pubkey.len(),
        });
    }
    if !policy.is_implemented() {
        return Err(ClientError::PolicyNotImplemented {
            policy: policy.as_u8(),
        });
    }

    let mut data = Vec::with_capacity(INITIALIZE_DATA_LEN);
    data.push(INITIALIZE_DISCRIMINATOR);
    data.extend_from_slice(&account_index.to_le_bytes());
    data.extend_from_slice(owner_ed25519);
    data.push(policy.as_u8());
    data.extend_from_slice(falcon_wire_pubkey);
    debug_assert_eq!(data.len(), INITIALIZE_DATA_LEN);
    Ok(data)
}

/// Build the full `Initialize` instruction.
///
/// Accounts, in the order the program requires: creator (signer, writable),
/// the HybridAccount PDA (writable), and the System program.
pub fn initialize_instruction(
    program_id: &Pubkey,
    creator: &Pubkey,
    account_index: u32,
    owner_ed25519: &[u8; 32],
    policy: AuthorizationPolicy,
    falcon_wire_pubkey: &[u8],
) -> Result<(Instruction, Pubkey, u8)> {
    let (hybrid_account, bump) = derive_hybrid_account(program_id, creator, account_index)?;
    let data = initialize_data(account_index, owner_ed25519, policy, falcon_wire_pubkey)?;

    let instruction = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(hybrid_account, false),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data,
    };
    Ok((instruction, hybrid_account, bump))
}
