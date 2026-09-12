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

use dualkey_core::{
    pda_seeds, AuthorizationIntent, AuthorizationPolicy, ExecuteIntentWire, IntentContext,
    ACCOUNT_INDEX_LEN, CHAIN_DOMAIN_LOCALNET, EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
    FALCON_WIRE_PUBKEY_LEN,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::error::{ClientError, Result};

/// `Initialize` discriminator, mirroring `DualKeyInstruction::Initialize`.
pub const INITIALIZE_DISCRIMINATOR: u8 = 0;

/// `Execute` discriminator, mirroring `DualKeyInstruction::Execute`.
pub const EXECUTE_DISCRIMINATOR: u8 = 1;

/// Milestone 4 reconstruction-harness discriminator.
pub const RECONSTRUCT_DIGEST_DISCRIMINATOR: u8 = 243;

/// Total `Initialize` instruction data length.
pub const INITIALIZE_DATA_LEN: usize = 1 + ACCOUNT_INDEX_LEN + 32 + 1 + FALCON_WIRE_PUBKEY_LEN;

/// Total `Execute` instruction data length (disc + wire intent + Falcon sig).
pub const EXECUTE_DATA_LEN: usize = 1 + EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

const _: () = assert!(INITIALIZE_DATA_LEN == 935);
const _: () = assert!(EXECUTE_DATA_LEN == 716);

/// Default chain domain for unmarked / research client builds.
///
/// Must match the program's default (`localnet`) so reconstruction digests
/// agree unless the program was built with an explicit cluster feature.
pub fn default_chain_domain() -> [u8; 32] {
    CHAIN_DOMAIN_LOCALNET
}

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

/// Build a signing intent whose derived fields match on-chain reconstruction.
///
/// `chain_domain` defaults to [`default_chain_domain`] when the program was
/// built without an explicit cluster feature.
pub fn signing_intent(
    program_id: &Pubkey,
    account: &Pubkey,
    nonce: u64,
    expiry_slot: u64,
    action: dualkey_core::Action,
) -> AuthorizationIntent {
    signing_intent_with_domain(
        default_chain_domain(),
        program_id,
        account,
        nonce,
        expiry_slot,
        action,
    )
}

/// Like [`signing_intent`], but with an explicit chain domain (for cluster-
/// specific program builds).
pub fn signing_intent_with_domain(
    chain_domain: [u8; 32],
    program_id: &Pubkey,
    account: &Pubkey,
    nonce: u64,
    expiry_slot: u64,
    action: dualkey_core::Action,
) -> AuthorizationIntent {
    AuthorizationIntent::new(
        chain_domain,
        program_id.to_bytes(),
        account.to_bytes(),
        nonce,
        expiry_slot,
        action,
    )
}

/// Trusted context the program will use when reconstructing `intent`.
pub fn intent_context_for(intent: &AuthorizationIntent) -> IntentContext {
    IntentContext {
        chain_domain: intent.chain_domain,
        program_id: intent.program_id,
        account: intent.account,
        nonce: intent.nonce,
    }
}

/// Encode the 49-byte Execute intent wire fragment (no discriminator, no sig).
pub fn encode_execute_intent_wire(intent: &AuthorizationIntent) -> [u8; 49] {
    ExecuteIntentWire::from_intent(intent).encode()
}

/// Build the Milestone 4 reconstruction-harness instruction.
///
/// Compares the on-chain reconstructed digest to `expected_digest`. Does not
/// authorize anything.
pub fn reconstruct_digest_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    intent: &AuthorizationIntent,
    expected_digest: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 49 + 32);
    data.push(RECONSTRUCT_DIGEST_DISCRIMINATOR);
    data.extend_from_slice(&encode_execute_intent_wire(intent));
    data.extend_from_slice(expected_digest);
    Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new_readonly(*hybrid_account, false)],
        data,
    }
}

/// Encode `Execute` instruction data: wire intent + Falcon signature.
pub fn execute_data(intent: &AuthorizationIntent, falcon_sig: &[u8]) -> Result<Vec<u8>> {
    if falcon_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon signature".to_string(),
            expected: FALCON_SIGNATURE_LEN,
            actual: falcon_sig.len(),
        });
    }
    let mut data = Vec::with_capacity(EXECUTE_DATA_LEN);
    data.push(EXECUTE_DISCRIMINATOR);
    data.extend_from_slice(&encode_execute_intent_wire(intent));
    data.extend_from_slice(falcon_sig);
    debug_assert_eq!(data.len(), EXECUTE_DATA_LEN);
    Ok(data)
}

/// The instructions sysvar address (`Sysvar1nstructions...`).
pub fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from(solana_sdk_ids::sysvar::instructions::ID.to_bytes())
}

/// Build the `Execute` instruction (authorize + `TransferSol`).
///
/// Accounts: HybridAccount (**writable**), recipient (**writable**, must equal
/// the signed action recipient), instructions sysvar (readonly). The Ed25519
/// precompile must be the **immediately preceding** instruction in the same
/// transaction when the policy requires Ed25519.
///
/// For SPL transfers, use [`execute_transfer_spl_instruction`].
pub fn execute_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    intent: &AuthorizationIntent,
    falcon_sig: &[u8],
) -> Result<Instruction> {
    let recipient = match intent.action {
        dualkey_core::Action::TransferSol { recipient, .. } => Pubkey::new_from_array(recipient),
        _ => {
            return Err(ClientError::IntentFormat {
                path: "execute".into(),
                reason: "Execute builder only accepts TransferSol; use execute_transfer_spl_instruction for SPL"
                    .into(),
            });
        }
    };
    let data = execute_data(intent, falcon_sig)?;
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*hybrid_account, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
        ],
        data,
    })
}

/// Classic SPL Token program id.
pub fn token_program_id() -> Pubkey {
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

/// Build `Execute` for [`dualkey_core::Action::TransferSpl`].
///
/// Accounts: HybridAccount, creator (PDA seed), source token, mint, destination
/// token, token program, instructions sysvar.
pub fn execute_transfer_spl_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    creator: &Pubkey,
    source_token: &Pubkey,
    mint: &Pubkey,
    intent: &AuthorizationIntent,
    falcon_sig: &[u8],
) -> Result<Instruction> {
    let destination = match intent.action {
        dualkey_core::Action::TransferSpl { destination, .. } => {
            Pubkey::new_from_array(destination)
        }
        _ => {
            return Err(ClientError::IntentFormat {
                path: "execute_transfer_spl".into(),
                reason: "intent action must be TransferSpl".into(),
            });
        }
    };
    let data = execute_data(intent, falcon_sig)?;
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*hybrid_account, false),
            AccountMeta::new_readonly(*creator, false),
            AccountMeta::new(*source_token, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(token_program_id(), false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
        ],
        data,
    })
}

/// Discriminator for `RotateEd25519Key`.
pub const ROTATE_ED25519_DISCRIMINATOR: u8 = 2;

/// Discriminator for `RotateFalconKey`.
pub const ROTATE_FALCON_DISCRIMINATOR: u8 = 3;

/// Discriminator for `ChangePolicy`.
pub const CHANGE_POLICY_DISCRIMINATOR: u8 = 4;

/// Full `RotateFalconKey` instruction data length.
pub const ROTATE_FALCON_DATA_LEN: usize = 1
    + EXECUTE_INTENT_WIRE_LEN
    + FALCON_SIGNATURE_LEN
    + FALCON_WIRE_PUBKEY_LEN
    + FALCON_SIGNATURE_LEN;

const _: () = assert!(ROTATE_FALCON_DATA_LEN == 2279);

/// Build `RotateEd25519Key` (discriminator 2). Payload shape matches Execute.
pub fn rotate_ed25519_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    intent: &AuthorizationIntent,
    falcon_sig: &[u8],
) -> Result<Instruction> {
    match intent.action {
        dualkey_core::Action::RotateEd25519Key { .. } => {}
        _ => {
            return Err(ClientError::IntentFormat {
                path: "rotate_ed25519".into(),
                reason: "intent action must be RotateEd25519Key".into(),
            });
        }
    }
    let mut data = Vec::with_capacity(EXECUTE_DATA_LEN);
    data.push(ROTATE_ED25519_DISCRIMINATOR);
    data.extend_from_slice(&encode_execute_intent_wire(intent));
    if falcon_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon signature".to_string(),
            expected: FALCON_SIGNATURE_LEN,
            actual: falcon_sig.len(),
        });
    }
    data.extend_from_slice(falcon_sig);
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*hybrid_account, false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
        ],
        data,
    })
}

/// Build `RotateFalconKey` (discriminator 3) with auth sig, new wire key, and PoP sig.
pub fn rotate_falcon_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    intent: &AuthorizationIntent,
    falcon_auth_sig: &[u8],
    new_wire_pubkey: &[u8],
    falcon_pop_sig: &[u8],
) -> Result<Instruction> {
    match intent.action {
        dualkey_core::Action::RotateFalconKey { .. } => {}
        _ => {
            return Err(ClientError::IntentFormat {
                path: "rotate_falcon".into(),
                reason: "intent action must be RotateFalconKey".into(),
            });
        }
    }
    if falcon_auth_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon auth signature".to_string(),
            expected: FALCON_SIGNATURE_LEN,
            actual: falcon_auth_sig.len(),
        });
    }
    if new_wire_pubkey.len() != FALCON_WIRE_PUBKEY_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon512.pk".to_string(),
            expected: FALCON_WIRE_PUBKEY_LEN,
            actual: new_wire_pubkey.len(),
        });
    }
    if falcon_pop_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon pop signature".to_string(),
            expected: FALCON_SIGNATURE_LEN,
            actual: falcon_pop_sig.len(),
        });
    }
    let mut data = Vec::with_capacity(ROTATE_FALCON_DATA_LEN);
    data.push(ROTATE_FALCON_DISCRIMINATOR);
    data.extend_from_slice(&encode_execute_intent_wire(intent));
    data.extend_from_slice(falcon_auth_sig);
    data.extend_from_slice(new_wire_pubkey);
    data.extend_from_slice(falcon_pop_sig);
    debug_assert_eq!(data.len(), ROTATE_FALCON_DATA_LEN);
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*hybrid_account, false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
        ],
        data,
    })
}

/// Build `ChangePolicy` (discriminator 4). Payload shape matches Execute.
///
/// Authorization uses the stricter of current and target policy requirements.
pub fn change_policy_instruction(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    intent: &AuthorizationIntent,
    falcon_sig: &[u8],
) -> Result<Instruction> {
    match intent.action {
        dualkey_core::Action::ChangePolicy { .. } => {}
        _ => {
            return Err(ClientError::IntentFormat {
                path: "change_policy".into(),
                reason: "intent action must be ChangePolicy".into(),
            });
        }
    }
    let mut data = Vec::with_capacity(EXECUTE_DATA_LEN);
    data.push(CHANGE_POLICY_DISCRIMINATOR);
    data.extend_from_slice(&encode_execute_intent_wire(intent));
    if falcon_sig.len() != FALCON_SIGNATURE_LEN {
        return Err(ClientError::KeyFileLength {
            path: "falcon signature".to_string(),
            expected: FALCON_SIGNATURE_LEN,
            actual: falcon_sig.len(),
        });
    }
    data.extend_from_slice(falcon_sig);
    Ok(Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*hybrid_account, false),
            AccountMeta::new_readonly(instructions_sysvar_id(), false),
        ],
        data,
    })
}

/// Build an Ed25519 precompile instruction over `message`.
///
/// For DualKey authorization, `message` is the 32-byte intent digest.
pub fn ed25519_precompile_instruction(
    message: &[u8],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
) -> Instruction {
    solana_ed25519_program::new_ed25519_instruction_with_signature(message, signature, pubkey)
}
