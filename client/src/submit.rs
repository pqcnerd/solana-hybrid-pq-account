//! Instruction construction for on-chain operations.
//!
//! Milestone 3 builds the `Initialize` instruction. It deliberately stops short
//! of broadcasting: submitting requires an RPC endpoint and a funded payer, and
//! signing a real transaction is the transfer milestone's concern. Emitting the
//! instruction keeps this testable offline and lets the artifact be inspected
//! before anything is sent.

use std::path::Path;

use dualkey_core::AuthorizationPolicy;
use serde::Serialize;
use solana_pubkey::Pubkey;

use crate::error::{ClientError, Result};
use crate::keys::{KeyPaths, PublicKeys};
use crate::onchain;

/// A built instruction, rendered for inspection or offline signing.
///
/// Contains public material only: an Ed25519 public key, a Falcon **public**
/// key, and derived addresses. No secret key bytes are read into it or printed.
#[derive(Debug, Serialize)]
pub struct InitializeArtifact {
    pub format: &'static str,
    pub program_id: String,
    pub creator: String,
    pub hybrid_account: String,
    pub bump: u8,
    pub account_index: u32,
    pub policy: u8,
    pub policy_name: &'static str,
    pub owner_ed25519: String,
    pub falcon512_public_key_sha256: String,
    pub accounts: Vec<AccountMetaJson>,
    pub data_len: usize,
    pub data_hex: String,
}

#[derive(Debug, Serialize)]
pub struct AccountMetaJson {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl InitializeArtifact {
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Program:          {}\n", self.program_id));
        s.push_str(&format!("Creator:          {}\n", self.creator));
        s.push_str(&format!("HybridAccount:    {}\n", self.hybrid_account));
        s.push_str(&format!("Bump:             {}\n", self.bump));
        s.push_str(&format!("Account index:    {}\n", self.account_index));
        s.push_str(&format!(
            "Policy:           {} ({})\n",
            self.policy, self.policy_name
        ));
        s.push_str(&format!("Owner Ed25519:    {}\n", self.owner_ed25519));
        s.push_str(&format!(
            "Falcon pk SHA256: {}\n",
            self.falcon512_public_key_sha256
        ));
        s.push_str(&format!("Instruction data: {} bytes\n", self.data_len));
        s.push_str("\nNot submitted. Broadcasting requires an RPC endpoint and a funded\n");
        s.push_str("creator; this milestone builds the instruction only.\n");
        s
    }
}

/// Build the `Initialize` instruction for a HybridAccount PDA.
///
/// `creator` is the fee payer and a PDA seed. It must sign the transaction, so
/// it is supplied as an address rather than read from the key directory: the
/// creator is typically an existing funded Solana wallet, not the Ed25519 owner
/// key DualKey generates.
pub fn init(
    keys_dir: &Path,
    account_index: u32,
    program_id: &str,
    creator: &str,
    policy: AuthorizationPolicy,
    out: Option<&Path>,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", program_id)?;
    let creator = parse_pubkey("creator", creator)?;

    // Public keys only: this path never opens a secret key file.
    let public = PublicKeys::load(&KeyPaths::new(keys_dir))?;

    let (instruction, hybrid_account, bump) = onchain::initialize_instruction(
        &program_id,
        &creator,
        account_index,
        public.ed25519(),
        policy,
        public.falcon_wire(),
    )?;

    let artifact = InitializeArtifact {
        format: "dualkey-initialize-v1",
        program_id: program_id.to_string(),
        creator: creator.to_string(),
        hybrid_account: hybrid_account.to_string(),
        bump,
        account_index,
        policy: policy.as_u8(),
        policy_name: policy.name(),
        owner_ed25519: hex::encode(public.ed25519()),
        falcon512_public_key_sha256: hex::encode(public.falcon_public_key_hash()),
        accounts: instruction
            .accounts
            .iter()
            .map(|m| AccountMetaJson {
                pubkey: m.pubkey.to_string(),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data_len: instruction.data.len(),
        data_hex: hex::encode(&instruction.data),
    };

    print!("{}", artifact.render());

    // The artifact holds public material only, so it is written 0644 like the
    // other public files.
    if let Some(path) = out {
        let json = serde_json::to_vec_pretty(&artifact)?;
        crate::keys::write_with_mode(path, &json, crate::keys::PUBLIC_MODE)?;
        println!("Instruction written to {}", path.display());
    }
    Ok(())
}

fn parse_pubkey(field: &'static str, value: &str) -> Result<Pubkey> {
    value
        .parse::<Pubkey>()
        .map_err(|_| ClientError::InvalidAddress { field })
}

/// Submit a hybrid-authorized SOL transfer.
pub fn transfer(keys_dir: &Path, recipient: &str, lamports: u64) -> Result<()> {
    let _ = (keys_dir, recipient, lamports);
    Err(ClientError::Unimplemented {
        what: "transfer",
        milestone: 7,
    })
}
