//! Instruction construction for on-chain operations.
//!
//! `Initialize` and `Transfer` build inspectable instruction artifacts offline.
//! Broadcasting still needs an RPC endpoint and a funded payer; emitting the
//! instructions keeps the path testable without a live cluster.

use std::path::Path;

use dualkey_core::{canonical_digest, Action, AuthorizationPolicy};
use ed25519_dalek::Signer;
use serde::Serialize;
use solana_pubkey::Pubkey;

use crate::error::{ClientError, Result};
use crate::falcon_interop;
use crate::keys::{Ed25519Keypair, FalconKeypair, KeyPaths, PublicKeys};
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

/// Offline HybridAnd transfer transaction fragment (Ed25519 precompile + Execute).
///
/// Public material only: signatures and addresses, never secret keys.
#[derive(Debug, Serialize)]
pub struct TransferArtifact {
    pub format: &'static str,
    pub program_id: String,
    pub hybrid_account: String,
    pub recipient: String,
    pub lamports: u64,
    pub nonce: u64,
    pub expiry_slot: u64,
    pub digest: String,
    pub ed25519_precompile_data_hex: String,
    pub execute_data_hex: String,
    pub execute_accounts: Vec<AccountMetaJson>,
}

impl TransferArtifact {
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Program:       {}\n", self.program_id));
        s.push_str(&format!("HybridAccount: {}\n", self.hybrid_account));
        s.push_str(&format!("Recipient:     {}\n", self.recipient));
        s.push_str(&format!("Lamports:      {}\n", self.lamports));
        s.push_str(&format!("Nonce:         {}\n", self.nonce));
        s.push_str(&format!("Expiry slot:   {}\n", self.expiry_slot));
        s.push_str(&format!("Digest:        {}\n", self.digest));
        s.push_str(&format!(
            "Ed25519 ix:    {} bytes\n",
            self.ed25519_precompile_data_hex.len() / 2
        ));
        s.push_str(&format!(
            "Execute ix:    {} bytes\n",
            self.execute_data_hex.len() / 2
        ));
        s.push_str("\nNot submitted. Include the Ed25519 precompile immediately before\n");
        s.push_str("Execute in the same transaction. Broadcasting needs RPC + payer.\n");
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

/// Parameters for [`transfer`].
pub struct TransferParams<'a> {
    pub keys_dir: &'a Path,
    pub program_id: &'a str,
    pub hybrid_account: &'a str,
    pub recipient: &'a str,
    pub lamports: u64,
    pub nonce: u64,
    pub expiry_slot: u64,
    pub out: Option<&'a Path>,
}

/// Build a HybridAnd-authorized `TransferSol` instruction pair offline.
///
/// Signs the canonical digest with both schemes, emits the Ed25519 precompile
/// instruction and the DualKey `Execute` instruction. Does **not** broadcast.
pub fn transfer(params: TransferParams<'_>) -> Result<()> {
    let TransferParams {
        keys_dir,
        program_id,
        hybrid_account,
        recipient,
        lamports,
        nonce,
        expiry_slot,
        out,
    } = params;

    let program_id = parse_pubkey("program_id", program_id)?;
    let hybrid_account = parse_pubkey("account", hybrid_account)?;
    let recipient = parse_pubkey("to", recipient)?;

    let paths = KeyPaths::new(keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        expiry_slot,
        Action::TransferSol {
            recipient: recipient.to_bytes(),
            lamports,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_pq, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;

    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());
    let exec_ix =
        onchain::execute_instruction(&program_id, &hybrid_account, &intent, wire.as_wire_bytes())?;

    let artifact = TransferArtifact {
        format: "dualkey-transfer-v1",
        program_id: program_id.to_string(),
        hybrid_account: hybrid_account.to_string(),
        recipient: recipient.to_string(),
        lamports,
        nonce,
        expiry_slot,
        digest: hex::encode(digest),
        ed25519_precompile_data_hex: hex::encode(&ed_ix.data),
        execute_data_hex: hex::encode(&exec_ix.data),
        execute_accounts: exec_ix
            .accounts
            .iter()
            .map(|m| AccountMetaJson {
                pubkey: m.pubkey.to_string(),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
    };

    print!("{}", artifact.render());

    if let Some(path) = out {
        let json = serde_json::to_vec_pretty(&artifact)?;
        crate::keys::write_with_mode(path, &json, crate::keys::PUBLIC_MODE)?;
        println!("Transfer artifact written to {}", path.display());
    }
    Ok(())
}
