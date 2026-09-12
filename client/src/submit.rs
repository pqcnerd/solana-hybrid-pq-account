//! Instruction construction for on-chain operations.
//!
//! Builds inspectable instruction artifacts offline. With `--broadcast`,
//! Milestone 13 submits them via JSON-RPC.

use std::path::Path;

use dualkey_core::{canonical_digest, Action, AuthorizationPolicy, RecoveryOp};
use ed25519_dalek::Signer;
use serde::Serialize;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer as _;

use crate::error::{ClientError, Result};
use crate::falcon_interop;
use crate::keys::{Ed25519Keypair, FalconKeypair, KeyPaths, PublicKeys};
use crate::onchain;
use crate::rpc::{self, BroadcastOpts, Rpc};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
        if let Some(sig) = &self.signature {
            s.push_str(&format!("Submitted:        {sig}\n"));
        } else {
            s.push_str("\nNot submitted. Pass --broadcast --rpc-url --payer to submit.\n");
        }
        s
    }
}

/// Offline HybridAnd transfer transaction fragment (Ed25519 precompile + Execute).
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
        if let Some(sig) = &self.signature {
            s.push_str(&format!("Submitted:     {sig}\n"));
        } else {
            s.push_str("\nNot submitted. Pass --broadcast --rpc-url --payer to submit.\n");
            s.push_str("Ed25519 precompile must immediately precede Execute.\n");
        }
        s
    }
}

fn metas(ix: &Instruction) -> Vec<AccountMetaJson> {
    ix.accounts
        .iter()
        .map(|m| AccountMetaJson {
            pubkey: m.pubkey.to_string(),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
        })
        .collect()
}

/// Build the `Initialize` instruction for a HybridAccount PDA.
pub fn init(
    keys_dir: &Path,
    account_index: u32,
    program_id: &str,
    creator: &str,
    policy: AuthorizationPolicy,
    out: Option<&Path>,
    broadcast: &BroadcastOpts,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", program_id)?;
    let creator = parse_pubkey("creator", creator)?;
    let public = PublicKeys::load(&KeyPaths::new(keys_dir))?;

    let (instruction, hybrid_account, bump) = onchain::initialize_instruction(
        &program_id,
        &creator,
        account_index,
        public.ed25519(),
        policy,
        public.falcon_wire(),
    )?;

    let mut signature = None;
    if broadcast.broadcast {
        let (url, payer_path) = broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        if payer.pubkey() != creator {
            return Err(ClientError::IntentFormat {
                path: "payer".into(),
                reason: "payer pubkey must equal --creator for Initialize".into(),
            });
        }
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            std::slice::from_ref(&instruction),
        )?);
    }

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
        accounts: metas(&instruction),
        data_len: instruction.data.len(),
        data_hex: hex::encode(&instruction.data),
        signature,
    };

    print!("{}", artifact.render());
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
    pub nonce: Option<u64>,
    pub expiry_slot: u64,
    pub out: Option<&'a Path>,
    pub broadcast: BroadcastOpts,
}

/// Build a HybridAnd-authorized `TransferSol` instruction pair.
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
        broadcast,
    } = params;

    let program_id = parse_pubkey("program_id", program_id)?;
    let hybrid_account = parse_pubkey("account", hybrid_account)?;
    let recipient = parse_pubkey("to", recipient)?;

    let paths = KeyPaths::new(keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;

    let nonce = match nonce {
        Some(n) => n,
        None => {
            let (url, _) =
                broadcast
                    .require_for_broadcast()
                    .map_err(|_| ClientError::IntentFormat {
                        path: "nonce".into(),
                        reason:
                            "--nonce is required unless --broadcast --rpc-url is set (reads chain)"
                                .into(),
                    })?;
            Rpc::new(url).get_hybrid_nonce(&hybrid_account)?
        }
    };

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

    let mut signature = None;
    if broadcast.broadcast {
        let (url, payer_path) = broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), exec_ix.clone()],
        )?);
    }

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
        execute_accounts: metas(&exec_ix),
        signature,
    };

    print!("{}", artifact.render());
    if let Some(path) = out {
        let json = serde_json::to_vec_pretty(&artifact)?;
        crate::keys::write_with_mode(path, &json, crate::keys::PUBLIC_MODE)?;
        println!("Transfer artifact written to {}", path.display());
    }
    Ok(())
}

/// Shared params for DualKey-authorized lifecycle instructions (716-byte shape).
pub struct LifecycleParams<'a> {
    pub keys_dir: &'a Path,
    pub program_id: &'a str,
    pub hybrid_account: &'a str,
    pub nonce: Option<u64>,
    pub expiry_slot: u64,
    pub broadcast: BroadcastOpts,
    pub out: Option<&'a Path>,
}

fn resolve_nonce(hybrid: &Pubkey, nonce: Option<u64>, broadcast: &BroadcastOpts) -> Result<u64> {
    match nonce {
        Some(n) => Ok(n),
        None => {
            let (url, _) =
                broadcast
                    .require_for_broadcast()
                    .map_err(|_| ClientError::IntentFormat {
                        path: "nonce".into(),
                        reason: "--nonce required unless --broadcast --rpc-url is set".into(),
                    })?;
            Rpc::new(url).get_hybrid_nonce(hybrid)
        }
    }
}

fn sign_lifecycle(
    params: &LifecycleParams<'_>,
    action: Action,
    build_ix: impl FnOnce(
        &Pubkey,
        &Pubkey,
        &dualkey_core::AuthorizationIntent,
        &[u8],
    ) -> Result<Instruction>,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", params.program_id)?;
    let hybrid_account = parse_pubkey("account", params.hybrid_account)?;
    let paths = KeyPaths::new(params.keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;
    let nonce = resolve_nonce(&hybrid_account, params.nonce, &params.broadcast)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        params.expiry_slot,
        action,
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_pq, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());
    let ix = build_ix(&program_id, &hybrid_account, &intent, wire.as_wire_bytes())?;

    let mut signature = None;
    if params.broadcast.broadcast {
        let (url, payer_path) = params.broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        // HybridAnd / Both: include Ed25519 precompile. Falcon-only paths still
        // tolerate a preceding precompile being absent when requirement is Falcon;
        // for lifecycle under HybridAnd we always send both.
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), ix.clone()],
        )?);
    }

    println!("Digest:    {}", hex::encode(digest));
    println!("Nonce:     {nonce}");
    println!("Ix data:   {} bytes", ix.data.len());
    if let Some(ref sig) = signature {
        println!("Submitted: {sig}");
    } else {
        println!("Not submitted. Pass --broadcast --rpc-url --payer to submit.");
    }
    if let Some(path) = params.out {
        let json = serde_json::json!({
            "digest": hex::encode(digest),
            "nonce": nonce,
            "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
            "instruction_data_hex": hex::encode(&ix.data),
            "signature": signature,
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}

pub fn change_policy(
    params: LifecycleParams<'_>,
    new_policy: AuthorizationPolicy,
    threshold: u64,
) -> Result<()> {
    sign_lifecycle(
        &params,
        Action::ChangePolicy {
            new_policy: new_policy.as_u8(),
            threshold,
        },
        onchain::change_policy_instruction,
    )
}

pub fn recover_enable(params: LifecycleParams<'_>) -> Result<()> {
    sign_lifecycle(
        &params,
        Action::RecoverAccount {
            op: RecoveryOp::Enable,
            new_ed25519: [0u8; 32],
        },
        onchain::recover_account_instruction,
    )
}

pub fn recover_disable(params: LifecycleParams<'_>) -> Result<()> {
    sign_lifecycle(
        &params,
        Action::RecoverAccount {
            op: RecoveryOp::Disable,
            new_ed25519: [0u8; 32],
        },
        onchain::recover_account_instruction,
    )
}

pub fn recover_rotate_ed25519(params: LifecycleParams<'_>, new_owner: &str) -> Result<()> {
    let new_ed25519 = parse_pubkey("new-owner", new_owner)?.to_bytes();
    sign_lifecycle(
        &params,
        Action::RecoverAccount {
            op: RecoveryOp::RotateEd25519,
            new_ed25519,
        },
        onchain::recover_account_instruction,
    )
}

pub fn rotate_ed25519(params: LifecycleParams<'_>, new_owner: &str) -> Result<()> {
    let new_pubkey = parse_pubkey("new-owner", new_owner)?.to_bytes();
    sign_lifecycle(
        &params,
        Action::RotateEd25519Key { new_pubkey },
        onchain::rotate_ed25519_instruction,
    )
}

/// Rotate the Falcon public key under the current policy (with PoP).
///
/// Offline artifact / `--out` only: instruction data is ~2279 bytes and cannot
/// fit a legacy `--broadcast` transaction (v0 + ALT is out of scope).
pub fn rotate_falcon(params: LifecycleParams<'_>, new_falcon_keys: &Path) -> Result<()> {
    if params.broadcast.broadcast {
        return Err(ClientError::IntentFormat {
            path: "broadcast".into(),
            reason: "RotateFalconKey instruction data is ~2279 bytes and cannot fit a \
                     legacy transaction; omit --broadcast and use --out (v0 + ALT \
                     submission is out of scope)"
                .into(),
        });
    }

    let program_id = parse_pubkey("program_id", params.program_id)?;
    let hybrid_account = parse_pubkey("account", params.hybrid_account)?;
    let paths = KeyPaths::new(params.keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;
    let new_falcon = FalconKeypair::load(&KeyPaths::new(new_falcon_keys))?;
    let new_wire = new_falcon.public_bytes();
    let new_pubkey_hash = crate::keys::sha256(new_wire);
    let nonce = resolve_nonce(&hybrid_account, params.nonce, &params.broadcast)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        params.expiry_slot,
        Action::RotateFalconKey { new_pubkey_hash },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_a, auth_wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;
    let (_p, pop_wire) = falcon_interop::sign_to_wire(&digest, new_falcon.secret())?;
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());
    let ix = onchain::rotate_falcon_instruction(
        &program_id,
        &hybrid_account,
        &intent,
        auth_wire.as_wire_bytes(),
        new_wire,
        pop_wire.as_wire_bytes(),
    )?;

    println!("Digest:    {}", hex::encode(digest));
    println!("Nonce:     {nonce}");
    println!("New Falcon SHA256: {}", hex::encode(new_pubkey_hash));
    println!("Ix data:   {} bytes", ix.data.len());
    println!("Not submitted. RotateFalconKey needs v0 + ALT; use --out for the offline artifact.");
    if let Some(path) = params.out {
        let json = serde_json::json!({
            "digest": hex::encode(digest),
            "nonce": nonce,
            "new_falcon_public_key_sha256": hex::encode(new_pubkey_hash),
            "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
            "instruction_data_hex": hex::encode(&ix.data),
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}

fn print_submit_result(digest: &[u8; 32], nonce: u64, ix_len: usize, signature: &Option<String>) {
    println!("Digest:    {}", hex::encode(digest));
    println!("Nonce:     {nonce}");
    println!("Ix data:   {ix_len} bytes");
    if let Some(sig) = signature {
        println!("Submitted: {sig}");
    } else {
        println!("Not submitted. Pass --broadcast --rpc-url --payer to submit.");
    }
}

/// Set / replace social-recovery guardian + delay (Milestone 15).
pub fn social_set_config(
    params: LifecycleParams<'_>,
    guardian: &str,
    delay_slots: u64,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", params.program_id)?;
    let hybrid_account = parse_pubkey("account", params.hybrid_account)?;
    let guardian_ed25519 = parse_pubkey("guardian", guardian)?.to_bytes();
    let (recovery_config, _) = onchain::derive_recovery_config(&program_id, &hybrid_account)?;
    let paths = KeyPaths::new(params.keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;
    let nonce = resolve_nonce(&hybrid_account, params.nonce, &params.broadcast)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        params.expiry_slot,
        Action::SetRecoveryConfig {
            guardian_ed25519,
            delay_slots,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_pq, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());

    if params.broadcast.broadcast {
        let (url, payer_path) = params.broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        let ix = onchain::set_recovery_config_instruction(
            &program_id,
            &hybrid_account,
            &recovery_config,
            &payer.pubkey(),
            &intent,
            wire.as_wire_bytes(),
        )?;
        let signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), ix.clone()],
        )?);
        print_submit_result(&digest, nonce, ix.data.len(), &signature);
        println!("RecoveryConfig: {recovery_config}");
        if let Some(path) = params.out {
            let json = serde_json::json!({
                "digest": hex::encode(digest),
                "nonce": nonce,
                "recovery_config": recovery_config.to_string(),
                "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
                "instruction_data_hex": hex::encode(&ix.data),
                "signature": signature,
            });
            crate::keys::write_with_mode(
                path,
                &serde_json::to_vec_pretty(&json)?,
                crate::keys::PUBLIC_MODE,
            )?;
            println!("Artifact written to {}", path.display());
        }
    } else {
        // Offline: use a placeholder payer pubkey (must match when broadcasting).
        let placeholder = Pubkey::new_from_array([0u8; 32]);
        let ix = onchain::set_recovery_config_instruction(
            &program_id,
            &hybrid_account,
            &recovery_config,
            &placeholder,
            &intent,
            wire.as_wire_bytes(),
        )?;
        print_submit_result(&digest, nonce, ix.data.len(), &None);
        println!("RecoveryConfig: {recovery_config}");
        println!("Note: offline artifact uses zero payer; rebuild with --broadcast.");
        if let Some(path) = params.out {
            let json = serde_json::json!({
                "digest": hex::encode(digest),
                "nonce": nonce,
                "recovery_config": recovery_config.to_string(),
                "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
                "instruction_data_hex": hex::encode(&ix.data),
            });
            crate::keys::write_with_mode(
                path,
                &serde_json::to_vec_pretty(&json)?,
                crate::keys::PUBLIC_MODE,
            )?;
            println!("Artifact written to {}", path.display());
        }
    }
    Ok(())
}

/// Guardian initiates a pending Ed25519 owner change.
pub fn social_initiate(
    program_id: &str,
    hybrid_account: &str,
    new_owner: &str,
    guardian_keys: &Path,
    nonce: Option<u64>,
    broadcast: &BroadcastOpts,
    out: Option<&Path>,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", program_id)?;
    let hybrid_account = parse_pubkey("account", hybrid_account)?;
    let new_ed25519 = parse_pubkey("new-owner", new_owner)?.to_bytes();
    let (recovery_config, _) = onchain::derive_recovery_config(&program_id, &hybrid_account)?;
    let guardian = Ed25519Keypair::load(&KeyPaths::new(guardian_keys))?;

    let nonce = match nonce {
        Some(n) => n,
        None => {
            let (url, _) =
                broadcast
                    .require_for_broadcast()
                    .map_err(|_| ClientError::IntentFormat {
                        path: "nonce".into(),
                        reason: "--nonce required unless --broadcast --rpc-url is set".into(),
                    })?;
            Rpc::new(url).get_hybrid_nonce(&hybrid_account)?
        }
    };

    let digest = dualkey_core::social_recover_digest(
        &dualkey_core::CHAIN_DOMAIN_LOCALNET,
        &program_id.to_bytes(),
        &hybrid_account.to_bytes(),
        &new_ed25519,
        nonce,
    );
    let g_sig = guardian.signing_key().sign(&digest).to_bytes();
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &g_sig, &guardian.public_bytes());
    let ix = onchain::initiate_social_recovery_instruction(
        &program_id,
        &hybrid_account,
        &recovery_config,
        &new_ed25519,
    );

    let mut signature = None;
    if broadcast.broadcast {
        let (url, payer_path) = broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), ix.clone()],
        )?);
    }

    print_submit_result(&digest, nonce, ix.data.len(), &signature);
    println!("RecoveryConfig: {recovery_config}");
    if let Some(path) = out {
        let json = serde_json::json!({
            "digest": hex::encode(digest),
            "nonce": nonce,
            "recovery_config": recovery_config.to_string(),
            "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
            "instruction_data_hex": hex::encode(&ix.data),
            "signature": signature,
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}

/// Permissionless finalize after the social-recovery timelock.
pub fn social_finalize(
    program_id: &str,
    hybrid_account: &str,
    broadcast: &BroadcastOpts,
    out: Option<&Path>,
) -> Result<()> {
    let program_id = parse_pubkey("program_id", program_id)?;
    let hybrid_account = parse_pubkey("account", hybrid_account)?;
    let (recovery_config, _) = onchain::derive_recovery_config(&program_id, &hybrid_account)?;
    let ix = onchain::finalize_social_recovery_instruction(
        &program_id,
        &hybrid_account,
        &recovery_config,
    );

    let mut signature = None;
    if broadcast.broadcast {
        let (url, payer_path) = broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            std::slice::from_ref(&ix),
        )?);
    }

    println!("RecoveryConfig: {recovery_config}");
    println!("Ix data:   {} bytes", ix.data.len());
    if let Some(ref sig) = signature {
        println!("Submitted: {sig}");
    } else {
        println!("Not submitted. Pass --broadcast --rpc-url --payer to submit.");
    }
    if let Some(path) = out {
        let json = serde_json::json!({
            "recovery_config": recovery_config.to_string(),
            "instruction_data_hex": hex::encode(&ix.data),
            "signature": signature,
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}

/// DualKey owner cancels a pending social recovery.
pub fn social_cancel(params: LifecycleParams<'_>) -> Result<()> {
    let program_id = parse_pubkey("program_id", params.program_id)?;
    let hybrid_account = parse_pubkey("account", params.hybrid_account)?;
    let (recovery_config, _) = onchain::derive_recovery_config(&program_id, &hybrid_account)?;
    let paths = KeyPaths::new(params.keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;
    let nonce = resolve_nonce(&hybrid_account, params.nonce, &params.broadcast)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        params.expiry_slot,
        Action::CancelSocialRecovery,
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_pq, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());
    let ix = onchain::cancel_social_recovery_instruction(
        &program_id,
        &hybrid_account,
        &recovery_config,
        &intent,
        wire.as_wire_bytes(),
    )?;

    let mut signature = None;
    if params.broadcast.broadcast {
        let (url, payer_path) = params.broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), ix.clone()],
        )?);
    }

    print_submit_result(&digest, nonce, ix.data.len(), &signature);
    println!("RecoveryConfig: {recovery_config}");
    if let Some(path) = params.out {
        let json = serde_json::json!({
            "digest": hex::encode(digest),
            "nonce": nonce,
            "recovery_config": recovery_config.to_string(),
            "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
            "instruction_data_hex": hex::encode(&ix.data),
            "signature": signature,
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}

/// Parameters for [`transfer_spl`].
pub struct TransferSplParams<'a> {
    pub keys_dir: &'a Path,
    pub program_id: &'a str,
    pub hybrid_account: &'a str,
    pub creator: &'a str,
    pub source: &'a str,
    pub mint: &'a str,
    pub destination: &'a str,
    pub amount: u64,
    pub nonce: Option<u64>,
    pub expiry_slot: u64,
    pub token_2022: bool,
    pub broadcast: BroadcastOpts,
    pub out: Option<&'a Path>,
}

/// Build (and optionally broadcast) a HybridAnd-authorized `TransferSpl`.
pub fn transfer_spl(params: TransferSplParams<'_>) -> Result<()> {
    let program_id = parse_pubkey("program_id", params.program_id)?;
    let hybrid_account = parse_pubkey("account", params.hybrid_account)?;
    let creator = parse_pubkey("creator", params.creator)?;
    let source = parse_pubkey("source", params.source)?;
    let mint = parse_pubkey("mint", params.mint)?;
    let destination = parse_pubkey("destination", params.destination)?;
    let token_program = if params.token_2022 {
        onchain::token_2022_program_id()
    } else {
        onchain::token_program_id()
    };

    let paths = KeyPaths::new(params.keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;
    let nonce = resolve_nonce(&hybrid_account, params.nonce, &params.broadcast)?;

    let intent = onchain::signing_intent(
        &program_id,
        &hybrid_account,
        nonce,
        params.expiry_slot,
        Action::TransferSpl {
            destination: destination.to_bytes(),
            amount: params.amount,
        },
    );
    let digest = canonical_digest(&intent);
    let ed_sig = ed.signing_key().sign(&digest).to_bytes();
    let (_pq, wire) = falcon_interop::sign_to_wire(&digest, falcon.secret())?;
    let ed_ix = onchain::ed25519_precompile_instruction(&digest, &ed_sig, &ed.public_bytes());
    let exec_ix = onchain::execute_transfer_spl_instruction_with_program(
        &program_id,
        &hybrid_account,
        &creator,
        &source,
        &mint,
        &token_program,
        &intent,
        wire.as_wire_bytes(),
    )?;

    let mut signature = None;
    if params.broadcast.broadcast {
        let (url, payer_path) = params.broadcast.require_for_broadcast()?;
        let rpc = Rpc::new(url);
        let payer = rpc::load_payer(payer_path)?;
        signature = Some(rpc::send_instructions(
            &rpc,
            &payer,
            &[ed_ix.clone(), exec_ix.clone()],
        )?);
    }

    println!("Digest:    {}", hex::encode(digest));
    println!("Nonce:     {nonce}");
    println!("Token prog: {token_program}");
    println!("Execute:   {} bytes", exec_ix.data.len());
    if let Some(ref sig) = signature {
        println!("Submitted: {sig}");
    } else {
        println!("Not submitted. Pass --broadcast --rpc-url --payer to submit.");
    }
    if let Some(path) = params.out {
        let json = serde_json::json!({
            "digest": hex::encode(digest),
            "nonce": nonce,
            "token_program": token_program.to_string(),
            "ed25519_precompile_data_hex": hex::encode(&ed_ix.data),
            "execute_data_hex": hex::encode(&exec_ix.data),
            "signature": signature,
        });
        crate::keys::write_with_mode(
            path,
            &serde_json::to_vec_pretty(&json)?,
            crate::keys::PUBLIC_MODE,
        )?;
        println!("Artifact written to {}", path.display());
    }
    Ok(())
}
