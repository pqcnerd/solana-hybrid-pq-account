//! Minimal Solana JSON-RPC helpers for broadcasting DualKey transactions.
//!
//! Uses blocking HTTP JSON-RPC rather than pinning a heavy `solana-rpc-client`
//! major that fights the Mollusk-aligned `solana-transaction` 4.x types.

use std::path::Path;
use std::thread;
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::error::{ClientError, Result};
use dualkey_core::{HybridAccount, ACCOUNT_DATA_LEN};

/// Broadcast / chain-read options shared by CLI commands.
#[derive(Clone, Debug, Default)]
pub struct BroadcastOpts {
    pub broadcast: bool,
    pub rpc_url: Option<String>,
    pub payer_path: Option<std::path::PathBuf>,
}

impl BroadcastOpts {
    pub fn require_for_broadcast(&self) -> Result<(&str, &Path)> {
        if !self.broadcast {
            return Err(ClientError::IntentFormat {
                path: "broadcast".into(),
                reason: "internal: require_for_broadcast called without --broadcast".into(),
            });
        }
        let url = self
            .rpc_url
            .as_deref()
            .ok_or_else(|| ClientError::IntentFormat {
                path: "rpc-url".into(),
                reason: "--broadcast requires --rpc-url".into(),
            })?;
        let payer = self
            .payer_path
            .as_deref()
            .ok_or_else(|| ClientError::IntentFormat {
                path: "payer".into(),
                reason: "--broadcast requires --payer <keypair.json>".into(),
            })?;
        Ok((url, payer))
    }
}

/// Thin JSON-RPC client.
pub struct Rpc {
    url: String,
    http: reqwest::blocking::Client,
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http: reqwest::blocking::Client::new(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp: JsonRpcResponse = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| ClientError::Rpc(e.to_string()))?
            .error_for_status()
            .map_err(|e| ClientError::Rpc(e.to_string()))?
            .json()
            .map_err(|e| ClientError::Rpc(e.to_string()))?;
        if let Some(err) = resp.error {
            return Err(ClientError::Rpc(err.to_string()));
        }
        resp.result
            .ok_or_else(|| ClientError::Rpc("empty RPC result".into()))
    }

    pub fn get_latest_blockhash(&self) -> Result<Hash> {
        let result = self.call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))?;
        let hash_str = result
            .pointer("/value/blockhash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::Rpc("missing blockhash".into()))?;
        hash_str
            .parse()
            .map_err(|_| ClientError::Rpc(format!("bad blockhash {hash_str}")))
    }

    pub fn get_slot(&self) -> Result<u64> {
        let result = self.call("getSlot", json!([{ "commitment": "confirmed" }]))?;
        result
            .as_u64()
            .ok_or_else(|| ClientError::Rpc("bad slot".into()))
    }

    /// Read HybridAccount data and return the on-chain nonce.
    pub fn get_hybrid_nonce(&self, account: &Pubkey) -> Result<u64> {
        let data = self.get_account_data(account)?;
        HybridAccount::nonce_from_slice(&data).map_err(|_| ClientError::IntentFormat {
            path: account.to_string(),
            reason: "account is not a DualKey HybridAccount".into(),
        })
    }

    pub fn get_account_data(&self, account: &Pubkey) -> Result<Vec<u8>> {
        let result = self.call(
            "getAccountInfo",
            json!([
                account.to_string(),
                { "encoding": "base64", "commitment": "confirmed" }
            ]),
        )?;
        let b64 = result
            .pointer("/value/data/0")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::Rpc(format!("account {account} not found")))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| ClientError::Rpc(e.to_string()))?;
        if bytes.len() != ACCOUNT_DATA_LEN && !bytes.is_empty() {
            // Allow other sizes for generic reads; HybridAccount callers check.
        }
        Ok(bytes)
    }

    pub fn send_and_confirm(&self, tx: &Transaction) -> Result<String> {
        let wire = bincode::serialize(tx).map_err(|e| ClientError::Rpc(e.to_string()))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(wire);
        let result = self.call(
            "sendTransaction",
            json!([
                encoded,
                {
                    "encoding": "base64",
                    "skipPreflight": false,
                    "preflightCommitment": "confirmed"
                }
            ]),
        )?;
        let sig = result
            .as_str()
            .ok_or_else(|| ClientError::Rpc("missing signature".into()))?
            .to_string();

        // Poll confirmation (simple research client; not production-grade).
        for _ in 0..60 {
            let status = self.call(
                "getSignatureStatuses",
                json!([[sig], { "searchTransactionHistory": true }]),
            )?;
            if let Some(entry) = status.pointer("/value/0") {
                if !entry.is_null() {
                    if let Some(err) = entry.get("err") {
                        if !err.is_null() {
                            return Err(ClientError::Rpc(format!(
                                "transaction {sig} failed: {err}"
                            )));
                        }
                    }
                    let conf = entry
                        .pointer("/confirmationStatus")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if conf == "confirmed" || conf == "finalized" {
                        return Ok(sig);
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
        Err(ClientError::Rpc(format!(
            "transaction {sig} not confirmed in time"
        )))
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

/// Load a Solana JSON keypair (byte array) from disk. Never prints the secret.
pub fn load_payer(path: &Path) -> Result<Keypair> {
    let bytes = std::fs::read(path).map_err(|e| ClientError::io(path, e))?;
    let arr: Vec<u8> = serde_json::from_slice(&bytes).map_err(|e| ClientError::IntentFormat {
        path: path.display().to_string(),
        reason: format!("payer keypair JSON: {e}"),
    })?;
    Keypair::try_from(arr.as_slice()).map_err(|_| ClientError::Ed25519Key("invalid payer keypair"))
}

/// Sign a legacy transaction with `payer` and broadcast it.
///
/// Signing is done manually (message serialize + `Signer::sign_message`) to
/// avoid enabling `solana-transaction`'s `blake3`/`wincode` features, which
/// currently conflict across transitive wincode majors in this stack.
pub fn send_instructions(
    rpc: &Rpc,
    payer: &Keypair,
    instructions: &[Instruction],
) -> Result<String> {
    let blockhash = rpc.get_latest_blockhash()?;
    let tx = sign_legacy_transaction(payer, instructions, blockhash)?;
    rpc.send_and_confirm(&tx)
}

fn sign_legacy_transaction(
    payer: &Keypair,
    instructions: &[Instruction],
    blockhash: Hash,
) -> Result<Transaction> {
    let mut tx = Transaction::new_with_payer(instructions, Some(&payer.pubkey()));
    tx.message.recent_blockhash = blockhash;
    // Legacy message wire bytes via bincode + short-vec serde (same as historical
    // Message::serialize without enabling conflicting wincode features).
    let message_bytes =
        bincode::serialize(&tx.message).map_err(|e| ClientError::Rpc(e.to_string()))?;
    let n = tx.message.header.num_required_signatures as usize;
    let mut signatures = vec![Signature::default(); n];
    // Payer is always account 0 for `new_with_payer`.
    signatures[0] = payer.sign_message(&message_bytes);
    tx.signatures = signatures;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::AccountMeta;

    #[test]
    fn assembles_legacy_transaction_without_rpc() {
        let payer = Keypair::new();
        let ix = Instruction {
            program_id: Pubkey::new_from_array([9u8; 32]),
            accounts: vec![AccountMeta::new(payer.pubkey(), true)],
            data: vec![1, 2, 3],
        };
        let blockhash = Hash::new_from_array([3u8; 32]);
        let tx = sign_legacy_transaction(&payer, &[ix], blockhash).unwrap();
        assert_eq!(tx.message.instructions.len(), 1);
        assert_ne!(tx.signatures[0], Signature::default());
        let wire = bincode::serialize(&tx).unwrap();
        assert!(wire.len() > 64);
    }
}
