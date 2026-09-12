//! Intent file parsing.
//!
//! The *input* file is JSON for human convenience. The *signed bytes* are
//! always the fixed-width canonical preimage produced by
//! [`dualkey_core::canonical_preimage`] — JSON is never signed.
//!
//! All 32-byte fields are lowercase hex (64 characters).

use std::path::Path;

use dualkey_core::{Action, AuthorizationIntent, INTENT_VERSION};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionSpec {
    TransferSol { recipient: String, lamports: u64 },
    RotateEd25519Key { new_pubkey: String },
    RotateFalconKey { new_pubkey_hash: String },
}

/// JSON representation of an [`AuthorizationIntent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSpec {
    #[serde(default = "default_version")]
    pub version: u8,
    pub chain_domain: String,
    pub program_id: String,
    pub account: String,
    pub nonce: u64,
    pub expiry_slot: u64,
    pub action: ActionSpec,
}

fn default_version() -> u8 {
    INTENT_VERSION
}

fn hex32(field: &'static str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|source| ClientError::Hex { field, source })?;
    bytes.try_into().map_err(|_| ClientError::IntentFormat {
        path: field.to_string(),
        reason: format!("{field} must be exactly 32 bytes (64 hex chars)"),
    })
}

impl IntentSpec {
    /// Convert to the canonical in-memory intent.
    pub fn to_intent(&self) -> Result<AuthorizationIntent> {
        let action = match &self.action {
            ActionSpec::TransferSol {
                recipient,
                lamports,
            } => Action::TransferSol {
                recipient: hex32("action.recipient", recipient)?,
                lamports: *lamports,
            },
            ActionSpec::RotateEd25519Key { new_pubkey } => Action::RotateEd25519Key {
                new_pubkey: hex32("action.new_pubkey", new_pubkey)?,
            },
            ActionSpec::RotateFalconKey { new_pubkey_hash } => Action::RotateFalconKey {
                new_pubkey_hash: hex32("action.new_pubkey_hash", new_pubkey_hash)?,
            },
        };

        Ok(AuthorizationIntent {
            version: self.version,
            chain_domain: hex32("chain_domain", &self.chain_domain)?,
            program_id: hex32("program_id", &self.program_id)?,
            account: hex32("account", &self.account)?,
            nonce: self.nonce,
            expiry_slot: self.expiry_slot,
            action,
        })
    }

    /// Build the JSON representation from a canonical intent.
    pub fn from_intent(intent: &AuthorizationIntent) -> Self {
        let action = match intent.action {
            Action::TransferSol {
                recipient,
                lamports,
            } => ActionSpec::TransferSol {
                recipient: hex::encode(recipient),
                lamports,
            },
            Action::RotateEd25519Key { new_pubkey } => ActionSpec::RotateEd25519Key {
                new_pubkey: hex::encode(new_pubkey),
            },
            Action::RotateFalconKey { new_pubkey_hash } => ActionSpec::RotateFalconKey {
                new_pubkey_hash: hex::encode(new_pubkey_hash),
            },
        };
        Self {
            version: intent.version,
            chain_domain: hex::encode(intent.chain_domain),
            program_id: hex::encode(intent.program_id),
            account: hex::encode(intent.account),
            nonce: intent.nonce,
            expiry_slot: intent.expiry_slot,
            action,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| ClientError::io(path, e))?;
        serde_json::from_slice(&bytes).map_err(|e| ClientError::IntentFormat {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json).map_err(|e| ClientError::io(path, e))
    }
}

/// Load an intent file and convert it to a canonical intent.
pub fn load_intent(path: &Path) -> Result<AuthorizationIntent> {
    IntentSpec::load(path)?.to_intent()
}
