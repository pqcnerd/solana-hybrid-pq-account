//! Client-side errors.
//!
//! Error values never embed secret key bytes.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("not implemented until Milestone {milestone}: {what}")]
    Unimplemented { what: &'static str, milestone: u8 },

    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed key file {path}: expected {expected} bytes, found {actual}")]
    KeyFileLength {
        path: String,
        expected: usize,
        actual: usize,
    },

    #[error("invalid Ed25519 key material: {0}")]
    Ed25519Key(&'static str),

    #[error("invalid Falcon key material: {0}")]
    FalconKey(&'static str),

    /// The PQClean compressed signature does not fit the 666-byte wire buffer
    /// that `solana-falcon512` requires. Falcon signing is randomized, so the
    /// correct response is to re-sign, never to truncate.
    #[error(
        "Falcon compressed signature is {actual} bytes, exceeding the {max}-byte \
         on-chain wire buffer; re-sign (Falcon signing is randomized) — truncation \
         would corrupt the signature"
    )]
    FalconSignatureTooLong { actual: usize, max: usize },

    #[error("malformed intent file {path}: {reason}")]
    IntentFormat { path: String, reason: String },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error in field {field}: {source}")]
    Hex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("{field} must be a base58 Solana address")]
    InvalidAddress { field: &'static str },

    /// Statistically improbable: no bump seed yields an off-curve address.
    #[error("could not derive a HybridAccount program address for these seeds")]
    PdaDerivation,

    /// The program refuses to store a policy it cannot evaluate, so the client
    /// rejects it before building the instruction.
    #[error(
        "authorization policy {policy} is declared but not implemented; \
         the program would reject it"
    )]
    PolicyNotImplemented { policy: u8 },

    #[error("rpc error: {0}")]
    Rpc(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

impl ClientError {
    pub(crate) fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}
