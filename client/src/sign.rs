//! `dualkey sign` and `dualkey verify`.
//!
//! # Single shared digest
//!
//! Exactly one 32-byte digest is computed, by [`dualkey_core`], and both
//! schemes sign *that same digest*:
//!
//! ```text
//! preimage = 0x11 || "DUALKEY_SOLANA_V1" || intent fields   (172 bytes)
//! digest   = SHA256(preimage)                               (32 bytes)
//!
//! ed_sig     = Ed25519.Sign(ed_sk, digest)
//! falcon_sig = Falcon512.Sign(falcon_sk, digest)
//! ```
//!
//! Neither scheme signs the preimage directly and neither signs a different
//! transform of it. The client never reimplements the canonical serialization
//! or the hash.

use std::path::Path;

use dualkey_core::{AuthorizationIntent, DIGEST_LEN};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::PublicKey as _;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};
use crate::falcon_interop::{self, WireSignature};
use crate::intent::{load_intent, IntentSpec};
use crate::keys::{sha256, Ed25519Keypair, FalconKeypair, KeyPaths};

/// Maximum Falcon signing attempts if a randomized signature overruns the
/// 666-byte wire buffer.
const MAX_FALCON_SIGN_ATTEMPTS: usize = 8;

/// A signed intent bundle. Public material only — no secret keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundle {
    pub format: String,
    pub intent: IntentSpec,
    /// The single 32-byte digest signed by BOTH schemes.
    pub digest: String,
    /// 172-byte canonical preimage, for auditability.
    pub canonical_preimage: String,
    pub ed25519_public_key: String,
    pub ed25519_signature: String,
    pub falcon512_public_key: String,
    pub falcon512_public_key_sha256: String,
    /// 666-byte zero-padded wire signature (what goes on-chain).
    pub falcon512_signature_wire: String,
    /// Length of the PQClean-encoded portion before zero padding.
    pub falcon512_signature_encoded_len: usize,
    pub falcon512_signature_padding_len: usize,
}

/// Result of computing the shared digest.
pub struct SigningMaterial {
    pub intent: AuthorizationIntent,
    pub preimage: [u8; dualkey_core::CANONICAL_PREIMAGE_LEN],
    pub digest: [u8; DIGEST_LEN],
}

/// Build the canonical preimage and the single digest via `dualkey-core`.
pub fn signing_material(intent: AuthorizationIntent) -> SigningMaterial {
    let preimage = dualkey_core::canonical_preimage(&intent);
    let digest = dualkey_core::digest_preimage(&preimage);
    SigningMaterial {
        intent,
        preimage,
        digest,
    }
}

/// Sign one digest with both schemes.
pub fn sign_intent(
    intent: AuthorizationIntent,
    ed: &Ed25519Keypair,
    falcon: &FalconKeypair,
) -> Result<SignedBundle> {
    let material = signing_material(intent);

    // Both schemes receive the identical 32-byte digest slice.
    let message: &[u8] = &material.digest;

    let ed_sig: Signature = ed.signing_key().sign(message);

    let (_pq_sig, wire, _attempts) = falcon_interop::sign_to_wire_with_retry(
        message,
        falcon.secret(),
        MAX_FALCON_SIGN_ATTEMPTS,
    )?;

    Ok(SignedBundle {
        format: "dualkey-signed-intent-v1".to_string(),
        intent: IntentSpec::from_intent(&material.intent),
        digest: hex::encode(material.digest),
        canonical_preimage: hex::encode(material.preimage),
        ed25519_public_key: hex::encode(ed.public_bytes()),
        ed25519_signature: hex::encode(ed_sig.to_bytes()),
        falcon512_public_key: hex::encode(falcon.public_bytes()),
        falcon512_public_key_sha256: hex::encode(sha256(falcon.public_bytes())),
        falcon512_signature_wire: hex::encode(wire.as_wire_bytes()),
        falcon512_signature_encoded_len: wire.encoded_len(),
        falcon512_signature_padding_len: wire.padding_len(),
    })
}

/// Outcome of verifying a bundle across all three verifiers.
#[derive(Debug, Clone, Copy)]
pub struct VerificationReport {
    pub digest: [u8; DIGEST_LEN],
    pub ed25519_valid: bool,
    pub falcon_pqclean_valid: bool,
    pub falcon_solana_valid: bool,
    pub falcon_solana_prepared_valid: bool,
    /// Whether the digest in the bundle matches a fresh recomputation from
    /// the intent, i.e. both schemes really covered the same canonical intent.
    pub shared_digest: bool,
}

impl VerificationReport {
    pub fn all_valid(&self) -> bool {
        self.ed25519_valid
            && self.falcon_pqclean_valid
            && self.falcon_solana_valid
            && self.falcon_solana_prepared_valid
            && self.shared_digest
    }

    /// Concise CLI summary. Contains no secret material.
    pub fn render(&self) -> String {
        fn mark(ok: bool) -> &'static str {
            if ok {
                "VALID"
            } else {
                "INVALID"
            }
        }
        let mut s = String::new();
        s.push_str(&format!("Digest:                 {}\n", hex::encode(self.digest)));
        s.push_str(&format!(
            "Ed25519 verification:   {}\n",
            mark(self.ed25519_valid)
        ));
        s.push_str(&format!(
            "Falcon (PQClean):       {}\n",
            mark(self.falcon_pqclean_valid)
        ));
        s.push_str(&format!(
            "Falcon (Solana impl):   {}\n",
            mark(self.falcon_solana_valid)
        ));
        s.push_str(&format!(
            "Falcon (Solana prep):   {}\n",
            mark(self.falcon_solana_prepared_valid)
        ));
        s.push_str(&format!(
            "Shared digest:          {}\n",
            if self.shared_digest { "YES" } else { "NO" }
        ));
        s
    }
}

/// Verify a bundle with Ed25519, PQClean Falcon, and the on-chain Falcon
/// verifier (both raw and prepared public-key paths).
pub fn verify_bundle(bundle: &SignedBundle) -> Result<VerificationReport> {
    // Recompute the digest from the intent; never trust the stored value.
    let intent = bundle.intent.to_intent()?;
    let recomputed = signing_material(intent);
    let stored = hex::decode(&bundle.digest).map_err(|source| ClientError::Hex {
        field: "digest",
        source,
    })?;
    let shared_digest = stored.as_slice() == recomputed.digest.as_slice();

    let message: &[u8] = &recomputed.digest;

    // --- Ed25519 -----------------------------------------------------------
    let ed_pk_bytes = hex::decode(&bundle.ed25519_public_key).map_err(|source| {
        ClientError::Hex {
            field: "ed25519_public_key",
            source,
        }
    })?;
    let ed_sig_bytes = hex::decode(&bundle.ed25519_signature).map_err(|source| {
        ClientError::Hex {
            field: "ed25519_signature",
            source,
        }
    })?;

    let ed25519_valid = verify_ed25519(&ed_pk_bytes, &ed_sig_bytes, message);

    // --- Falcon ------------------------------------------------------------
    let falcon_pk_bytes = hex::decode(&bundle.falcon512_public_key).map_err(|source| {
        ClientError::Hex {
            field: "falcon512_public_key",
            source,
        }
    })?;
    let falcon_wire_bytes =
        hex::decode(&bundle.falcon512_signature_wire).map_err(|source| ClientError::Hex {
            field: "falcon512_signature_wire",
            source,
        })?;

    let wire = WireSignature::from_wire_bytes(&falcon_wire_bytes)?;

    let falcon_pqclean_valid = match (
        falcon512::PublicKey::from_bytes(&falcon_pk_bytes),
        wire.to_pqclean(),
    ) {
        (Ok(pk), Ok(sig)) => falcon_interop::verify_pqclean(&sig, message, &pk),
        _ => false,
    };

    let falcon_solana_valid = falcon_interop::verify_solana_raw(&wire, message, &falcon_pk_bytes);

    let falcon_solana_prepared_valid = match falcon_interop::prepare_pubkey(&falcon_pk_bytes) {
        Ok(prepared) => falcon_interop::verify_solana_prepared(&wire, message, &prepared),
        Err(_) => false,
    };

    Ok(VerificationReport {
        digest: recomputed.digest,
        ed25519_valid,
        falcon_pqclean_valid,
        falcon_solana_valid,
        falcon_solana_prepared_valid,
        shared_digest,
    })
}

/// Verify an Ed25519 signature, returning `false` on any malformed input.
///
/// Never panics on attacker-controlled bytes.
pub fn verify_ed25519(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Ok(pk_arr): std::result::Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_arr): std::result::Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    verifying.verify(message, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// CLI entry points
// ---------------------------------------------------------------------------

/// `dualkey sign --intent <file> --keys <dir> [--out <file>]`
pub fn run(intent_path: &Path, keys_dir: &Path, out_path: Option<&Path>) -> Result<()> {
    let intent = load_intent(intent_path)?;
    let paths = KeyPaths::new(keys_dir);
    let ed = Ed25519Keypair::load(&paths)?;
    let falcon = FalconKeypair::load(&paths)?;

    let bundle = sign_intent(intent, &ed, &falcon)?;
    let json = serde_json::to_vec_pretty(&bundle)?;

    match out_path {
        Some(path) => {
            std::fs::write(path, &json).map_err(|e| ClientError::io(path, e))?;
            println!("Digest:                 {}", bundle.digest);
            println!(
                "Falcon signature:       {} encoded + {} padding = 666 bytes",
                bundle.falcon512_signature_encoded_len, bundle.falcon512_signature_padding_len
            );
            println!("Signed bundle written:  {}", path.display());
        }
        None => {
            println!("{}", String::from_utf8_lossy(&json));
        }
    }
    Ok(())
}

/// `dualkey verify --input <bundle.json>`
pub fn verify(input_path: &Path) -> Result<()> {
    let bytes = std::fs::read(input_path).map_err(|e| ClientError::io(input_path, e))?;
    let bundle: SignedBundle = serde_json::from_slice(&bytes)?;

    let report = verify_bundle(&bundle)?;
    print!("{}", report.render());

    if !report.all_valid() {
        return Err(ClientError::VerificationFailed(
            "one or more checks did not pass".to_string(),
        ));
    }
    Ok(())
}
