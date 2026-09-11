//! `dualkey keygen`.
//!
//! Generates an Ed25519 keypair and a Falcon-512 keypair, writing every file
//! that contains secret material with Unix mode `0600`.
//!
//! Secret key bytes are never printed and never placed into data destined for
//! the on-chain account. The `falcon512.prepared` artifact is derived solely
//! from the Falcon *public* key.

use std::fs;
use std::path::Path;

use crate::error::{ClientError, Result};
use crate::keys::{Ed25519Keypair, FalconKeypair, KeyPaths, KeySet};

/// Summary of a keygen run. Public material only.
#[derive(Debug)]
pub struct KeygenReport {
    pub dir: String,
    pub ed25519_public_key: String,
    pub falcon_public_key_sha256: String,
    pub falcon_public_key_len: usize,
    pub falcon_secret_key_len: usize,
    pub prepared_public_key_len: usize,
    pub secret_files: Vec<String>,
    pub public_files: Vec<String>,
}

impl KeygenReport {
    /// Human-readable summary. Contains no secret material.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Key directory:          {}\n", self.dir));
        s.push_str(&format!(
            "Ed25519 public key:     {}\n",
            self.ed25519_public_key
        ));
        s.push_str(&format!(
            "Falcon pubkey SHA-256:  {}\n",
            self.falcon_public_key_sha256
        ));
        s.push_str(&format!(
            "Falcon public key:      {} bytes\n",
            self.falcon_public_key_len
        ));
        s.push_str(&format!(
            "Falcon secret key:      {} bytes (not shown)\n",
            self.falcon_secret_key_len
        ));
        s.push_str(&format!(
            "Prepared public key:    {} bytes\n",
            self.prepared_public_key_len
        ));
        s.push_str(&format!(
            "Private files (0600):   {}\n",
            self.secret_files.join(", ")
        ));
        s.push_str(&format!(
            "Public files:           {}\n",
            self.public_files.join(", ")
        ));
        s
    }
}

/// Generate a fresh DualKey key set into `out_dir`.
pub fn generate(out_dir: &Path) -> Result<KeygenReport> {
    fs::create_dir_all(out_dir).map_err(|e| ClientError::io(out_dir, e))?;
    #[cfg(unix)]
    {
        // The directory itself should not be group/world traversable.
        let perms = std::os::unix::fs::PermissionsExt::from_mode(0o700);
        fs::set_permissions(out_dir, perms).map_err(|e| ClientError::io(out_dir, e))?;
    }

    let paths = KeyPaths::new(out_dir);

    let ed = Ed25519Keypair::generate();
    let falcon = FalconKeypair::generate();

    ed.write(&paths)?;
    falcon.write(&paths)?;

    let keyset = KeySet::build(&ed, &falcon);
    keyset.write(&paths)?;

    Ok(KeygenReport {
        dir: out_dir.display().to_string(),
        ed25519_public_key: hex::encode(ed.public_bytes()),
        falcon_public_key_sha256: keyset.falcon512_public_key_sha256.clone(),
        falcon_public_key_len: pqcrypto_falcon::falcon512::public_key_bytes(),
        falcon_secret_key_len: pqcrypto_falcon::falcon512::secret_key_bytes(),
        prepared_public_key_len: dualkey_core::PREPARED_FALCON_PUBKEY_LEN,
        secret_files: crate::keys::SECRET_FILES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        public_files: vec![
            crate::keys::ED25519_PK_FILE.to_string(),
            crate::keys::FALCON_PK_FILE.to_string(),
            crate::keys::FALCON_PREPARED_FILE.to_string(),
            crate::keys::KEYSET_FILE.to_string(),
        ],
    })
}

/// CLI entry point.
pub fn run(out_dir: &Path) -> Result<()> {
    let report = generate(out_dir)?;
    print!("{}", report.render());
    Ok(())
}
