//! Key file layout and I/O.
//!
//! # On-disk format (all raw binary, no encoding)
//!
//! | File | Bytes | Mode | Contents |
//! |------|------:|------|----------|
//! | `ed25519.sk` | 32 | `0600` | Ed25519 seed (RFC 8032 private key) |
//! | `ed25519.pk` | 32 | `0644` | Ed25519 public key |
//! | `ed25519-id.json` | JSON | `0600` | Solana-style 64-byte array (seed ‖ pubkey) |
//! | `falcon512.sk` | 1281 | `0600` | PQClean falcon-512 secret key |
//! | `falcon512.pk` | 897 | `0644` | PQClean falcon-512 public key (wire format) |
//! | `falcon512.prepared` | 1024 | `0644` | NTT-form public key for account data |
//! | `keyset.json` | JSON | `0644` | Public manifest (no secret material) |
//!
//! Raw binary is used for key material so the files are directly consumable
//! by `include_bytes!` and by the on-chain verifier's wire parsers.
//!
//! `falcon512.prepared` is derived purely from the public key. It is the exact
//! 1024 bytes written into the DualKey account, and contains **no** secret
//! material.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

use crate::error::{ClientError, Result};

/// Unix mode for files containing secret material.
pub const SECRET_MODE: u32 = 0o600;
/// Unix mode for public files.
pub const PUBLIC_MODE: u32 = 0o644;

pub const ED25519_SK_FILE: &str = "ed25519.sk";
pub const ED25519_PK_FILE: &str = "ed25519.pk";
pub const ED25519_ID_FILE: &str = "ed25519-id.json";
pub const FALCON_SK_FILE: &str = "falcon512.sk";
pub const FALCON_PK_FILE: &str = "falcon512.pk";
pub const FALCON_PREPARED_FILE: &str = "falcon512.prepared";
pub const KEYSET_FILE: &str = "keyset.json";

/// Every file that holds secret material and therefore requires mode `0600`.
pub const SECRET_FILES: [&str; 3] = [ED25519_SK_FILE, ED25519_ID_FILE, FALCON_SK_FILE];

/// Paths for a DualKey key directory.
#[derive(Clone, Debug)]
pub struct KeyPaths {
    pub dir: PathBuf,
}

impl KeyPaths {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn ed25519_sk(&self) -> PathBuf {
        self.dir.join(ED25519_SK_FILE)
    }
    pub fn ed25519_pk(&self) -> PathBuf {
        self.dir.join(ED25519_PK_FILE)
    }
    pub fn ed25519_id(&self) -> PathBuf {
        self.dir.join(ED25519_ID_FILE)
    }
    pub fn falcon_sk(&self) -> PathBuf {
        self.dir.join(FALCON_SK_FILE)
    }
    pub fn falcon_pk(&self) -> PathBuf {
        self.dir.join(FALCON_PK_FILE)
    }
    pub fn falcon_prepared(&self) -> PathBuf {
        self.dir.join(FALCON_PREPARED_FILE)
    }
    pub fn keyset(&self) -> PathBuf {
        self.dir.join(KEYSET_FILE)
    }
}

/// Write a file, creating it with the requested Unix mode before any bytes are
/// written, so secret material is never briefly world-readable.
pub fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .map_err(|e| ClientError::io(path, e))?;
        file.write_all(bytes)
            .map_err(|e| ClientError::io(path, e))?;
        file.sync_all().map_err(|e| ClientError::io(path, e))?;
        // Re-assert the mode in case the file already existed with looser bits.
        let perms = std::os::unix::fs::PermissionsExt::from_mode(mode);
        fs::set_permissions(path, perms).map_err(|e| ClientError::io(path, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::write(path, bytes).map_err(|e| ClientError::io(path, e))?;
    }
    Ok(())
}

/// Read a file expected to be exactly `expected` bytes long.
pub fn read_exact_len(path: &Path, expected: usize) -> Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|e| ClientError::io(path, e))?;
    if bytes.len() != expected {
        return Err(ClientError::KeyFileLength {
            path: path.display().to_string(),
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Unix mode bits (permission bits only) of a path.
#[cfg(unix)]
pub fn file_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).map_err(|e| ClientError::io(path, e))?;
    Ok(meta.mode() & 0o777)
}

/// Ed25519 keypair held in memory.
///
/// Deliberately has no `Debug` impl so the secret cannot be printed
/// accidentally via `{:?}`.
pub struct Ed25519Keypair {
    signing: SigningKey,
}

impl Ed25519Keypair {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        // Clear the stack copy of the seed.
        seed.fill(0);
        Self { signing }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; SECRET_KEY_LENGTH] = seed
            .try_into()
            .map_err(|_| ClientError::Ed25519Key("seed must be 32 bytes"))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Solana-style 64-byte keypair array: seed followed by public key.
    fn id_json_bytes(&self) -> Vec<u8> {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&self.signing.to_bytes());
        combined.extend_from_slice(&self.public_bytes());
        combined
    }

    /// Write `ed25519.sk` (0600), `ed25519.pk` (0644), `ed25519-id.json` (0600).
    pub fn write(&self, paths: &KeyPaths) -> Result<()> {
        write_with_mode(&paths.ed25519_sk(), &self.signing.to_bytes(), SECRET_MODE)?;
        write_with_mode(&paths.ed25519_pk(), &self.public_bytes(), PUBLIC_MODE)?;

        let id = self.id_json_bytes();
        let json = serde_json::to_vec(&id)?;
        write_with_mode(&paths.ed25519_id(), &json, SECRET_MODE)?;
        Ok(())
    }

    /// Load from `ed25519.sk`.
    pub fn load(paths: &KeyPaths) -> Result<Self> {
        let seed = read_exact_len(&paths.ed25519_sk(), SECRET_KEY_LENGTH)?;
        Self::from_seed(&seed)
    }
}

/// Falcon-512 keypair held in memory.
///
/// No `Debug` impl is derived; PQClean's own `Debug` only prints a byte count,
/// but this type avoids exposing one at all.
pub struct FalconKeypair {
    public: falcon512::PublicKey,
    secret: falcon512::SecretKey,
}

impl FalconKeypair {
    pub fn generate() -> Self {
        let (public, secret) = falcon512::keypair();
        Self { public, secret }
    }

    pub fn public(&self) -> &falcon512::PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &falcon512::SecretKey {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8] {
        self.public.as_bytes()
    }

    /// Write `falcon512.sk` (0600), `falcon512.pk` (0644),
    /// `falcon512.prepared` (0644).
    ///
    /// The prepared file is derived only from the public key.
    pub fn write(&self, paths: &KeyPaths) -> Result<()> {
        write_with_mode(&paths.falcon_sk(), self.secret.as_bytes(), SECRET_MODE)?;
        write_with_mode(&paths.falcon_pk(), self.public.as_bytes(), PUBLIC_MODE)?;

        let prepared = crate::falcon_interop::prepare_pubkey(self.public.as_bytes())?;
        write_with_mode(&paths.falcon_prepared(), prepared.as_bytes(), PUBLIC_MODE)?;
        Ok(())
    }

    pub fn load(paths: &KeyPaths) -> Result<Self> {
        let sk_bytes = read_exact_len(&paths.falcon_sk(), falcon512::secret_key_bytes())?;
        let pk_bytes = read_exact_len(&paths.falcon_pk(), falcon512::public_key_bytes())?;
        let secret = falcon512::SecretKey::from_bytes(&sk_bytes)
            .map_err(|_| ClientError::FalconKey("PQClean rejected the secret key encoding"))?;
        let public = falcon512::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| ClientError::FalconKey("PQClean rejected the public key encoding"))?;
        Ok(Self { public, secret })
    }
}

/// Public key material only, loaded without opening any secret key file.
///
/// Building on-chain instructions needs the Ed25519 owner key and the Falcon
/// wire public key and nothing else. Loading through this type rather than
/// [`Ed25519Keypair::load`] / [`FalconKeypair::load`] means the `Initialize`
/// path never reads, and so can never leak, secret bytes.
#[derive(Clone)]
pub struct PublicKeys {
    ed25519: [u8; 32],
    falcon_wire: Vec<u8>,
}

impl PublicKeys {
    pub fn load(paths: &KeyPaths) -> Result<Self> {
        let ed = read_exact_len(&paths.ed25519_pk(), 32)?;
        let falcon_wire = read_exact_len(&paths.falcon_pk(), falcon512::public_key_bytes())?;
        let ed25519: [u8; 32] = ed
            .try_into()
            .map_err(|_| ClientError::Ed25519Key("public key must be 32 bytes"))?;
        Ok(Self {
            ed25519,
            falcon_wire,
        })
    }

    pub fn ed25519(&self) -> &[u8; 32] {
        &self.ed25519
    }

    pub fn falcon_wire(&self) -> &[u8] {
        &self.falcon_wire
    }

    /// SHA-256 of the Falcon wire public key, as stored in account data.
    pub fn falcon_public_key_hash(&self) -> [u8; 32] {
        sha256(&self.falcon_wire)
    }
}

/// Public key manifest. Contains no secret material.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeySet {
    pub format: String,
    pub ed25519_public_key: String,
    pub falcon512_public_key: String,
    pub falcon512_public_key_sha256: String,
    pub falcon512_prepared_public_key_len: usize,
    pub notes: String,
}

impl KeySet {
    pub fn build(ed: &Ed25519Keypair, falcon: &FalconKeypair) -> Self {
        Self {
            format: "dualkey-keyset-v1".to_string(),
            ed25519_public_key: hex::encode(ed.public_bytes()),
            falcon512_public_key: hex::encode(falcon.public_bytes()),
            falcon512_public_key_sha256: hex::encode(sha256(falcon.public_bytes())),
            falcon512_prepared_public_key_len: dualkey_core::PREPARED_FALCON_PUBKEY_LEN,
            notes: "Public material only. Secret keys live in 0600 files and never on-chain."
                .to_string(),
        }
    }

    pub fn write(&self, paths: &KeyPaths) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        write_with_mode(&paths.keyset(), &json, PUBLIC_MODE)
    }

    pub fn load(paths: &KeyPaths) -> Result<Self> {
        let path = paths.keyset();
        let bytes = fs::read(&path).map_err(|e| ClientError::io(&path, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// SHA-256 helper for public material (Falcon public key hash).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
