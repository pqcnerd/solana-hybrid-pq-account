//! Fixed-size DualKey account layout (1120 bytes).
//!
//! No `Vec`, no Borsh. Explicit offsets so the prepared Falcon pubkey can be
//! borrowed zero-copy at an 8-byte-aligned offset (required by
//! `solana-falcon512::Falcon512PreparedPubkey::try_from_slice`).
//!
//! ```text
//! Offset  Size  Field
//! 0       1     version
//! 1       1     bump
//! 2       1     policy
//! 3       1     flags
//! 4       4     reserved
//! 8       32    owner_ed25519
//! 40      32    falcon_public_key_hash
//! 72      8     nonce (u64 LE)
//! 80      8     falcon_required_above (u64 LE; meaningful iff FLAG_FALCON_THRESHOLD_SET)
//! 88      8     reserved
//! 96      1024  prepared_falcon_public_key
//! 1120          end
//! ```

use crate::error::DualKeyError;
use crate::policy::AuthorizationPolicy;

/// PDA seed prefix: `["dualkey", creator, account_index_le]`.
pub const PDA_SEED: &[u8] = b"dualkey";

/// Width of the `account_index` seed (u32 little-endian).
pub const ACCOUNT_INDEX_LEN: usize = 4;

/// Number of seeds before the bump.
pub const PDA_SEED_COUNT: usize = 3;

/// Build the PDA seed list, without the bump.
///
/// The seeds are deliberately **not** derived from any key material. Deriving
/// the address from the Ed25519 or Falcon public key would make the address
/// change when a key rotates, stranding any funds at the old address. Keying on
/// `(creator, account_index)` instead keeps the address stable across the key
/// rotation that Milestone 9 introduces.
///
/// Both the on-chain program and the off-chain client call this, so the two can
/// never disagree on seed order or encoding. Callers append `&[bump]` to obtain
/// the full signer seeds.
pub fn pda_seeds<'a>(
    creator: &'a [u8; 32],
    account_index_le: &'a [u8; ACCOUNT_INDEX_LEN],
) -> [&'a [u8]; PDA_SEED_COUNT] {
    [PDA_SEED, creator.as_slice(), account_index_le.as_slice()]
}

/// On-chain account data length.
pub const ACCOUNT_DATA_LEN: usize = 1120;

/// Length of a prepared Falcon-512 public key (`solana-falcon512`).
pub const PREPARED_FALCON_PUBKEY_LEN: usize = 1024;

/// Wire Falcon-512 public key length (header + packed coefficients).
pub const FALCON_WIRE_PUBKEY_LEN: usize = 897;

/// Compressed Falcon-512 signature buffer length (zero-padded).
pub const FALCON_SIGNATURE_LEN: usize = 666;

/// Account schema version written at initialization.
pub const ACCOUNT_VERSION: u8 = 1;

/// `flags` bit 0: recovery enabled.
pub const FLAG_RECOVERY_ENABLED: u8 = 1 << 0;
/// `flags` bit 1: `falcon_required_above` field is set.
pub const FLAG_FALCON_THRESHOLD_SET: u8 = 1 << 1;

// ---------------------------------------------------------------------------
// Compile-time layout guarantees.
//
// The prepared Falcon public key must occupy exactly the tail of the account
// and must never be able to exceed the fixed account bounds. These assertions
// fail the build (not a test run) if the layout is edited inconsistently.
// ---------------------------------------------------------------------------

/// The prepared-pubkey region ends exactly at the end of the account.
const _: () = assert!(
    offsets::PREPARED_FALCON_PUBLIC_KEY + PREPARED_FALCON_PUBKEY_LEN == ACCOUNT_DATA_LEN,
    "prepared Falcon pubkey region must end exactly at the account boundary"
);

/// The region cannot overflow the account.
const _: () = assert!(
    offsets::PREPARED_FALCON_PUBLIC_KEY + PREPARED_FALCON_PUBKEY_LEN <= ACCOUNT_DATA_LEN,
    "prepared Falcon pubkey region exceeds fixed account bounds"
);

/// The region starts after every header field (no overlap with the header).
const _: () = assert!(
    offsets::PREPARED_FALCON_PUBLIC_KEY >= offsets::RESERVED1 + 8,
    "prepared Falcon pubkey region overlaps the account header"
);

/// `solana-falcon512` borrows the prepared pubkey zero-copy and requires at
/// least 2-byte alignment. Solana account data is 8-byte aligned by ABI, so an
/// 8-byte-aligned offset always satisfies it.
const _: () = assert!(
    offsets::PREPARED_FALCON_PUBLIC_KEY.is_multiple_of(8),
    "prepared Falcon pubkey offset must be 8-byte aligned for zero-copy borrow"
);

/// Prepared form is 512 u16 NTT coefficients.
const _: () = assert!(PREPARED_FALCON_PUBKEY_LEN == 512 * 2);

pub mod offsets {
    pub const VERSION: usize = 0;
    pub const BUMP: usize = 1;
    pub const POLICY: usize = 2;
    pub const FLAGS: usize = 3;
    pub const RESERVED0: usize = 4;
    pub const OWNER_ED25519: usize = 8;
    pub const FALCON_PUBLIC_KEY_HASH: usize = 40;
    pub const NONCE: usize = 72;
    pub const FALCON_REQUIRED_ABOVE: usize = 80;
    pub const RESERVED1: usize = 88;
    pub const PREPARED_FALCON_PUBLIC_KEY: usize = 96;
}

/// Zero-copy view over DualKey account data.
///
/// Does not allocate. All mutators write through the provided buffer.
#[derive(Debug)]
pub struct HybridAccount<'a> {
    data: &'a mut [u8],
}

impl HybridAccount<'_> {
    /// Read `version` from a borrowed account buffer without requiring mutability.
    pub fn version_from_slice(data: &[u8]) -> Result<u8, DualKeyError> {
        if data.len() != ACCOUNT_DATA_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        Ok(data[offsets::VERSION])
    }

    /// Read `nonce` from a borrowed account buffer without requiring mutability.
    pub fn nonce_from_slice(data: &[u8]) -> Result<u64, DualKeyError> {
        if data.len() != ACCOUNT_DATA_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[offsets::NONCE..offsets::NONCE + 8]);
        Ok(u64::from_le_bytes(buf))
    }
}

impl<'a> HybridAccount<'a> {
    /// Borrow account bytes as a DualKey account.
    ///
    /// Returns [`DualKeyError::InvalidAccountData`] if length != [`ACCOUNT_DATA_LEN`].
    pub fn try_from_bytes(data: &'a mut [u8]) -> Result<Self, DualKeyError> {
        if data.len() != ACCOUNT_DATA_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        Ok(Self { data })
    }

    /// Immutable borrow of the full account buffer.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    pub fn version(&self) -> u8 {
        self.data[offsets::VERSION]
    }

    pub fn set_version(&mut self, version: u8) {
        self.data[offsets::VERSION] = version;
    }

    pub fn bump(&self) -> u8 {
        self.data[offsets::BUMP]
    }

    pub fn set_bump(&mut self, bump: u8) {
        self.data[offsets::BUMP] = bump;
    }

    pub fn policy(&self) -> Result<AuthorizationPolicy, DualKeyError> {
        AuthorizationPolicy::from_u8(self.data[offsets::POLICY])
            .ok_or(DualKeyError::InvalidAccountData)
    }

    pub fn set_policy(&mut self, policy: AuthorizationPolicy) {
        self.data[offsets::POLICY] = policy.as_u8();
    }

    pub fn flags(&self) -> u8 {
        self.data[offsets::FLAGS]
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.data[offsets::FLAGS] = flags;
    }

    pub fn recovery_enabled(&self) -> bool {
        self.flags() & FLAG_RECOVERY_ENABLED != 0
    }

    pub fn set_recovery_enabled(&mut self, enabled: bool) {
        let mut flags = self.flags();
        if enabled {
            flags |= FLAG_RECOVERY_ENABLED;
        } else {
            flags &= !FLAG_RECOVERY_ENABLED;
        }
        self.set_flags(flags);
    }

    pub fn owner_ed25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offsets::OWNER_ED25519..offsets::OWNER_ED25519 + 32]);
        out
    }

    pub fn set_owner_ed25519(&mut self, pubkey: &[u8; 32]) {
        self.data[offsets::OWNER_ED25519..offsets::OWNER_ED25519 + 32].copy_from_slice(pubkey);
    }

    pub fn falcon_public_key_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(
            &self.data[offsets::FALCON_PUBLIC_KEY_HASH..offsets::FALCON_PUBLIC_KEY_HASH + 32],
        );
        out
    }

    pub fn set_falcon_public_key_hash(&mut self, hash: &[u8; 32]) {
        self.data[offsets::FALCON_PUBLIC_KEY_HASH..offsets::FALCON_PUBLIC_KEY_HASH + 32]
            .copy_from_slice(hash);
    }

    pub fn nonce(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[offsets::NONCE..offsets::NONCE + 8]);
        u64::from_le_bytes(buf)
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.data[offsets::NONCE..offsets::NONCE + 8].copy_from_slice(&nonce.to_le_bytes());
    }

    /// Returns `Some(threshold)` when the threshold flag is set.
    pub fn falcon_required_above(&self) -> Option<u64> {
        if self.flags() & FLAG_FALCON_THRESHOLD_SET == 0 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(
            &self.data[offsets::FALCON_REQUIRED_ABOVE..offsets::FALCON_REQUIRED_ABOVE + 8],
        );
        Some(u64::from_le_bytes(buf))
    }

    pub fn set_falcon_required_above(&mut self, threshold: Option<u64>) {
        let mut flags = self.flags();
        match threshold {
            Some(v) => {
                flags |= FLAG_FALCON_THRESHOLD_SET;
                self.data[offsets::FALCON_REQUIRED_ABOVE..offsets::FALCON_REQUIRED_ABOVE + 8]
                    .copy_from_slice(&v.to_le_bytes());
            }
            None => {
                flags &= !FLAG_FALCON_THRESHOLD_SET;
                self.data[offsets::FALCON_REQUIRED_ABOVE..offsets::FALCON_REQUIRED_ABOVE + 8]
                    .fill(0);
            }
        }
        self.set_flags(flags);
    }

    /// Borrow the prepared Falcon public key region (1024 bytes, offset 96).
    pub fn prepared_falcon_public_key(&self) -> &[u8; PREPARED_FALCON_PUBKEY_LEN] {
        self.data[offsets::PREPARED_FALCON_PUBLIC_KEY..ACCOUNT_DATA_LEN]
            .try_into()
            .expect("layout guarantees 1024 bytes")
    }

    /// Mutable borrow of the prepared Falcon public key region.
    pub fn prepared_falcon_public_key_mut(&mut self) -> &mut [u8; PREPARED_FALCON_PUBKEY_LEN] {
        (&mut self.data[offsets::PREPARED_FALCON_PUBLIC_KEY..ACCOUNT_DATA_LEN])
            .try_into()
            .expect("layout guarantees 1024 bytes")
    }

    /// Initialize every field **except** the prepared Falcon public key, whose
    /// region is left zeroed for the caller to fill in place.
    ///
    /// The on-chain program uses this rather than [`HybridAccount::initialize`]
    /// so the 1024-byte prepared key is never materialized in the calling stack
    /// frame: SBF allows only 4 KB per frame, and `try_prepare_pubkey` returns
    /// the key by value. The caller writes it straight into
    /// [`HybridAccount::prepared_falcon_public_key_mut`] from a separate,
    /// `#[inline(never)]` frame.
    pub fn initialize_without_falcon_key(
        data: &'a mut [u8],
        bump: u8,
        owner_ed25519: &[u8; 32],
        falcon_public_key_hash: &[u8; 32],
        policy: AuthorizationPolicy,
    ) -> Result<Self, DualKeyError> {
        if data.len() != ACCOUNT_DATA_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        data.fill(0);
        let mut account = Self { data };
        account.set_version(ACCOUNT_VERSION);
        account.set_bump(bump);
        account.set_policy(policy);
        account.set_owner_ed25519(owner_ed25519);
        account.set_falcon_public_key_hash(falcon_public_key_hash);
        account.set_nonce(0);
        Ok(account)
    }

    /// Initialize a fresh account buffer (caller must zero or provide empty data).
    pub fn initialize(
        data: &'a mut [u8],
        bump: u8,
        owner_ed25519: &[u8; 32],
        falcon_public_key_hash: &[u8; 32],
        prepared_falcon_public_key: &[u8; PREPARED_FALCON_PUBKEY_LEN],
        policy: AuthorizationPolicy,
    ) -> Result<Self, DualKeyError> {
        let mut account = Self::initialize_without_falcon_key(
            data,
            bump,
            owner_ed25519,
            falcon_public_key_hash,
            policy,
        )?;
        account
            .prepared_falcon_public_key_mut()
            .copy_from_slice(prepared_falcon_public_key);
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_length_and_prepared_offset() {
        assert_eq!(ACCOUNT_DATA_LEN, 1120);
        assert_eq!(offsets::PREPARED_FALCON_PUBLIC_KEY, 96);
        assert_eq!(offsets::PREPARED_FALCON_PUBLIC_KEY % 8, 0);
        assert_eq!(
            offsets::PREPARED_FALCON_PUBLIC_KEY + PREPARED_FALCON_PUBKEY_LEN,
            ACCOUNT_DATA_LEN
        );
    }

    /// The prepared-pubkey accessors must address exactly the intended region
    /// and must not be able to read or write outside the fixed account bounds.
    #[test]
    fn prepared_pubkey_region_is_exact_and_bounded() {
        let mut buf = [0u8; ACCOUNT_DATA_LEN];
        // Mark the whole buffer, then overwrite only the prepared region.
        buf.fill(0xAB);
        {
            let mut acct = HybridAccount::try_from_bytes(&mut buf).unwrap();
            acct.prepared_falcon_public_key_mut().fill(0xCD);
        }

        // Header bytes (0..96) untouched.
        assert!(
            buf[..offsets::PREPARED_FALCON_PUBLIC_KEY]
                .iter()
                .all(|&b| b == 0xAB),
            "writing the prepared pubkey must not touch the account header"
        );
        // Prepared region (96..1120) fully written.
        assert!(
            buf[offsets::PREPARED_FALCON_PUBLIC_KEY..]
                .iter()
                .all(|&b| b == 0xCD),
            "prepared pubkey region must cover 96..1120 exactly"
        );
        // Region length is exactly the prepared-pubkey length.
        assert_eq!(
            buf.len() - offsets::PREPARED_FALCON_PUBLIC_KEY,
            PREPARED_FALCON_PUBKEY_LEN
        );
    }

    /// Falcon wire lengths that the client and program both rely on.
    #[test]
    fn falcon_length_constants() {
        assert_eq!(FALCON_WIRE_PUBKEY_LEN, 897);
        assert_eq!(FALCON_SIGNATURE_LEN, 666);
        assert_eq!(PREPARED_FALCON_PUBKEY_LEN, 1024);
        // Prepared form costs 127 extra bytes vs the wire pubkey.
        assert_eq!(PREPARED_FALCON_PUBKEY_LEN - FALCON_WIRE_PUBKEY_LEN, 127);
    }

    #[test]
    fn initialize_roundtrip() {
        let mut buf = [0u8; ACCOUNT_DATA_LEN];
        let owner = [7u8; 32];
        let hash = [9u8; 32];
        let prepared = [3u8; PREPARED_FALCON_PUBKEY_LEN];
        let mut acct = HybridAccount::initialize(
            &mut buf,
            255,
            &owner,
            &hash,
            &prepared,
            AuthorizationPolicy::HybridAnd,
        )
        .unwrap();
        assert_eq!(acct.version(), ACCOUNT_VERSION);
        assert_eq!(acct.bump(), 255);
        assert_eq!(acct.policy().unwrap(), AuthorizationPolicy::HybridAnd);
        assert_eq!(acct.owner_ed25519(), owner);
        assert_eq!(acct.falcon_public_key_hash(), hash);
        assert_eq!(acct.nonce(), 0);
        assert_eq!(acct.prepared_falcon_public_key(), &prepared);
        acct.set_nonce(42);
        assert_eq!(acct.nonce(), 42);
        acct.set_falcon_required_above(Some(1_000_000));
        assert_eq!(acct.falcon_required_above(), Some(1_000_000));
        acct.set_falcon_required_above(None);
        assert_eq!(acct.falcon_required_above(), None);
    }

    #[test]
    fn rejects_wrong_length() {
        let mut buf = [0u8; 16];
        assert_eq!(
            HybridAccount::try_from_bytes(&mut buf).unwrap_err(),
            DualKeyError::InvalidAccountData
        );
    }
}
