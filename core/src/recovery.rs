//! Social recovery config PDA layout and guardian digest (Milestone 15).
//!
//! Seeds: `["dualkey-rec", hybrid_account]`. Fixed 128-byte account.

#[cfg(feature = "sha2")]
use crate::canonical::DIGEST_LEN;
use crate::canonical::{DOMAIN_TAG, DOMAIN_TAG_LEN};
use crate::error::DualKeyError;

/// PDA seed prefix for [`RecoveryConfig`].
pub const RECOVERY_PDA_SEED: &[u8] = b"dualkey-rec";

/// Number of seeds before the bump.
pub const RECOVERY_PDA_SEED_COUNT: usize = 2;

/// Fixed RecoveryConfig account size.
pub const RECOVERY_CONFIG_LEN: usize = 128;

/// Schema version written at initialization.
pub const RECOVERY_CONFIG_VERSION: u8 = 1;

/// Build RecoveryConfig PDA seeds (without bump).
pub fn recovery_pda_seeds(hybrid_account: &[u8; 32]) -> [&[u8]; RECOVERY_PDA_SEED_COUNT] {
    [RECOVERY_PDA_SEED, hybrid_account.as_slice()]
}

pub mod recovery_offsets {
    pub const VERSION: usize = 0;
    pub const BUMP: usize = 1;
    pub const FLAGS: usize = 2;
    pub const RESERVED0: usize = 3;
    pub const GUARDIAN_ED25519: usize = 4;
    pub const DELAY_SLOTS: usize = 36;
    pub const PENDING_NEW_ED25519: usize = 44;
    pub const PENDING_READY_SLOT: usize = 76;
    pub const RESERVED1: usize = 84;
}

const _: () = assert!(recovery_offsets::RESERVED1 + 44 == RECOVERY_CONFIG_LEN);

/// ASCII tag inside the social-recover preimage (after the DualKey domain tag).
pub const SOCIAL_RECOVER_TAG: &[u8] = b"SOCIAL_RECOVER";
/// Length of [`SOCIAL_RECOVER_TAG`].
pub const SOCIAL_RECOVER_TAG_LEN: usize = 14;

/// Social-recover signing preimage length:
/// ```text
/// 1+17 domain + 1 tag_len + 14 SOCIAL_RECOVER + 32 chain + 32 program
/// + 32 account + 32 new_ed25519 + 8 nonce = 169
/// ```
pub const SOCIAL_RECOVER_PREIMAGE_LEN: usize = 169;

const _: () = assert!(SOCIAL_RECOVER_TAG_LEN == 14);

/// Build the fixed preimage the guardian Ed25519-signs to initiate social recovery.
pub fn social_recover_preimage(
    chain_domain: &[u8; 32],
    program_id: &[u8; 32],
    account: &[u8; 32],
    new_ed25519: &[u8; 32],
    nonce: u64,
) -> [u8; SOCIAL_RECOVER_PREIMAGE_LEN] {
    let mut out = [0u8; SOCIAL_RECOVER_PREIMAGE_LEN];
    out[0] = DOMAIN_TAG_LEN as u8;
    out[1..1 + DOMAIN_TAG_LEN].copy_from_slice(DOMAIN_TAG);
    let mut i = 1 + DOMAIN_TAG_LEN;
    out[i] = SOCIAL_RECOVER_TAG_LEN as u8;
    i += 1;
    out[i..i + SOCIAL_RECOVER_TAG_LEN].copy_from_slice(SOCIAL_RECOVER_TAG);
    i += SOCIAL_RECOVER_TAG_LEN;
    out[i..i + 32].copy_from_slice(chain_domain);
    i += 32;
    out[i..i + 32].copy_from_slice(program_id);
    i += 32;
    out[i..i + 32].copy_from_slice(account);
    i += 32;
    out[i..i + 32].copy_from_slice(new_ed25519);
    i += 32;
    out[i..i + 8].copy_from_slice(&nonce.to_le_bytes());
    debug_assert_eq!(i + 8, SOCIAL_RECOVER_PREIMAGE_LEN);
    out
}

/// Host digest of [`social_recover_preimage`].
#[cfg(feature = "sha2")]
pub fn social_recover_digest(
    chain_domain: &[u8; 32],
    program_id: &[u8; 32],
    account: &[u8; 32],
    new_ed25519: &[u8; 32],
    nonce: u64,
) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let preimage = social_recover_preimage(chain_domain, program_id, account, new_ed25519, nonce);
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Zero-copy view over RecoveryConfig account data.
#[derive(Debug)]
pub struct RecoveryConfig<'a> {
    data: &'a mut [u8],
}

impl RecoveryConfig<'_> {
    pub fn try_from_bytes(data: &mut [u8]) -> Result<RecoveryConfig<'_>, DualKeyError> {
        if data.len() != RECOVERY_CONFIG_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        if data[recovery_offsets::VERSION] != RECOVERY_CONFIG_VERSION {
            return Err(DualKeyError::InvalidAccountData);
        }
        Ok(RecoveryConfig { data })
    }

    /// Initialize a zeroed buffer as a RecoveryConfig.
    pub fn initialize<'a>(
        data: &'a mut [u8],
        bump: u8,
        guardian_ed25519: &[u8; 32],
        delay_slots: u64,
    ) -> Result<RecoveryConfig<'a>, DualKeyError> {
        if data.len() != RECOVERY_CONFIG_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        data.fill(0);
        data[recovery_offsets::VERSION] = RECOVERY_CONFIG_VERSION;
        data[recovery_offsets::BUMP] = bump;
        data[recovery_offsets::GUARDIAN_ED25519..recovery_offsets::GUARDIAN_ED25519 + 32]
            .copy_from_slice(guardian_ed25519);
        data[recovery_offsets::DELAY_SLOTS..recovery_offsets::DELAY_SLOTS + 8]
            .copy_from_slice(&delay_slots.to_le_bytes());
        Ok(RecoveryConfig { data })
    }

    pub fn bump(&self) -> u8 {
        self.data[recovery_offsets::BUMP]
    }

    pub fn guardian_ed25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(
            &self.data[recovery_offsets::GUARDIAN_ED25519..recovery_offsets::GUARDIAN_ED25519 + 32],
        );
        out
    }

    pub fn set_guardian_ed25519(&mut self, guardian: &[u8; 32]) {
        self.data[recovery_offsets::GUARDIAN_ED25519..recovery_offsets::GUARDIAN_ED25519 + 32]
            .copy_from_slice(guardian);
    }

    pub fn delay_slots(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(
            &self.data[recovery_offsets::DELAY_SLOTS..recovery_offsets::DELAY_SLOTS + 8],
        );
        u64::from_le_bytes(buf)
    }

    pub fn set_delay_slots(&mut self, delay: u64) {
        self.data[recovery_offsets::DELAY_SLOTS..recovery_offsets::DELAY_SLOTS + 8]
            .copy_from_slice(&delay.to_le_bytes());
    }

    pub fn pending_new_ed25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(
            &self.data
                [recovery_offsets::PENDING_NEW_ED25519..recovery_offsets::PENDING_NEW_ED25519 + 32],
        );
        out
    }

    pub fn set_pending_new_ed25519(&mut self, key: &[u8; 32]) {
        self.data
            [recovery_offsets::PENDING_NEW_ED25519..recovery_offsets::PENDING_NEW_ED25519 + 32]
            .copy_from_slice(key);
    }

    pub fn pending_ready_slot(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(
            &self.data
                [recovery_offsets::PENDING_READY_SLOT..recovery_offsets::PENDING_READY_SLOT + 8],
        );
        u64::from_le_bytes(buf)
    }

    pub fn set_pending_ready_slot(&mut self, slot: u64) {
        self.data[recovery_offsets::PENDING_READY_SLOT..recovery_offsets::PENDING_READY_SLOT + 8]
            .copy_from_slice(&slot.to_le_bytes());
    }

    pub fn has_pending(&self) -> bool {
        self.pending_new_ed25519() != [0u8; 32]
    }

    pub fn clear_pending(&mut self) {
        self.set_pending_new_ed25519(&[0u8; 32]);
        self.set_pending_ready_slot(0);
    }

    pub fn guardian_from_slice(data: &[u8]) -> Result<[u8; 32], DualKeyError> {
        if data.len() != RECOVERY_CONFIG_LEN
            || data[recovery_offsets::VERSION] != RECOVERY_CONFIG_VERSION
        {
            return Err(DualKeyError::InvalidAccountData);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(
            &data[recovery_offsets::GUARDIAN_ED25519..recovery_offsets::GUARDIAN_ED25519 + 32],
        );
        Ok(out)
    }
}
