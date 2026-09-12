//! HybridAccount PDA derivation.
//!
//! Seeds are `["dualkey", creator, account_index_le]`, built by
//! [`dualkey_core::pda_seeds`] so the program and the off-chain client cannot
//! disagree on their order or encoding.

use dualkey_core::{pda_seeds, DualKeyError, ACCOUNT_INDEX_LEN, PDA_SEED_COUNT};
use solana_pubkey::Pubkey;

/// Full signer seeds: the three address seeds plus the bump.
pub const SIGNER_SEED_COUNT: usize = PDA_SEED_COUNT + 1;

/// Derive the HybridAccount address and its **canonical** bump.
///
/// On-chain this is a single `sol_try_find_program_address` syscall, which
/// performs the whole bump search inside the runtime.
pub fn derive(
    program_id: &Pubkey,
    creator: &Pubkey,
    account_index: u32,
) -> Result<(Pubkey, u8), DualKeyError> {
    let creator_bytes = creator.to_bytes();
    let index_le = account_index.to_le_bytes();
    let seeds = pda_seeds(&creator_bytes, &index_le);
    Pubkey::try_find_program_address(&seeds, program_id).ok_or(DualKeyError::InvalidPda)
}

/// Check that `expected` is the canonically-derived HybridAccount address, and
/// return the bump needed to sign for it.
///
/// The bump is derived here rather than accepted from instruction data. Taking a
/// caller-supplied bump would let a caller present a *non-canonical* bump, which
/// yields a different but still valid program address for the same logical
/// `(creator, account_index)` — allowing several accounts where the design
/// intends exactly one. Deriving it makes that impossible.
pub fn verify(
    program_id: &Pubkey,
    creator: &Pubkey,
    account_index: u32,
    expected: &Pubkey,
) -> Result<u8, DualKeyError> {
    let (address, bump) = derive(program_id, creator, account_index)?;
    if address != *expected {
        return Err(DualKeyError::InvalidPda);
    }
    Ok(bump)
}

/// Owned storage for the signer seeds, which must outlive the `invoke_signed`
/// call that borrows them.
pub struct SignerSeeds {
    creator: [u8; 32],
    index_le: [u8; ACCOUNT_INDEX_LEN],
    bump: [u8; 1],
}

impl SignerSeeds {
    pub fn new(creator: &Pubkey, account_index: u32, bump: u8) -> Self {
        Self {
            creator: creator.to_bytes(),
            index_le: account_index.to_le_bytes(),
            bump: [bump],
        }
    }

    /// Borrow as `["dualkey", creator, account_index_le, [bump]]`.
    pub fn as_slices(&self) -> [&[u8]; SIGNER_SEED_COUNT] {
        let [prefix, creator, index] = pda_seeds(&self.creator, &self.index_le);
        [prefix, creator, index, self.bump.as_slice()]
    }
}
