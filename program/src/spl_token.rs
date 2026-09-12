//! SPL Token CPI helpers for `TransferSpl`.
//!
//! Classic SPL Token only (not Token-2022 extensions). Instruction bytes are
//! hand-rolled so the program does not depend on `spl-token` / interface crates.

use dualkey_core::DualKeyError;
use solana_account_info::AccountInfo;
use solana_cpi::invoke_signed;
use solana_instruction::{AccountMeta, Instruction};
use solana_msg::msg;
use solana_pubkey::Pubkey;

use crate::pda;

/// Classic SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
pub const TOKEN_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// Packed SPL Token account length.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// Packed SPL Mint length.
pub const MINT_LEN: usize = 82;

/// `TransferChecked` instruction discriminator.
const IX_TRANSFER_CHECKED: u8 = 12;

mod token_account_offsets {
    pub const MINT: usize = 0;
    pub const OWNER: usize = 32;
    pub const AMOUNT: usize = 64;
}

mod mint_offsets {
    pub const DECIMALS: usize = 44;
}

/// Verify PDA seeds and CPI `transfer_checked` with the HybridAccount as authority.
#[allow(clippy::too_many_arguments)]
pub fn transfer_spl<'a>(
    program_id: &Pubkey,
    hybrid_account: &AccountInfo<'a>,
    creator: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    expected_destination: &[u8; 32],
) -> Result<(), DualKeyError> {
    if destination.key.to_bytes() != *expected_destination {
        return Err(DualKeyError::InvalidAccountData);
    }
    if source.key == destination.key {
        return Err(DualKeyError::InvalidAccountData);
    }
    if token_program.key != &TOKEN_PROGRAM_ID {
        return Err(DualKeyError::InvalidProgramAccount);
    }
    if source.owner != token_program.key
        || destination.owner != token_program.key
        || mint.owner != token_program.key
    {
        return Err(DualKeyError::InvalidAccountData);
    }
    if !source.is_writable || !destination.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let bump = data[dualkey_core::account_offsets::BUMP];
    let account_index = dualkey_core::HybridAccount::account_index_from_slice(&data)?;
    drop(data);

    // Prove creator + stored index + bump reconstruct this HybridAccount PDA.
    let seeds = pda::SignerSeeds::new(creator.key, account_index, bump);
    let seed_slices = seeds.as_slices();
    let derived = Pubkey::create_program_address(&seed_slices, program_id)
        .map_err(|_| DualKeyError::InvalidPda)?;
    if &derived != hybrid_account.key {
        return Err(DualKeyError::InvalidPda);
    }

    let decimals = {
        let mint_data = mint
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if mint_data.len() < MINT_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        mint_data[mint_offsets::DECIMALS]
    };

    {
        let source_data = source
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if source_data.len() < TOKEN_ACCOUNT_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        if source_data[token_account_offsets::MINT..token_account_offsets::MINT + 32]
            != mint.key.to_bytes()
        {
            return Err(DualKeyError::InvalidAccountData);
        }
        if source_data[token_account_offsets::OWNER..token_account_offsets::OWNER + 32]
            != hybrid_account.key.to_bytes()
        {
            return Err(DualKeyError::InvalidAccountData);
        }
        let mut amt_buf = [0u8; 8];
        amt_buf.copy_from_slice(
            &source_data[token_account_offsets::AMOUNT..token_account_offsets::AMOUNT + 8],
        );
        if u64::from_le_bytes(amt_buf) < amount {
            return Err(DualKeyError::InsufficientFunds);
        }
    }
    {
        let dest_data = destination
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if dest_data.len() < TOKEN_ACCOUNT_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        if dest_data[token_account_offsets::MINT..token_account_offsets::MINT + 32]
            != mint.key.to_bytes()
        {
            return Err(DualKeyError::InvalidAccountData);
        }
    }

    if amount == 0 {
        return Ok(());
    }

    let ix = transfer_checked_instruction(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        hybrid_account.key,
        amount,
        decimals,
    );

    invoke_signed(
        &ix,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            hybrid_account.clone(),
            token_program.clone(),
        ],
        &[&seed_slices],
    )
    .map_err(|e| {
        msg!("DualKey: SPL transfer_checked CPI failed: {:?}", e);
        DualKeyError::InsufficientFunds
    })?;

    Ok(())
}

fn transfer_checked_instruction(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = [0u8; 10];
    data[0] = IX_TRANSFER_CHECKED;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    data[9] = decimals;
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: data.to_vec(),
    }
}
