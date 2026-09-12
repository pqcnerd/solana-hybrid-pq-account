//! SPL Token CPI helpers for `TransferSpl`.
//!
//! Accepts classic SPL Token **or** Token-2022 for base (non-hook) accounts.
//! Transfer-hook extensions are refused — DualKey does not resolve extra metas.
//! Instruction bytes are hand-rolled (no `spl-token` dep in the program).

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

/// Token-2022 program id (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Packed SPL Token account length (base, no extensions).
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// Packed SPL Mint length (base, no extensions).
pub const MINT_LEN: usize = 82;
/// Multisig packed length — Token-2022 may pad base state up to this before TLV.
const MULTISIG_LEN: usize = 355;

/// `TransferChecked` instruction discriminator (same for Token and Token-2022).
const IX_TRANSFER_CHECKED: u8 = 12;

/// `ExtensionType::TransferHook` (mint-side).
const EXT_TRANSFER_HOOK: u16 = 14;
/// `ExtensionType::TransferHookAccount` (token-account-side).
const EXT_TRANSFER_HOOK_ACCOUNT: u16 = 15;

mod token_account_offsets {
    pub const MINT: usize = 0;
    pub const OWNER: usize = 32;
    pub const AMOUNT: usize = 64;
}

mod mint_offsets {
    pub const DECIMALS: usize = 44;
}

fn is_supported_token_program(id: &Pubkey) -> bool {
    *id == TOKEN_PROGRAM_ID || *id == TOKEN_2022_PROGRAM_ID
}

/// Walk Token-2022 TLV after the base mint/account blob; reject transfer hooks.
///
/// Layout: `[base || optional zero-pad to 355 || AccountType(1) || TLV…]`.
/// Classic Token accounts are exactly `base_len` and skip this check.
fn reject_if_transfer_hook(data: &[u8], base_len: usize) -> Result<(), DualKeyError> {
    if data.len() <= base_len {
        return Ok(());
    }

    let mut tlv_start = base_len;
    // Optional padding between base and account-type (Token-2022 convention).
    if data.len() > MULTISIG_LEN
        && base_len < MULTISIG_LEN
        && data[base_len..MULTISIG_LEN].iter().all(|&b| b == 0)
    {
        tlv_start = MULTISIG_LEN;
    }
    // AccountType byte.
    if tlv_start >= data.len() {
        return Ok(());
    }
    tlv_start += 1;

    let mut i = tlv_start;
    while i + 4 <= data.len() {
        let mut ty_buf = [0u8; 2];
        ty_buf.copy_from_slice(&data[i..i + 2]);
        let ext_type = u16::from_le_bytes(ty_buf);
        let mut len_buf = [0u8; 2];
        len_buf.copy_from_slice(&data[i + 2..i + 4]);
        let ext_len = u16::from_le_bytes(len_buf) as usize;
        i += 4;
        if i + ext_len > data.len() {
            return Err(DualKeyError::InvalidAccountData);
        }
        if ext_type == EXT_TRANSFER_HOOK || ext_type == EXT_TRANSFER_HOOK_ACCOUNT {
            msg!("DualKey: Token-2022 transfer-hook accounts are not supported");
            return Err(DualKeyError::InvalidAccountData);
        }
        // Uninitialized (0) with zero length ends some TLV buffers; keep scanning
        // only while there is a real payload or a non-zero type.
        if ext_type == 0 && ext_len == 0 {
            break;
        }
        i += ext_len;
    }
    Ok(())
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
    if !is_supported_token_program(token_program.key) {
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
        reject_if_transfer_hook(&mint_data, MINT_LEN)?;
        mint_data[mint_offsets::DECIMALS]
    };

    {
        let source_data = source
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if source_data.len() < TOKEN_ACCOUNT_LEN {
            return Err(DualKeyError::InvalidAccountData);
        }
        reject_if_transfer_hook(&source_data, TOKEN_ACCOUNT_LEN)?;
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
        reject_if_transfer_hook(&dest_data, TOKEN_ACCOUNT_LEN)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_len_accounts_pass_hook_check() {
        assert!(reject_if_transfer_hook(&[0u8; MINT_LEN], MINT_LEN).is_ok());
        assert!(reject_if_transfer_hook(&[0u8; TOKEN_ACCOUNT_LEN], TOKEN_ACCOUNT_LEN).is_ok());
    }

    #[test]
    fn transfer_hook_mint_tlv_is_rejected() {
        // mint base || AccountType(Mint=1) || TLV TransferHook
        let mut data = vec![0u8; MINT_LEN];
        data.push(1); // AccountType::Mint
        data.extend_from_slice(&EXT_TRANSFER_HOOK.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes()); // program id length
        data.extend_from_slice(&[0xAB; 32]);
        assert!(reject_if_transfer_hook(&data, MINT_LEN).is_err());
    }
}
