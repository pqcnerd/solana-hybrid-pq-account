//! Social recovery: guardian + timelock (Milestone 15).
//!
//! - `SetRecoveryConfig` (6) — DualKey-authorized; creates/updates RecoveryConfig PDA
//! - `InitiateSocialRecovery` (7) — guardian Ed25519 via precompile; no Falcon
//! - `FinalizeSocialRecovery` (8) — permissionless after delay
//! - `CancelSocialRecovery` (9) — DualKey-authorized; clears pending
//!
//! Requires `FLAG_RECOVERY_ENABLED` for initiate / finalize / cancel.
//! Falcon-only `RecoverAccount::RotateEd25519` remains the PQ escape hatch.

use dualkey_core::{
    recovery_pda_seeds, social_recover_preimage, Action, DualKeyError, ExecuteIntentWire,
    HybridAccount, RecoveryConfig, ACCOUNT_DATA_LEN, EXECUTE_INTENT_WIRE_LEN, FALCON_SIGNATURE_LEN,
    RECOVERY_CONFIG_LEN, SOCIAL_RECOVER_PREIMAGE_LEN,
};
use solana_account_info::AccountInfo;
use solana_clock::Clock;
use solana_cpi::invoke_signed;
use solana_get_sysvar::GetSysvar;
use solana_msg::msg;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_system_interface::instruction as system_instruction;

use crate::auth::ed25519::verify_ed25519_precompile;
use crate::authorize;
use crate::hash::sha256;

/// Payload after discriminator for Set / Cancel (same as Execute).
pub const AUTH_PAYLOAD_LEN: usize = EXECUTE_INTENT_WIRE_LEN + FALCON_SIGNATURE_LEN;

const _: () = assert!(1 + AUTH_PAYLOAD_LEN == 716);

/// Derive RecoveryConfig PDA address + bump.
pub fn derive_recovery_config(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
) -> Result<(Pubkey, u8), DualKeyError> {
    let hybrid_bytes = hybrid_account.to_bytes();
    let seeds = recovery_pda_seeds(&hybrid_bytes);
    Pubkey::try_find_program_address(&seeds, program_id).ok_or(DualKeyError::InvalidPda)
}

fn verify_recovery_config_pda(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    recovery_config: &Pubkey,
) -> Result<u8, DualKeyError> {
    let (address, bump) = derive_recovery_config(program_id, hybrid_account)?;
    if address != *recovery_config {
        return Err(DualKeyError::InvalidPda);
    }
    Ok(bump)
}

/// After an Ed25519 owner change: clear social pending if RecoveryConfig exists.
///
/// `recovery_config` must be the RecoveryConfig PDA. Empty/uninitialized is a
/// no-op. If the account is owned by this program, pending is cleared so a
/// later `FinalizeSocialRecovery` cannot overwrite the new owner.
pub fn clear_pending_after_ed25519_owner_change(
    program_id: &Pubkey,
    hybrid_account: &Pubkey,
    recovery_config: &AccountInfo,
) -> Result<(), DualKeyError> {
    verify_recovery_config_pda(program_id, hybrid_account, recovery_config.key)?;
    if recovery_config.data_is_empty() {
        return Ok(());
    }
    if recovery_config.owner != program_id {
        return Err(DualKeyError::InvalidAccountData);
    }
    if !recovery_config.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    let mut data = recovery_config
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut cfg = RecoveryConfig::try_from_bytes(&mut data)?;
    cfg.clear_pending();
    Ok(())
}

struct RecoverySignerSeeds {
    hybrid: [u8; 32],
    bump: [u8; 1],
}

impl RecoverySignerSeeds {
    fn new(hybrid: &Pubkey, bump: u8) -> Self {
        Self {
            hybrid: hybrid.to_bytes(),
            bump: [bump],
        }
    }

    fn as_slices(&self) -> [&[u8]; 3] {
        let [prefix, hybrid] = recovery_pda_seeds(&self.hybrid);
        [prefix, hybrid, self.bump.as_slice()]
    }
}

fn create_recovery_config_account<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    recovery_config: &AccountInfo<'a>,
    hybrid_account: &Pubkey,
    bump: u8,
) -> Result<(), DualKeyError> {
    if !recovery_config.data_is_empty() {
        return Err(DualKeyError::AccountAlreadyInitialized);
    }
    let rent = Rent::get().map_err(|_| DualKeyError::InvalidAccountData)?;
    let lamports = rent.minimum_balance(RECOVERY_CONFIG_LEN);
    let seeds = RecoverySignerSeeds::new(hybrid_account, bump);
    let seed_slices = seeds.as_slices();

    let transfer_ix = system_instruction::transfer(payer.key, recovery_config.key, lamports);
    invoke_signed(&transfer_ix, &[payer.clone(), recovery_config.clone()], &[])
        .map_err(|_| DualKeyError::InsufficientFunds)?;

    let allocate_ix = system_instruction::allocate(recovery_config.key, RECOVERY_CONFIG_LEN as u64);
    invoke_signed(
        &allocate_ix,
        std::slice::from_ref(recovery_config),
        &[&seed_slices],
    )
    .map_err(|_| DualKeyError::InvalidAccountData)?;

    let assign_ix = system_instruction::assign(recovery_config.key, program_id);
    invoke_signed(
        &assign_ix,
        std::slice::from_ref(recovery_config),
        &[&seed_slices],
    )
    .map_err(|_| DualKeyError::InvalidAccountData)?;

    Ok(())
}

/// `SetRecoveryConfig` — create or update guardian + delay under DualKey auth.
pub fn process_set_recovery_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != AUTH_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let [hybrid_account, recovery_config, payer, system_program, instructions_sysvar] = accounts
    else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable || !recovery_config.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    if !payer.is_signer {
        return Err(DualKeyError::MissingSigner);
    }
    if !solana_system_interface::program::check_id(system_program.key) {
        return Err(DualKeyError::InvalidProgramAccount);
    }
    if hybrid_account.owner != program_id || hybrid_account.data_len() != ACCOUNT_DATA_LEN {
        return Err(DualKeyError::InvalidAccountData);
    }

    let bump = verify_recovery_config_pda(program_id, hybrid_account.key, recovery_config.key)?;

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;
    let Action::SetRecoveryConfig {
        guardian_ed25519,
        delay_slots,
    } = wire.action
    else {
        return Err(DualKeyError::UnsupportedAction);
    };
    if guardian_ed25519 == [0u8; 32] {
        return Err(DualKeyError::InvalidAccountData);
    }
    if delay_slots < 1 {
        return Err(DualKeyError::InvalidAccountData);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_sig,
    )?;

    if recovery_config.data_is_empty() {
        create_recovery_config_account(
            program_id,
            payer,
            recovery_config,
            hybrid_account.key,
            bump,
        )?;
        let mut data = recovery_config
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        RecoveryConfig::initialize(&mut data, bump, &guardian_ed25519, delay_slots)?;
    } else {
        if recovery_config.owner != program_id {
            return Err(DualKeyError::InvalidAccountData);
        }
        let mut data = recovery_config
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut cfg = RecoveryConfig::try_from_bytes(&mut data)?;
        if cfg.has_pending() {
            return Err(DualKeyError::InvalidAccountData);
        }
        cfg.set_guardian_ed25519(&guardian_ed25519);
        cfg.set_delay_slots(delay_slots);
    }

    {
        let mut data = hybrid_account
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut account = HybridAccount::try_from_bytes(&mut data)?;
        account.set_nonce(auth.next_nonce);
    }

    msg!(
        "DualKey: SetRecoveryConfig OK; delay_slots={}; nonce {} -> {}",
        delay_slots,
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}

/// `InitiateSocialRecovery` — guardian proposes a new Ed25519 owner.
///
/// Instruction data: `new_ed25519[32]`. Prefixed Ed25519 precompile must sign
/// the social-recover digest under the configured guardian key.
pub fn process_initiate_social_recovery(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != 32 {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let [hybrid_account, recovery_config, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !recovery_config.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    if hybrid_account.owner != program_id || recovery_config.owner != program_id {
        return Err(DualKeyError::InvalidAccountData);
    }
    verify_recovery_config_pda(program_id, hybrid_account.key, recovery_config.key)?;

    let new_ed25519: [u8; 32] = payload
        .try_into()
        .map_err(|_| DualKeyError::MalformedInstructionData)?;
    if new_ed25519 == [0u8; 32] {
        return Err(DualKeyError::InvalidAccountData);
    }

    let data = hybrid_account
        .try_borrow_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    if data.len() != ACCOUNT_DATA_LEN {
        return Err(DualKeyError::InvalidAccountData);
    }
    if !HybridAccount::recovery_enabled_from_slice(&data)? {
        return Err(DualKeyError::InvalidAccountData);
    }
    let current_owner = HybridAccount::owner_ed25519_from_slice(&data)?;
    let nonce = HybridAccount::nonce_from_slice(&data)?;
    drop(data);

    if new_ed25519 == current_owner {
        return Err(DualKeyError::InvalidAccountData);
    }

    let guardian = {
        let cfg_data = recovery_config
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        RecoveryConfig::guardian_from_slice(&cfg_data)?
    };

    let chain_domain = crate::chain_domain::CHAIN_DOMAIN;
    let preimage = social_recover_preimage(
        &chain_domain,
        &program_id.to_bytes(),
        &hybrid_account.key.to_bytes(),
        &new_ed25519,
        nonce,
    );
    debug_assert_eq!(preimage.len(), SOCIAL_RECOVER_PREIMAGE_LEN);
    let digest = sha256(&preimage);
    verify_ed25519_precompile(instructions_sysvar, &guardian, &digest)?;

    let clock = Clock::get().map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut cfg_data = recovery_config
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut cfg = RecoveryConfig::try_from_bytes(&mut cfg_data)?;
    if cfg.has_pending() {
        // Refuse re-initiate so a guardian cannot push pending_ready_slot forward.
        return Err(DualKeyError::InvalidAccountData);
    }
    let ready = clock
        .slot
        .checked_add(cfg.delay_slots())
        .ok_or(DualKeyError::MathOverflow)?;
    cfg.set_pending_new_ed25519(&new_ed25519);
    cfg.set_pending_ready_slot(ready);

    msg!(
        "DualKey: InitiateSocialRecovery pending; ready_slot={}",
        ready
    );
    Ok(())
}

/// `FinalizeSocialRecovery` — permissionless after the timelock.
pub fn process_finalize_social_recovery(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if !payload.is_empty() {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let [hybrid_account, recovery_config] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable || !recovery_config.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    if hybrid_account.owner != program_id || recovery_config.owner != program_id {
        return Err(DualKeyError::InvalidAccountData);
    }
    verify_recovery_config_pda(program_id, hybrid_account.key, recovery_config.key)?;

    {
        let data = hybrid_account
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if !HybridAccount::recovery_enabled_from_slice(&data)? {
            return Err(DualKeyError::InvalidAccountData);
        }
    }

    let clock = Clock::get().map_err(|_| DualKeyError::InvalidAccountData)?;
    let pending = {
        let mut cfg_data = recovery_config
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut cfg = RecoveryConfig::try_from_bytes(&mut cfg_data)?;
        if !cfg.has_pending() {
            return Err(DualKeyError::InvalidAccountData);
        }
        if clock.slot < cfg.pending_ready_slot() {
            return Err(DualKeyError::IntentExpired);
        }
        let pending = cfg.pending_new_ed25519();
        cfg.clear_pending();
        pending
    };

    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::try_from_bytes(&mut data)?;
    let nonce = account.nonce();
    let next = nonce.checked_add(1).ok_or(DualKeyError::MathOverflow)?;
    account.set_owner_ed25519(&pending);
    account.set_nonce(next);

    msg!(
        "DualKey: FinalizeSocialRecovery OK; nonce {} -> {}",
        nonce,
        next
    );
    Ok(())
}

/// `CancelSocialRecovery` — DualKey owner clears pending under current policy.
pub fn process_cancel_social_recovery(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    if payload.len() != AUTH_PAYLOAD_LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }
    let [hybrid_account, recovery_config, instructions_sysvar] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };
    if !hybrid_account.is_writable || !recovery_config.is_writable {
        return Err(DualKeyError::InvalidAccountData);
    }
    if hybrid_account.owner != program_id || recovery_config.owner != program_id {
        return Err(DualKeyError::InvalidAccountData);
    }
    verify_recovery_config_pda(program_id, hybrid_account.key, recovery_config.key)?;

    {
        let data = hybrid_account
            .try_borrow_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        if !HybridAccount::recovery_enabled_from_slice(&data)? {
            return Err(DualKeyError::InvalidAccountData);
        }
    }

    let (wire_bytes, falcon_sig) = authorize::split_wire_and_falcon(payload)?;
    let wire = ExecuteIntentWire::decode(wire_bytes)?;
    if !matches!(wire.action, Action::CancelSocialRecovery) {
        return Err(DualKeyError::UnsupportedAction);
    }

    let auth = authorize::authorize(
        program_id,
        hybrid_account,
        instructions_sysvar,
        &wire,
        falcon_sig,
    )?;

    {
        let mut cfg_data = recovery_config
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut cfg = RecoveryConfig::try_from_bytes(&mut cfg_data)?;
        if !cfg.has_pending() {
            return Err(DualKeyError::InvalidAccountData);
        }
        cfg.clear_pending();
    }

    {
        let mut data = hybrid_account
            .try_borrow_mut_data()
            .map_err(|_| DualKeyError::InvalidAccountData)?;
        let mut account = HybridAccount::try_from_bytes(&mut data)?;
        account.set_nonce(auth.next_nonce);
    }

    msg!(
        "DualKey: CancelSocialRecovery OK; nonce {} -> {}",
        auth.account_nonce,
        auth.next_nonce
    );
    Ok(())
}
