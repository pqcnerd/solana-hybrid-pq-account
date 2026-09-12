//! `Initialize` — create and populate a HybridAccount PDA.
//!
//! This milestone establishes the account only. It performs **no authorized
//! value movement**: the sole lamport flow is the creator funding the new
//! account's rent-exempt minimum, which is account creation rather than a
//! transfer out of a vault. Nothing here consults an authorization policy,
//! because no policy is enforceable until Milestone 5.
//!
//! ## Instruction data (935 bytes)
//!
//! ```text
//! Offset  Size  Field
//! 0       1     discriminator (0)
//! 1       4     account_index (u32 LE)
//! 5       32    owner_ed25519
//! 37      1     policy
//! 38      897   falcon_wire_public_key
//! 935           end
//! ```
//!
//! Only the 897-byte wire public key travels on the wire; the 1024-byte prepared
//! form is derived on-chain.
//!
//! ## Accounts
//!
//! | # | Account | |
//! |---|---------|--|
//! | 0 | `creator` | signer, writable — funds rent and is a PDA seed |
//! | 1 | `hybrid_account` | writable — the PDA to create |
//! | 2 | `system_program` | readonly |

use dualkey_core::{
    AuthorizationPolicy, DualKeyError, HybridAccount, ACCOUNT_DATA_LEN, ACCOUNT_INDEX_LEN,
    FALCON_WIRE_PUBKEY_LEN,
};
use solana_account_info::AccountInfo;
use solana_cpi::invoke_signed;
use solana_falcon512::Falcon512Pubkey;
use solana_get_sysvar::GetSysvar;
use solana_msg::msg;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

use crate::hash::sha256;
use crate::pda;

/// Offsets within the instruction payload (after the discriminator byte).
mod payload {
    use super::{ACCOUNT_INDEX_LEN, FALCON_WIRE_PUBKEY_LEN};

    pub const ACCOUNT_INDEX: usize = 0;
    pub const OWNER_ED25519: usize = ACCOUNT_INDEX + ACCOUNT_INDEX_LEN;
    pub const POLICY: usize = OWNER_ED25519 + 32;
    pub const FALCON_PUBKEY: usize = POLICY + 1;
    pub const LEN: usize = FALCON_PUBKEY + FALCON_WIRE_PUBKEY_LEN;
}

/// Total instruction data length including the discriminator byte.
pub const INITIALIZE_DATA_LEN: usize = 1 + payload::LEN;

const _: () = assert!(INITIALIZE_DATA_LEN == 935);

/// Parsed, validated `Initialize` arguments.
struct Args<'a> {
    account_index: u32,
    owner_ed25519: &'a [u8; 32],
    policy: AuthorizationPolicy,
    falcon_wire_pubkey: &'a [u8],
}

fn parse(payload: &[u8]) -> Result<Args<'_>, DualKeyError> {
    if payload.len() != payload::LEN {
        return Err(DualKeyError::MalformedInstructionData);
    }

    let index_le: [u8; ACCOUNT_INDEX_LEN] = payload
        [payload::ACCOUNT_INDEX..payload::ACCOUNT_INDEX + ACCOUNT_INDEX_LEN]
        .try_into()
        .map_err(|_| DualKeyError::MalformedInstructionData)?;

    let owner_ed25519: &[u8; 32] = payload[payload::OWNER_ED25519..payload::OWNER_ED25519 + 32]
        .try_into()
        .map_err(|_| DualKeyError::MalformedInstructionData)?;

    // Reject an unknown policy byte, and also reject a *known but unenforceable*
    // one. Storing a policy this program cannot evaluate would leave an account
    // that can never authorize anything, or worse, invite a later version to
    // treat it permissively.
    let policy = AuthorizationPolicy::from_u8(payload[payload::POLICY])
        .ok_or(DualKeyError::PolicyRejected)?;
    if !policy.is_implemented() {
        return Err(DualKeyError::PolicyNotImplemented);
    }

    Ok(Args {
        account_index: u32::from_le_bytes(index_le),
        owner_ed25519,
        policy,
        falcon_wire_pubkey: &payload
            [payload::FALCON_PUBKEY..payload::FALCON_PUBKEY + FALCON_WIRE_PUBKEY_LEN],
    })
}

/// Create the HybridAccount PDA and write its initial state.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> Result<(), DualKeyError> {
    let args = parse(payload)?;

    let [creator, hybrid_account, system_program] = accounts else {
        return Err(DualKeyError::MalformedInstructionData);
    };

    // The creator is a PDA seed and pays rent, so its signature is required:
    // without this check anyone could create accounts seeded by someone else's
    // address and choose the owner key stored in them.
    if !creator.is_signer {
        return Err(DualKeyError::MissingSigner);
    }
    if !solana_system_interface::program::check_id(system_program.key) {
        return Err(DualKeyError::InvalidProgramAccount);
    }

    let bump = pda::verify(
        program_id,
        creator.key,
        args.account_index,
        hybrid_account.key,
    )?;

    // Refuse to touch an account that already holds data. `create_account` would
    // fail anyway, but checking first turns a confusing system-program error
    // into an explicit one, and makes the no-re-initialization property
    // testable.
    if !hybrid_account.data_is_empty() {
        return Err(DualKeyError::AccountAlreadyInitialized);
    }

    // Binds the stored prepared key to the wire key the client holds, so a
    // rotation or recovery flow can prove which Falcon key an account expects
    // without storing the 897-byte original.
    let falcon_public_key_hash = sha256(args.falcon_wire_pubkey);

    create_pda_account(
        program_id,
        creator,
        hybrid_account,
        args.account_index,
        bump,
    )?;

    let mut data = hybrid_account
        .try_borrow_mut_data()
        .map_err(|_| DualKeyError::InvalidAccountData)?;
    let mut account = HybridAccount::initialize_without_falcon_key(
        &mut data,
        bump,
        args.owner_ed25519,
        &falcon_public_key_hash,
        args.policy,
    )?;
    store_prepared_falcon_key(
        account.prepared_falcon_public_key_mut(),
        args.falcon_wire_pubkey,
    )?;

    msg!("DualKey: HybridAccount initialized");
    Ok(())
}

/// Fund, allocate and assign the PDA via System program CPIs.
///
/// A PDA has no private key, so only this program can sign for it; the bump is
/// the one derived above, never one supplied by the caller.
///
/// ## Why not `create_account`
///
/// `create_account` refuses a destination that already holds lamports
/// ("account already in use"). Because the seeds are public, anyone can compute
/// a vault's future address and send it one lamport, which would **permanently**
/// block creation of that `(creator, account_index)` pair — a denial of service
/// costing the attacker 1 lamport. This was reproduced before the fix; see
/// `prefunded_pda_can_still_be_initialized`.
///
/// Transfer-then-allocate-then-assign is immune, because a transfer tops the
/// account up rather than requiring it to be empty. The sequence is fixed by the
/// System program's preconditions: `transfer` needs the *source* to be
/// data-less, and `allocate` needs the target to be system-owned with zero data,
/// so assignment must come last. Any prefunded lamports simply stay in the
/// account.
///
/// ## On the error mappings below
///
/// When a CPI's *callee* fails, the runtime propagates the callee's error code
/// straight to the transaction result; these `map_err` arms never run. An
/// underfunded creator, for example, surfaces as System error `0x1`
/// (`ResultWithNegativeLamports`), not as `InsufficientFunds`. The mappings cover
/// only the case where `invoke_signed` returns before invoking anything, which it
/// does if its account-borrow checks fail. Both are failures, so the transaction
/// reverts either way; the codes are not interchangeable when interpreting logs.
///
/// `#[inline(never)]` keeps the `Instruction` construction and its serialization
/// buffers out of the caller's stack frame, which SBF limits to 4 KB.
#[inline(never)]
fn create_pda_account<'a>(
    program_id: &Pubkey,
    creator: &AccountInfo<'a>,
    hybrid_account: &AccountInfo<'a>,
    account_index: u32,
    bump: u8,
) -> Result<(), DualKeyError> {
    let required = Rent::get()
        .map_err(|_| DualKeyError::InvalidAccountData)?
        .minimum_balance(ACCOUNT_DATA_LEN);

    let seeds = pda::SignerSeeds::new(creator.key, account_index, bump);
    let signer_seeds = seeds.as_slices();

    // Only the shortfall, so a prefunded account is not double-charged.
    let shortfall = required.saturating_sub(hybrid_account.lamports());
    if shortfall > 0 {
        invoke_signed(
            &solana_system_interface::instruction::transfer(
                creator.key,
                hybrid_account.key,
                shortfall,
            ),
            &[creator.clone(), hybrid_account.clone()],
            &[&signer_seeds],
        )
        .map_err(|_| DualKeyError::InsufficientFunds)?;
    }

    invoke_signed(
        &solana_system_interface::instruction::allocate(
            hybrid_account.key,
            ACCOUNT_DATA_LEN as u64,
        ),
        std::slice::from_ref(hybrid_account),
        &[&signer_seeds],
    )
    .map_err(|_| DualKeyError::AccountAlreadyInitialized)?;

    // Assign last: `allocate` requires a system-owned account, so ownership can
    // only change once the space exists.
    invoke_signed(
        &solana_system_interface::instruction::assign(hybrid_account.key, program_id),
        std::slice::from_ref(hybrid_account),
        &[&signer_seeds],
    )
    .map_err(|_| DualKeyError::InvalidProgramAccount)
}

/// Derive the prepared (NTT-form) Falcon key on-chain and write it into the
/// account.
///
/// The prepared form is derived here rather than accepted from the client. That
/// is a security property, not an optimization: the prepared form is
/// unvalidated by construction — any 1024 bytes decode to *some* polynomial — so
/// a client-supplied blob could not be checked for well-formedness.
/// `try_prepare_pubkey` instead validates the wire encoding (header byte and
/// modq decode) and computes the NTT itself, so the stored key is always the
/// transform of a genuine Falcon-512 public key. It also keeps 127 bytes off the
/// wire.
///
/// `#[inline(never)]` is required for correctness, not style:
/// `try_prepare_pubkey` returns the 1024-byte key **by value**, and inlining it
/// into `process` pushed that frame to 4288 bytes — past SBF's 4 KB limit.
/// Writing straight into the account's own buffer keeps the large value confined
/// to this frame.
///
/// Called after account creation, so a malformed key fails here rather than
/// before allocation. That is safe because a failed instruction reverts every
/// account change atomically; no partially initialized account can persist.
#[inline(never)]
fn store_prepared_falcon_key(
    dst: &mut [u8; dualkey_core::PREPARED_FALCON_PUBKEY_LEN],
    falcon_wire_pubkey: &[u8],
) -> Result<(), DualKeyError> {
    let prepared = Falcon512Pubkey::try_from_slice(falcon_wire_pubkey)
        .map_err(|_| DualKeyError::MalformedFalcon)?
        .try_prepare_pubkey()
        .map_err(|_| DualKeyError::MalformedFalcon)?;
    dst.copy_from_slice(prepared.as_bytes());
    Ok(())
}
