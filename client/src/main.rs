//! DualKey CLI — hybrid Ed25519 + Falcon-512 smart-account client.
//!
//! Never prints secret key material.

use clap::{Parser, Subcommand};
use dualkey_client::rpc::BroadcastOpts;
use dualkey_client::{keygen, sign, submit};
use dualkey_core::AuthorizationPolicy;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "dualkey")]
#[command(about = "DualKey — Hybrid Ed25519 + Falcon-512 Smart Accounts for Solana")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Shared RPC / broadcast flags (Milestone 13). Default remains offline artifacts.
#[derive(clap::Args, Debug, Clone)]
struct RpcArgs {
    /// Submit the built transaction to a cluster (default: print artifacts only).
    #[arg(long, default_value_t = false)]
    broadcast: bool,
    /// Solana JSON-RPC URL (required with `--broadcast`; also used to read
    /// HybridAccount nonce when `--nonce` is omitted).
    #[arg(long)]
    rpc_url: Option<String>,
    /// Payer keypair JSON path (required with `--broadcast`). Never printed.
    #[arg(long)]
    payer: Option<PathBuf>,
}

impl RpcArgs {
    fn opts(&self) -> BroadcastOpts {
        BroadcastOpts {
            broadcast: self.broadcast,
            rpc_url: self.rpc_url.clone(),
            payer_path: self.payer.clone(),
        }
    }
}

const POLICY_HELP: &str = "ed25519-only, falcon-only, hybrid-and, hybrid-or, \
    falcon-for-privileged, falcon-above-threshold";

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate Ed25519 and Falcon-512 keypairs.
    Keygen {
        /// Output directory for key material.
        #[arg(long, default_value = "keys")]
        out: PathBuf,
    },
    /// Sign a canonical authorization intent with both schemes.
    Sign {
        /// Path to an intent JSON file.
        #[arg(long)]
        intent: PathBuf,
        /// Directory containing key material.
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        /// Write the signed bundle here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a signed bundle with Ed25519, PQClean Falcon, and the on-chain
    /// Falcon verifier.
    Verify {
        /// Path to a signed bundle JSON file.
        #[arg(long)]
        input: PathBuf,
    },
    /// Build (and optionally broadcast) Initialize for a HybridAccount PDA.
    Init {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        /// Selects among multiple vaults for the same creator.
        #[arg(long, default_value_t = 0)]
        account_index: u32,
        /// Deployed DualKey program address (base58).
        #[arg(long)]
        program_id: String,
        /// Creator address (base58). Pays rent, signs, and is a PDA seed.
        #[arg(long)]
        creator: String,
        /// Authorization policy (see `--help` for names).
        #[arg(long, default_value = "hybrid-and", help = POLICY_HELP)]
        policy: String,
        /// Also write the instruction as JSON here.
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Build (and optionally broadcast) a HybridAnd SOL transfer.
    Transfer {
        /// Destination address (base58).
        #[arg(long)]
        to: String,
        /// Lamports to transfer from the HybridAccount.
        #[arg(long)]
        lamports: u64,
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        /// Deployed DualKey program address (base58).
        #[arg(long)]
        program_id: String,
        /// HybridAccount PDA address (base58).
        #[arg(long)]
        account: String,
        /// Current on-chain nonce. Omit when `--rpc-url` is set to read from chain.
        #[arg(long)]
        nonce: Option<u64>,
        /// Last slot at which the intent is valid (inclusive).
        #[arg(long)]
        expiry_slot: u64,
        /// Also write the artifact as JSON here.
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Change the HybridAccount authorization policy (Milestone 10).
    ChangePolicy {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long, help = POLICY_HELP)]
        policy: String,
        /// Threshold lamports for falcon-above-threshold (ignored otherwise).
        #[arg(long, default_value_t = 0)]
        threshold: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Rotate the Ed25519 owner under the current policy (Milestone 9).
    RotateEd25519 {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        /// New Ed25519 owner pubkey (base58).
        #[arg(long)]
        new_owner: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// RecoverAccount lifecycle (Milestone 12).
    Recover {
        #[command(subcommand)]
        op: RecoverCmd,
    },
    /// Build (and optionally broadcast) a TransferSpl (Milestone 11/14).
    TransferSpl {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        /// Creator pubkey (PDA seed; must match Initialize).
        #[arg(long)]
        creator: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        mint: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        /// Use Token-2022 program id instead of classic SPL Token.
        #[arg(long, default_value_t = false)]
        token_2022: bool,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Rotate the Falcon-512 public key (Milestone 9; PoP under new key).
    ///
    /// Offline / `--out` only: ~2279-byte ix cannot fit legacy `--broadcast`
    /// (v0 + ALT submission is out of scope).
    RotateFalcon {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        /// Directory holding the *new* Falcon keypair (`falcon512.sk` / `.pk`).
        #[arg(long)]
        new_falcon_keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Social recovery (guardian + timelock, Milestone 15).
    ///
    /// Prerequisite: `social set-config`, then `recover enable` before
    /// initiate / finalize / cancel (flag required for those three only).
    Social {
        #[command(subcommand)]
        op: SocialCmd,
    },
}

#[derive(Subcommand, Debug)]
enum SocialCmd {
    /// Set / replace guardian Ed25519 + delay_slots (does not require recovery flag).
    SetConfig {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        /// Guardian Ed25519 pubkey (base58).
        #[arg(long)]
        guardian: String,
        #[arg(long)]
        delay_slots: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Guardian proposes a new Ed25519 owner (requires recovery enabled + config).
    Initiate {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        new_owner: String,
        /// Key directory for the guardian Ed25519 keypair.
        #[arg(long)]
        guardian_keys: PathBuf,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Permissionless finalize after the slot delay (requires recovery enabled).
    Finalize {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// DualKey owner cancels a pending social recovery (requires recovery enabled).
    Cancel {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
}

#[derive(Subcommand, Debug)]
enum RecoverCmd {
    /// Opt in to Falcon-only Ed25519 recovery.
    Enable {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Opt out of Falcon-only Ed25519 recovery.
    Disable {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
    /// Rotate Ed25519 owner with Falcon alone (requires recovery enabled; no ed25519.sk).
    RotateEd25519 {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        new_owner: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long)]
        expiry_slot: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        rpc: RpcArgs,
    },
}

fn parse_policy(policy: &str) -> Result<AuthorizationPolicy, ExitCode> {
    AuthorizationPolicy::from_name(policy).ok_or_else(|| {
        eprintln!("error: unknown policy {policy:?}; expected one of {POLICY_HELP}");
        ExitCode::FAILURE
    })
}

fn lifecycle<'a>(
    keys: &'a PathBuf,
    program_id: &'a str,
    account: &'a str,
    nonce: Option<u64>,
    expiry_slot: u64,
    out: Option<&'a PathBuf>,
    rpc: &RpcArgs,
) -> submit::LifecycleParams<'a> {
    submit::LifecycleParams {
        keys_dir: keys,
        program_id,
        hybrid_account: account,
        nonce,
        expiry_slot,
        broadcast: rpc.opts(),
        out: out.map(|p| p.as_path()),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Keygen { out } => keygen::run(&out),
        Commands::Sign { intent, keys, out } => sign::run(&intent, &keys, out.as_deref()),
        Commands::Verify { input } => sign::verify(&input),
        Commands::Init {
            keys,
            account_index,
            program_id,
            creator,
            policy,
            out,
            rpc,
        } => match parse_policy(&policy) {
            Ok(policy) => submit::init(
                &keys,
                account_index,
                &program_id,
                &creator,
                policy,
                out.as_deref(),
                &rpc.opts(),
            ),
            Err(code) => return code,
        },
        Commands::Transfer {
            to,
            lamports,
            keys,
            program_id,
            account,
            nonce,
            expiry_slot,
            out,
            rpc,
        } => submit::transfer(submit::TransferParams {
            keys_dir: &keys,
            program_id: &program_id,
            hybrid_account: &account,
            recipient: &to,
            lamports,
            nonce,
            expiry_slot,
            out: out.as_deref(),
            broadcast: rpc.opts(),
        }),
        Commands::ChangePolicy {
            keys,
            program_id,
            account,
            policy,
            threshold,
            nonce,
            expiry_slot,
            out,
            rpc,
        } => match parse_policy(&policy) {
            Ok(policy) => submit::change_policy(
                lifecycle(
                    &keys,
                    &program_id,
                    &account,
                    nonce,
                    expiry_slot,
                    out.as_ref(),
                    &rpc,
                ),
                policy,
                threshold,
            ),
            Err(code) => return code,
        },
        Commands::RotateEd25519 {
            keys,
            program_id,
            account,
            new_owner,
            nonce,
            expiry_slot,
            out,
            rpc,
        } => submit::rotate_ed25519(
            lifecycle(
                &keys,
                &program_id,
                &account,
                nonce,
                expiry_slot,
                out.as_ref(),
                &rpc,
            ),
            &new_owner,
        ),
        Commands::Recover { op } => match op {
            RecoverCmd::Enable {
                keys,
                program_id,
                account,
                nonce,
                expiry_slot,
                out,
                rpc,
            } => submit::recover_enable(lifecycle(
                &keys,
                &program_id,
                &account,
                nonce,
                expiry_slot,
                out.as_ref(),
                &rpc,
            )),
            RecoverCmd::Disable {
                keys,
                program_id,
                account,
                nonce,
                expiry_slot,
                out,
                rpc,
            } => submit::recover_disable(lifecycle(
                &keys,
                &program_id,
                &account,
                nonce,
                expiry_slot,
                out.as_ref(),
                &rpc,
            )),
            RecoverCmd::RotateEd25519 {
                keys,
                program_id,
                account,
                new_owner,
                nonce,
                expiry_slot,
                out,
                rpc,
            } => submit::recover_rotate_ed25519(
                lifecycle(
                    &keys,
                    &program_id,
                    &account,
                    nonce,
                    expiry_slot,
                    out.as_ref(),
                    &rpc,
                ),
                &new_owner,
            ),
        },
        Commands::TransferSpl {
            keys,
            program_id,
            account,
            creator,
            source,
            mint,
            destination,
            amount,
            nonce,
            expiry_slot,
            token_2022,
            out,
            rpc,
        } => submit::transfer_spl(submit::TransferSplParams {
            keys_dir: &keys,
            program_id: &program_id,
            hybrid_account: &account,
            creator: &creator,
            source: &source,
            mint: &mint,
            destination: &destination,
            amount,
            nonce,
            expiry_slot,
            token_2022,
            broadcast: rpc.opts(),
            out: out.as_deref(),
        }),
        Commands::RotateFalcon {
            keys,
            new_falcon_keys,
            program_id,
            account,
            nonce,
            expiry_slot,
            out,
            rpc,
        } => submit::rotate_falcon(
            lifecycle(
                &keys,
                &program_id,
                &account,
                nonce,
                expiry_slot,
                out.as_ref(),
                &rpc,
            ),
            &new_falcon_keys,
        ),
        Commands::Social { op } => match op {
            SocialCmd::SetConfig {
                keys,
                program_id,
                account,
                guardian,
                delay_slots,
                nonce,
                expiry_slot,
                out,
                rpc,
            } => submit::social_set_config(
                lifecycle(
                    &keys,
                    &program_id,
                    &account,
                    nonce,
                    expiry_slot,
                    out.as_ref(),
                    &rpc,
                ),
                &guardian,
                delay_slots,
            ),
            SocialCmd::Initiate {
                program_id,
                account,
                new_owner,
                guardian_keys,
                nonce,
                out,
                rpc,
            } => submit::social_initiate(
                &program_id,
                &account,
                &new_owner,
                &guardian_keys,
                nonce,
                &rpc.opts(),
                out.as_deref(),
            ),
            SocialCmd::Finalize {
                program_id,
                account,
                out,
                rpc,
            } => submit::social_finalize(&program_id, &account, &rpc.opts(), out.as_deref()),
            SocialCmd::Cancel {
                keys,
                program_id,
                account,
                nonce,
                expiry_slot,
                out,
                rpc,
            } => submit::social_cancel(lifecycle(
                &keys,
                &program_id,
                &account,
                nonce,
                expiry_slot,
                out.as_ref(),
                &rpc,
            )),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
