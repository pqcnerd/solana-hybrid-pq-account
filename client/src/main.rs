//! DualKey CLI — hybrid Ed25519 + Falcon-512 smart-account client.
//!
//! Never prints secret key material.

use clap::{Parser, Subcommand};
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
    /// Build the Initialize instruction for a DualKey HybridAccount PDA.
    ///
    /// Prints the derived address and instruction; does not broadcast.
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
        /// Authorization policy: ed25519-only, falcon-only, or hybrid-and.
        #[arg(long, default_value = "hybrid-and")]
        policy: String,
        /// Also write the instruction as JSON here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Submit a hybrid-authorized SOL transfer (Milestone 7).
    Transfer {
        #[arg(long)]
        to: String,
        #[arg(long)]
        lamports: u64,
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
    },
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
        } => match AuthorizationPolicy::from_name(&policy) {
            Some(policy) => submit::init(
                &keys,
                account_index,
                &program_id,
                &creator,
                policy,
                out.as_deref(),
            ),
            None => {
                eprintln!(
                    "error: unknown policy {policy:?}; expected one of \
                     ed25519-only, falcon-only, hybrid-and"
                );
                return ExitCode::FAILURE;
            }
        },
        Commands::Transfer { to, lamports, keys } => submit::transfer(&keys, &to, lamports),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
