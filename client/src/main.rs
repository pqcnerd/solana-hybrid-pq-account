//! DualKey CLI — hybrid Ed25519 + Falcon-512 smart-account client.
//!
//! Milestone 0: subcommands are wired but return an explicit "not implemented"
//! status. Milestone 1 implements keygen / sign / verify.

mod error;
mod intent;
mod keygen;
mod sign;
mod submit;

use clap::{Parser, Subcommand};
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
    /// Generate Ed25519 and Falcon-512 keypairs (Milestone 1).
    Keygen {
        /// Output directory for key material.
        #[arg(long, default_value = "keys")]
        out: PathBuf,
    },
    /// Sign a canonical authorization intent with both schemes (Milestone 1).
    Sign {
        /// Path to an intent description file.
        #[arg(long)]
        intent: PathBuf,
        /// Directory containing key material.
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
    },
    /// Verify Ed25519 + Falcon signatures over an intent digest (Milestone 1).
    Verify {
        /// Path to signature bundle / intent file.
        #[arg(long)]
        input: PathBuf,
    },
    /// Initialize a DualKey HybridAccount on-chain (Milestone 3).
    Init {
        /// Key directory.
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        /// Creator account index for PDA derivation.
        #[arg(long, default_value_t = 0)]
        account_index: u32,
    },
    /// Submit a hybrid-authorized SOL transfer (Milestone 7).
    Transfer {
        /// Recipient pubkey (base58).
        #[arg(long)]
        to: String,
        /// Lamports to transfer.
        #[arg(long)]
        lamports: u64,
        /// Key directory.
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Keygen { out } => keygen::run(&out),
        Commands::Sign { intent, keys } => sign::run(&intent, &keys),
        Commands::Verify { input } => sign::verify(&input),
        Commands::Init {
            keys,
            account_index,
        } => submit::init(&keys, account_index),
        Commands::Transfer {
            to,
            lamports,
            keys,
        } => submit::transfer(&keys, &to, lamports),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
