//! DualKey CLI — hybrid Ed25519 + Falcon-512 smart-account client.
//!
//! Never prints secret key material.

use clap::{Parser, Subcommand};
use dualkey_client::{keygen, sign, submit};
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
    /// Initialize a DualKey HybridAccount on-chain (Milestone 3).
    Init {
        #[arg(long, default_value = "keys")]
        keys: PathBuf,
        #[arg(long, default_value_t = 0)]
        account_index: u32,
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
