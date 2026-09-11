#!/usr/bin/env bash
# DualKey toolchain bootstrap.
#
# Installs (does not invoke) the host and Solana/SBF tooling needed from
# Milestone 2 onward. Safe to re-run; skips steps that are already present.
#
# Usage:
#   ./scripts/setup-toolchain.sh
#
# Environment overrides:
#   SOLANA_VERSION   Agave/Solana release tag (default: stable)
#   RUST_VERSION     rustup toolchain (default: from rust-toolchain.toml)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUST_VERSION="${RUST_VERSION:-$(grep -E '^channel' rust-toolchain.toml | sed 's/.*= *"\(.*\)"/\1/')}"
SOLANA_VERSION="${SOLANA_VERSION:-stable}"

echo "==> DualKey toolchain setup"
echo "    rust:   ${RUST_VERSION}"
echo "    solana: ${SOLANA_VERSION}"
echo

# --- rustup -----------------------------------------------------------------
if ! command -v rustup >/dev/null 2>&1; then
  echo "==> Installing rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain "${RUST_VERSION}"
  # shellcheck disable=SC1091
  source "${HOME}/.cargo/env"
else
  echo "==> rustup already installed"
fi

echo "==> Ensuring rustc toolchain ${RUST_VERSION}"
rustup toolchain install "${RUST_VERSION}"
rustup component add rustfmt clippy --toolchain "${RUST_VERSION}"

# --- C compiler (needed by pqcrypto-falcon / PQClean) ------------------------
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
  echo "ERROR: no C compiler found (cc/gcc). Install build-essential / clang." >&2
  exit 1
fi
echo "==> C compiler: $(command -v cc || command -v gcc)"

# --- Solana / Agave CLI + cargo-build-sbf -----------------------------------
if ! command -v solana >/dev/null 2>&1 || ! command -v cargo-build-sbf >/dev/null 2>&1; then
  echo "==> Installing Solana CLI (${SOLANA_VERSION})"
  sh -c "$(curl -sSfL https://release.anza.xyz/${SOLANA_VERSION}/install)"
  export PATH="${HOME}/.local/share/solana/install/active_release/bin:${PATH}"
  if ! grep -q 'solana/install/active_release/bin' "${HOME}/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"' >> "${HOME}/.bashrc"
  fi
else
  echo "==> Solana CLI already installed: $(solana --version 2>/dev/null || true)"
fi

echo
echo "==> Installed versions"
rustc --version || true
cargo --version || true
solana --version || true
cargo-build-sbf --version || true

echo
echo "Toolchain bootstrap complete."
echo "Milestone 0 / 1 need only the host Rust toolchain."
echo "Milestone 2 onward requires cargo-build-sbf (installed above)."
