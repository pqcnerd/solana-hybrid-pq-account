#!/usr/bin/env bash
# Localnet smoke: keygen → init → transfer with --broadcast.
#
# Prerequisites:
#   - solana-test-validator running at http://127.0.0.1:8899
#   - DualKey program deployed; PROGRAM_ID set below or via env
#   - cargo build -p dualkey-client (provides target/debug/dualkey)
#   - A funded payer keypair JSON (Solana CLI format)
#
# This script is a research demo, not a production wallet flow.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
PROGRAM_ID="${PROGRAM_ID:?set PROGRAM_ID to the deployed DualKey program address}"
PAYER="${PAYER:?set PAYER to a funded keypair.json path}"
KEYS="${KEYS:-$ROOT/keys-demo}"
DUALKEY="${DUALKEY:-$ROOT/target/debug/dualkey}"

if [[ ! -x "$DUALKEY" ]]; then
  echo "building dualkey CLI…"
  unset CARGO_TARGET_DIR
  export CARGO_TARGET_DIR="$ROOT/target"
  cargo build -p dualkey-client
fi

mkdir -p "$KEYS"
if [[ ! -f "$KEYS/ed25519.sk" ]]; then
  "$DUALKEY" keygen --out "$KEYS"
fi

CREATOR="$(solana-keygen pubkey "$PAYER")"
echo "Creator / payer: $CREATOR"
echo "RPC: $RPC_URL"

"$DUALKEY" init \
  --keys "$KEYS" \
  --program-id "$PROGRAM_ID" \
  --creator "$CREATOR" \
  --policy hybrid-and \
  --broadcast --rpc-url "$RPC_URL" --payer "$PAYER"

# Derive HybridAccount offline (printed by init); for a full demo, capture it:
HYBRID="${HYBRID:?after init, set HYBRID to the HybridAccount address and re-run transfer}"

# Fund the vault, then transfer a small amount.
solana transfer --url "$RPC_URL" --keypair "$PAYER" "$HYBRID" 0.01 --allow-unfunded-recipient

SLOT="$(solana slot --url "$RPC_URL")"
EXPIRY=$((SLOT + 10_000))

"$DUALKEY" transfer \
  --keys "$KEYS" \
  --program-id "$PROGRAM_ID" \
  --account "$HYBRID" \
  --to "$CREATOR" \
  --lamports 1000 \
  --expiry-slot "$EXPIRY" \
  --broadcast --rpc-url "$RPC_URL" --payer "$PAYER"

echo "demo-localnet: ok"
