#!/usr/bin/env bash
# Localnet smoke: keygen → init → fund → transfer with --broadcast (one shot).
#
# Prerequisites:
#   - solana-test-validator running (default http://127.0.0.1:8899)
#   - DualKey program deployed; set PROGRAM_ID
#   - A funded Solana CLI keypair JSON; set PAYER
#   - solana / solana-keygen / python3 on PATH
#   - Optional: build the CLI first, or this script builds target/debug/dualkey
#
# Usage:
#   PROGRAM_ID=… PAYER=./payer.json ./scripts/demo-localnet.sh
#
# This is a research demo, not a production wallet flow.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
PROGRAM_ID="${PROGRAM_ID:?set PROGRAM_ID to the deployed DualKey program address}"
PAYER="${PAYER:?set PAYER to a funded keypair.json path}"
KEYS="${KEYS:-$ROOT/keys-demo}"
DUALKEY="${DUALKEY:-$ROOT/target/debug/dualkey}"
ACCOUNT_INDEX="${ACCOUNT_INDEX:-0}"

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
INIT_OUT="$(mktemp "${TMPDIR:-/tmp}/dualkey-init.XXXXXX.json")"
trap 'rm -f "$INIT_OUT"' EXIT

echo "Creator / payer: $CREATOR"
echo "RPC:             $RPC_URL"
echo "Program:         $PROGRAM_ID"

"$DUALKEY" init \
  --keys "$KEYS" \
  --account-index "$ACCOUNT_INDEX" \
  --program-id "$PROGRAM_ID" \
  --creator "$CREATOR" \
  --policy hybrid-and \
  --out "$INIT_OUT" \
  --broadcast --rpc-url "$RPC_URL" --payer "$PAYER"

HYBRID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hybrid_account"])' "$INIT_OUT")"
echo "HybridAccount:   $HYBRID"

# Fund the vault, then transfer a small amount back to the creator.
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
