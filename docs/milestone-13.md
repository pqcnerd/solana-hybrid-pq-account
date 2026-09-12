# Milestone 13 — CLI RPC broadcast

**Goal:** `dualkey` can submit built transactions to a cluster (localnet/devnet),
not only print offline artifacts.

## What shipped

- `client/src/rpc.rs`: thin JSON-RPC via `reqwest` (blockhash, account data,
  HybridAccount nonce, send+confirm). Avoids pinning a heavy `solana-rpc-client`
  that conflicts with Mollusk’s `solana-transaction` 4.x stack.
- Shared flags: `--broadcast` (default off), `--rpc-url`, `--payer` (JSON
  keypair path). Secrets are never printed.
- Wired flows: `init`, `transfer`, `transfer-spl`, `change-policy`,
  `rotate-ed25519`, `recover {enable,disable,rotate-ed25519}` (and later
  `rotate-falcon` / `social …` under the same flags).
- When `--nonce` is omitted and `--broadcast --rpc-url --payer` is set, the CLI
  reads the HybridAccount nonce from chain.
- Legacy transaction assembly for HybridAnd TransferSol (unit-tested without
  RPC in `client/src/rpc.rs`). Oversized Falcon rotate paths may still need
  ALT/v0 manually.

## Usage sketch

```bash
dualkey init --program-id … --creator … --broadcast \
  --rpc-url http://127.0.0.1:8899 --payer ./payer.json

dualkey transfer --to … --lamports 1000 --program-id … --account … \
  --expiry-slot 999999999 --broadcast --rpc-url … --payer …
```

Live localnet smoke: [`scripts/demo-localnet.sh`](../scripts/demo-localnet.sh)
(requires a running `solana-test-validator`, deployed program, and funded payer).

## Non-goals

- Production-grade confirmation / retry policy
- Automatic Address Lookup Tables for oversized Falcon txs
