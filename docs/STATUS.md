# DualKey — Project status

**Research complete through Milestone 16** (out-of-scope finish items included).

DualKey is a research-grade Solana smart-account architecture for **hybrid
authorization**: classical Ed25519 and post-quantum Falcon-512 over the same
canonical intent, evaluated by a configurable policy engine.

## Delivered surface

| Area | Status |
|------|--------|
| Shared `dualkey-core` intent / policy / 1120-byte layout | Done |
| Falcon verify under SBF (`solana-falcon512`) | Done |
| HybridAccount PDA + Initialize | Done |
| Canonical intent + on-chain reconstruction | Done |
| All six authorization policies | Done |
| Replay protection + expiry | Done |
| TransferSol + TransferSpl (classic Token + Token-2022 base) | Done |
| Key rotation + Falcon PoP | Done |
| ChangePolicy (stricter-of) | Done |
| RecoverAccount (opt-in Falcon-only Ed recover) | Done |
| CLI RPC broadcast (`--broadcast` / `--rpc-url` / `--payer`) | Done |
| Social recovery (guardian + timelock) | Done |
| CU + legacy tx-size benches (M8) | Done |
| Mollusk SBF attack/integration harness | Done |

## Explicit non-goals (still)

- Production security audit / formal verification
- Claiming “quantum proof”
- Full Token-2022 transfer-hook account resolution
- Multi-guardian thresholds (single guardian only)

## Verify

```bash
./scripts/setup-toolchain.sh   # once
unset CARGO_TARGET_DIR && export CARGO_TARGET_DIR="$PWD/target"
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional localnet smoke (one-shot): [`scripts/demo-localnet.sh`](../scripts/demo-localnet.sh)
with `PROGRAM_ID` and `PAYER` set.

See milestone docs under [`docs/`](.).
