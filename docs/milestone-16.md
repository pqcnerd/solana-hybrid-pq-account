# Milestone 16 — Polish

**Goal:** Repo reads as finished for research use.

## Delivered

- [`STATUS.md`](STATUS.md) and README milestone table through M16; former
  non-goals that shipped (CLI RPC, Token-2022 base, social recovery) listed as
  Delivered.
- CLI: all six policies in help; subcommands for `change-policy`,
  `rotate-ed25519`, `rotate-falcon`, `recover`, `transfer-spl`,
  `social {set-config,initiate,finalize,cancel}`, plus `--broadcast` flags.
- [`scripts/demo-localnet.sh`](../scripts/demo-localnet.sh): one-shot keygen →
  init (`--out` JSON) → fund → transfer against `solana-test-validator`
  (`PROGRAM_ID` + `PAYER` required).
- Threat model: guardian+timelock and Token-2022 hook refusal rows.
- Verification: `cargo fmt` / `clippy -D warnings` / SBF build / workspace tests.

## Still never in scope

- Formal verification / third-party audit
- Claiming the system is “quantum proof”
- Full Token-2022 transfer-hook account resolution
- Multi-guardian thresholds
