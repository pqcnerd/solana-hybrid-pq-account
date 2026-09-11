# DualKey

**Hybrid Ed25519 + Falcon-512 Smart Accounts for Solana**

Research repository: `solana-hybrid-pq-account`

DualKey studies how a Solana account can transition safely from classical
authentication toward post-quantum authentication **without abandoning**
existing Ed25519 infrastructure.

This is **not** simply a Falcon wallet. It is a PDA-backed smart-account /
vault with a configurable **authorization-policy engine**.

> Terminology: **post-quantum**, **hybrid authorization**, **cryptographic
> agility**, **defense in depth**. DualKey does **not** claim to be “quantum
> proof” or formally secure.

## Motivation

Ed25519 is deeply embedded in Solana. Cryptographically relevant quantum
computers would threaten classical discrete-log signatures, while lattice-based
schemes such as Falcon-512 are designed as post-quantum alternatives. A
practical migration path needs:

1. Continued interoperability with Ed25519 tooling
2. Incremental introduction of Falcon (or future PQ schemes)
3. Policy knobs for when PQ signatures are required
4. Measured costs (compute units, transaction size, account size)

**Central research question:**  
*How can a Solana account transition safely from classical authentication to
post-quantum authentication without abandoning existing Ed25519 infrastructure?*

## Why hybrid signatures

```text
Ed25519 private key
        │
        ├──── sign(intent) ──────┐
        │                        │
        │                        ▼
        │                  Hybrid Policy
        │                        ▲
        │                        │
Falcon private key              │
        │                        │
        └──── sign(intent) ──────┘
                                 │
                                 ▼
                         DualKey Smart Account
                                 │
                                 ▼
                              Action
```

**HybridAnd** requires both:

```text
Verify_Ed25519(sig_ed, digest, ed_pubkey)
  AND
Verify_Falcon512(sig_falcon, digest, falcon_pubkey)
```

Both signatures cover the **same canonical intent digest**. Compromising only
one private key (or breaking only one scheme) is not enough to spend under
HybridAnd — that is defense in depth across signature families, not a proof of
quantum immunity.

## Architecture

Four layers (details in [`docs/architecture.md`](docs/architecture.md)):

| Layer | Path | Role |
|-------|------|------|
| Shared core | [`core/`](core/) | Intent, policy, fixed account layout, canonical constants |
| On-chain program | [`program/`](program/) | PDA vault, auth, nonce/expiry, actions |
| Off-chain client | [`client/`](client/) | Keygen, dual signing, submission |
| Tests / benches | `program/tests`, `program/benches` | Attack tests (LiteSVM), CU benches (Mollusk) |

**Crypto (selected):**

- On-chain Falcon verify: [`solana-falcon512`](https://crates.io/crates/solana-falcon512) 0.1.2 (prepared pubkey in account)
- Off-chain Falcon keygen/sign: `pqcrypto-falcon` 0.4 (client only)
- Ed25519: Solana Ed25519 precompile + instructions-sysvar introspection

**PDA seeds (stable under key rotation):**

```text
["dualkey", creator, account_index_le]
```

Authenticators live in mutable account data so keys can rotate without moving
the vault address. See architecture doc for the rejected keys-as-seeds design.

## Authorization modes

| Mode | Status | Rule |
|------|--------|------|
| `Ed25519Only` | Planned (early) | Ed25519 |
| `FalconOnly` | Planned (early) | Falcon-512 |
| `HybridAnd` | Primary research mode | Ed25519 **AND** Falcon (no fallback) |
| `HybridOr` | Later | either scheme |
| `FalconForPrivileged` | Later | Falcon for privileged ops |
| `FalconAboveThreshold` | Later | Falcon above value threshold |

Also planned: Falcon required for key rotation / recovery (policy composition).

## Threat model (summary)

Full document: [`docs/threat-model.md`](docs/threat-model.md).

Under **HybridAnd**, theft or break of a **single** scheme must not authorize
spends. Replay is blocked by a per-account nonce and expiry. Intents bind
`program_id`, account PDA, chain domain, and full action body. Policy
downgrades must not be performable with only the weaker authenticator.
Falcon secret keys never appear on-chain.

Residual research risks include an **unaudited** Falcon verifier crate and
tight legacy transaction size budgets.

## Project status

**Milestone 0 — complete (scaffolding + docs).**

| Milestone | Description | Status |
|----------:|-------------|--------|
| 0 | Scaffolding, README, architecture, threat model, benchmark plan | **Done** |
| 1 | Off-chain CLI: Falcon + Ed25519 keygen/sign/verify same digest | Next |
| 2 | Falcon verify under SBF (minimal program) | Pending |
| 3 | HybridAccount PDA (no transfers yet) | Pending |
| 4 | Canonical intent encoding | Pending |
| 5 | HybridAnd authorization | Pending |
| 6 | Replay protection + expiry | Pending |
| 7 | Hybrid-authorized SOL transfer | Pending |
| 8 | CU + transaction-size benchmarks | Pending |
| 9 | Key rotation | Pending |
| 10 | Richer policies | Pending |
| 11 | SPL Token | Pending |

## Repository layout

```text
solana-hybrid-pq-account/
├── Cargo.toml
├── README.md
├── LICENSE
├── rust-toolchain.toml
├── scripts/setup-toolchain.sh
├── core/                 # dualkey-core (shared, no_std-friendly)
├── program/              # dualkey-program (on-chain)
├── client/               # dualkey CLI
└── docs/
    ├── architecture.md
    ├── canonical-intent.md
    ├── threat-model.md
    └── benchmark-plan.md
```

## Build instructions

### Host toolchain (Milestone 0–1)

Requires a recent stable Rust (see `rust-toolchain.toml`) and a C compiler
(`gcc`/`cc`) for `pqcrypto-falcon` once Milestone 1 links signing for real.

`cargo fmt` / `cargo clippy` need the `rustfmt` and `clippy` components
(installed by `./scripts/setup-toolchain.sh` via rustup). This environment may
only have a bare `rustc`/`cargo` until that script is run.

```bash
# Optional: install rustup + Solana/SBF tooling (needed from Milestone 2)
./scripts/setup-toolchain.sh

cargo check --workspace
cargo test -p dualkey-core
cargo build -p dualkey-client
# after toolchain script:
# cargo fmt --all -- --check
# cargo clippy --workspace --all-targets -- -D warnings
```

CLI (Milestone 0 returns explicit “not implemented” errors):

```bash
cargo run -p dualkey-client -- --help
```

### SBF / on-chain (Milestone 2+)

After `./scripts/setup-toolchain.sh`:

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
```

## Test instructions

```bash
# Shared types / layout
cargo test -p dualkey-core

# Integration / attack tests (Milestone 5+; LiteSVM)
# cargo test -p dualkey-program --test valid_hybrid_signature

# CU benches (Milestone 8; Mollusk)
# cargo bench -p dualkey-program
```

Planned attack/integration tests (under `program/tests/`):  
`valid_hybrid_signature`, `invalid_ed25519`, `invalid_falcon`, `replay_attack`,
`expired_intent`, `altered_message`, `wrong_program`, `wrong_vault`,
`key_rotation`.

## Benchmarks

Plan: [`docs/benchmark-plan.md`](docs/benchmark-plan.md).

Upstream Falcon verify baselines (`solana-falcon512`):

| Path | CU |
|------|---:|
| Prepared pubkey verify | ~173k–183k |
| Raw pubkey verify | ~270k |

DualKey measurements (fill at Milestone 8):

| Metric | Ed25519Only | FalconOnly | HybridAnd |
|--------|------------:|-----------:|----------:|
| Auth CU (instruction) | — | — | — |
| Auth CU (transaction) | — | — | — |
| Tx size (bytes) | — | — | — |
| Account data (bytes) | 1120 | 1120 | 1120 |

Known sizes: Falcon sig 666 B · prepared pubkey 1024 B · account 1120 B ·
canonical preimage 172 B.

## Roadmap

See milestones above. Do not advance until the current milestone’s tests pass.

Research questions guiding the work:

1. CU overhead of hybrid PQ authorization on Solana  
2. Transaction-size overhead  
3. Value of prepared Falcon pubkeys  
4. Fit within normal transaction constraints  
5. Falcon on every tx vs privileged-only  
6. Practical migration: Ed25519 → hybrid → Falcon / future schemes  
7. Cryptographic agility without permanent coupling to one algorithm  

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — layers, PDA, layout, deps  
- [`docs/canonical-intent.md`](docs/canonical-intent.md) — signing encoding  
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries and invariants  
- [`docs/benchmark-plan.md`](docs/benchmark-plan.md) — measurement plan  

## License

MIT — see [`LICENSE`](LICENSE).
