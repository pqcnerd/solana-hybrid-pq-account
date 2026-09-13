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
| Tests / benches | `client/tests` | Host tests, plus SBF attack tests and CU benches (Mollusk) against the compiled `.so` |

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
| `Ed25519Only` | **Done** | Ed25519 |
| `FalconOnly` | **Done** | Falcon-512 |
| `HybridAnd` | **Done** (primary) | Ed25519 **AND** Falcon (no fallback) |
| `HybridOr` | **Done** | either scheme |
| `FalconForPrivileged` | **Done** | Falcon for privileged ops |
| `FalconAboveThreshold` | **Done** | Falcon above value threshold |

Key rotation, policy changes, and recovery controls are privileged under
`FalconForPrivileged`. `ChangePolicy` uses the stricter-of signature lattice.

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

**Milestones 0–16 complete** (research path plus out-of-scope finish items).
See [`docs/STATUS.md`](docs/STATUS.md).

| Milestone | Description | Status |
|----------:|-------------|--------|
| 0 | Scaffolding, README, architecture, threat model, benchmark plan | **Done** |
| 1 | Off-chain CLI: Falcon + Ed25519 keygen/sign/verify same digest | **Done** |
| 2 | Falcon verify under SBF (minimal program) | **Done** |
| 3 | HybridAccount PDA (no transfers yet) | **Done** |
| 4 | Canonical intent encoding + on-chain reconstruction | **Done** |
| 5 | HybridAnd authorization | **Done** |
| 6 | Replay protection + expiry | **Done** |
| 7 | Hybrid-authorized SOL transfer | **Done** |
| 8 | CU + transaction-size benchmarks | **Done** |
| 9 | Key rotation | **Done** |
| 10 | Richer policies | **Done** |
| 11 | SPL Token | **Done** |
| 12 | RecoverAccount (Falcon-only Ed recover) | **Done** |
| 13 | CLI RPC broadcast | **Done** |
| 14 | Token-2022 TransferSpl (base; hooks refused) | **Done** |
| 15 | Social recovery (guardian + timelock) | **Done** |
| 16 | Docs / CLI / localnet demo polish | **Done** |

## Repository layout

```text
solana-hybrid-pq-account/
├── Cargo.toml
├── README.md
├── LICENSE
├── rust-toolchain.toml
├── scripts/
│   ├── setup-toolchain.sh
│   └── demo-localnet.sh      # one-shot init → transfer (M16)
├── core/                     # dualkey-core (intent, policy, RecoveryConfig)
├── program/                  # dualkey-program (on-chain; verify only)
├── client/                   # dualkey CLI + Mollusk SBF tests
│   └── src/{main,onchain,submit,rpc,…}.rs
└── docs/
    ├── STATUS.md
    ├── architecture.md
    ├── canonical-intent.md
    ├── threat-model.md
    └── milestone-*.md
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

## CLI usage

```bash
cargo run -p dualkey-client -- --help
```

### 1. Generate keys

```bash
cargo run -p dualkey-client -- keygen --out ./keys
```

```text
Key directory:          ./keys
Ed25519 public key:     7307449afbe5a8b27e5531a3ae512218a443e4ecb4c76ab628a461923c4844c9
Falcon pubkey SHA-256:  94ffded21098db66daf7bd804dae0da51fde5c5665c972c08f4cc37a91447b6d
Falcon public key:      897 bytes
Falcon secret key:      1281 bytes (not shown)
Prepared public key:    1024 bytes
Private files (0600):   ed25519.sk, ed25519-id.json, falcon512.sk
```

Secret key bytes are never printed, and `Ed25519Keypair` / `FalconKeypair`
deliberately have no `Debug` implementation.

#### Key file formats

Key material is stored as raw binary so files are directly consumable by
`include_bytes!` and by the on-chain wire parsers.

| File | Bytes | Mode | Contents |
|------|------:|------|----------|
| `ed25519.sk` | 32 | `0600` | Ed25519 seed (RFC 8032 private key) |
| `ed25519.pk` | 32 | `0644` | Ed25519 public key |
| `ed25519-id.json` | JSON | `0600` | Solana-style 64-byte array (seed ‖ pubkey) |
| `falcon512.sk` | 1281 | `0600` | PQClean falcon-512 secret key |
| `falcon512.pk` | 897 | `0644` | PQClean falcon-512 public key (wire format) |
| `falcon512.prepared` | 1024 | `0644` | NTT-form public key for account data |
| `keyset.json` | JSON | `0644` | Public manifest (no secret material) |

`falcon512.prepared` is derived **only** from the public key and is the exact
1024 bytes written into the DualKey account. It contains no secret material.

### 2. Sign an intent

`intent.json` (all 32-byte fields are lowercase hex; JSON is an input format
only — the *signed* bytes are always the fixed-width canonical preimage):

```json
{
  "chain_domain": "1111111111111111111111111111111111111111111111111111111111111111",
  "program_id":   "2222222222222222222222222222222222222222222222222222222222222222",
  "account":      "3333333333333333333333333333333333333333333333333333333333333333",
  "nonce": 0,
  "expiry_slot": 250000,
  "action": {
    "type": "transfer_sol",
    "recipient": "4444444444444444444444444444444444444444444444444444444444444444",
    "lamports": 1500000
  }
}
```

```bash
cargo run -p dualkey-client -- sign --intent intent.json --keys ./keys --out bundle.json
```

```text
Digest:                 639880d43755ad6339e26a2ac68948e07b4ba7ed7669e5bd9eb83837a6cf9f6f
Falcon signature:       658 encoded + 8 padding = 666 bytes
Signed bundle written:  bundle.json
```

### 3. Verify

```bash
cargo run -p dualkey-client -- verify --input bundle.json
```

```text
Digest:                 639880d43755ad6339e26a2ac68948e07b4ba7ed7669e5bd9eb83837a6cf9f6f
Ed25519 verification:   VALID
Falcon (PQClean):       VALID
Falcon (Solana impl):   VALID
Falcon (Solana prep):   VALID
Shared digest:          YES
```

`verify` exits non-zero if any check fails. Falcon is checked against **both**
PQClean and the on-chain verifier (raw and prepared public-key paths), so an
off-chain/on-chain divergence cannot pass unnoticed.

### 4. On-chain builders and broadcast (Milestones 3–16)

```bash
# Offline artifact (default) or submit with --broadcast --rpc-url --payer
cargo run -p dualkey-client -- init \
  --keys ./keys --program-id <PROGRAM> --creator <CREATOR> --policy hybrid-and

cargo run -p dualkey-client -- transfer \
  --to <RECIPIENT> --lamports 1000 --program-id <PROGRAM> --account <HYBRID> \
  --expiry-slot <SLOT> --broadcast --rpc-url http://127.0.0.1:8899 --payer ./payer.json

# Also: transfer-spl, change-policy, rotate-ed25519, recover {…},
# social {set-config,initiate,finalize,cancel} (after `recover enable`).
# rotate-falcon: offline/--out only (legacy --broadcast cannot fit ~2279 B ix).
# Omit --nonce when --rpc-url is set (CLI reads chain nonce); --broadcast still needs --payer.
```

One-shot localnet smoke: `PROGRAM_ID=… PAYER=… ./scripts/demo-localnet.sh`.

This also demonstrates the HybridAnd property directly: flipping one bit of
the Falcon signature yields `Ed25519 VALID` but `Falcon INVALID`, and the
overall result is rejection.

### SBF / on-chain

After `./scripts/setup-toolchain.sh`:

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
```

This writes `target/deploy/dualkey_program.so`, which the SBF tests load. Build
it before running `cargo test --workspace`, or those tests will fail with a
message telling you to.

## Test instructions

```bash
# Everything (needs the .so built first; ~200 tests as of Milestone 16)
cargo test --workspace

# Shared types, layout, canonical encoding
cargo test -p dualkey-core

# Falcon interoperability gate
cargo test -p dualkey-client --test falcon_interop -- --nocapture

# Falcon verification inside the SBF VM (Mollusk)
cargo test -p dualkey-client --release --test sbf_falcon -- --nocapture

# HybridAccount PDA initialization, with CU and rent figures
cargo test -p dualkey-client --release --test sbf_initialize -- --nocapture

# On-chain intent reconstruction (Milestone 4)
cargo test -p dualkey-client --release --test sbf_reconstruct -- --nocapture

# HybridAnd + replay/expiry + TransferSol (Milestones 5–7; needs mollusk precompiles)
cargo test -p dualkey-client --release --test sbf_hybrid -- --nocapture

# CU + legacy tx size matrix (Milestone 8)
cargo test -p dualkey-client --release --test sbf_bench -- --nocapture

# Key rotation (Milestone 9)
cargo test -p dualkey-client --release --test sbf_rotate -- --nocapture

# Richer policies + ChangePolicy (Milestone 10)
cargo test -p dualkey-client --release --test sbf_policy -- --nocapture

# SPL Token transfer (Milestone 11)
cargo test -p dualkey-client --release --test sbf_spl -- --nocapture

# RecoverAccount (Milestone 12)
cargo test -p dualkey-client --release --test sbf_recover -- --nocapture

# Token-2022 + hook refusal (Milestone 14; included in sbf_spl)
cargo test -p dualkey-client --release --test sbf_spl -- --nocapture

# Social recovery (Milestone 15)
cargo test -p dualkey-client --release --test sbf_social_recovery -- --nocapture

# Signature length distribution soak (10,000 signatures)
cargo test -p dualkey-client --release --test falcon_interop -- --ignored --nocapture

# Compute-unit profile by message length
cargo test -p dualkey-client --release --test sbf_falcon -- --ignored --nocapture
```

Test groups (all under `client/tests/`):

| File | Group | Covers |
|------|-------|--------|
| `falcon_interop.rs` | Gate | Lengths, padding, byte-for-byte cross-impl verification, alignment |
| `dual_signing.rs` | A (positive) | Keygen/sign/verify, shared digest, round-trip, core test vectors |
| `digest_mutation.rs` | B | Every one-bit digest flip rejected by all verifiers |
| `signature_mutation.rs` | C | Signature bit flips, malformed/oversized input, no panics |
| `wrong_keys.rs` | D | Wrong public keys, tampered intents, per-scheme independence |
| `file_safety.rs` | E | `0600` modes, no secrets in output/errors/on-chain data |
| `encoding_review.rs` | Review | Compressed-encoding invariants; PQClean accepts the padded 666-byte form |
| `sbf_falcon.rs` | SBF (M2) | Falcon verify + `sol_sha256` inside the SBF VM; malformed input; CU |
| `sbf_initialize.rs` | SBF (M3) | HybridAccount PDA creation, on-chain Falcon key preparation, rejection paths, CU and rent |
| `sbf_reconstruct.rs` | SBF (M4) | Intent reconstruction from trusted context + 49-byte wire; digest match; wrong context fails |
| `sbf_hybrid.rs` | SBF (M5–M7) | HybridAnd / policies; nonce/replay/expiry; TransferSol + rent floor |
| `sbf_bench.rs` | SBF (M8) | Policy CU matrix (9 samples); legacy tx size ≤ 1232 without ALT |
| `sbf_rotate.rs` | SBF (M9) | RotateEd25519 / RotateFalcon + PoP; old key cannot authorize after rotate |
| `sbf_policy.rs` | SBF (M10) | HybridOr / FalconForPrivileged / FalconAboveThreshold; ChangePolicy stricter-of |
| `sbf_spl.rs` | SBF (M11/M14) | TransferSpl classic + Token-2022 base; transfer-hook refusal |
| `sbf_recover.rs` | SBF (M12) | Enable/disable recovery; Falcon-only Ed25519 recover rotate |
| `sbf_social_recovery.rs` | SBF (M15) | Guardian + timelock set/initiate/finalize/cancel |

The SBF tests live in `client/tests/` rather than `program/tests/` on purpose:
it keeps every Falcon **signer** out of the program package's dependency graph,
even as a dev-dependency, and makes each test a genuine cross-layer check —
the client signs with PQClean, the program verifies with `solana-falcon512`.

On-chain coverage: HybridAnd, replay/expiry, TransferSol/SPL (classic +
Token-2022 base), CU/size benches, key rotation + PoP, richer policies,
ChangePolicy, RecoverAccount, social recovery, and CLI RPC broadcast. Still
excluded: full transfer-hook resolution, multi-guardian thresholds, formal
audit / “quantum proof” claims.

Localnet demo sketch: [`scripts/demo-localnet.sh`](scripts/demo-localnet.sh)
(requires `solana-test-validator`, a deployed program, and a funded payer).

## Benchmarks

Plan: [`docs/benchmark-plan.md`](docs/benchmark-plan.md).

Falcon verify cost, **measured under SBF** in Milestone 2 (Mollusk 0.15.1
against the compiled `.so`, 32-byte digest) — see
[`docs/milestone-2.md`](docs/milestone-2.md):

| Path | Measured | Upstream |
|------|---------:|---------:|
| Prepared pubkey verify | 172.6k – 193.4k CU | ~173k–183k |
| Raw pubkey verify | 224.6k – 245.4k CU | ~270k |
| Prepared-vs-raw saving | **51,991 CU** (deterministic) | ~99k |
| Canonical digest via `sol_sha256` | 417 CU | — |
| `Initialize` (Milestone 3) | **60,854 CU** (deterministic) | — |
| ↳ one-time `try_prepare_pubkey` | **52,410 CU** (deterministic) | ~99k |
| FalconOnly `TransferSol` (Milestone 7) | **~175,350 CU** | — |

Absolute cost is quantized in ~10,150 CU steps (one Keccak-f permutation) and
varies per signature because `hash_to_point` rejection-samples, so it is quoted
as a range. The prepared-vs-raw *difference* is deterministic, since the two
paths differ only by the wire-key decode and forward NTT.

Preparing the key costs almost exactly what one raw verify wastes (52,410 vs
51,991 CU), because preparing *is* the work the raw path repeats each time. So
storing the prepared key breaks even after a single authorization.

Measured in Milestone 1 (host, 10,000 signatures) — see
[`docs/falcon-interop.md`](docs/falcon-interop.md):

| Quantity | Value |
|----------|------:|
| Falcon compressed signature length | 647–663 bytes (mode 655) |
| On-chain wire signature buffer | 666 bytes (zero-padded) |
| Signatures exceeding the buffer | 0 / 10,000 |

DualKey measurements (Milestone 8 — Mollusk multi-ix tx CU, 9 samples;
legacy `bincode` size). Full write-up: [`docs/milestone-8.md`](docs/milestone-8.md).

| Metric | Ed25519Only | FalconOnly | HybridAnd |
|--------|------------:|-----------:|----------:|
| Auth+transfer CU (median) | **3,208** | **185,034** | **185,495** |
| Auth+transfer CU (min–max) | 3,207–3,208 | 175k–185k | 176k–186k |
| Tx size (bytes) | **1,165** | **985** | **1,165** |
| Headroom to 1232 | 67 | 247 | **67** |
| Account data (bytes) | 1120 | 1120 | 1120 |

**Legacy fit:** HybridAnd TransferSol is **1,165 / 1,232** bytes — fits **without**
an Address Lookup Table. Marginal HybridAnd cost vs Ed25519Only is ~**182k CU**
(Falcon-dominated). Well-formed Falcon rejections cost ~184k CU (DoS surface).

Known sizes: Falcon sig 666 B · prepared pubkey 1024 B · account 1120 B ·
canonical preimage 172 B.

## Roadmap

Milestones **0–16 are complete**. Remaining items are explicit non-goals
(formal audit, transfer-hook resolution, multi-guardian, “quantum proof”).
See [`docs/STATUS.md`](docs/STATUS.md).

Research questions the repo answered:

1. CU overhead of hybrid PQ authorization on Solana  
2. Transaction-size overhead  
3. Value of prepared Falcon pubkeys  
4. Fit within normal transaction constraints  
5. Falcon on every tx vs privileged-only  
6. Practical migration: Ed25519 → hybrid → Falcon / future schemes  
7. Cryptographic agility without permanent coupling to one algorithm  

## Documentation

- [`docs/STATUS.md`](docs/STATUS.md) — delivered surface + verify commands  
- [`docs/architecture.md`](docs/architecture.md) — layers, PDA, layout, deps  
- [`docs/canonical-intent.md`](docs/canonical-intent.md) — signing encoding  
- [`docs/falcon-interop.md`](docs/falcon-interop.md) — PQClean ↔ on-chain Falcon encoding findings  
- [`docs/milestone-2.md`](docs/milestone-2.md) — Falcon under SBF: measured CU  
- [`docs/milestone-6.md`](docs/milestone-6.md) — replay protection + expiry  
- [`docs/milestone-7.md`](docs/milestone-7.md) — hybrid-authorized SOL transfer  
- [`docs/milestone-8.md`](docs/milestone-8.md) — CU + legacy transaction size  
- [`docs/milestone-9.md`](docs/milestone-9.md) — key rotation + Falcon PoP  
- [`docs/milestone-10.md`](docs/milestone-10.md) — richer policies + ChangePolicy  
- [`docs/milestone-11.md`](docs/milestone-11.md) — SPL Token transfer  
- [`docs/milestone-12.md`](docs/milestone-12.md) — RecoverAccount  
- [`docs/milestone-13.md`](docs/milestone-13.md) — CLI RPC broadcast  
- [`docs/milestone-14.md`](docs/milestone-14.md) — Token-2022 TransferSpl  
- [`docs/milestone-15.md`](docs/milestone-15.md) — social recovery  
- [`docs/milestone-16.md`](docs/milestone-16.md) — polish  
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries and invariants  
- [`docs/benchmark-plan.md`](docs/benchmark-plan.md) — measurement plan  

## License

MIT — see [`LICENSE`](LICENSE).
