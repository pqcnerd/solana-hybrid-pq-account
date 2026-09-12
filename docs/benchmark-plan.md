# DualKey Benchmark Plan

**Status:** Milestone 8 complete — primary CU and legacy tx-size tables filled.
See [`milestone-8.md`](milestone-8.md) and `target/benches/dualkey-milestone-8.md`.

## Research questions (cost)

1. What is the compute-unit overhead of hybrid post-quantum authorization?
2. What is the transaction-size overhead vs Ed25519-only?
3. Is storing a prepared Falcon public key worthwhile?
4. Can hybrid signatures fit within normal Solana transaction constraints?

## Methodology

| Metric class | Harness | Notes |
|--------------|---------|-------|
| Instruction / multi-ix CU | **Mollusk** + `precompiles` | Transaction totals for Ed25519+Execute; Falcon variance → min/median/max |
| Legacy tx size | `bincode` of `solana_transaction::Transaction` | Same encoding as the UDP packet budget (≤ 1232) |
| Account size / rent | Static layout + cluster rent sysvar | `ACCOUNT_DATA_LEN = 1120` |
| Host crypto microbench | `criterion` (optional, later) | Keygen / sign only; not on-chain CU |

Mollusk multi-ix with `precompiles` is DualKey’s transaction CU harness
(Milestone 5+). A separate LiteSVM CU column was not required for Milestone 8.

### Upstream Falcon baselines (`solana-falcon512` 0.1.2)

Use these as comparison targets when DualKey benches land:

| Path | Upstream | Measured in DualKey (Milestone 2) |
|------|---------:|----------------------------------:|
| `verify_with_prepared` (success) | ~173k–183k | 172.6k – 193.4k |
| `verify_with_prepared` (rejection) | ~173k–183k | ~173.0k (invalid signature) |
| `verify` (raw pubkey) | ~270k | 224.6k – 245.4k |
| Prepared-vs-raw delta | ~99k | **51,991 CU, deterministic** |
| Safe CU limit (prepared) | 195,000 | holds; 205,000 tail ceiling |
| `Initialize` (Milestone 3) | — | **60,854 CU, deterministic** |
| ↳ `try_prepare_pubkey` alone | ~99k | **52,410 CU, deterministic** |

Measured over a 32-byte digest with Mollusk 0.15.1 against the compiled `.so`;
full table in [`milestone-2.md`](milestone-2.md).

Variance comes from SHAKE-256 rejection sampling in `hash_to_point`, and it is
**quantized**: cost moves in ~10,150 CU steps, one Keccak-f[1600] permutation.
Benchmarks must therefore report a range over several signatures. A single
sample is not a meaningful figure for this primitive, and a median over a small
sample is not stable either — two runs of the same 9-sample measurement gave
medians 9,500 CU apart. Report min/max, and prefer deterministic *deltas*
(e.g. prepared vs raw) when comparing designs.

## Metrics to record

### Compute units

- Ed25519-only authorization path — **done (M8): ~3,208 CU median**
- Falcon-only authorization path — **done (M8): ~185k CU median**
- HybridAnd authorization path — **done (M8): ~185.5k CU median**
- Falcon verification alone (prepared vs raw) — **done (M2)**
- Account initialization — **done (M3): 60,854 CU**
- SOL-transfer action portion (post-auth) — included in M8 Execute+TransferSol totals (transfer bookkeeping negligible vs Falcon)

### Sizes

| Item | Expected / layout | Measured (M8) |
|------|-------------------|--------------:|
| Falcon compressed signature | 666 bytes (zero-padded) | 666 |
| Falcon wire pubkey | 897 bytes | 897 |
| Prepared Falcon pubkey | 1024 bytes | 1024 |
| HybridAccount data | 1120 bytes | 1120 |
| Ed25519 precompile ix | 144 bytes | 144 |
| Legacy tx (HybridAnd transfer) | target ≤ 1232 | **1,165** |
| DualKey execute ix data | ~716 bytes | 716 |

### Costs

- Account initialization lamports (rent-exempt minimum): **8,686,080**
- Marginal CU of HybridAnd vs Ed25519Only: **~182,287 CU (median)**

## Results table (Milestone 8)

| Metric | Ed25519Only | FalconOnly | HybridAnd | Notes |
|--------|------------:|-----------:|----------:|-------|
| Auth+transfer CU (median) | 3,208 | 185,034 | 185,495 | Mollusk multi-ix |
| Auth+transfer CU (min–max) | 3,207–3,208 | 175k–185k | 176k–186k | 9 samples |
| Tx serialized size (B) | 1,165 | 985 | 1,165 | legacy bincode |
| Account data size (B) | 1120 | 1120 | 1120 | fixed layout |
| Prepared Falcon pubkey (B) | 1024 | 1024 | 1024 | |
| Falcon signature (B) | 666* | 666 | 666 | *slot present, ignored |
| Init CU | — | — | 60,854 | includes prepare |
| Transfer CU (full) | 3,208 | 185,034 | 185,495 | same path as auth |

### Size-only reference (known a priori)

| Item | Bytes |
|------|------:|
| HybridAccount | 1120 |
| Prepared Falcon pubkey | 1024 |
| Falcon signature | 666 |
| Falcon wire pubkey | 897 |
| Canonical preimage | 172 |
| Intent digest | 32 |

## Procedure checklist

1. Build program with `cargo-build-sbf` (release, fat LTO — match upstream).
2. Mollusk benches for: prepared Falcon verify probe, HybridAnd execute, init.
3. Construct full HybridAnd transfer tx; record CU and `bincode` serialized size.
4. Negative path: well-formed invalid Falcon still consumes ~same CU (document DoS surface).
5. Commit markdown bench output under `target/benches/` locally; copy summary
   tables into README when stable.
6. Re-run after any auth or serialization change; track deltas.

## Success criteria for the research write-up

- [x] HybridAnd CU and tx size reported with methodology and toolchain versions
- [x] Prepared-vs-raw CU delta measured in DualKey’s own program frame (not only
  upstream’s demo program) — Milestone 2
- [x] Clear statement whether legacy txs fit without ALT — **yes, 1,165 / 1,232**
- [x] Explicit non-claim: numbers are empirical, not a security proof
