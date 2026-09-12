# DualKey Benchmark Plan

**Status:** Milestone 0 plan. Measurements begin at Milestone 8 (with early
Falcon CU probes possible from Milestone 2).

## Research questions (cost)

1. What is the compute-unit overhead of hybrid post-quantum authorization?
2. What is the transaction-size overhead vs Ed25519-only?
3. Is storing a prepared Falcon public key worthwhile?
4. Can hybrid signatures fit within normal Solana transaction constraints?

## Methodology

| Metric class | Harness | Notes |
|--------------|---------|-------|
| Instruction CU | **Mollusk** + `mollusk-svm-bencher` | Markdown baselines + deltas; instruction-level |
| End-to-end CU + tx size | **LiteSVM** | Real transaction model, precompile, account keys |
| Account size / rent | Static layout + cluster rent sysvar | `ACCOUNT_DATA_LEN = 1120` |
| Host crypto microbench | `criterion` (optional, later) | Keygen / sign only; not on-chain CU |

Do **not** compare Mollusk instruction CU to LiteSVM transaction CU as if
they were the same number — LiteSVM includes transaction overhead.

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

- Ed25519-only authorization path (when implemented)
- Falcon-only authorization path
- HybridAnd authorization path
- Falcon verification alone (prepared vs raw, if raw probe retained)
- ~~Account initialization (includes `try_prepare_pubkey`)~~ — **measured in
  Milestone 3: 60,854 CU total**, of which `try_prepare_pubkey` is 52,410 CU and
  parsing + PDA derivation + three System CPIs are 8,444 CU. Fully deterministic
  across runs, unlike verification. The ~99k estimate does not reproduce for
  this quantity either; see [`milestone-3.md`](milestone-3.md).
- SOL-transfer action portion (post-auth)

### Sizes

| Item | Expected / layout |
|------|-------------------|
| Falcon compressed signature | 666 bytes (zero-padded) |
| Falcon wire pubkey | 897 bytes |
| Prepared Falcon pubkey | 1024 bytes |
| HybridAccount data | 1120 bytes |
| Ed25519 precompile ix | 144 bytes |
| Legacy tx serialized size (HybridAnd transfer) | target ≤ 1232 |
| DualKey execute ix data | ~716 bytes |

### Costs

- Account initialization lamports (rent-exempt minimum)
- Marginal CU of HybridAnd vs Ed25519Only

## Results table schema (README / paper)

Fill during Milestone 8; leave placeholders until then.

| Metric | Ed25519Only | FalconOnly | HybridAnd | Notes |
|--------|------------:|-----------:|----------:|-------|
| Auth CU (instruction) | — | — | — | Mollusk |
| Auth CU (transaction) | — | — | — | LiteSVM |
| Tx serialized size (B) | — | — | — | |
| Account data size (B) | 1120 | 1120 | 1120 | fixed layout |
| Prepared Falcon pubkey (B) | 1024 | 1024 | 1024 | |
| Falcon signature (B) | — | 666 | 666 | |
| Init CU | — | — | — | includes prepare |
| Transfer CU (full) | — | — | — | |

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
3. LiteSVM: construct full HybridAnd transfer tx; record
   `compute_units_consumed` and `bincode`/`packet` serialized size.
4. Negative path: invalid Falcon still consumes ~same CU (document DoS surface).
5. Commit markdown bench output under `target/benches/` locally; copy summary
   tables into README when stable.
6. Re-run after any auth or serialization change; track deltas.

## Success criteria for the research write-up

- HybridAnd CU and tx size reported with methodology and toolchain versions
- Prepared-vs-raw CU delta measured in DualKey’s own program frame (not only
  upstream’s demo program)
- Clear statement whether legacy txs fit without ALT
- Explicit non-claim: numbers are empirical, not a security proof
