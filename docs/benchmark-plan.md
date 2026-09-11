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

| Path | Compute units (upstream) |
|------|-------------------------:|
| `verify_with_prepared` (success) | ~173k–183k |
| `verify_with_prepared` (rejection) | ~173k–183k |
| `verify` (raw pubkey) | ~270k |
| Safe CU limit (prepared) | 195,000 |

Variance comes from SHAKE-256 rejection sampling in `hash_to_point`.

## Metrics to record

### Compute units

- Ed25519-only authorization path (when implemented)
- Falcon-only authorization path
- HybridAnd authorization path
- Falcon verification alone (prepared vs raw, if raw probe retained)
- Account initialization (includes `try_prepare_pubkey` ~99k CU)
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
