# Milestone 8 — CU + transaction-size benchmarks

**Goal:** measure DualKey’s compute-unit cost and legacy transaction size for
Ed25519Only, FalconOnly, and HybridAnd transfer paths, and answer whether a
HybridAnd transfer fits the 1232-byte legacy limit without an ALT.

**Status:** complete. 151 tests pass, fmt/clippy clean. Results also written to
`target/benches/dualkey-milestone-8.md` by the bench harness.

**Not a security proof** — these are empirical cost measurements.

---

## 1. Methodology

| Metric | Harness |
|--------|---------|
| Auth + transfer CU | Mollusk 0.15 (`precompiles`), multi-ix tx via `process_and_validate_transaction_instructions` |
| Legacy tx size | `bincode::serialized_size` of `solana_transaction::Transaction` (UDP packet encoding) |
| Sample size | 9 independent signatures / fresh keys per policy (Falcon cost is quantized ~10k CU) |

LiteSVM was **not** required for this milestone: Mollusk’s `precompiles` feature
already runs the Ed25519 precompile and DualKey `Execute` in one transaction
with a shared instructions sysvar (proven in Milestone 5). CU figures below are
therefore **transaction totals**, not isolated DualKey-instruction numbers for
paths that include the precompile.

Toolchain: `cargo-build-sbf` release / fat LTO, Mollusk 0.15.1, Solana platform
tools matching the workspace lockfile.

---

## 2. Compute units (Execute + TransferSol)

| Policy | min | median | max |
|--------|----:|-------:|----:|
| Ed25519Only | 3,207 | **3,208** | 3,208 |
| FalconOnly | 175,215 | **185,034** | 185,457 |
| HybridAnd | 175,675 | **185,495** | 186,002 |
| HybridAnd + bit-flipped Falcon (reject) | 174,334 | **184,339** | 184,981 |

### Marginal cost vs Ed25519Only (medians)

| Path | Δ CU |
|------|-----:|
| FalconOnly | +181,826 |
| HybridAnd | +182,287 |

HybridAnd’s overhead over FalconOnly is small (~0.5k CU median): Ed25519
precompile + introspection is negligible next to Falcon verify.

### DoS surface

A **well-formed but invalid** Falcon signature still burns Falcon-class CU
(~184k). An all-zero / decode-rejecting buffer fails in ~2k CU — cheap failures
are possible, but a crafted rejection matches the success path’s cost.

---

## 3. Legacy transaction size

| Policy | Serialized bytes | Headroom to 1232 |
|--------|-----------------:|-----------------:|
| Ed25519Only | **1,165** | 67 |
| FalconOnly | **985** | 247 |
| HybridAnd | **1,165** | 67 |

Ed25519Only and HybridAnd match because `Execute` always carries the 666-byte
Falcon signature slot (ignored under Ed25519Only) and both include the 144-byte
Ed25519 precompile instruction. FalconOnly drops the precompile.

### Verdict

**HybridAnd TransferSol fits a legacy transaction without an Address Lookup
Table** (1,165 ≤ 1,232), with **67 bytes** of headroom. That matches the
Milestone 0 estimate (~1,200 / ~26 B headroom) to within measurement error from
account-key packing.

---

## 4. Answers to research cost questions

1. **Hybrid PQ CU overhead:** ~182k CU vs Ed25519Only (dominated by Falcon).
2. **Tx size overhead vs Ed25519Only:** **0 bytes** on DualKey’s wire format
   (Falcon slot always present). FalconOnly is 180 B smaller (no precompile).
3. **Prepared Falcon pubkey:** already measured in M2/M3 — ~52k CU one-time at
   init; saves ~52k CU per verify vs raw.
4. **Fit normal constraints:** **yes**, legacy limit, no ALT required for the
   measured HybridAnd transfer shape.

---

## 5. Tests / artifacts

| Artifact | Role |
|----------|------|
| `client/tests/sbf_bench.rs` | Always-on size assert + 9-sample CU matrix |
| `target/benches/dualkey-milestone-8.md` | Regenerated markdown summary |

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
cargo test -p dualkey-client --release --test sbf_bench -- --nocapture
```

---

## 6. Explicitly not done

- **No key rotation** (Milestone 9)
- **No richer policies** (Milestone 10)
- **No SPL** (Milestone 11)
- No separate LiteSVM CU column (Mollusk multi-ix is the transaction figure)

Milestone 8 is complete. See [`docs/milestone-9.md`](milestone-9.md) for key
rotation (Milestone 9).
