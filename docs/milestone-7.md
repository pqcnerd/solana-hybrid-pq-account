# Milestone 7 — Hybrid-authorized SOL transfer

**Goal:** after successful authorization (and nonce consumption), move lamports
from the HybridAccount PDA to the signed recipient without dropping the vault
below its rent-exempt floor.

**Status:** complete. 149 tests pass, fmt/clippy clean, SBF build clean.

---

## 1. What was built

`Execute` now finishes the architecture flow:

1. …(Milestone 5–6 auth + expiry + nonce bump)…
2. Debit `lamports` from the HybridAccount
3. Credit the **writable** recipient account whose address equals the signed
   `TransferSol.recipient`

### Accounts (updated)

| # | Account |
|---|---------|
| 0 | HybridAccount (**writable**) — nonce + lamport debit |
| 1 | recipient (**writable**) — must match the signed action |
| 2 | instructions sysvar (readonly) |

The client derives the recipient `AccountMeta` from the intent so the wire
action and the account list cannot drift.

### Transfer mechanics

- Direct lamport mutation (not a System CPI): the vault is DualKey-owned.
- `amount == 0` is a no-op that still consumes the nonce.
- Remaining balance must stay `>= Rent::minimum_balance(ACCOUNT_DATA_LEN)`
  (~8,686,080 lamports); otherwise `InsufficientFunds`.
- Recipient ≠ HybridAccount; wrong recipient pubkey → `InvalidAccountData`.
- Failed transfer reverts the whole instruction, including the nonce write
  (Solana atomicity).

### Client

`dualkey transfer` builds an offline HybridAnd artifact (Ed25519 precompile +
Execute), signs with both schemes, and writes public material only. It does
**not** broadcast.

---

## 2. Measurements

| Path | CU (Mollusk tx total) |
|------|----------------------:|
| FalconOnly `TransferSol` 1M lamports | **~175,350** |
| HybridAnd auth + transfer | dominated by Falcon (~185k class) |

Transfer bookkeeping is negligible next to Falcon verify.

---

## 3. Explicitly not done

- **No LiteSVM legacy-tx size** measurement (Milestone 8)
- **No RPC broadcast** in the CLI (artifact only)
- **No key rotation** (Milestone 9)
- **No SPL** (Milestone 11)

---

## 4. Tests (`client/tests/sbf_hybrid.rs`, 25)

Prior Milestone 5–6 coverage retained (now with recipient accounts), plus:

| Test | Property |
|------|----------|
| `transfer_sol_moves_lamports_to_recipient` | debit/credit + nonce bump |
| `transfer_that_would_breach_rent_exempt_floor_is_rejected` | `InsufficientFunds` |
| `transfer_down_to_exact_rent_exempt_floor_succeeds` | remaining == rent min |
| `insufficient_funds_does_not_consume_nonce` | atomic revert of nonce |
| `wrong_recipient_account_is_rejected` | account ≠ signed recipient |
| `zero_lamport_transfer_succeeds_without_moving_funds` | nonce-only burn |
| `execute_accounts_include_writable_recipient` | client meta shape |
| `hybrid_and_succeeds_with_both_signatures` | also asserts lamport move |

---

## 5. Verification

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace                          # 149 passed, 2 ignored
cargo tree -p dualkey-program --all-features    # no pqcrypto-falcon
```

Milestone 7 is complete. See [`docs/milestone-8.md`](milestone-8.md) for CU and
legacy transaction-size benchmarks (Milestone 8).
