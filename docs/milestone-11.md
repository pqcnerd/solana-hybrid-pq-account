# Milestone 11 — SPL Token transfer

**Goal:** move classic SPL tokens out of a DualKey-controlled token account under
the same hybrid authorization path as `TransferSol`, with the HybridAccount PDA
signing the Token program CPI.

**Status:** complete. 6 SBF SPL tests pass; fmt/clippy clean after verification.

---

## 1. What was built

### `Action::TransferSpl` (tag 2)

```text
action_body = destination_token_account[32] || amount:u64 LE
```

Same 40-byte shape as `TransferSol`. Destination is bound into the signed
digest (threat-model invariant 12).

### `Execute` account list for SPL

| # | Account |
|---|---------|
| 0 | HybridAccount (**writable**) — nonce; PDA authority |
| 1 | creator (readonly) — PDA seed |
| 2 | source token (**writable**) — owner must be the HybridAccount |
| 3 | mint (readonly) |
| 4 | destination token (**writable**) — must match signed destination |
| 5 | classic SPL Token program |
| 6 | instructions sysvar |

`TransferSol` keeps its original 3-account layout. `Execute` branches on the
action tag after decoding the wire fragment.

### PDA signing

`Initialize` now stores `account_index` at offset 4 (formerly reserved).
`TransferSpl` reconstructs seeds `["dualkey", creator, account_index_le, bump]`
and verifies they form the HybridAccount address before
`invoke_signed(transfer_checked, …)`.

Wrong creator → `InvalidPda`. Source not owned by the PDA →
`InvalidAccountData`. Insufficient token balance → `InsufficientFunds`.

### CPI details

- Classic SPL Token (`Tokenkeg…`); Token-2022 base accounts are Milestone 14
- Hand-rolled `TransferChecked` (disc 12) — no `spl-token` dep in the program
- Mint decimals read from the mint account; source/dest mint fields checked
- `amount == 0` still consumes the nonce (parity with `TransferSol`)

### Policy interaction

| Policy | `TransferSpl` |
|--------|----------------|
| `FalconForPrivileged` | normal (Ed25519) — same as `TransferSol` |
| `FalconAboveThreshold` | compares `amount` to threshold in **raw token units** |

### Client

`execute_transfer_spl_instruction` builds the 7-account Execute ix.
`ActionSpec::TransferSpl` is available for JSON intents.

---

## 2. Tests (`client/tests/sbf_spl.rs`, 6)

| Test | Property |
|------|----------|
| `transfer_spl_under_hybrid_and_moves_tokens` | HybridAnd auth + token debit/credit + nonce |
| `transfer_spl_rejects_wrong_destination_account` | signed dest ≠ account meta |
| `transfer_spl_rejects_wrong_creator_seed` | `InvalidPda` |
| `transfer_spl_rejects_insufficient_token_balance` | `InsufficientFunds` |
| `transfer_spl_zero_amount_consumes_nonce_only` | no token move |
| `initialize_stores_account_index_for_pda_signing` | layout field set at init |

---

## 3. Explicitly not done (at M11 ship time)

Historical — later milestones closed several of these:

- Token-2022 base accounts: [`milestone-14.md`](milestone-14.md) (hooks still refused)
- `RecoverAccount`: [`milestone-12.md`](milestone-12.md)
- CLI `transfer-spl` (+ `--broadcast`): Milestone 16 / [`milestone-13.md`](milestone-13.md)
- No minting / ATA creation helpers on-chain (still true)

---

## 4. Verification

```bash
unset CARGO_TARGET_DIR
export CARGO_TARGET_DIR="$PWD/target"
cargo-build-sbf --manifest-path program/Cargo.toml
cargo test -p dualkey-client --test sbf_spl
```

Milestone 11 completes classic SPL spend. See [`milestone-14.md`](milestone-14.md)
for Token-2022 and [`STATUS.md`](STATUS.md) for the full surface.

