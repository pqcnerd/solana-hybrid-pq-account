# Milestone 9 — Key rotation

**Goal:** rotate the Ed25519 owner key and the Falcon-512 public key under the
account’s **current** authorization policy, without moving the PDA address.
Falcon registration requires proof-of-possession so a bogus key cannot brick
HybridAnd accounts.

**Status:** complete. 160 tests pass, fmt/clippy clean, SBF build clean.

---

## 1. What was built

### `RotateEd25519Key` (discriminator 2)

| | |
|--|--|
| Payload | Same 715-byte shape as `Execute` (wire + Falcon auth sig) |
| Action body | `new_ed25519_pubkey[32] ‖ 0u64` |
| Accounts | HybridAccount (writable), instructions sysvar |
| Auth | Current policy over the reconstructed digest |
| Effect | `owner_ed25519 ← new`; nonce `N → N+1` |

No separate Ed25519 PoP: anyone who can authorize can already drain the vault.
The new pubkey is bound into the signed digest.

### `RotateFalconKey` (discriminator 3)

| | |
|--|--|
| Payload | `wire(49) ‖ falcon_auth(666) ‖ new_wire_pk(897) ‖ falcon_pop(666)` → **2279** bytes total with disc |
| Action body | `SHA256(new_wire_pk)[32] ‖ 0u64` |
| Accounts | HybridAccount (writable), instructions sysvar |
| Auth | Current policy (auth Falcon sig uses the **stored** prepared key) |
| PoP | `falcon_pop` verified with `verify_falcon_raw` against the **new** wire key over the same digest |
| Effect | hash + prepared key updated via on-chain `try_prepare_pubkey`; nonce bumped |

Prepared keys are still never accepted from the client — only derived on-chain.

### Shared authorization

`program/src/authorize.rs` factors the Milestone 5–6 auth path (expiry, reconstruct,
policy verify, next-nonce). `Execute` and both rotate instructions call it.

### PDA address stability

Seeds remain `["dualkey", creator, account_index]`. Rotating keys does **not**
change the vault address (the Milestone 0 design constraint).

---

## 2. Transaction size note

`RotateFalconKey` instruction data alone is 2279 bytes. A HybridAnd rotation
(Ed25519 precompile + this ix) **cannot** fit a legacy 1232-byte packet.
This path is intended for **v0 transactions with an Address Lookup Table**.
Mollusk tests cover correctness without the UDP size limit.

`RotateEd25519Key` uses the same 716-byte envelope as `Execute` and fits the
same legacy budget as HybridAnd TransferSol (~1165 B).

---

## 3. Tests (`client/tests/sbf_rotate.rs`, 9)

| Test | Property |
|------|----------|
| `rotate_ed25519_under_hybrid_and_updates_owner` | HybridAnd auth; owner swapped; Falcon unchanged |
| `rotate_ed25519_rejects_same_pubkey` | no-op rotate refused |
| `rotate_ed25519_requires_current_policy_auth` | HybridAnd never falls back |
| `rotate_falcon_under_hybrid_and_with_pop` | PoP + prepare; hash/prepared updated |
| `rotate_falcon_rejects_missing_pop` | zero PoP → `InvalidFalcon` |
| `rotate_falcon_rejects_hash_mismatch` | body hash ≠ `SHA256(wire)` |
| `rotate_falcon_rejects_pop_under_old_key` | PoP must be the new key |
| `after_ed25519_rotation_old_key_cannot_authorize_transfer` | old owner rejected |
| `rotate_falcon_data_length_is_2279` | layout lock |

---

## 4. Explicitly not done

- **No `ChangePolicy`** (Milestone 10)
- **No recovery** (Milestone 10)
- **No SPL** (Milestone 11)
- No CLI `rotate` subcommand (builders live in `onchain`; signing via existing `sign`)

---

## 5. Verification

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

Milestone 9 is complete. Milestone 10 (richer policies) is documented in
[`milestone-10.md`](milestone-10.md).
