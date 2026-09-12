# Milestone 6 — Replay protection + expiry

**Goal:** a successfully authorized intent cannot be replayed, and an expired
intent cannot authorize. Still **no SOL transfer** (Milestone 7).

**Status:** complete. 142 tests pass, fmt/clippy clean, SBF build clean.

---

## 1. What was built

`Execute` now enforces the architecture’s anti-replay / freshness rules on top
of Milestone 5 authorization:

1. HybridAccount must be **writable** (nonce is mutated on success)
2. `Clock::get().slot > wire.expiry_slot` → `IntentExpired`  
   (inclusive: valid while `slot <= expiry_slot`)
3. Reconstruct intent + digest (nonce always from account state)
4. Redundant `ctx.nonce == account.nonce` → else `InvalidNonce`
5. `next_nonce = account_nonce.checked_add(1)` → else `MathOverflow`  
   (refuse to authorize if the bump cannot be recorded)
6. Verify under policy (unchanged from Milestone 5)
7. On success: `HybridAccount::set_nonce(next_nonce)`

Expiry is checked **before** Falcon verify so stale intents fail cheaply.

### Replay defense

The nonce is **not** on the wire (Milestone 4 design). After a successful
Execute, reconstruction binds the new account nonce into the digest. The same
signatures (over the old digest) no longer verify — typically
`InvalidFalcon` / `InvalidEd25519`, not `InvalidNonce`. Explicit `InvalidNonce`
remains for the reconstruction/account invariant if those paths diverge.

Failed authorization (bad signature, expired, overflow) leaves the nonce
unchanged; Solana atomicity would also revert a later transfer failure
(Milestone 7).

### Accounts

| # | Account |
|---|---------|
| 0 | HybridAccount (**writable**) |
| 1 | instructions sysvar (readonly) |

---

## 2. Measurements

HybridAnd success path (Ed25519 precompile + Execute, Mollusk `precompiles`):
**~184,955 CU** total (≈10k above Milestone 5, dominated by Falcon; Clock +
nonce write are small).

---

## 3. Explicitly not done

- **No SOL transfer** (Milestone 7)
- **No LiteSVM full legacy-tx size** measurement (Milestone 8)
- **No key rotation** (Milestone 9)

---

## 4. Tests (`client/tests/sbf_hybrid.rs`, 18)

Milestone 5 coverage retained, plus:

| Test | Property |
|------|----------|
| `successful_execute_bumps_nonce_by_one` | FalconOnly: nonce `N → N+1` |
| `hybrid_and_succeeds_with_both_signatures` | HybridAnd success bumps nonce |
| `replay_of_the_same_signatures_is_rejected` | same sigs after bump fail |
| `expired_intent_is_rejected_before_authorization` | `slot > expiry` → `IntentExpired`; nonce untouched |
| `intent_valid_on_exact_expiry_slot` | `slot == expiry` succeeds |
| `intent_expires_one_slot_after_expiry_slot` | `expiry+1` fails |
| `failed_authorization_does_not_consume_nonce` | bad Falcon leaves nonce |
| `max_nonce_refuses_to_authorize` | `u64::MAX` → `MathOverflow` |

Expiry tests use Mollusk `warp_to_slot`.

---

## 5. Client

`execute_instruction` marks the HybridAccount writable
(`AccountMeta::new(..., false)`).

---

## 6. Verification

```bash
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace                          # 142 passed, 2 ignored
cargo tree -p dualkey-program --all-features    # no pqcrypto-falcon
```

Milestone 6 is complete. See [`docs/milestone-7.md`](milestone-7.md) for
hybrid-authorized SOL transfer (Milestone 7).
