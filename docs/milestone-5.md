# Milestone 5 — HybridAnd authorization

**Goal:** prove HybridAnd: Ed25519 **and** Falcon must both verify over the same
reconstructed digest. Never fall back to a single scheme.

**Status:** complete. 135 tests pass, fmt/clippy clean, SBF build clean.

---

## 1. What was built

`Execute` (discriminator 1) is an **authorization oracle**:

1. Parse the 716-byte payload: wire intent (49) + Falcon signature (666)
2. Reconstruct the intent from HybridAccount context + wire fields; `sol_sha256`
3. Load the account policy
4. Verify what the policy requires
5. Log success — **no nonce bump, no transfer**

| Policy | Ed25519 precompile | Falcon on wire |
|--------|--------------------|----------------|
| `HybridAnd` | required (previous ix) | required |
| `Ed25519Only` | required | ignored |
| `FalconOnly` | not consulted | required |

### Ed25519 introspection (SOL-035)

```text
get_instruction_relative(-1)
→ program id == Ed25519SigVerify111111111111111111111111111
→ exactly one signature; offsets point into this instruction (u16::MAX)
→ message length == 32
→ pubkey == HybridAccount.owner_ed25519
→ message == reconstructed digest
```

Crypto is performed by the precompile. DualKey only binds that success to the
owner key and digest. Scanning the whole transaction for “any Ed25519 success”
is deliberately rejected.

### Accounts

| # | Account |
|---|---------|
| 0 | HybridAccount (readonly) |
| 1 | instructions sysvar (readonly) |

### Instruction data (716 bytes)

```text
[1] ‖ expiry(8) ‖ action_tag(1) ‖ action_body(40) ‖ falcon_sig(666)
```

---

## 2. Measurements

HybridAnd success path (Ed25519 precompile + Execute in one Mollusk
transaction, `precompiles` feature): **~174,955 CU** total.

That is dominated by Falcon prepared verify (~173k); Ed25519 precompile +
reconstruction + introspection are small by comparison.

---

## 3. Explicitly not done

- **No expiry check** against the clock (Milestone 6)
- **No nonce consumption** (Milestone 6) — successful `Execute` leaves account
  bytes unchanged (asserted in tests)
- **No SOL transfer** (Milestone 7)
- **No LiteSVM end-to-end legacy tx size** measurement (Milestone 8)

---

## 4. Tests (`client/tests/sbf_hybrid.rs`, 11)

| Test | Property |
|------|----------|
| `hybrid_and_succeeds_with_both_signatures` | both valid → success; account unchanged |
| `ed25519_only_succeeds_without_valid_falcon` | garbage Falcon ignored |
| `falcon_only_succeeds_without_ed25519_precompile` | no predecessor required |
| `hybrid_and_rejects_ed25519_without_falcon` | no fallback |
| `hybrid_and_rejects_falcon_without_ed25519` | no fallback |
| `hybrid_and_rejects_ed25519_over_wrong_digest` | message binding |
| `hybrid_and_rejects_wrong_ed25519_pubkey` | owner binding |
| `hybrid_and_rejects_tampered_falcon_signature` | Falcon required |
| `unrelated_earlier_ed25519_is_not_accepted` | relative −1 only |
| `wrong_nonce_in_intent_fails_digest_binding` | reconstruction binding |
| `execute_data_length_is_716` | wire size lock |

Host unit tests: `evaluate_policy` never falls back under HybridAnd.

---

## 5. Client

- `onchain::execute_instruction` / `execute_data`
- `onchain::ed25519_precompile_instruction`
- Mollusk tests enable `precompiles` and use
  `process_and_validate_transaction_instructions` so both ixs share one message
  (required for a correct instructions sysvar)

---

## 6. Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace                          # 135 passed, 2 ignored
cargo-build-sbf --manifest-path program/Cargo.toml
cargo tree -p dualkey-program --all-features    # no pqcrypto-falcon
```

Milestone 5 is complete. Milestone 6 (replay protection + expiry) has not been
started.
