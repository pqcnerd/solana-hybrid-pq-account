# Milestone 10 — Richer policies + ChangePolicy

**Goal:** enable `HybridOr`, `FalconForPrivileged`, and `FalconAboveThreshold`,
and implement `ChangePolicy` under the **stricter of current and target**
signature requirements so a stolen Ed25519 key alone cannot disable Falcon on a
HybridAnd account.

**Status:** complete. Core/program unit tests + 13 SBF policy tests pass;
fmt/clippy expected clean after verification.

---

## 1. What was built

### New policies (all `is_implemented() == true`)

| Policy | Rule |
|--------|------|
| `HybridOr` | Ed25519 **or** Falcon |
| `FalconForPrivileged` | Falcon for privileged actions (rotate / ChangePolicy); Ed25519 for `TransferSol` |
| `FalconAboveThreshold` | Falcon when `TransferSol.lamports > threshold`; Ed25519 at or below; Falcon for non-transfers |

Threshold lives in account layout (`falcon_required_above` +
`FLAG_FALCON_THRESHOLD_SET`). If the policy is `FalconAboveThreshold` and the
flag is unset, the threshold is treated as `0` (any positive transfer needs
Falcon).

### `SignatureRequirement` lattice

```text
Either < Ed25519, Falcon < Both
Ed25519 ∩ Falcon = Both
```

`ChangePolicy` authorizes under `meet(current_req, target_req)` for the
`ChangePolicy` action itself. Downgrading HybridAnd → Ed25519Only therefore
still requires **both** signatures.

### `ChangePolicy` (discriminator 4)

| | |
|--|--|
| Payload | Same 715-byte shape as `Execute` (wire + Falcon auth sig) |
| Action body | `new_policy[1] ‖ pad[7] ‖ threshold_u64_le[8] ‖ reserved[24]` |
| Accounts | HybridAccount (writable), instructions sysvar |
| Auth | Stricter of current and target requirements |
| Effect | `policy` + threshold flag/value updated; nonce bumped |

No-op changes (same policy and resulting threshold) are refused with
`InvalidAccountData`.

### Shared authorization

`program/src/authorize.rs` now computes an effective `SignatureRequirement`
(including the ChangePolicy meet) and probes Ed25519 / Falcon accordingly.
`HybridOr` soft-probes both schemes so a missing Ed25519 predecessor does not
hard-fail a Falcon-only path.

---

## 2. Tests (`client/tests/sbf_policy.rs`, 13)

| Test | Property |
|------|----------|
| `hybrid_or_accepts_ed25519_alone` | OR with Ed only |
| `hybrid_or_accepts_falcon_alone` | OR with Falcon only |
| `hybrid_or_rejects_neither` | `PolicyRejected` |
| `falcon_for_privileged_transfer_uses_ed25519` | normal transfer |
| `falcon_for_privileged_rotate_rejects_ed25519_alone` | privileged needs Falcon |
| `falcon_for_privileged_rotate_with_falcon` | privileged OK |
| `falcon_above_threshold_below_uses_ed25519` | `lamports <= threshold` |
| `falcon_above_threshold_above_requires_falcon` | above needs Falcon |
| `change_policy_hybrid_and_to_ed25519_requires_both` | stricter-of success |
| `change_policy_hybrid_and_to_ed25519_rejects_ed_alone` | stolen Ed cannot downgrade |
| `change_policy_sets_falcon_above_threshold` | threshold flag set |
| `change_policy_noop_is_rejected` | same policy refused |
| `after_downgrade_ed25519_only_authorizes_transfer` | post-change auth |

`sbf_initialize` now accepts the three richer policies at init.
`sbf_falcon` expects a bare `ChangePolicy` discriminator to be
`MalformedInstructionData` (full payload required).

---

## 3. Explicitly not done

- **No `RecoverAccount`** (tag 6 remains reserved; recovery flag exists but is unused)
- **No SPL** (Milestone 11)
- No CLI `change-policy` subcommand (builder in `onchain`; sign via existing path)

---

## 4. Verification

```bash
unset CARGO_TARGET_DIR
export CARGO_TARGET_DIR="$PWD/target"
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo test -p dualkey-client --release --test sbf_policy
```

Milestone 10 is complete. Milestone 11 (SPL) is documented in
[`milestone-11.md`](milestone-11.md).
