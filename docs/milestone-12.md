# Milestone 12 — RecoverAccount

**Goal:** wire the reserved `RecoverAccount` action and `FLAG_RECOVERY_ENABLED`
so a DualKey vault can opt into Falcon-only Ed25519 recovery after a lost
classical key.

**Status:** complete. Later milestones (13–16) add CLI RPC, Token-2022 base
transfers, social recovery, and polish — see [`STATUS.md`](STATUS.md).

---

## 1. What was built

### Recovery model

| Op | Body | Auth | Effect |
|----|------|------|--------|
| `Enable` (0) | `op ‖ pad[7] ‖ 0³²` | Current policy (privileged) | Set `FLAG_RECOVERY_ENABLED` |
| `Disable` (1) | same | Current policy (privileged) | Clear flag |
| `RotateEd25519` (2) | `op ‖ pad[7] ‖ new_ed25519[32]` | **Falcon alone** (flag must be set) | Replace Ed25519 owner |

Enabling recovery is deliberate: under HybridAnd it still needs both keys, but
once enabled, **Falcon alone** can rotate Ed25519. That is the lost-Ed escape
hatch; it also means a stolen Falcon key can rotate the classical owner while
the flag is set.

### Instruction

`RecoverAccount` discriminator **5**, 716-byte payload (same as Execute /
ChangePolicy). Accounts: HybridAccount (writable), instructions sysvar.

### Shared auth

`authorize.rs` special-cases `RecoverAccount::RotateEd25519` to
`SignatureRequirement::Falcon` when the flag is set; otherwise returns
`InvalidAccountData`.

---

## 2. Tests (`client/tests/sbf_recover.rs`, 5)

| Test | Property |
|------|----------|
| `enable_recovery_under_hybrid_and` | both sigs; flag set |
| `rotate_ed25519_without_recovery_flag_is_rejected` | flag required |
| `falcon_alone_recovers_ed25519_when_flag_set` | no Ed25519 precompile |
| `recovery_rotate_rejects_ed25519_alone_even_with_flag` | Falcon required |
| `disable_recovery_clears_flag` | FalconOnly disable |

---

## 3. Historical note

At ship time, M12 closed the last reserved action tag in the original research
set. Items that were deferred then and later shipped:

| Item | Milestone |
|------|-----------|
| CLI RPC broadcast | [13](milestone-13.md) |
| Token-2022 base TransferSpl | [14](milestone-14.md) |
| Social recovery (guardian + timelock) | [15](milestone-15.md) |
| Docs / CLI / localnet polish | [16](milestone-16.md) |

Still never in scope: formal audit, “quantum proof”, full transfer-hook
resolution, multi-guardian thresholds.

---

## 4. Verification

```bash
unset CARGO_TARGET_DIR && export CARGO_TARGET_DIR="$PWD/target"
cargo-build-sbf --manifest-path program/Cargo.toml
cargo test -p dualkey-client --test sbf_recover
```
