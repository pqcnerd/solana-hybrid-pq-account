# Milestone 12 — RecoverAccount (project completion)

**Goal:** wire the reserved `RecoverAccount` action and `FLAG_RECOVERY_ENABLED`
so a DualKey vault can opt into Falcon-only Ed25519 recovery after a lost
classical key — then mark the research milestone set complete.

**Status:** complete.

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

## 3. Project completion notes

Milestones **0–11** delivered the planned DualKey research surface. Milestone
**12** closes the last reserved action tag. Explicitly still out of scope for
this research repo:

- Token-2022 / transfer hooks
- On-chain RPC broadcast in the CLI
- Social recovery / guardians / timelocks
- Formal verification or production audit

---

## 4. Verification

```bash
unset CARGO_TARGET_DIR && export CARGO_TARGET_DIR="$PWD/target"
cargo-build-sbf --manifest-path program/Cargo.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo test -p dualkey-client --release --test sbf_recover
```
