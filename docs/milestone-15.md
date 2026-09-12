# Milestone 15 — Social recovery (guardian + timelock)

**Goal:** Beyond Falcon-only Ed recover: a **guardian** can propose an Ed25519
owner change that finalizes only after a **slot delay**; the DualKey owner can
cancel under the current policy.

## Layout

`RecoveryConfig` PDA, seeds `["dualkey-rec", hybrid_account]`, 128 bytes:

| Field | Notes |
|-------|--------|
| `guardian_ed25519` | Single guardian |
| `delay_slots` | Inclusive finalize wait |
| `pending_new_ed25519` | Zero = none |
| `pending_ready_slot` | Earliest finalize slot |

Social paths require `FLAG_RECOVERY_ENABLED` **and** an initialized config.
M12 Falcon-only `RecoverAccount::RotateEd25519` remains when social config is
unset / unused.

## Instructions

| Disc | Name | Auth |
|------|------|------|
| 6 | `SetRecoveryConfig` | DualKey; action tag **7**; body `guardian[32] ‖ delay u64` |
| 7 | `InitiateSocialRecovery` | Guardian Ed25519 precompile over social digest; data `new_ed25519[32]` |
| 8 | `FinalizeSocialRecovery` | Permissionless after `Clock::slot >= pending_ready_slot` |
| 9 | `CancelSocialRecovery` | DualKey; action tag **8**; clears pending |

Guardian digest: DualKey domain tag + `SOCIAL_RECOVER` + chain/program/account +
`new_ed25519` + HybridAccount nonce.

## Tests (`sbf_social_recovery.rs`)

Set → initiate → too-early finalize fails → after delay succeeds; cancel;
wrong guardian; flag required; Falcon-only recover still works.

## Non-goals

- Multi-guardian thresholds (single guardian only)
