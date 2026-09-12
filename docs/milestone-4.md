# Milestone 4 — Canonical intent + on-chain reconstruction

**Goal:** lock the signing preimage contract and prove the program reconstructs
the same digest the client signs, without putting the full intent on the wire.

**Status:** complete. 122 tests pass, `cargo fmt --all -- --check` clean, clippy
clean across the workspace with `--all-targets`, and the SBF build produces no
stack-frame diagnostics.

---

## 1. What was already done (Milestone 1–2)

Milestone 4 was marked **Partial** for a reason: most of the encoding landed
early.

| Piece | When |
|-------|------|
| 172-byte `canonical_preimage` | Milestone 1 (`dualkey-core`) |
| Domain tag `0x11 ‖ "DUALKEY_SOLANA_V1"` | Milestone 1 |
| Client `sha2` digest + dual signing | Milestone 1 |
| Known-answer `TEST_VECTOR_DIGEST` | Milestone 1 |
| On-chain `sol_sha256` over a supplied preimage (harness 242) | Milestone 2 |

What remained was the **transaction-size design constraint**: the program must
rebuild fields from trusted context so a legacy transaction can still fit a
Falcon signature + Ed25519 precompile.

---

## 2. What Milestone 4 added

### Wire fragment (49 bytes)

```text
expiry_slot: u64 LE     (8)
action_tag:  u8         (1)
action_body: [u8; 40]   (40)
─────────────────────────
total                   49
```

Implemented as `dualkey_core::ExecuteIntentWire` with `encode` / `decode` /
`from_intent`. Unknown action tags return `UnsupportedAction`.

Derived fields (never on the wire): `version`, `chain_domain`, `program_id`,
`account`, `nonce` — **105 bytes** saved (`EXECUTE_INTENT_DERIVED_LEN`).

Full `Execute` instruction body estimate for Milestone 5:

```text
1 (disc) + 49 (wire) + 666 (Falcon sig) = 716 bytes
```

### Reconstruction

```rust
reconstruct_intent(ctx: &IntentContext, wire: &ExecuteIntentWire) -> AuthorizationIntent
```

`IntentContext` is filled only from trusted sources:

| Field | Source |
|-------|--------|
| `chain_domain` | compile-time program constant |
| `program_id` | entrypoint argument |
| `account` | HybridAccount pubkey |
| `nonce` | `HybridAccount.nonce` in account data |

### Compile-time `chain_domain`

| Feature | Label (zero-padded to 32) |
|---------|---------------------------|
| `mainnet` | `dualkey:mainnet` |
| `devnet` | `dualkey:devnet` |
| `localnet` (default) | `dualkey:localnet` |

Constants live in `dualkey-core`. The program selects one via Cargo features;
enabling more than one is a `compile_error!`. Unmarked builds default to
`localnet`, matching `dualkey_client::onchain::default_chain_domain()`.

Cross-network replay resistance holds only between differently featured
binaries — the genesis hash is still not readable on-chain (unchanged threat-
model limitation).

### Harness instruction 243

`ReconstructCanonicalDigest` — reconstruct, `sol_sha256`, compare to expected
digest. Authorizes nothing.

```text
Accounts: [0] HybridAccount (readonly)
Data:     [243] ‖ wire(49) ‖ expected_digest(32)
```

Measured cost: **968 CU** (deterministic in this fixture).

### Client helpers

- `onchain::signing_intent` / `signing_intent_with_domain`
- `onchain::encode_execute_intent_wire`
- `onchain::reconstruct_digest_instruction`

---

## 3. What is still not done

- **No HybridAnd.** Signatures are not checked. `Execute` returns `Unimplemented`.
- **No expiry / nonce consumption.** Reconstruction binds the nonce into the
  digest; enforcement is Milestone 6.
- **No transfers.** Milestone 7.
- **No end-to-end legacy tx size measurement** with a real signed transaction —
  Milestone 8. The 49-byte wire + 716-byte execute estimate is locked in code
  constants and tests.

---

## 4. Tests

15 new SBF tests in `client/tests/sbf_reconstruct.rs`, plus 6 new core wire /
chain-domain unit tests. 122 total.

| Property | Coverage |
|----------|----------|
| Client digest == on-chain reconstructed digest | `reconstructed_digest_matches_client_sha2` |
| Default domain is localnet on both sides | `program_default_chain_domain_is_localnet` |
| Wire is 49 bytes; derived savings 105 | `wire_fragment_is_exactly_49_bytes_and_saves_105` |
| Wrong digest / nonce / account / program_id / chain_domain | dedicated negative tests |
| Flipped wire expiry | `DigestMismatch` |
| Unsupported action tag | `UnsupportedAction` |
| Bad framing, missing account, wrong owner, bad version | exact error codes |
| `Execute` discriminator is 1 | `execute_discriminator_is_one` |

---

## 5. Verification performed

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets          # 0 warnings
cargo test --workspace                          # 122 passed, 2 ignored
cargo-build-sbf --manifest-path program/Cargo.toml
```

Milestone 4 is complete. Milestone 5 (HybridAnd authorization) has not been
started.
