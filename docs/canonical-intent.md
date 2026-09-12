# Canonical Authorization Intent

**Status:** Implemented. Encoding landed in Milestone 1; on-chain reconstruction
and compile-time `chain_domain` selection closed in Milestone 4.

The encoding was pulled forward from Milestone 4 because Milestone 1 requires
both schemes to sign one digest built through the shared crate. Milestone 4
adds the reconstruction rule the program uses so the full intent never needs to
travel on the wire.

Both Ed25519 and Falcon-512 MUST sign the exact same digest:

```text
digest = SHA256(canonical_preimage(intent))
```

The preimage is a fixed-width binary encoding. DualKey never signs JSON, never
signs ambiguous strings, and never signs a partial action (amount or recipient
alone).

## Domain separation

The preimage begins with a length-prefixed domain tag:

```text
0x11 || "DUALKEY_SOLANA_V1"
```

- `0x11` is the byte length of the ASCII tag (17).
- The tag prevents cross-protocol replay if the same Falcon or Ed25519 key is
  reused in another application that also hashes arbitrary messages.

Falcon’s `hash_to_point` digests `SHAKE256(nonce ‖ message)` with **no**
built-in domain separation (`solana-falcon512` footgun #3). Application-level
domain separation in the signed message is therefore mandatory.

## Preimage layout (172 bytes)

All multi-byte integers are little-endian. There are no length prefixes inside
the body and no optional fields — unused action body bytes are zero.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Domain tag length (`0x11`) |
| 1 | 17 | Domain tag ASCII (`DUALKEY_SOLANA_V1`) |
| 18 | 1 | Intent `version` (`1`) |
| 19 | 32 | `chain_domain` |
| 51 | 32 | `program_id` |
| 83 | 32 | `account` (HybridAccount PDA) |
| 115 | 8 | `nonce` (u64 LE) |
| 123 | 8 | `expiry_slot` (u64 LE) |
| 131 | 1 | `action_tag` |
| 132 | 40 | `action_body` |
| **172** | | **end** |

Constants live in [`dualkey-core::canonical`](../core/src/canonical.rs):

- `CANONICAL_PREIMAGE_LEN = 172`
- `DOMAIN_TAG = b"DUALKEY_SOLANA_V1"`
- `ACTION_BODY_LEN = 40`
- `DIGEST_LEN = 32`

## Action encoding

### Tag `1` — `TransferSol` (Milestone 7)

```text
action_body = recipient[32] || lamports:u64 LE
```

### Tag `2` — `TransferSpl` (Milestone 11)

```text
action_body = destination_token_account[32] || amount:u64 LE
```

Source token account, mint, and token program are Execute accounts (not in the
40-byte body). The HybridAccount PDA must own the source account and signs the
SPL `TransferChecked` CPI.

### Tag `3` — `RotateEd25519Key` (Milestone 9)

```text
action_body = new_ed25519_pubkey[32] || 0u64
```

### Tag `4` — `RotateFalconKey` (Milestone 9)

```text
action_body = SHA256(new_falcon_wire_pubkey)[32] || 0u64
```

The 897-byte wire public key and Falcon PoP signature travel in the
`RotateFalconKey` instruction payload (not in the 40-byte action body).

### Tag `5` — `ChangePolicy` (Milestone 10)

```text
action_body = new_policy[1] || pad[7] || threshold_u64_le[8] || reserved[24]
```

`threshold` is stored when the target policy is `FalconAboveThreshold`;
otherwise the threshold flag is cleared. Authorization uses the **stricter** of
the current and target policies' signature requirements for this action.

### Tag `6` — `RecoverAccount` (Milestone 12)

```text
action_body = op[1] || pad[7] || new_ed25519[32]
```

| `op` | Meaning |
|-----:|---------|
| 0 | Enable recovery flag (current policy; `new_ed25519` must be zero) |
| 1 | Disable recovery flag |
| 2 | Rotate Ed25519 under Falcon-only auth (flag must already be set) |

### Tag `7` — `SetRecoveryConfig` (Milestone 15)

```text
action_body = guardian_ed25519[32] || delay_slots_u64_le[8]
```

### Tag `8` — `CancelSocialRecovery` (Milestone 15)

```text
action_body = 0⁴⁰
```

Guardian initiate uses a separate social-recover digest (not this 172-byte
preimage); see [`milestone-15.md`](milestone-15.md).

## Shared preimage, separate hashers

[`dualkey-core`](../core/) is hasher-agnostic and has no required
dependencies. It exposes:

```rust
pub fn canonical_preimage(intent: &AuthorizationIntent) -> [u8; CANONICAL_PREIMAGE_LEN];

// Host only, behind the `sha2` feature:
pub fn digest_preimage(preimage: &[u8; CANONICAL_PREIMAGE_LEN]) -> [u8; 32];
pub fn canonical_digest(intent: &AuthorizationIntent) -> [u8; 32];
```

Each consumer hashes those identical bytes with its own SHA-256:

| Layer | Hasher | Reason |
|-------|--------|--------|
| Client | `sha2` crate (`sha2` feature) | Portable host crypto |
| Program | `sol_sha256` syscall | Far cheaper compute units on SBF |

The program deliberately does **not** enable the `sha2` feature.

### Known-answer vectors

`dualkey-core` publishes cross-layer vectors so each layer can assert
agreement without duplicating the fixture:

| Constant | Value |
|----------|-------|
| `test_vector_intent()` | Deterministic fixture intent |
| `TEST_VECTOR_PREIMAGE_PREFIX` | `0x11 ‖ "DUALKEY_SOLANA_V1" ‖ 0x01` |
| `TEST_VECTOR_DIGEST` | `6182ba27c082b3e8110e47a2af27e0ece6f5eee8fcea6e7927e40707f8deb5ec` |

Changing `TEST_VECTOR_DIGEST` is a breaking protocol change. Milestone 2 will
assert the on-chain `sol_sha256` path reproduces the same value, closing
invariant 10 across both layers.

Covered by `client_sha256_agrees_with_core_test_vectors`, which also asserts
that Ed25519 and Falcon verify over the 32-byte **digest** and explicitly
**fail** over the 172-byte preimage — so neither scheme can be signing a
different transform.

## On-chain reconstruction (transaction-size constraint)

A legacy Solana transaction is capped at **1232 bytes**. Putting the full
intent on the wire (with Falcon signature + Ed25519 precompile) overflows that
budget by ~70+ bytes.

Therefore the **program reconstructs** fields that are already known from
trusted context, and the **instruction only carries** what cannot be derived:

| Field | Signing preimage | On wire? | Program source |
|-------|------------------|----------|----------------|
| `version` | yes | no (constant) | `INTENT_VERSION` |
| `chain_domain` | yes | no | compile-time cluster constant |
| `program_id` | yes | no | `program_id` argument |
| `account` | yes | no | validated HybridAccount PDA |
| `nonce` | yes | no | `HybridAccount.nonce` |
| `expiry_slot` | yes | **yes** | instruction data |
| `action` | yes | **yes** | instruction data |

The client still populates **all** fields when building the signing preimage.
The program rebuilds the same struct from context + wire fields, recomputes
the preimage, and hashes it. A mismatched reconstruction fails signature
verification.

This strengthens security: a field derived from trusted context cannot be
lied about on the wire at all.

### Wire payload (execute intent fragment)

```text
expiry_slot:   u64 LE
action_tag:    u8
action_body:   [u8; 40]
```

Encoded by `dualkey_core::ExecuteIntentWire` (49 bytes). The Milestone 5
`Execute` instruction prepends discriminator `1` and appends the 666-byte Falcon
signature (`1 + 49 + 666 = 716`).

Approximate DualKey instruction data for Execute: **716 bytes**, plus a separate
144-byte Ed25519 precompile instruction.

## `chain_domain` and the genesis-hash problem

Solana programs **cannot read the cluster genesis hash** at runtime. A value
supplied by the user at initialization would be attacker-chosen and would not
provide cross-network protection.

DualKey therefore uses a **compile-time** `chain_domain` constant, selected
via Cargo features on `dualkey-program` (`mainnet` / `devnet` / `localnet`).
Cross-network replay resistance holds only between differently built program
binaries.

| Feature | Constant | Bytes (ASCII, zero-padded to 32) |
|---------|----------|----------------------------------|
| `mainnet` | `CHAIN_DOMAIN_MAINNET` | `dualkey:mainnet` |
| `devnet` | `CHAIN_DOMAIN_DEVNET` | `dualkey:devnet` |
| `localnet` (default) | `CHAIN_DOMAIN_LOCALNET` | `dualkey:localnet` |

When no feature is selected the program defaults to `localnet`, matching
`dualkey_client::onchain::default_chain_domain()`. Enabling more than one
cluster feature is a compile error.

Local validators mint a fresh genesis hash per start; localnet builds use the
fixed research label above rather than pretending to track genesis.

## What must never be omitted from the signed digest

- Domain tag
- Intent version
- Chain / network domain
- Program id
- Vault / account address
- Nonce
- Expiry slot
- Action type and full action body (recipient + lamports for transfers)

Changing any single bit of the preimage MUST invalidate both signatures.

## Implementation checklist

- [x] Implement `canonical_preimage` in `dualkey-core` (Milestone 1)
- [x] Client: `sha2::Sha256` over preimage (Milestone 1)
- [x] Publish known-answer vectors (Milestone 1)
- [x] Negative tests: one-bit flips fail both schemes (Milestone 1)
- [x] Program: `sol_sha256` over preimage bytes (Milestone 2 harness 242)
- [x] Cross-layer test: `sol_sha256` matches `TEST_VECTOR_DIGEST` (Milestone 2)
- [x] On-chain field reconstruction (Milestone 4: harness 243 + `ExecuteIntentWire`)
- [x] Compile-time `chain_domain` constants + program features (Milestone 4)
- [x] Measure serialized transaction size against the 1232-byte legacy limit (Milestone 8: **1,165 B**, fits without ALT)
