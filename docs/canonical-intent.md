# Canonical Authorization Intent

**Status:** Specification (Milestone 0). Encoding implementation lands in Milestone 4.

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

Remaining action tags are reserved (not encoded until later milestones):

| Tag | Action | Milestone |
|----:|--------|----------:|
| 2 | TransferSpl | 11 |
| 3 | RotateEd25519Key | 9 |
| 4 | RotateFalconKey | 9 |
| 5 | ChangePolicy | 10 |
| 6 | RecoverAccount | 10 |

## Shared preimage, separate hashers

[`dualkey-core`](../core/) is hasher-agnostic and dependency-free. It will
expose (Milestone 4):

```rust
pub fn canonical_preimage(intent: &AuthorizationIntent) -> [u8; CANONICAL_PREIMAGE_LEN];
```

Each consumer hashes those identical bytes with its own SHA-256:

| Layer | Hasher | Reason |
|-------|--------|--------|
| Client | `sha2` crate | Portable host crypto |
| Program | `sol_sha256` syscall | Far cheaper compute units on SBF |

A host test (Milestone 1 / 4) MUST assert that both hashers produce the same
digest for the same preimage. This makes invariant 10 (“both schemes sign the
exact same canonical intent”) true by construction.

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

### Wire payload (execute instruction, conceptual)

```text
discriminator: u8           // Execute = 1
expiry_slot:   u64 LE
action_tag:    u8
action_body:   [u8; 40]
falcon_sig:    [u8; 666]    // compressed, zero-padded
```

Approximate size: `1 + 8 + 1 + 40 + 666 = 716` bytes of DualKey instruction
data, plus a separate 144-byte Ed25519 precompile instruction.

## `chain_domain` and the genesis-hash problem

Solana programs **cannot read the cluster genesis hash** at runtime. A value
supplied by the user at initialization would be attacker-chosen and would not
provide cross-network protection.

DualKey therefore uses a **compile-time** `chain_domain` constant, selected
via Cargo features (`mainnet` / `devnet` / `localnet`). Cross-network replay
resistance holds only between differently built program binaries.

Local validators mint a fresh genesis hash per start; localnet builds use a
fixed research domain string (documented in architecture) plus a build-time
override path when needed.

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

## Implementation checklist (Milestone 4)

- [ ] Implement `canonical_preimage` in `dualkey-core`
- [ ] Client: `sha2::Sha256` over preimage
- [ ] Program: `sol_sha256` over reconstructed preimage
- [ ] Host test: hashers agree
- [ ] Negative tests: one-bit flips fail both schemes
- [ ] Measure serialized transaction size against the 1232-byte legacy limit
