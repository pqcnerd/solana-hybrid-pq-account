# DualKey Architecture

**Status:** Milestone 0 design document.

DualKey is a research-grade Solana smart-account architecture for **hybrid
authorization**: classical Ed25519 and post-quantum Falcon-512 over the same
canonical intent, evaluated by a configurable policy engine.

This is **not** “a Falcon wallet.” The product surface is a PDA-backed vault
with an authorization-policy engine.

## Four layers

| Layer | Crate / path | Responsibility |
|-------|--------------|----------------|
| Shared types | `core/` (`dualkey-core`) | Intent, policy, fixed account layout, canonical constants |
| On-chain program | `program/` (`dualkey-program`) | PDA, auth, nonce/expiry, action execution |
| Off-chain client | `client/` (`dualkey` CLI) | Keygen, signing, submission |
| Test / bench | `program/tests`, `program/benches` | LiteSVM attack tests; Mollusk CU benches |

UI / wallet frontend code is intentionally excluded from this repository.

```text
Ed25519 private key
        │
        ├──── sign(intent) ──────┐
        │                        │
        │                        ▼
        │                  Hybrid Policy
        │                        ▲
        │                        │
Falcon private key              │
        │                        │
        └──── sign(intent) ──────┘
                                 │
                                 ▼
                         DualKey Smart Account
                                 │
                                 ▼
                              Action
```

## Dependency choices

### On-chain Falcon verification — `solana-falcon512` 0.1.2

- Pure Rust, `no_std`, allocation-free, optimised for Solana SBF.
- Compressed Falcon-512 signatures only (header `0x39`).
- Prepared pubkey path: ~173–183k CU; raw pubkey: ~270k CU.
- Prepared form is **1024 bytes** (NTT coefficients as `u16`, with `N⁻¹` pre-folded).
- Verify only — never keygen or sign on-chain.
- **Not audited.** Research use; do not treat as production-ready.

### Off-chain Falcon keygen / sign — `pqcrypto-falcon` 0.4

- PQClean “clean” Falcon-512 bindings.
- Exact pairing soak-tested by `solana-falcon512` (1,000,000 signatures).
- Lives **only** in `client/` — must never appear in the program dependency tree
  (C code / std assumptions incompatible with SBF).

### Ed25519 — Solana precompile + instructions sysvar

Confirmed design (not `is_signer`-only):

1. Client hand-builds a 144-byte Ed25519 precompile instruction over the
   **32-byte intent digest**.
2. Program pins `Sysvar1nstructions1111111111111111111111111` by key.
3. Loads the precompile ix; asserts program id; asserts exactly one signature.
4. Compares extracted pubkey to `HybridAccount.owner_ed25519` **and** message
   to the reconstructed digest.

A bare “did an Ed25519 instruction run?” check is exploitable (SOL-035).

### Rejected alternatives

| Crate | Why not |
|-------|---------|
| `fn-dsa-vrfy` | Solid FN-DSA, not SBF-tuned, no prepared-pubkey concept |
| `falcon-rust` | Not oriented to `no_std` / SBF |
| From-scratch Falcon | Out of scope; error-prone |

### Related work (honest)

Crates such as `falconed` and `post-quantum-web3-security` advertise
Ed25519+Falcon hybrids but have negligible adoption and no policy engine.
DualKey’s research contribution is the **configurable policy engine**,
measured CU / size costs, and a safe migration path — not the hybrid
primitive itself.

## PDA derivation

### Rejected: keys-as-seeds

```text
["dualkey", owner_ed25519, falcon_public_key_hash]   # REJECTED
```

Binding the vault **address** to the vault’s **keys** makes key rotation
change the PDA. Funds would be stranded at the old address — defeating
Milestones 9–10 and cryptographic agility.

### Chosen: stable identity seeds

```text
["dualkey", creator.as_ref(), account_index.to_le_bytes()]
```

| Seed | Lifetime | Role |
|------|----------|------|
| `b"dualkey"` | constant | Namespace |
| `creator` | fixed at init | Who created the vault |
| `account_index` (u32 LE) | fixed at init | Multiple vaults per creator |

Authenticators (`owner_ed25519`, prepared Falcon pubkey, policy) live in
**mutable account data** and can rotate without moving the address.

**Tradeoff:** the address is no longer self-authenticating over the keys. The
program must always read authenticators from validated account data, never
from seeds. `falcon_public_key_hash` remains in state as an identification /
integrity field, not a seed.

## Account layout (1120 bytes)

Fixed offsets; no `Vec`; no Borsh on the hot path.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `version` |
| 1 | 1 | `bump` |
| 2 | 1 | `policy` |
| 3 | 1 | `flags` (bit0 recovery, bit1 threshold set) |
| 4 | 4 | reserved |
| 8 | 32 | `owner_ed25519` |
| 40 | 32 | `falcon_public_key_hash` |
| 72 | 8 | `nonce` |
| 80 | 8 | `falcon_required_above` |
| 88 | 8 | reserved |
| 96 | 1024 | `prepared_falcon_public_key` |

Offset 96 is 8-byte aligned so
`Falcon512PreparedPubkey::try_from_slice` can borrow without memcpy.

**Rent-exempt minimum (approx):** `(128 + 1120) × 6960 = 8,686,080` lamports
(~0.00869 SOL). Re-measure on the target cluster.

### Prepared vs raw Falcon pubkey

| Approach | Storage | Verify CU (upstream) |
|----------|--------:|---------------------:|
| Raw wire pubkey in every tx | 897 B on wire | ~270k |
| Prepared in account | 1024 B in PDA | ~173–183k |

Prepared storage is **required for DualKey**: a raw 897-byte pubkey plus
666-byte signature cannot fit a normal transaction alongside Ed25519
precompile data. Initialization prepares once (`try_prepare_pubkey`); every
later verify uses `verify_with_prepared`.

## Transaction size budget

Legacy limit: **1232 bytes**.

| Component | Approx. bytes |
|-----------|--------------:|
| Signatures + message header + blockhash | ~100 |
| ~7 account keys × 32 | ~224 |
| Compute-budget ix(s) | ~20–50 |
| Ed25519 precompile ix | 144 |
| DualKey execute ix (expiry+action+Falcon sig) | ~716 |
| **Estimated total (reconstructed intent)** | **~1200** |
| Full intent on wire (+96 B domains) | **~1300 (over limit)** |

Headroom is tight (~26 B in the optimistic estimate). If measurements show
overflow, fall back to v0 transactions with an Address Lookup Table.

Details: [`canonical-intent.md`](canonical-intent.md).

## Authorization policies

Declared in `dualkey_core::AuthorizationPolicy`:

| Mode | Early milestones | Rule |
|------|------------------|------|
| `Ed25519Only` | yes | Ed25519 |
| `FalconOnly` | yes | Falcon |
| `HybridAnd` | yes (default) | Ed25519 **AND** Falcon — no silent fallback |
| `HybridOr` | Milestone 10 | either |
| `FalconForPrivileged` | Milestone 10 | Falcon for privileged ops |
| `FalconAboveThreshold` | Milestone 10 | Falcon above lamport threshold |

## Authorization flow (target)

1. Load `HybridAccount`; validate PDA + bump  
2. Validate version / chain domain  
3. Validate `intent.nonce == account.nonce`  
4. Validate `current_slot <= expiry_slot`  
5. Reconstruct intent; compute digest  
6. Verify Ed25519 via precompile introspection  
7. Verify Falcon via prepared pubkey  
8. Evaluate policy (reject on failure)  
9. Increment nonce  
10. Execute action (e.g. SOL transfer)

State updates rely on Solana transaction atomicity: failure reverts all.

## Test / benchmark harness split

| Harness | Use |
|---------|-----|
| **LiteSVM** | Integration + attack tests (real tx pipeline, Ed25519 precompile, instructions sysvar, size limits) |
| **Mollusk + bencher** | Instruction-level CU benchmarks with markdown baselines |

Whether Mollusk populates the instructions sysvar / runs precompiles is an
open question; attack tests are therefore LiteSVM-first.

## Module map

```text
core/src/{lib,canonical,intent,policy,state,error}.rs
program/src/{lib,instruction,processor,error}.rs
program/src/auth/{mod,policy,ed25519,falcon}.rs
client/src/{main,keygen,sign,intent,submit,error}.rs
```

## Security posture (summary)

- HybridAnd ⇒ compromise of one scheme alone must not spend funds.
- Falcon secret keys never on-chain.
- No placeholder / fake verification functions.
- Policy downgrades must be authorized under the stricter of current vs target
  policy (see threat model).
- Falcon pubkey registration requires proof-of-possession (init / rotate).

Terminology used throughout: **post-quantum**, **hybrid authorization**,
**cryptographic agility**, **defense in depth**. DualKey does **not** claim
to be “quantum proof” or formally verified.
