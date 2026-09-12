# DualKey Architecture

**Status:** Current through Milestone 16 (research complete). See [`STATUS.md`](STATUS.md).

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
| Test / bench | `client/tests` | Host tests; Mollusk SBF attack tests and CU benches against the compiled `.so`. Kept out of `program/` so no Falcon signer enters the program's dependency graph, even as a dev-dependency. |

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
- Prepared pubkey path: **~172.6–193.4k CU**, raw pubkey **~224.6–245.4k CU**,
  measured in DualKey's own program frame over a 32-byte digest
  ([`milestone-2.md`](milestone-2.md)). Upstream reports ~173–183k and ~270k.
  Ranges, not points: cost is stochastic (see below).
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

**Social recovery config** (Milestone 15) is a separate PDA:

```text
["dualkey-rec", hybrid_account]
```

Fixed 128-byte `RecoveryConfig` (guardian Ed25519, delay slots, pending fields).
See [`milestone-15.md`](milestone-15.md).

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
| 4 | 4 | `account_index` (u32 LE; PDA seed) |
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

| Approach | Storage | Verify CU (measured, 32-byte digest) | Upstream |
|----------|--------:|------------------------------------:|---------:|
| Raw wire pubkey in every tx | 897 B on wire | 224.6k – 245.4k | ~270k |
| Prepared in account | 1024 B in PDA | 172.6k – 193.4k | ~173–183k |

Prepared storage is **required for DualKey**: a raw 897-byte pubkey plus
666-byte signature cannot fit a normal transaction alongside Ed25519
precompile data. Initialization prepares once (`try_prepare_pubkey`); every
later verify uses `verify_with_prepared`.

The per-verification saving is **exactly 51,991 CU**, measured and deterministic
(both paths differ only by the wire decode plus forward NTT). This is not the
~99k figure recorded in Milestone 0. Milestone 2 guessed that ~99k described the
one-time `try_prepare_pubkey` cost instead; Milestone 3 measured that cost
directly and it is **52,410 CU**, so ~99k matches neither quantity and is simply
not reproducible here.

Those two measurements are near-identical for a good reason: preparing a key
*is* the work the raw path repeats on every verify. Paying 52,410 CU once at
`Initialize` therefore saves 51,991 CU on every subsequent verification — the
prepared-key design breaks even after a single authorization and wins from the
second onward.

Absolute cost moves in ~10,150 CU steps (one Keccak-f permutation) and varies per
signature because `hash_to_point` rejection-samples, so it must be quoted as a
range; see [`milestone-2.md`](milestone-2.md).

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
| **Measured HybridAnd TransferSol (M8)** | **1,165** |
| Full intent on wire (+96 B domains) | **~1300 (over limit)** |

Measured headroom: **67 bytes** without an ALT. Details:
[`milestone-8.md`](milestone-8.md), [`canonical-intent.md`](canonical-intent.md).

## Authorization policies

Declared in `dualkey_core::AuthorizationPolicy`:

| Mode | Status | Rule |
|------|--------|------|
| `Ed25519Only` | implemented | Ed25519 |
| `FalconOnly` | implemented | Falcon |
| `HybridAnd` | implemented (default) | Ed25519 **AND** Falcon — no silent fallback |
| `HybridOr` | implemented | either |
| `FalconForPrivileged` | implemented | Falcon for privileged ops; Ed25519 for normal transfers |
| `FalconAboveThreshold` | implemented | Falcon when amount > threshold |

## Authorization flow

1. Load `HybridAccount`; validate PDA + bump  
2. Validate version / chain domain  
3. Validate `current_slot <= expiry_slot` (cheap reject before crypto)  
4. Reconstruct intent; compute digest (nonce always from account state)  
5. Validate reconstructed nonce matches account (invariant / `InvalidNonce`)  
6. Verify Ed25519 via precompile introspection (when required)  
7. Verify Falcon via prepared pubkey (when required)  
8. Evaluate policy (reject on failure)  
9. Increment nonce  
10. Execute action (TransferSol, TransferSpl, rotate, ChangePolicy, recover, …)

State updates rely on Solana transaction atomicity: failure reverts all.
Replay of a used intent fails because reconstruction binds the new nonce into
the digest; signatures over the old digest no longer verify. `TransferSol`
preserves the HybridAccount rent-exempt floor; the recipient account must match
the signed action recipient.

## Test / benchmark harness split

| Harness | Use |
|---------|-----|
| **Mollusk + `precompiles`** | Instruction and multi-ix CU; Ed25519 precompile + DualKey in one tx; size via legacy `Transaction` serialization (Milestone 8) |
| **LiteSVM** | Optional fuller validator-shaped integration (not required for M8 figures) |

Mollusk with `precompiles` populates the instructions sysvar and runs the
Ed25519 precompile — DualKey’s HybridAnd path is exercised end-to-end there.

## Module map

```text
core/src/{lib,canonical,intent,policy,state,recovery,wire,error}.rs
program/src/{lib,instruction,processor,initialize,execute,authorize,
             rotate,change_policy,recover,social_recovery,spl_token,
             reconstruct,pda,hash,chain_domain,error}.rs
program/src/auth/{mod,policy,ed25519,falcon}.rs
client/src/{main,keygen,sign,intent,onchain,submit,rpc,keys,error}.rs
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
