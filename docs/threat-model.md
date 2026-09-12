# DualKey Threat Model

**Status:** Milestone 0. Research / prototype — not a production security audit.

DualKey’s primary mode, **HybridAnd**, provides **defense in depth** across
classical (Ed25519) and post-quantum (Falcon-512) signature families. If
either private key is compromised in isolation, an attacker still cannot
authorize HybridAnd actions without compromising the second scheme.

This document does **not** claim formal security or quantum-proofness.

## Assets

- Lamports held by HybridAccount PDAs
- Authorization policy and authenticator material (Ed25519 pubkey, prepared Falcon pubkey)
- Off-chain Falcon and Ed25519 secret keys
- Canonical intent digests and signatures in flight

## Trust assumptions

| Assumed | Not assumed |
|---------|-------------|
| Solana runtime / consensus integrity for included txs | Long-term classical hardness of Ed25519 under cryptographically relevant quantum computers |
| `solana-falcon512` correctly verifies compressed Falcon-512 (crate is unaudited) | That any 897-byte “pubkey” corresponds to a real Falcon trapdoor |
| Client and program share identical `canonical_preimage` bytes | Genesis-hash-based network binding readable on-chain |
| Fee payer / relayer may be untrusted | Relayer honesty |

## Adversaries

- Network observers and malicious relayers
- Thieves of one (but not both) private keys
- Attackers who break one signature family
- Callers who craft malformed signatures, PDAs, or instruction data
- Attackers who attempt replay, cross-program, or cross-account substitution

## Threat catalogue

### Cryptographic compromise

| Threat | HybridAnd impact | Mitigation |
|--------|------------------|------------|
| Stolen Ed25519 private key | Cannot alone authorize spend | Require Falcon too; no silent fallback |
| Stolen Falcon private key | Cannot alone authorize spend | Require Ed25519 too |
| Classical scheme broken (e.g. future quantum vs Ed25519) | Falcon half still required | Migration toward Falcon-heavier policies; key rotation |
| Falcon / lattice break | Ed25519 half still required (classical) | Policy agility; scheme replacement behind interfaces |
| Both keys stolen or both schemes broken | Full loss of HybridAnd protection | Operational key hygiene; consider thresholds later |

### Replay and binding

| Threat | Mitigation |
|--------|------------|
| Replay attack (reuse signed intent) | Per-account `nonce`; increment on success; intent must match |
| Cross-program replay | `program_id` in canonical preimage |
| Cross-account replay | `account` (PDA) in canonical preimage |
| Cross-network replay | Compile-time `chain_domain` (limitation: not live genesis hash) |
| Signature substitution | Both sigs bound to same digest; policy checks both |
| Message / instruction substitution | Reconstruct digest on-chain; bind Ed25519 precompile message to it |
| Account / PDA spoofing | Derive + check PDA seeds and bump; owner program check |

### Falcon-specific

| Threat | Mitigation |
|--------|------------|
| Malformed Falcon signatures | `try_from_slice` + verify returns false → `InvalidFalcon` / `MalformedFalcon` |
| Oversized signatures | Fixed 666-byte buffer; reject wrong lengths |
| Unverifiable Falcon pubkey registration | Any parsable 897-byte buffer can be “prepared”; under HybridAnd a bogus key **bricks** the account. Require Falcon **proof-of-possession** at init and on `RotateFalconKey` for the *new* key |
| Never dedup by signature value | Falcon nonces make signatures non-unique; replay protection is the **nonce counter**, never a signature-set |
| Non-zero signature padding | `solana-falcon512` requires all trailing bytes past the encoded signature to be zero; verified by `non_zero_padding_is_rejected` |
| Signature length overrun | Compressed signatures are variable (647–663 observed over 10,000 samples, spec-bounded at 666). Oversized signatures are **rejected, never truncated**; the client re-signs. See [`falcon-interop.md`](falcon-interop.md) |
| Misaligned prepared pubkey (availability) | `Falcon512PreparedPubkey` needs ≥2-byte alignment or verification fails on **correct** bytes. On-chain safety depends on the account offset being 8-byte aligned, asserted at compile time in `core/src/state.rs`. A Milestone 1 client bug of exactly this kind is documented in [`falcon-interop.md`](falcon-interop.md) |

### Ed25519 precompile

| Threat | Mitigation |
|--------|------------|
| “Ed25519 ix present” without binding | Introspect pubkey + message; compare to owner + digest (SOL-035) |
| Instructions sysvar substitution | Pin sysvar account by well-known key before read |
| Unrelated signatures in the tx | Ignore; only the bound precompile contents count |

### Policy and lifecycle

| Threat | Mitigation |
|--------|------------|
| Downgrade HybridAnd → Ed25519Only | `ChangePolicy` authorized under the **stricter** of current and target policies so a stolen Ed25519 key alone cannot disable Falcon |
| Malicious key rotation | Rotation intents authenticated under current policy; new Falcon key needs PoP; nonce advances |
| Nonce desynchronization | Client reads on-chain nonce before signing; failed txs do not advance nonce |
| Policy not implemented / fallback | Unreachable modes return `PolicyNotImplemented`; HybridAnd never falls back |

### Availability / resource

| Threat | Mitigation |
|--------|------------|
| DoS via expensive Falcon verify | Measured 172.6k–193.4k CU for the prepared path over a 32-byte digest (~173.0k when the signature is invalid, so rejection is no cheaper than success), inside the ~195k budget; malformed lengths are rejected before any crypto runs; the prepared pubkey avoids 51,991 CU of wire decode per verify |
| Transaction size exhaustion | Reconstruct intent on-chain; store prepared pubkey in PDA; measure vs 1232 B |

### Relayer

| Threat | Mitigation |
|--------|------------|
| Malicious relayer | Relayer cannot alter signed digest fields; can only withhold, delay, or front-run inclusion. Expiry limits delayed inclusion |

## Security invariants → mechanism → test

| # | Invariant | Mechanism | Test (planned) |
|--:|-----------|-----------|----------------|
| 1 | Sig for account A cannot authorize B | `account` in preimage + PDA check | `wrong_vault.rs` |
| 2 | Sig for program P cannot authorize Q | `program_id` in preimage | `wrong_program.rs` |
| 3 | Cross-network replay limited | `chain_domain` constant | domain mismatch case |
| 4 | One-bit intent change fails verify | Canonical digest binding | `altered_message.rs` |
| 5 | Intent executes at most once | Nonce increment | `replay_of_the_same_signatures_is_rejected` (M6, done) |
| 6 | Expired intent fails | `expiry_slot` vs clock | `expired_intent_is_rejected_before_authorization` (M6, done) |
| 7 | HybridAnd needs Ed25519 | Policy eval | `hybrid_and_rejects_falcon_without_ed25519` (M5, done) |
| 8 | HybridAnd needs Falcon | Policy eval | `hybrid_and_rejects_ed25519_without_falcon` (M5, done) |
| 9 | No Falcon sk on-chain | Client-only keygen; account layout | `prepared_account_data_contains_no_secret_material` (M1, done) |
| 10 | Same canonical intent | Shared `dualkey-core` preimage | `both_schemes_sign_exactly_the_same_digest` (M1, done) |
| 11 | Amount immutable post-sign | Amount in action body | altered amount case |
| 12 | Recipient immutable post-sign | Recipient in action body | altered recipient case |
| 13 | Nonce immutable post-sign | Nonce in preimage | modified nonce case |
| 14 | Policy changes authenticated | `ChangePolicy` under stricter-of | `sbf_policy.rs` (M10, done) |
| 15 | Rotation cannot bypass old policy | Auth under current policy + PoP | `sbf_rotate.rs` (M9, done) |

## Key material handling (Milestone 1, implemented)

| Control | Mechanism | Test |
|---------|-----------|------|
| Private key files not readable by others | Created with mode `0600` via `OpenOptions::mode` before any bytes are written | `private_key_files_have_mode_0600`, `no_secret_file_is_group_or_world_readable` |
| Key directory not traversable | Directory set to `0700` | manual + keygen path |
| Secrets never printed | `KeygenReport` carries only public material; `FalconKeypair` and `Ed25519Keypair` expose no `Debug` impl | `keygen_report_output_contains_no_secret_bytes` |
| Secrets never in signed output | Bundle and manifest contain public fields only | `signed_bundle_contains_no_secret_material`, `keyset_manifest_contains_no_secret_material` |
| Secrets never in error text | Errors report paths and lengths only | `error_messages_contain_no_secret_material` |
| Secrets never in on-chain data | `falcon512.prepared` is reproducible from the public key alone | `prepared_account_data_contains_no_secret_material` |

File formats are documented in [`../client/src/keys.rs`](../client/src/keys.rs)
and summarised in the README.

## Residual risks (accepted for research)

1. **`solana-falcon512` is unaudited.** CU and correctness claims come from upstream tests, not an external audit.
2. **Falcon-512 is NIST PQC level 1** (~128-bit classical / ~117-bit PQ). Suitable for research and medium-lifetime auth; rotate keys periodically.
3. **`chain_domain` is compile-time**, not a live genesis hash — weaker than ideal network binding.
4. **Transaction size headroom is small**; v0 + ALT may be required.
5. **HybridOr** and threshold policies are weaker than HybridAnd by design when enabled.

## Out of scope (this repo)

- Hardware key custody UX
- Formal verification of the DualKey policy engine
- Consensus-layer quantum resistance
- Guaranteeing Falcon pubkeys correspond to trapdoors without PoP protocols we define
