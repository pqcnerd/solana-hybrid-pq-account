# Falcon-512 Interoperability Report

**Status:** Milestone 1 gate — **PASSED**.

Question: does a Falcon-512 signature produced off-chain by
`pqcrypto-falcon` (PQClean) verify under the on-chain verifier
`solana-falcon512`, and if so what exactly must be done to the bytes?

**Answer: yes, directly, with zero-padding as the only adaptation.**

Crate versions measured: `pqcrypto-falcon 0.4.1`, `pqcrypto-traits 0.3.5`,
`solana-falcon512 0.1.2`.

## Observed lengths

| Item | Value | Source |
|------|------:|--------|
| PQClean public key (`CRYPTO_PUBLICKEYBYTES`) | **897** | `falcon512::public_key_bytes()` |
| PQClean secret key (`CRYPTO_SECRETKEYBYTES`) | **1281** | `falcon512::secret_key_bytes()` |
| PQClean signature *buffer* (`CRYPTO_BYTES`) | **752** | `falcon512::signature_bytes()` |
| PQClean detached signature *on the wire* | **variable, 647–663 observed** | `DetachedSignature::as_bytes()` |
| `solana-falcon512` expected signature input | **exactly 666** | `FALCON_512_SIGNATURE_LEN` |
| `solana-falcon512` expected public key | **exactly 897** | `FALCON_512_PUBKEY_LEN` |
| `solana-falcon512` prepared public key | **exactly 1024** | `FALCON_512_PREPARED_PUBKEY_LEN` |

Public keys match byte-for-byte at 897 bytes. **Signatures do not match
lengths** and this is the whole substance of the gate.

### Why `CRYPTO_BYTES` is 752 and not 666

`pqcrypto_falcon::falcon512::DetachedSignature` is a 752-byte array plus a
used-length field:

```rust
pub struct DetachedSignature([u8; PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES], usize);

fn as_bytes(&self) -> &[u8] {
    &self.0[..self.1]     // variable-length prefix, NOT 752 bytes
}
```

752 is PQClean's conservative upper bound for its combined
`crypto_sign` (message ‖ signature) API. It is **not** the compressed
signature width. The compressed Falcon-512 signature is variable length and
spec-bounded at 666 bytes — which is exactly why the *padded* variant
(`falcon-padded-512`) is a fixed 666 bytes.

## Are signatures naturally 666 bytes?

**No. They are variable-length and always shorter than 666.**

Distribution over 10,000 signatures across 20 keypairs
(`signature_length_distribution_soak`):

```
samples=10000 min=647 max=663 over_666=0
margin below the 666-byte buffer: 3 bytes

 647 bytes :      1  ( 0.01%)
 648 bytes :     10  ( 0.10%)
 649 bytes :     37  ( 0.37%)
 650 bytes :    117  ( 1.17%)
 651 bytes :    326  ( 3.26%)
 652 bytes :    676  ( 6.76%)
 653 bytes :   1230  (12.30%)
 654 bytes :   1615  (16.15%)
 655 bytes :   1853  (18.53%)   <- mode
 656 bytes :   1687  (16.87%)
 657 bytes :   1109  (11.09%)
 658 bytes :    778  ( 7.78%)
 659 bytes :    359  ( 3.59%)
 660 bytes :    140  ( 1.40%)
 661 bytes :     38  ( 0.38%)
 662 bytes :     18  ( 0.18%)
 663 bytes :      6  ( 0.06%)
```

Length varies because Falcon signing samples a fresh 40-byte nonce per
signature and the Golomb-Rice encoding of `s2` compresses to a different size
each time. The header byte was `0x39` (compressed) in **every** observed case.

## Is zero padding present, and must it be added?

- PQClean **does not** emit padding; `as_bytes()` returns only the encoded bytes.
- `solana-falcon512` **requires** exactly 666 bytes **and requires every
  trailing byte past the encoded signature to be zero.** From its `codec.rs`:

  ```rust
  // The compressed encoding may end before the buffer; remaining bytes are
  // zero-padding and must all be zero.
  if chunk != 0 { return false; }
  ```

So padding **must be added** by the client. Non-zero padding is rejected
(covered by `non_zero_padding_is_rejected`).

## The adaptation performed

Exactly one operation, in
[`client/src/falcon_interop.rs`](../client/src/falcon_interop.rs):

```rust
let mut bytes = [0u8; 666];
bytes[..encoded.len()].copy_from_slice(encoded);   // right zero-pad
```

- No re-encoding, no byte reordering, no header rewriting, no re-compression.
- The signature bytes are passed through **byte-for-byte**; the test
  `pqclean_signature_verifies_under_solana_verifier` asserts
  `wire.encoded_bytes() == pq_sig.as_bytes()`.
- The operation is exactly reversible: stripping trailing zeros recovers the
  original PQClean signature, and `WireSignature::to_pqclean()` round-trips it
  back into a signature PQClean itself re-verifies.

### Oversized signatures are rejected, never truncated

If an encoded signature ever exceeded 666 bytes, truncation would corrupt it.
Instead `WireSignature::from_encoded_bytes` returns
`ClientError::FalconSignatureTooLong { actual, max }`.

Because Falcon signing is randomized, `sign_to_wire_with_retry` simply signs
again (up to 8 attempts). This path was never triggered in 10,000 samples and
is spec-unreachable; it exists as defense in depth rather than as a normalization.

## Is the wire format accepted byte-for-byte?

| Check | Result |
|-------|--------|
| PQClean verifies its own signature | Yes |
| Encoded bytes identical after adaptation | Yes |
| `solana-falcon512` raw-pubkey path (`verify`) | **Yes** |
| `solana-falcon512` prepared-pubkey path (`verify_with_prepared`) | **Yes** |
| Public key accepted at 897 bytes unchanged | Yes |
| Padded-format header `0x49` accepted | No (correctly rejected) |

Verified across 25 independent keypairs
(`cross_implementation_verification_holds_across_many_signatures`) and 10,000
signatures in the soak test, with the prepared path exercised in every case.

## Bug found: prepared public keys need ≥2-byte alignment

This was a real defect caught by the Milestone 1 test suite, not a
documentation note.

`Falcon512PreparedPubkey` is `[u16; 512]` underneath, so
`Falcon512PreparedPubkey::try_from_slice` **rejects any slice that is not at
least 2-byte aligned**. The first implementation held the prepared key in a
plain `[u8; 1024]`, which has alignment 1. Roughly half of all stack
placements landed on an odd address, so `verify_with_prepared` failed
**nondeterministically on correct bytes** — the raw path passed while the
prepared path reported `INVALID`.

Fix: a `#[repr(align(8))]` newtype, so misalignment is impossible by
construction:

```rust
#[repr(align(8))]
pub struct PreparedPubkey([u8; 1024]);
```

Regression test: `prepared_pubkey_is_always_sufficiently_aligned`.

**On-chain impact: none, but only because the layout already accounts for it.**
Solana account data is 8-byte aligned by ABI and the DualKey layout places the
prepared key at offset 96 (8-byte aligned), which is asserted at compile time
in [`core/src/state.rs`](../core/src/state.rs). Had that offset been odd, the
program would have failed the same way. The assertion is load-bearing.

## Architectural consequences

None. The Milestone 0 architecture is unchanged:

- Prepared public key stays 1024 bytes at account offset 96.
- Falcon signature stays 666 bytes on the wire.
- Both schemes still sign one 32-byte digest.
- Off-chain signing (`pqcrypto-falcon`) and on-chain verification
  (`solana-falcon512`) are confirmed compatible, so the split holds.

## Reproducing

```bash
# Gate + encoding tests
cargo test -p dualkey-client --test falcon_interop -- --nocapture

# Length distribution soak (10,000 signatures)
cargo test -p dualkey-client --release --test falcon_interop -- --ignored --nocapture
```
