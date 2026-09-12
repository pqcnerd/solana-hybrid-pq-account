# Milestone 2 — Falcon-512 verification under Solana SBF

Goal: get Falcon-512 verification compiling and **running** under SBF, in the
simplest possible program — message + Falcon signature in, success or failure
out. No vault, no PDA, no authorization policy.

Status: **complete**. Falcon-512 signatures produced off-chain by PQClean verify
inside the SBF virtual machine, and the on-chain `sol_sha256` digest reproduces
the client's `sha2` digest bit-for-bit.

## What was built

`program/src/auth/falcon.rs` is now a real verifier, replacing the Milestone 0
stub that returned `Unimplemented`:

| Function | Public key form | Underlying call |
|----------|-----------------|-----------------|
| `verify_falcon_prepared` | 1024-byte NTT ("prepared") | `Falcon512Signature::verify_with_prepared` |
| `verify_falcon_raw` | 897-byte wire | `Falcon512Signature::verify` |

`program/src/hash.rs` adds the on-chain digest via the `sol_sha256` syscall.

Three **verification-harness** instructions (discriminators 240–242) expose these
under SBF. They authorize nothing: they own no account, move no lamports and
mutate no state. They are numbered far from the real instruction set (0–4) so
they can be removed without renumbering anything.

| Disc. | Instruction | Data layout | Public key source |
|------:|-------------|-------------|-------------------|
| 240 | `VerifyFalconPrepared` | `sig(666) ‖ message(..)` | `accounts[0].data[..1024]` |
| 241 | `VerifyFalconRaw` | `sig(666) ‖ pubkey(897) ‖ message(..)` | instruction data |
| 242 | `VerifyCanonicalDigest` | `preimage(172) ‖ expected(32)` | n/a |

Discriminator 240 reads the prepared key from **account data**, which is the
Milestone 3+ production shape and exercises the 8-byte account-data alignment
guarantee the design depends on.

## Toolchain

`scripts/setup-toolchain.sh` was run for the first time.

| Component | Version |
|-----------|---------|
| Agave / Solana CLI | 4.2.2 (`src:e29e5d91`, `feat:21b0d33a`) |
| `cargo-build-sbf` | 4.1.0 |
| platform-tools | v1.54 |
| rustc (host) | 1.93.0 |

The SBF build succeeded on the first attempt, producing a 120,592-byte
`target/deploy/dualkey_program.so` with **no stack-frame warnings**.

## Compute units (measured, not upstream)

Measured with Mollusk 0.15.1 against the compiled `.so`, over a **32-byte
digest** — the shape the vault will actually verify.

| Path | Observed | Notes |
|------|---------:|-------|
| Falcon-512 verify, prepared pubkey from account | **172,600 – 193,400 CU** | production path; clusters at ~172.6k / ~182.9k |
| Falcon-512 verify, raw 897-byte wire pubkey | **224,600 – 245,400 CU** | comparison only |
| Falcon-512 verify, invalid signature | **~173,000 CU** | rejection costs the same as success |
| Canonical digest via `sol_sha256` (172 bytes) | **417 CU** | negligible |
| Prepared representation saves | **exactly 51,991 CU** | deterministic; see below |

The absolute figures are ranges, not points, and a median over a handful of
samples is *not* stable — two runs of the same 9-sample test produced medians of
173,336 and 182,816 CU. Quote the range.

The **prepared-vs-raw delta, by contrast, is deterministic**: 51,991 CU,
reproduced exactly across independent runs. That is expected, because both paths
are measured on the same signature and differ only by the wire public-key decode
plus forward NTT, neither of which involves rejection sampling. This is the
number to cite for the value of the prepared representation.

### Absolute cost is quantized, and stochastic

Verification cost is **not** a single number for a fixed message length. It moves
in steps of about **10,150 CU**, which is the cost of one Keccak-f[1600]
permutation on SBF. Two things drive the permutation count:

1. **Absorb** — `hash_to_point` absorbs a 40-byte nonce plus the message at
   SHAKE-256's 136-byte rate, so longer messages cost more blocks.
2. **Squeeze** — coefficients are rejection-sampled (values ≥ 61445 are
   discarded, ~6.2% of draws), so the number of squeeze blocks varies *per
   signature* even when the message is identical in length.

Measured with a single fixed keypair, 12 samples per length:

| Message bytes | Prepared min | Prepared median | Prepared max | Raw median |
|--------------:|-------------:|----------------:|-------------:|-----------:|
| 0 | 172,684 | 173,123 | 183,089 | 225,114 |
| 32 | 172,574 | 182,816 | 183,366 | 234,807 |
| 64 | 172,806 | 183,079 | 183,658 | 235,070 |
| 96 | 182,963 | 192,859 | 193,394 | 244,850 |
| 128 | 182,457 | 183,278 | 193,718 | 235,269 |
| 172 | 182,860 | 193,101 | 193,354 | 245,092 |
| 256 | 193,212 | 203,131 | 203,443 | 255,122 |
| 512 | 213,203 | 223,453 | 223,753 | 275,444 |

Reproduce with:

```
cargo test -p dualkey-client --release --test sbf_falcon -- --ignored --nocapture
```

### Consequences for the design

- **Signing a 32-byte digest rather than the 172-byte preimage is worth ~10,000
  CU on-chain**, on top of the transaction-size saving it was chosen for. The
  canonical-preimage design is now cheaper for a second, independent reason.
- The documented 195,000 CU safe budget for the prepared path **holds** for a
  32-byte digest, but with less margin than a single-sample measurement
  suggests: the stochastic tail can add one permutation, reaching ~193,000 CU.
  The regression test therefore asserts the *median* against 195,000 and the
  *worst case* against a 205,000 tail ceiling, rather than pinning one number
  that would be flaky.
- Roughly 1.2M CU remain for Ed25519 introspection, state writes and the
  transfer CPI that Milestones 5–7 add.

### Correction to earlier documentation

Milestone 0 recorded upstream's figures of ~270k CU for the raw path and a
~99k CU saving from the prepared representation. Measured in DualKey's own
program frame, the raw path costs **~224.6–245.4k CU** and the prepared
representation saves **51,991 CU**, not ~99,000. The prepared-path figure
(~173–183k) does reproduce.

The ~99k number appears to describe `try_prepare_pubkey` — the one-time cost of
*producing* the prepared key at account initialization — rather than the
per-verification saving. That is a cost paid once at `Initialize`, and it will be
measured directly in Milestone 3. The affected claims in `architecture.md`,
`benchmark-plan.md`, `threat-model.md` and `README.md` have been corrected.

The conclusion is unchanged and now rests on measurement: the prepared
representation is required, and is meaningfully cheaper per verification.

## Open questions resolved

| Question (open since Milestone 0/1) | Resolution |
|---|---|
| Does Falcon verification fit the SBF 4 KB stack frame? | **Yes.** No stack-frame warnings. `verify_with_prepared` is `#[inline(never)]` and uses ~2 KB (two `[_; 512]` buffers); `norm_check_with_prepared` uses a further ~2 KB in its *own* frame. The split is what keeps each frame legal. |
| Does Mollusk support the instructions sysvar / precompiles? | **Yes.** Mollusk 0.15.1 ships `mollusk_svm::instructions_sysvar` and a `precompiles` Cargo feature (gating `agave-precompiles`), plus its own `instructions_sysvar` and `precompile` tests. Milestone 5 must enable the `precompiles` feature to exercise the Ed25519 precompile. |
| Is the prepared key safely aligned on-chain? | **Yes, and now proven end-to-end.** Solana guarantees 8-byte-aligned account data; the layout puts the prepared key at offset 96, asserted 8-byte aligned at compile time. Verification through account data succeeds, and undersized account data is rejected cleanly. |
| Does `sol_sha256` agree with the client's `sha2`? | **Yes.** Asserted against the shared known-answer vector `TEST_VECTOR_DIGEST` and over arbitrary intents. |

Still open, deliberately: the transaction-size question (whether ~26 bytes of
legacy-transaction headroom is real, or whether v0 + address lookup tables are
needed) and the localnet `chain_domain` build path. Neither is testable at
instruction level; both need the real transaction pipeline in Milestone 7.

## Dependency isolation

Re-verified after adding the verifier call:

- `cargo tree -p dualkey-program --all-features` contains **`solana-falcon512`
  only**. No `pqcrypto-falcon`, no PQClean, no C toolchain — not even under
  `[dev-dependencies]`, which are intentionally empty.
- The compiled `.so` contains **zero** strings matching
  `sign|keygen|secret|private`.
- The SBF integration tests live in `client/tests/sbf_falcon.rs`, not
  `program/tests/`, precisely so that no Falcon *signer* is ever reachable from
  the program package. This also makes the tests a genuine cross-layer check:
  the client signs with PQClean, the program verifies with `solana-falcon512`,
  and the two implementations must agree.

The Falcon secret key never enters the program, the account layout, or the
instruction data.

## Tests

17 SBF tests in `client/tests/sbf_falcon.rs`, all executing the compiled ELF
inside Mollusk (78 tests pass workspace-wide).

**Positive:** prepared-key verification from account data; raw wire-key
verification; 12 independent keypairs; message lengths 0 / 1 / 32 / 172 / 500;
`sol_sha256` against the known-answer vector and arbitrary intents.

**Negative — every one must fail, and fail cleanly:**

| Test | Expected error |
|------|----------------|
| Tampered message | `InvalidFalcon` (7) |
| Signature bit flip (header, nonce, body) | `InvalidFalcon` |
| Signature under a different public key | `InvalidFalcon` |
| Non-zero trailing padding | `InvalidFalcon` |
| Garbage prepared key (0x00 / 0xFF / 0xA5 fill) | error, no VM abort |
| Empty or unknown discriminator | `MalformedInstructionData` (16) |
| Truncated signature / public key / preimage | `MalformedInstructionData` |
| Account data shorter than 1024 bytes | `InvalidAccountData` (1) |
| Wrong expected digest, preimage bit flips | `DigestMismatch` (17) |
| Instructions 0–4 | `Unimplemented` (0) |

Two properties worth calling out:

- **No panics on attacker-controlled input.** A panic in SBF surfaces as
  `ProgramFailedToComplete`; every negative test asserts a specific custom error
  code instead, so malformed data is rejected rather than aborting the VM.
- **Non-zero padding is rejected on-chain**, matching the off-chain verifier. If
  padding were ignored, the 666-byte encoding would be malleable — the same
  signature could be re-encoded 19 different ways.

## Milestone 0/1 code review

Reviewed alongside this milestone. Findings:

1. **`rust-toolchain.toml` pinned an unbuildable toolchain.** It specified Rust
   1.85.0, but `Cargo.lock` resolves `solana-pubkey` 4.x, `solana-hash` 4.x and
   `solana-address` 2.x, which declare `rust-version = "1.89.0"`; Mollusk's
   `solana-syscalls` needs newer still. This went unnoticed because no `rustup`
   was installed, so `cargo` silently used the system toolchain and ignored the
   pin. Now 1.93.0, and verified with `rustup` active.
2. **`WireSignature` length recovery was sound but load-bearing.**
   `from_wire_bytes` recovered the encoded length by stripping trailing zeros;
   PQClean verification then used that reconstruction. The reasoning was correct
   — a `comp_encode` output always ends with the final coefficient's unary
   terminator bit, so its last byte is never zero (confirmed over 2,000
   signatures) — but it made verification depend on encoder internals.

   PQClean's `do_verify` explicitly accepts a `sigbuflen` of 625 (`666 - 40 - 1`)
   with all-zero padding, so `verify_pqclean_wire` now hands PQClean the **same
   666 bytes the on-chain verifier sees**. Length recovery is retained for
   reporting only. This also strengthens the interop guarantee: both verifiers
   now provably consume identical input.
3. **`jiff` 0.2.36 is a broken upstream publish** — it `include_str!`s markdown
   files absent from the archive. It reaches the project only through
   `mollusk-svm → solana-logger → env_logger`, and is pinned to 0.2.35 in
   `Cargo.lock`. Test-only; the program is unaffected.
4. **rustfmt and clippy ran for the first time** (both were unavailable in
   Milestone 1 with no rustup). Cosmetic formatting was applied and two trivial
   clippy lints fixed. No logic defects were found.

No architectural change was required, and none was made.

## Explicitly not done

No vault, no PDA, no authorization policy, no replay protection, no expiry, no
lamport movement, and no Ed25519 precompile introspection. The account
instructions still return `Unimplemented`. Milestone 3 introduces the
HybridAccount PDA.

Falcon signing and key generation remain off-chain only.
