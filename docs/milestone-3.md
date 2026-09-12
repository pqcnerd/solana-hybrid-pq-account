# Milestone 3 — HybridAccount PDA

**Goal:** create the on-chain account that holds an Ed25519 owner key, a prepared
Falcon-512 public key, a nonce, and an authorization policy. No transfers.

**Status:** complete. 99 tests pass, `cargo fmt --all -- --check` clean, clippy
clean across the workspace with `--all-targets`, and the SBF build produces no
stack-frame diagnostics.

---

## 1. What was built

`Initialize` (discriminator 0) is now implemented. Everything else that could
authorize or move value — `Execute`, `RotateEd25519Key`, `RotateFalconKey`,
`ChangePolicy` — still returns `Unimplemented`. **A HybridAccount created by this
milestone cannot spend anything**, because no code path evaluates its policy yet.

### Accounts and data

| # | Account | Role |
|---|---------|------|
| 0 | `creator` | signer, writable — funds rent, and is a PDA seed |
| 1 | `hybrid_account` | writable — the PDA to create |
| 2 | `system_program` | readonly |

```text
Offset  Size  Field
0       1     discriminator (0)
1       4     account_index (u32 LE)
5       32    owner_ed25519
37      1     policy
38      897   falcon_wire_public_key
935           end
```

### Order of checks

1. Exact instruction-data length (935 bytes); any other length is
   `MalformedInstructionData`.
2. Policy byte known (`PolicyRejected` if not) **and** implemented
   (`PolicyNotImplemented` if not).
3. Exactly three accounts.
4. `creator.is_signer`, else `MissingSigner`.
5. `system_program` is the real System program, else `InvalidProgramAccount`.
6. PDA matches the canonical derivation, else `InvalidPda`.
7. Target account holds no data, else `AccountAlreadyInitialized`.
8. Rent-exempt minimum read from the Rent sysvar; the account is funded,
   allocated and assigned via three System CPIs.
9. Header fields written; Falcon key prepared on-chain and stored.

---

## 2. Design decisions and why

### The prepared Falcon key is derived on-chain, never accepted from the client

The instruction carries the **897-byte wire** public key. The program calls
`try_prepare_pubkey` itself to produce the 1024-byte NTT form it stores.

This is a security property, not an optimization. The prepared form is
*unvalidated by construction*: any 1024 bytes decode to some polynomial, so there
is nothing to check. A client-supplied prepared blob could therefore be arbitrary
— and the program would then verify future signatures against a key nobody holds,
or against a maliciously chosen one. Deriving it from the wire encoding means the
stored key is always the transform of a genuine Falcon-512 public key, because
`try_prepare_pubkey` validates the header byte and the modq decode first.

It also keeps 127 bytes off the wire, which matters for the transaction budget.

Verified two ways: the stored bytes equal off-chain preparation exactly
(`on_chain_preparation_matches_off_chain_preparation`), and a real Falcon
signature verifies against the stored key through the on-chain verifier
(`signature_verifies_against_the_key_stored_by_initialize`).

### The bump is derived, not supplied

`Initialize` calls `find_program_address` (one `sol_try_find_program_address`
syscall on-chain, measured at 1,536 CU) rather than accepting a bump from
instruction data.

Accepting a caller-supplied bump would allow a **non-canonical** bump, which
yields a different but still valid program address for the same
`(creator, account_index)`. A caller could then create several accounts where the
design intends exactly one. Deriving the bump makes that impossible, and the
derived bump is what gets stored, so it always matches the address it was derived
for.

### Seeds are not keyed on key material

`["dualkey", creator, account_index_le]`, unchanged from Milestone 0. Seeding on
the Ed25519 or Falcon key would change the address on rotation and strand funds,
defeating Milestone 9.

Both sides build these seeds through the same `dualkey_core::pda_seeds` function,
so the client and program cannot drift on seed order or encoding. This is
asserted directly in `client_and_program_derive_identical_addresses`, which
compares `dualkey_client::onchain::derive_hybrid_account` against
`dualkey_program::pda::derive` across several creators and indices.

### Unenforceable policies are refused at creation

`HybridOr`, `FalconForPrivileged` and `FalconAboveThreshold` are declared but not
implemented, so `Initialize` rejects them with `PolicyNotImplemented` rather than
storing them. Storing one would create an account whose policy this program
cannot evaluate — an account that either can never authorize anything, or that
invites a future version to treat it permissively. An *unknown* byte is a
separate error (`PolicyRejected`) and is never coerced to a default.

### No money movement

The only lamport flow is the creator funding the new account's rent-exempt
minimum. `initialize_compute_units_and_rent` asserts that every lamport leaving
the creator lands in the new account, so nothing is diverted anywhere else.

---

## 3. Measurements

All figures from Mollusk 0.15.1 against the compiled `.so`, and **deterministic**
— identical across three independent runs, unlike Falcon verification.

| Quantity | Value |
|----------|------:|
| `Initialize` total | **60,854 CU** |
| ↳ parse + PDA derivation + 3 System CPIs + state write | 8,444 CU |
| ↳ `try_prepare_pubkey` (NTT) | **52,410 CU** |
| Instruction data | 935 bytes |
| Account data | 1,120 bytes |
| Rent-exempt minimum | 8,686,080 lamports (~0.00869 SOL) |
| Estimated legacy transaction size | 1,164 of 1,232 bytes |
| Headroom to the 1.4M per-instruction ceiling | 1,339,146 CU |

Using three CPIs instead of `create_account` costs 3,072 CU (57,782 → 60,854).
That is the price of closing the prefunding denial of service in §4.

The NTT figure comes from corrupting the wire key's header byte, which fails at
the start of `try_prepare_pubkey` — after parsing, PDA derivation and the CPI have
all been paid for. The difference isolates the NTT.

Rejection paths are cheap, which matters because they are the paths an attacker
can trigger for free:

| Rejection | CU |
|-----------|---:|
| Bad policy byte, wrong system program (before PDA derivation) | 825 |
| Wrong PDA (after derivation) | 2,361 |
| ↳ implied cost of the `sol_try_find_program_address` syscall | **1,536** |

Deriving the bump on-chain rather than trusting a caller-supplied one therefore
costs 1,536 CU — 2.7% of `Initialize`, for the guarantee that only one canonical
address exists per `(creator, account_index)`.

Rent matches the Milestone 0 prediction exactly: `(128 + 1120) × 6960 = 8,686,080`.

### The ~99k CU estimate, resolved

Milestone 0 recorded ~99k CU as the prepared-vs-raw benefit. Milestone 2 measured
that benefit as 51,991 CU and *hypothesised* that ~99k must instead describe the
one-time `try_prepare_pubkey` cost. **That hypothesis was wrong.** Measured
directly, `try_prepare_pubkey` is 52,410 CU. The ~99k figure matches neither
quantity and does not reproduce in this project; the docs no longer cite it as
anything but an upstream number.

What the two measurements do show is a clean relationship: 52,410 ≈ 51,991.
Preparing a key is exactly the work the raw verify path repeats every time, so
paying it once at `Initialize` breaks even after a **single** authorization and
saves ~52k CU on every one after that. That is a stronger justification for
storing the prepared form than the size argument alone.

---

## 4. Findings and corrections

### A 1-lamport denial of service against account creation (found and fixed)

The first working implementation used `solana_system_interface::instruction::create_account`,
which is what almost every tutorial uses. It refuses a destination that already
holds lamports.

Because PDA seeds are public, **anyone can compute a vault's address before it
exists and send it one lamport.** `create_account` then fails with "account
already in use" — permanently. That `(creator, account_index)` pair can never be
initialized. The attacker's cost is 1 lamport; the victim's only recourse is to
abandon the index.

Reproduced directly against the compiled program before fixing:

```text
Create Account: account ApoEUEH7jsAYNBdWTsG154iVdkmW8nwZNsXjLZ8eNdoK already in use
Failure(Custom(0))     # SystemError::AccountAlreadyInUse
```

Fixed by replacing the single `create_account` CPI with **transfer → allocate →
assign**. A transfer tops an account up rather than demanding it be empty, so
prefunding no longer blocks anything. The order is forced by the System program's
preconditions: `transfer` requires the *source* to be data-less, and `allocate`
requires the target to be system-owned with zero data, so assignment must come
last. Only the shortfall is transferred, so prefunded lamports are credited to
the creator rather than double-charged, and any excess simply stays in the
account.

`create_account_allow_prefund` exists in the interface crate and would do this in
one CPI, but it is a newer System instruction subject to runtime feature
activation, so it was not relied on.

`prefunded_pda_can_still_be_initialized` covers prefunds of 1, 1,000, one lamport
below the rent minimum, exactly the rent minimum, and well above it, asserting in
each case that the account ends up rent-exempt, program-owned, correctly
populated, and that the creator paid exactly the shortfall.

### CPI failures propagate the callee's error code, not ours

An underfunded creator produces `custom program error: 0x1` — the System
program's `ResultWithNegativeLamports` — propagated unchanged to the transaction
result. The `map_err` arms on the `invoke_signed` calls do **not** run in that
case; they cover only the path where `invoke_signed` returns before invoking
anything, which happens if its account-borrow checks fail.

This matters for reading logs and for tests: a CPI-failure test must assert on the
callee's error code, not a DualKey code. Tests for those paths therefore assert
"fails without producing an account" rather than a specific DualKey error, while
every check the program performs *itself* is asserted by exact error code.

### `cargo-build-sbf` reports stack overflows as `Error:` but exits 0

The first working version of `Initialize` produced:

```text
Error: Function ...initialize7process... overflows the maximum allowed frame
space by accessing an offset 192 bytes greater than the maximum of 4096.
Estimated function frame size: 4288 bytes.
Error: A function call in method ... overwrites values in the frame. ...
may cause undefined behavior during execution.
```

**and still exited 0, emitting a loadable `.so`.** A build script that only
checks exit status would have shipped a binary the toolchain itself describes as
possibly undefined behaviour. Any CI for this project must grep the build output,
not just trust the exit code.

Cause: `try_prepare_pubkey` returns the 1024-byte prepared key **by value**, and
inlining it into `process` pushed that frame over SBF's 4 KB limit. Fixed by
moving the call into an `#[inline(never)]` helper that writes straight into the
account's own buffer, so the large value is confined to its own frame — the same
technique `solana-falcon512` uses internally to split `verify_with_prepared` from
`norm_check_with_prepared`. `dualkey_core` gained
`HybridAccount::initialize_without_falcon_key` to support this: it writes the
header and leaves the prepared region zeroed for the caller to fill in place.
`#[inline(never)]` here is load-bearing for correctness, and is commented as such.

### `solana-pubkey` v3 vs v4 in the program

The program declared `solana-pubkey = "3"` while `solana-program-entrypoint`
depends on v4, which looked like it should have been a type mismatch on
`process_instruction`'s `&Pubkey` argument. It was not: `Pubkey` is an alias for
`solana_address::Address`, and `solana-address` 1.1.0 is a facade whose entire
body is `pub use solana_address_v2::*`, so both paths resolved to the same
`solana-address` 2.x type. No bug existed. The dependency is now `"4"` anyway, to
match the entrypoint directly and drop the facade hop and a duplicate crate.

### PDA derivation needs a host-only feature

`find_program_address` is gated on `any(target_os = "solana", feature =
"curve25519")`: on-chain it is a syscall, off-chain it needs a software
off-curve check. Enabling `curve25519` unconditionally would compile
`curve25519-dalek` into the SBF binary, where it is dead weight. It is therefore
scoped to non-Solana targets:

```toml
[target.'cfg(not(target_os = "solana"))'.dependencies]
solana-pubkey = { version = "4", features = ["curve25519"] }
```

Verified: `cargo tree --target sbpf-solana-solana` shows **0** curve25519 crates,
`--target x86_64-unknown-linux-gnu` shows 2.

### Milestone 2 test updated, not deleted

`account_instructions_remain_unimplemented` asserted that all of instructions 0–4
return `Unimplemented`. Now that `Initialize` is implemented it is renamed
`authorizing_instructions_remain_unimplemented` and covers 1–4, with a comment
explaining that `Initialize` is excluded because it authorizes nothing on its own.

### The Milestone 2 harness is layout-agnostic

Harness instruction 240 reads a prepared key from offset 0 of its account, while a
real HybridAccount stores it at offset 96. That is intentional — the harness
predates the account layout and will be deleted — but it means tests must lift
the stored region out before handing it to the harness. Noted here because it is
an easy source of a confusing `InvalidFalcon`.

---

## 5. Dependency isolation

Still holds. The program's dependency graph contains `solana-falcon512` (verifier
only) and **no** `pqcrypto-falcon`, so no Falcon *signer* can reach the on-chain
binary, not even through `[dev-dependencies]` — which remain empty, with the SBF
tests living in the `client` crate for exactly this reason.

New program dependencies are all first-party Solana crates: `solana-cpi`,
`solana-instruction`, `solana-system-interface` (`bincode` feature),
`solana-rent` (`sysvar`), `solana-get-sysvar`.

The `.so` grew from 120,592 to 173,872 bytes, essentially all of it serde/bincode
from `solana-system-interface`. Hand-encoding the 52-byte System `CreateAccount`
payload would avoid that; it was not done because the official builder is less
error-prone, and `Initialize` is a one-time operation where neither the size nor
the ~5k CU matters. Worth revisiting only if binary size becomes a constraint.

Two string scans of the `.so` now return one hit each, both benign and checked:
`sol_invoke_signed_rust` (the CPI syscall name) matches `/sign/`, and
`00010203...9899` matches a long-hex-run search — it is the standard decimal
digit-pair table used by integer formatting, pulled in with serde. Neither is key
material.

---

## 6. Tests

20 new SBF tests in `client/tests/sbf_initialize.rs`, plus one new leakage test in
`client/tests/file_safety.rs`. 99 total.

| Test | Property |
|------|----------|
| `initialize_writes_every_field_of_the_account` | version, bump, policy, owner, Falcon hash, nonce = 0, flags clear |
| `on_chain_preparation_matches_off_chain_preparation` | on-chain NTT is byte-identical to off-chain |
| `signature_verifies_against_the_key_stored_by_initialize` | a real signature verifies against the stored key; a different message does not |
| `distinct_account_indices_yield_distinct_accounts` | indices 0, 1, 2, 7, `u32::MAX` give distinct PDAs; stored bump matches |
| `distinct_creators_yield_distinct_accounts` | no cross-creator collision at the same index |
| `client_and_program_derive_identical_addresses` | client and program agree on address and bump |
| `every_implemented_policy_is_accepted` | all three implemented policies round-trip |
| `wrong_pda_is_rejected` | wrong index, wrong creator's PDA, unrelated address |
| `unsigned_creator_is_rejected` | `MissingSigner` |
| `wrong_system_program_is_rejected` | `InvalidProgramAccount`, before any CPI |
| `already_initialized_account_is_rejected` | no nonce reset, no key swap |
| `unimplemented_policy_is_rejected` | policies 3–5 refused |
| `unknown_policy_byte_is_rejected` | bytes 6, 7, 100, 255 refused, not defaulted |
| `malformed_falcon_public_key_is_rejected` | bad header, all-zero, all-ones |
| `malformed_instruction_data_is_rejected` | 5 truncations and one over-long, all clean errors |
| `wrong_account_count_is_rejected` | 2 and 4 accounts both refused |
| `prefunded_pda_can_still_be_initialized` | 5 prefund amounts; rent-exempt, program-owned, creator pays only the shortfall |
| `underfunded_creator_fails_cleanly` | no account produced, no panic |
| `initialize_compute_units_and_rent` | CU, rent, and that every lamport spent lands in the new account |
| `initialize_instruction_fits_a_legacy_transaction` | 935 bytes; 1,164 of 1,232 estimated |
| `initialize_instruction_contains_no_secret_material` | both public keys present; no 16-byte window of either secret key |

Negative tests assert specific error codes rather than "any failure", so a wrong
rejection reason fails the test.

---

## 7. Client changes

`dualkey init` now builds the instruction and prints the derived address, bump,
policy, and Falcon public-key hash. `--out` writes the same artifact as JSON
(mode 0644; it contains public material only).

It deliberately does **not** broadcast. Submitting needs an RPC endpoint and a
funded payer, and signing a real transaction belongs with the transfer milestone.
Building the instruction keeps this testable offline and lets the artifact be
inspected before anything is sent.

`creator` and `program-id` are supplied as base58 arguments rather than read from
the key directory, because the creator is normally an existing funded wallet, not
the Ed25519 owner key DualKey generates. The two roles are distinct: `creator`
pays and seeds the address, `owner_ed25519` is what the account will
authenticate against.

Instruction building loads keys through a new `keys::PublicKeys`, which reads only
`ed25519.pk` and `falcon512.pk`. The `Initialize` path therefore never opens a
secret key file at all, so it cannot leak one.

---

## 8. Explicitly not done

- **No authorization.** No signature is checked by `Initialize`, and no policy is
  evaluated anywhere. `Execute` remains `Unimplemented`.
- **No transfers.** Milestone 7.
- **No nonce consumption or expiry.** The nonce is written as 0 and never read.
  Milestone 6.
- **No rotation.** Milestone 9. The layout and stable-address seed choice are what
  make it possible.
- **No `declare_id!`.** The program has no fixed address yet; `program_id` is a
  parameter everywhere. It gets pinned at first deployment.
- **No transaction submission**, so the localnet `chain_domain` path and real
  transaction-size headroom remain untested end to end — same two open items
  carried from Milestone 2, both of which need the real pipeline in Milestone 7.
- **`reserved0`, `reserved1`, `falcon_required_above`, and the flags byte** are
  written as zero and not otherwise used.

---

## 9. Verification performed

```bash
cargo fmt --all -- --check                     # clean
cargo clippy --workspace --all-targets         # 0 warnings
cargo test --workspace                         # 99 passed, 2 ignored
cargo-build-sbf --manifest-path program/Cargo.toml   # no stack-frame diagnostics
cargo tree -p dualkey-program --all-features    # no pqcrypto-falcon
```

Milestone 3 is complete. Milestone 4 (canonical `AuthorizationIntent` and domain
separation) has not been started.
