# Milestone 14 — Token-2022 TransferSpl

**Goal:** DualKey can CPI `transfer_checked` into **either** classic Token or
Token-2022 for base (non-hook) accounts.

## What shipped

- `program/src/spl_token.rs` accepts `TOKEN_PROGRAM_ID` **or** Token-2022
  (`TokenzQd…`). Same hand-rolled `TransferChecked` (disc 12) layout.
- Light TLV walk on mint / source / destination: reject
  `ExtensionType::TransferHook` (14) and `TransferHookAccount` (15). No hook
  CPI resolution.
- Account list unchanged (7 accounts); `token_program` must own source, dest,
  and mint.
- Client: `execute_transfer_spl_instruction_with_program` takes an explicit
  program id; classic remains the default helper.

## Tests

| Test | Property |
|------|----------|
| `transfer_spl_token2022_base_accounts_under_hybrid_and` | Token-2022 happy path |
| `transfer_spl_rejects_token2022_transfer_hook_mint` | Hook TLV → `InvalidAccountData` |

## Non-goals

- Full transfer-hook extra-meta resolution
- Other Token-2022 extensions beyond hook refusal
