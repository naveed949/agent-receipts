# Reference pending kinds

`vectors/reference/pending-kinds.txt` lists every reference kind other than `canonicalize`. Those rows are printed and counted. This checkout has no API for them.

## Sub-features

- `pending-listed` requires the allowlist file, one kind per line, with no duplicate and no `canonicalize` line.
- `pending-printed` requires each kind in the file to appear on a `pending` line from the reference runner.
- `pending-absent` confirms the kind strings are not present under `crates/core/src` or the binding sources and tests.

## How to get to it (user POV)

- There is no user entry point. The reference file carries the rows. `docs/DECISIONS.md` says they are not implemented.
- The kinds in the allowlist today are `controlled-integrity`, `audit.verifyAuditReceipt`, and `compareAuthorityContracts`.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run. Doctor does not make these kinds exist.
- `vectors/reference/pending-kinds.txt` exists.

- **Record absence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `reference-pending-kinds` row is `NOT_IMPLEMENTED` with `reference kinds other than canonicalize have no API`.
- **Stale skill.** If one of those kind strings appears in the core or the binding sources or tests, the row is `FAIL`. It is still not `PASS`.
- **Count.** `node-napi.log` and `cross-language-agreement.log` contain `pending 12` and `canonicalize 8 ok` or `reference 8 ok`. `cargo-test.log` contains `test reference::reference_vectors ... ok`.
- **Proof.** The summary table shows `NOT_IMPLEMENTED` or `FAIL`. Never `PASS`.

## Gotchas

- A passing canonicalize row is not one of these kinds.
- Do not hardcode the kind names in binding tests. The runners print `kind` from the file.
- Do not mark this passed because `canonical_json` succeeded.
