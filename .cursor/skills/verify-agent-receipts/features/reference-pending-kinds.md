# Reference pending kinds

`vectors/reference/pending-kinds.txt` lists every reference kind that still has no API. This checkout implements `canonicalize`, the HMAC kinds, and `compareAuthorityContracts`. The file is empty.

## Sub-features

- `pending-listed` requires the allowlist file to exist.
- `pending-empty` requires the file to contain no kind names.

## How to get to it (user POV)

- There is no pending kind. Every row in `vectors/reference/vectors.json` has an API.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run.
- `vectors/reference/pending-kinds.txt` exists.

- **Record emptiness.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `reference-pending-kinds` row is `PASS` with `no pending kinds`.
- **Stale list.** If the file names a kind that appears in core or binding sources, including Python and Node tests, the row is `FAIL` with `pending kind is present in source; this skill does not drive it`.
- **Orphan list.** If the file is non-empty and no listed kind hits those trees, the row is `FAIL` with `pending kinds remain`.
- **Count.** `node-napi.log` and `cross-language-agreement.log` contain `pending 0`, `canonicalize 8 ok` or `reference 8 ok`, `hmac 8 ok`, and `compare 7 ok`.
- **Proof.** The summary table shows `PASS`. Never `NOT_IMPLEMENTED`.

## Gotchas

- Do not treat an empty allowlist as a missing file. The file must exist.
- Do not mark this passed because canonicalize or HMAC tests passed while a kind remains listed.
