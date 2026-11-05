# Authority-contract comparison

`compare_authority_contracts` compares two authority policies. Python uses that name. Node uses `compareAuthorityContracts`. `normalize_authority_policy`, `normalize_https_authority_rules`, and `is_https_authority_subset` are exported too. Bindings call Rust.

## Sub-features

- `compare-vectors` requires the seven `compareAuthorityContracts` rows in `vectors/reference/vectors.json` to match in Rust, Python, and Node, including every `cmp-rejections` subcase as `TypeError`.
- `compare-helpers` requires the normalize and subset exports to call Rust.
- `compare-dump-duplicate-keys` requires the Rust, Python, and Node dumps to print `err invalid_input` on wrapper JSON whose `next.filesystem.read` repeats the key, first with a wider grant then an empty list, then with `"/admin"` then a match of previous. A last-win parse of those payloads is `FAIL`.

## How to get to it (user POV)

- Call `compare_authority_contracts` (Node: `compareAuthorityContracts`) with two policy objects.
- Invalid input raises `TypeError`.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run.

- **Record presence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `authority-contract-comparison` row is `PASS` with `rust python node compare 7 ok`.
- **Counts.** `node-napi.log` and `cross-language-agreement.log` contain the exact line `compare 7 ok`. `cargo-test.log` contains `test reference::reference_vectors ... ok`.
- **Proof.** The summary table shows `PASS`. Never `NOT_IMPLEMENTED`.

## Gotchas

- A passing canonicalize or HMAC row is not this feature.
- Agreement must compare the live Rust, Python, and Node results to each other, not only to the vector file.
- A dump that last-wins a duplicate JSON key is not this feature. `compare_authority_contracts_bytes` returns `invalid_input` on that text. The dumps must print that code, not a relationship.
