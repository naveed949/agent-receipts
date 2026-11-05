# Authority-contract comparison

`compare_authority_contracts` compares two authority policies. Python uses that name. Node uses `compareAuthorityContracts`. `normalize_authority_policy`, `normalize_https_authority_rules`, and `is_https_authority_subset` are exported too. Bindings call Rust.

## Sub-features

- `compare-vectors` requires the seven `compareAuthorityContracts` rows in `vectors/reference/vectors.json` to match in Rust, Python, and Node, including every `cmp-rejections` subcase as `TypeError`.
- `compare-helpers` requires the normalize and subset exports to call Rust.

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
