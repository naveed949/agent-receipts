# Cross-language agreement

Rust, Python, and Node produce the same canonical hex and the same `stableHash` on every reference success row. Rust and Python produce the same bytes or the same error code on every file in `vectors/text`. Node is not a text caller.

## Sub-features

- `agree-reference` requires identical canonical hex and `stableHash` from Rust, Python, and Node, matching the reference row.
- `agree-reject` requires `type_error` from Python and Node for each child of the reference rejection row.
- `agree-text` requires identical Rust and Python results for every `vectors/text` file, and prints `text <name> rust-python ok`.
- `agree-pending` prints each non-canonicalize kind and requires `pending 12` and `reference 8 ok`.
- `agree-toolchain` fails closed if the Python wheel or Node addon is not importable.

## How to get to it (user POV)

- Compare `canonical_json` and `stable_hash` on one value in each language.
- Run `scripts/verify.sh`, which builds a Rust dump, runs the Node dump, and compares them with the installed Python module as the `cross-language-agreement` surface.

## Driving it with verify.sh

Preconditions:

- The `python-abi3` and `node-napi` surfaces have actually built in this run. Agreement does not use stubs.
- `vectors/reference/vectors.json` and a non-empty `vectors/text` directory exist.

- **Dump and compare.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cross-language-agreement` row is `PASS`.
- **Per row.** `cross-language-agreement.log` lists every reference success as `rust-python-node ok`, the rejection row as `python-node type_error`, every text file as `rust-python ok`, then `pending 12`, `reference 8 ok`, `text 9 ok`, and `agreement: ok`.
- **Missing build.** If the wheel is not importable or `bindings/node/index.js` is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- Matching each language only against the vector file, without comparing the live results to each other, is not this surface.
- Text files are Rust and Python only. A log that launches Node for those files is not this surface.
- Do not mark this passed when any language was skipped.
- Pending lines are required. A runner that skips them without counting fails the `pending 12` line.
- `--evidence-dir` may sit inside the checkout. The dump crate has its own `[workspace]` and its own `target/`. A failed dump build is `FAIL`. The agreement row does not reuse `target/debug/dump-canonicalize` from the workspace.
