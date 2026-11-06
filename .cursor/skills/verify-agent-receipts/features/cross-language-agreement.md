# Cross-language agreement

Rust, Python, and Node produce the same canonical hex and the same `stableHash` on every reference success row. The same run also compares HMAC dumps, the gondolin case, compare dumps, and the duplicate-key pair. Rust and Python produce the same bytes or the same error code on every file in `vectors/text`, matching `output_b64` or the file's `error`. Node is not a text caller.

## Sub-features

- `agree-reference` requires identical canonical hex and `stableHash` from Rust, Python, and Node, matching the reference row.
- `agree-reject` requires `type_error` from Python and Node for each child of the reference rejection row.
- `agree-text` requires identical Rust and Python results for every `vectors/text` file, matching `output_b64` or the file's `error`, and prints `text <name> rust-python ok`.
- `agree-pending` requires `pending 0`, the exact line `hmac 8 ok`, the exact line `compare 7 ok`, and `reference 8 ok`.
- `agree-compare` drives every `compareAuthorityContracts` row and every `cmp-rejections` subcase through Rust, Python, and Node dumps and requires identical output lines.
- `agree-compare-duplicate-keys` drives two wrapper payloads whose `next.filesystem.read` key repeats, and requires `err invalid_input` from all three dumps. Last-win `unchanged` or `narrowing` is `FAIL`.
- `agree-hmac` drives every HMAC subcase — including uppercase, null, missing integrity, and every `v2Mutations` / `v1Mutations` label — through Rust, Python, and Node dumps and requires identical output lines.
- `agree-toolchain` fails closed if the Python wheel or Node addon is not importable.

## How to get to it (user POV)

- Compare `canonical_json` and `stable_hash` on one value in each language.
- Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`, which builds the canonicalize, HMAC, and compare dumps and compares them with the installed Python module.

## Driving it with verify.sh

Preconditions:

- The `python-abi3` and `node-napi` surfaces have actually built in this run. Agreement does not use stubs.
- `vectors/reference/vectors.json` and a non-empty `vectors/text` directory exist.

- **Dump and compare.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cross-language-agreement` row is `PASS`.
- **Per row.** `cross-language-agreement.log` lists every reference success as `rust-python-node ok`, the rejection row as `python-node type_error` in `vectors.json` order, the HMAC rows, the compare rows, `hmac gondolin-https rust-python-node ok`, `compare dump-duplicate-keys rust-python-node ok`, then `pending 0`, `hmac 8 ok`, `compare 7 ok`, `reference 8 ok`, each text file as `rust-python ok`, `text 9 ok`, and `agreement: ok`.
- **Missing build.** If the wheel is not importable, `bindings/node/index.js` is missing, or `cargo` is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- Matching each language only against the vector file, without comparing the live results to each other, is not this surface.
- Text files are Rust and Python only. A log that launches Node for those files is not this surface.
- Do not mark this passed when any language was skipped.
- Pending count is required. A runner that skips it fails the `pending 0` line. HMAC and compare rows are implemented and must print `hmac 8 ok` and `compare 7 ok`. They are not pending.
- `--evidence-dir` may sit inside the checkout. The dump crate has its own `[workspace]` and its own `target/`. A failed dump build is `FAIL`. The agreement row does not reuse `target/debug/dump-canonicalize` from the workspace.
