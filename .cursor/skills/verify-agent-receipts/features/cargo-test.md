# Cargo tests

`cargo test --workspace` runs the Rust unit tests, the public-API pin, `keys.rs`, `no_panic.rs`, the reference runner, and the custom vector runner that reads `vectors/text`.

## Sub-features

- `test-workspace` builds and tests every workspace member that has tests.
- `test-reference` runs the in-crate reference walker over `vectors/reference/vectors.json`.
- `test-text` runs `crates/core/tests/vectors.rs` over every `vectors/text/*.json` file.
- `test-empty` fails when that directory has no JSON files or the file set changes.
- `test-public-api` runs `crates/core/tests/public_api.rs`. The log records `test public_signatures_compile ... ok` and the other `fn name()` tests in that file.

## How to get to it (user POV)

- Run `cargo test --workspace` from the repository root.
- Run `cargo test -p agent-receipts` to run the core tests, including the text cases and the reference rows.
- Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`, which runs the workspace command as the `cargo-test` surface.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `vectors/reference/vectors.json` and `vectors/text` exist.

- **Workspace tests.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS`. The same log also contains `cargo test -p agent-receipts --features stream`, including `test stream_public_items_are_pinned ... ok`.
- **Text runner.** Open `cargo-test.log`. It contains `running 9 vector cases`, then `test result: ok`.
- **Reference runner.** The same log contains `test reference::reference_vectors ... ok` and `test reference::gondolin_https_is_v1_only ... ok`. Cargo hides that test's stdout when it passes. `hmac 8 ok` and `compare 7 ok` are asserted inside the test and printed by the Node and Python runs.
- **Missing cargo.** If cargo is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- The text vector test uses `harness = false`. A silent skip of that target is a failure.
- Success text vectors also require a second canonicalize pass that returns the same bytes.
- Binding crates set `test = false`. Their behavior is covered by the Python and Node surfaces, not by this one.
- An empty pending-kinds file is the `reference-pending-kinds` row. A passing `cargo-test.log` does not contain `pending 0`. Cargo hides that stdout.
