# Cargo tests

`cargo test --workspace` runs the Rust unit tests and the custom vector runner that reads `vectors/canonicalize`.

## Sub-features

- `test-workspace` builds and tests every workspace member that has tests.
- `test-vectors` runs `crates/core/tests/vectors.rs` over every `vectors/canonicalize/*.json` file.
- `test-empty` fails when that directory has no JSON files.

## How to get to it (user POV)

- Run `cargo test --workspace` from the repository root.
- Run `cargo test -p agent-receipts` to run only the core vector cases.
- Run `scripts/verify.sh`, which runs the workspace command as the `cargo-test` surface.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `vectors/canonicalize` exists.

- **Workspace tests.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS`.
- **Vector runner.** Open `cargo-test.log`. It contains `running N vector cases` with N equal to the number of JSON files, then `test result: ok`.
- **Missing cargo.** If cargo is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- The vector test uses `harness = false`. A silent skip of that target is a failure.
- Success vectors also require a second canonicalize pass that returns the same bytes.
- Binding crates set `test = false`. Their behavior is covered by the Python and Node surfaces, not by this one.
