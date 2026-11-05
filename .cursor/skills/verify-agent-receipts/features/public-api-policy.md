# Public API policy

A breaking change to a documented public signature fails a compile-time or inspect test. The human contract is `docs/VERSIONING.md`.

## Sub-features

- `rust-signatures` assigns every crate-public function to a function pointer with the exact type in `crates/core/tests/public_api.rs`.
- `rust-enums` matches every public enum variant exhaustively in that same test.
- `python-inspect` asserts exported names and `inspect.signature` in `bindings/python/tests/test_public_api.py`.
- `node-exports` asserts export names and documented `error.code` values in `bindings/node/test/public_api.test.cjs`.

## How to get to it (user POV)

- Change a public Rust signature and run `cargo test -p agent-receipts --test public_api`. The test fails at compile time.
- Rename a Python export or change its parameter names and run pytest on `bindings/python/tests/test_public_api.py`.
- Rename a Node export or change `error.code` and run `npm test` in `bindings/node`.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.

- **Rust pin.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `public-api-policy` row is `PASS`. `cargo-test.log` contains `test public_signatures_compile ... ok` and `test public_enum_variants_are_exhaustive ... ok`.
- **Python pin.** `python-abi3.log` contains `test_public_api.py` and a zero-failure pytest summary.
- **Node pin.** `node-napi.log` contains `ok` for `exported names`.
- **Missing pin.** If those lines are absent, the row is `FAIL`. It is not `NOT_IMPLEMENTED`.

## Gotchas

- Adding a public item does not fail the Rust compile test until a pointer is added. That miss is a missed minor.
- `index.d.ts` is generated and gitignored. The Node pin is the live module, not that file.
- A `cargo check` of the library is not this feature.
