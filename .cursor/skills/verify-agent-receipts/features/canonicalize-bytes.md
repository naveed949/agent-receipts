# Canonical JSON bytes

`canonicalize_bytes` takes JSON bytes and returns rewritten bytes, or a stable error code, with the same result from Rust, Python, and Node.

## Sub-features

- `canon-success` rewrites valid JSON to the bytes stored in each success vector.
- `canon-stable` returns the same bytes when the successful output is passed in again.
- `canon-error` returns `not_utf8` or `invalid_json` for the error vectors.
- `canon-host-types` returns Python `bytes` and a Node `Buffer` on success.

## How to get to it (user POV)

- Call `agent_receipts::canonicalize_bytes` from Rust.
- Call `agent_receipts.canonicalize_bytes` from Python after installing the abi3 wheel.
- Call `canonicalize_bytes` from Node after `npm run build` in `bindings/node`.
- Run the shared cases in `vectors/canonicalize` through those three entry points.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `vectors/canonicalize` contains at least one `.json` file.

- **Rust cases.** Run the workspace tests. Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS` and `cargo-test.log` contains `running 11 vector cases` or the current file count, then `test result: ok`.
- **Python cases.** Read `python-abi3.log`. pytest collected the parametrized vector tests and exited 0.
- **Node cases.** Read `node-napi.log`. `node --test` passed `test/canonicalize.test.cjs`.
- **Host types.** Python tests assert `type(got) is bytes`. Node tests assert `Buffer.isBuffer(got)`.
- **Proof.** The `cross-language-agreement` row is `PASS`. Every vector file is `ok` in `cross-language-agreement.log`.

## Gotchas

- A passing `cargo check` is not this feature.
- `maturin develop` is not the abi3 wheel path. The Python entry is the installed `*cp39-abi3*.whl`.
- Error vectors must match the `code` string (`not_utf8`, `invalid_json`), not only the exception class.
- An empty `vectors/canonicalize` directory is a failure, not a pass with zero cases.
