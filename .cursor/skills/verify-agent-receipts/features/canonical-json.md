# Canonical JSON

`canonical_json` and `stable_hash` rewrite one JSON value into the reference form, or return a stable error code. Python and Node expose the same two operations. Eight reference rows match. The HMAC rows run separately. The remaining reference rows are pending.

## Sub-features

- `canon-success` matches `canonicalUtf8Hex` and `stableHash` for each canonicalize row that carries `expected`.
- `canon-stable` returns the same bytes when the successful output is passed in again.
- `canon-reject` returns `type_error` for each child of the canonicalize row that carries `expectedError`.
- `canon-text` runs `vectors/text` through the Rust and Python bytes entry. Node does not read that directory.
- `canon-pending` prints each still-pending kind and counts 7 pending rows beside 8 canonicalize rows and 8 HMAC rows.

## How to get to it (user POV)

- Call `agent_receipts::canonical_json` and `agent_receipts::stable_hash` from Rust with JSON bytes.
- Call `canonical_json` and `stable_hash` from Python after installing the abi3 wheel. `bytes` and `bytearray` are a document. A `str` is a JSON string.
- Call `canonicalJson` and `stableHash` from Node after `npm run build` in `bindings/node`. A buffer is rejected.
- Run `vectors/reference/vectors.json` through those value entries, and run `vectors/text` through the bytes entry.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `vectors/reference/vectors.json` exists.
- `vectors/text` contains the JSON files named by the Rust vector runner.

- **Rust cases.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS`. `cargo-test.log` contains `running 9 vector cases` and `test reference::reference_vectors ... ok`.
- **Python cases.** Read `python-abi3.log`. pytest exits 0. The reference test checks the captured `pending 0`, `canonicalize 8 ok`, `hmac 8 ok`, and `compare 7 ok` lines.
- **Node cases.** Read `node-napi.log`. It contains `pending 0`, `canonicalize 8 ok`, `hmac 8 ok`, and `compare 7 ok`.
- **Proof.** The `cross-language-agreement` row is `PASS`. Success rows are `rust-python-node ok`. Text files are `rust-python ok`.

## Gotchas

- A passing `cargo check` is not this feature.
- `maturin develop` is not the abi3 wheel path. The Python entry is the installed `*cp39-abi3*.whl`.
- Compare `canonicalUtf8Hex` and `stableHash`. `expected.canonical` is not the oracle.
- Pending rows are printed and counted. They are not a pass of those kinds.
- An empty `vectors/text` directory fails doctor.
