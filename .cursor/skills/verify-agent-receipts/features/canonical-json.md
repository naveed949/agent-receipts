# Canonical JSON

`canonical_json` and `stable_hash` rewrite one JSON value into the reference form, or return a stable error code. Python and Node expose the same two operations. Eight canonicalize rows exist. Seven carry `expected.canonicalUtf8Hex` and `expected.stableHash`. `canon-rejections` carries `expectedError`. The HMAC rows and the seven `compareAuthorityContracts` rows run separately. `pending-kinds.txt` is empty.

## Sub-features

- `canon-success` matches `canonicalUtf8Hex` and `stableHash` for each canonicalize row that carries `expected`.
- `canon-stable` returns the same bytes when Rust or Python passes the successful output in again as bytes. Node calls the value entry again on the original decoded value, because a buffer is `type_error`.
- `canon-reject` returns `type_error` for each child of the canonicalize row that carries `expectedError`.
- `canon-text` runs `vectors/text` through the Rust and Python bytes entry. Node does not read that directory.
- `canon-pending` prints `pending 0`. Every reference kind has an API.

## How to get to it (user POV)

- Call `agent_receipts::canonical_json` and `agent_receipts::stable_hash` from Rust with JSON bytes, or the `*_value` entries with a `Json` tree. The reference success path uses the value entries first.
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
- **Proof.** The `cross-language-agreement` row is `PASS`. Success rows are `rust-python-node ok`. The rejection row is `python-node type_error`. Text files are `rust-python ok`.

## Gotchas

- A passing `cargo check` is not this feature.
- `maturin develop` is not the abi3 wheel path. The Python entry is the installed `*cp39-abi3*.whl`.
- Compare `canonicalUtf8Hex` and `stableHash`. `expected.canonical` is not the oracle.
- An empty pending-kinds file is a pass of this kind list. It is not a skip.
- An empty `vectors/text` directory fails doctor.
