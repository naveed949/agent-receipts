# Cross-language agreement

Rust, Python, and Node produce the same canonical bytes or the same error code on every file in `vectors/canonicalize`.

## Sub-features

- `agree-success` requires identical output bytes from all three languages, matching `output_b64`.
- `agree-error` requires identical error codes from all three languages, matching `error`.
- `agree-coverage` fails if the vector directory is empty.
- `agree-toolchain` fails closed if the Python wheel or Node addon is not importable.

## How to get to it (user POV)

- Compare the three `canonicalize_bytes` entry points on the same input bytes.
- Run `scripts/verify.sh`, which dumps each language and compares hex or error codes as the `cross-language-agreement` surface.

## Driving it with verify.sh

Preconditions:

- The `python-abi3` and `node-napi` surfaces have actually built in this run. Agreement does not use stubs.

- **Dump and compare.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cross-language-agreement` row is `PASS`.
- **Per vector.** `cross-language-agreement.log` lists every `vectors/canonicalize/*.json` file as `ok`, then `agreement: ok`.
- **Missing build.** If the wheel is not importable or `bindings/node/index.js` is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- Matching each language only against the vector file, without comparing the three live dumps to each other, is not this surface. The script compares Rust, Python, and Node to each other first.
- A passing language-specific test with a different fixture directory is not agreement.
- Do not mark this passed when any language was skipped.
