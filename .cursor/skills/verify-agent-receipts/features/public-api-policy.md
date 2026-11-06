# Public API policy

A breaking change to a documented public signature or enum variant fails a compile-time pin. A changed `.code` string fails a runtime `assert_eq` in `public_api.rs` or a host test. The contract is `docs/VERSIONING.md`. Signer failures on Python leave `.code` unset. Signer failures on Node use the napi status strings `TypeError` and `RangeError`.

## Sub-features

- `rust-signatures` assigns every crate-public function to a function pointer with the exact type in `crates/core/tests/public_api.rs`.
- `rust-enums` matches every public enum variant exhaustively in that same file. The file also asserts the sha256 of `vectors/reference/vectors.json`.
- `python-inspect` asserts exported names, positional-or-keyword parameters with no default, compare result keys, and live `.code` strings in `bindings/python/tests/test_public_api.py`.
- `node-exports` asserts export names, required parameter names from generated `index.d.ts`, deep-frozen compare and normalize results, compare result keys, and live `.code` strings in `bindings/node/test/public_api.test.cjs`.

## How to get to it (user POV)

- Change a public Rust signature and run `cargo test -p agent-receipts --test public_api`. The test fails at compile time.
- Add a default to a Python parameter, rename an export, or change a host `.code`, then run `python -m pytest -v bindings/python/tests/test_public_api.py`.
- Add an optional Node parameter, drop a required parameter, thaw a normalize result, or change a host `.code`, then run `npm test` in `bindings/node`. The arity check reads `index.d.ts` from `npm run build`.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.

- **Rust log.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `public-api-policy` row is `PASS`. `cargo-test.log` has a full line `test <name> ... ok` for every `fn name()` test in `crates/core/tests/public_api.rs`, including `signing_key_variants_are_exhaustive`.
- **Python log.** `verify.sh` runs `python -m pytest -v`. `python-abi3.log` has a `PASSED` line for every `def test_` in `test_public_api.py`. The summary is `N passed in Ts` with no skipped count and no failed count. `SKIPPED`, `FAILED`, `ERROR`, or `XFAIL` on those tests is `FAIL`.
- **Node log.** `node-napi.log` has a full line `ok <n> - exported names`, no full line `not ok`, a full line `# fail 0`, and a full line `# skipped 0`. Node 22 prints `# skipped 0`. The predicate also accepts `# skip 0`.
- **Planted logs.** `.cursor/skills/verify-agent-receipts/scripts/prove-public-api-surface.sh` feeds planted logs to `public_api_policy_ok`. Each plant makes the predicate fail. The script prints `RESULT=PASS`.
- **Missing pin.** If those lines are absent, the row is `FAIL`. It is not `NOT_IMPLEMENTED`.

## Gotchas

- Adding a public item does not fail the Rust compile test until a pointer is added. That miss is a missed minor.
- `index.d.ts` is generated and gitignored. The Node test reads parameter names from that file after the build. The file is not committed. `Function.length` is 0 for these exports, so the test does not read it.
- A `cargo check` of the library is not this feature.
- `python_log_hmac_ok` still accepts a skipped pytest summary. `public-api-policy` uses `public_api_policy_ok` instead.
