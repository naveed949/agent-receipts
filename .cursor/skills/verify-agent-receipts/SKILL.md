---
name: verify-agent-receipts
description: "Use when verifying agent-receipts on a local checkout, before a push, after changing canonical_json, stable_hash, HMAC verify or resign, compare_authority_contracts, their public signatures, or their Python or Node bindings, after changing files under vectors/reference or vectors/text, or when fmt, clippy, cargo test, maturin, pytest, or napi results are in doubt."
---

# Verify agent-receipts

This skill drives the real local build and test path for agent-receipts. It is a library with a Rust core, a Python abi3 module, and a Node napi module. There is no server, UI, or published package.

Read [features/README.md](features/README.md) before you drive. Run the commands below as written. Do not substitute a subset, a cached result, or `maturin develop`.

A missing toolchain is `FAIL`. A reserved feature that does not exist is `NOT_IMPLEMENTED`. Never record either as `PASS`.

Do not edit product code to make this skill pass. If a real surface fails, report the failure.

## Launch

There is no long-lived process. Launch means the checkout can run the same commands as `.github/workflows/ci.yml`.

1. Work from the repository root. One verification run per checkout. `target/` is shared, so two runs in the same tree corrupt each other.
2. Run the doctor command in [Doctor](#doctor). Stop if it fails.
3. Full verification installs `maturin==1.16.0` and `pytest` through `python3 -m pip` (a venv under the evidence directory when `python3 -m venv` works, otherwise `--user`). It also runs `npm ci` in `bindings/node`.
4. Ready means `scripts/verify.sh doctor` exits 0 and the evidence directory exists. Ready is not a passing test run.

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh doctor
```

## Doctor

Doctor is read-only. It answers whether this machine is worth driving. Run it first, and run it again after any failed drive.

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh doctor
```

It checks, from the repository root:

- `Cargo.toml` is the workspace that contains `crates/core`
- `rustc` is 1.83, matching `rust-toolchain.toml`
- `cargo`, `rustfmt`, and `clippy` are on `PATH`
- `python3` is 3.9 or later and `python3 -m pip` works
- `node` major version is 22 and `npm` is on `PATH`

A failed check is `FAIL`, not `UNSUPPORTED`. `UNSUPPORTED` is only for a surface that exists in the product and cannot run on this OS even with the toolchain present. No such surface exists on the CI targets (`ubuntu-24.04`, `ubuntu-24.04-arm`).

## Drive

Run exactly this command from any directory:

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh
```

To keep logs:

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh --evidence-dir /tmp/agent-receipts-verify-manual
```

The script drives every surface that exists on this checkout:

| Surface | Command |
| --- | --- |
| `rustfmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `cargo-test` | `cargo test --workspace` (includes `crates/core/tests/public_api.rs`, `crates/core/tests/vectors.rs` over `vectors/text`, and the reference runner) |
| `python-abi3` | `maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3`, install the wheel path maturin reports for this build, then `python3 -m pytest bindings/python/tests` |
| `node-napi` | in `bindings/node`: `npm ci`, `npm run build`, `npm test` |
| `cross-language-agreement` | compare Rust, Python, and Node on every reference success row (`canonicalUtf8Hex` and `stableHash`), compare Rust, Python, and Node on every HMAC subcase, compare Rust, Python, and Node on every `compareAuthorityContracts` row and subcase, reject dump last-win on duplicate `filesystem.read` keys as `invalid_input`, and compare Rust and Python on every `vectors/text` file |
| `hmac-verification` | require a zero-failure pytest summary, the exact line `hmac 8 ok` from Node and from agreement, `test reference::reference_vectors ... ok` from cargo, and the verify/resign HMAC API in source |
| `authority-contract-comparison` | require `compare 7 ok` from Node and from agreement, `test reference::reference_vectors ... ok` from cargo, and the compare API in source |
| `public-api-policy` | require `test public_signatures_compile ... ok` from cargo, `test_public_api.py` and a zero-failure pytest summary from the installed abi3 wheel, and `exported names` from Node |

It then records reserved names from `docs/DECISIONS.md` that have no API yet:

- `async-streaming-verifier`
- `benchmarks`

Those rows are `NOT_IMPLEMENTED` when source under `crates/core/src` and the bindings has no matching API. If that API appears, the row is `FAIL` (stale skill), never `PASS`. Canonicalization, HMAC verification, authority-contract comparison, and the public-API policy stay `PASS` when the script actually drove them. `reference-pending-kinds` is `PASS` when the allowlist file exists and is empty.

Drive each mapped feature through this script. The feature file names the surface id and the log to read. Do not mark a feature passed because a different surface passed.

## Evidence

Logs live in `$VERIFY_EVIDENCE_DIR` when set, else `/tmp/agent-receipts-verify-<timestamp>-<pid>/`.

Proof for an existing surface is the command log plus a `PASS` or `FAIL` line. Proof for agreement is `reference <name> rust-python-node ok` for each success row, `reference <name> python-node type_error` for the rejection row, `text <name> rust-python ok` for every file in `vectors/text`, `compare <name> rust-python-node ok` for each comparison row, then `pending 0`, the exact line `hmac 8 ok`, the exact line `compare 7 ok`, `reference 8 ok`, and `text` with a count equal to the number of text files. Proof for HMAC is a pytest summary with no `N failed` clause, `hmac 8 ok` in `node-napi.log`, the exact line `hmac 8 ok` in `cross-language-agreement.log`, and `test reference::reference_vectors ... ok` in `cargo-test.log`. A pytest summary such as `19 passed, 1 skipped in` is still a zero-failure run. A mixed pytest summary such as `1 failed, 17 passed` is `FAIL`. Proof for authority-contract comparison is `compare 7 ok` in `node-napi.log` and in `cross-language-agreement.log`. Proof for a reserved feature is a `NOT_IMPLEMENTED` line, not a skipped `PASS`. Proof for the public-API policy is `test public_signatures_compile ... ok` in `cargo-test.log`, `test_public_api.py` plus a zero-failure pytest summary in `python-abi3.log`, and `exported names` in `node-napi.log`.

`verify.sh` unsets `CARGO_TARGET_DIR` and points it at this checkout's `target/`. It deletes stale `*cp39-abi3*.whl` files before the maturin build and installs the wheel path printed by that build. It does not glob `$REPO_ROOT/target/wheels` blindly.

`summary.txt` and `summary.tsv` in the evidence directory are the pass/fail table. Keep them. Cleanup must not delete that directory.

Exercise the real `cargo`, wheel, and napi paths. Do not call `canonical_json` through a test-only stub. Do not treat `cargo check` as `cargo test`.

## Cleanup

`verify.sh` removes the evidence venv and the scratch dump crate after it writes the summary. It does not kill processes by name. It starts none.

Leave `target/`, `bindings/node/node_modules/`, and generated napi files in place. They are gitignored build output.

Never delete the evidence directory.

## Helpers

Run these as written.

Doctor:

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh doctor
```

Full drive:

```sh
.cursor/skills/verify-agent-receipts/scripts/verify.sh
```

Layout check for this skill:

```sh
.cursor/skills/verify-agent-receipts/scripts/check-layout.sh
```

`scripts/agree.py`, `scripts/dump_canonicalize.rs`, `scripts/dump_canonicalize.cjs`, `scripts/dump_hmac.rs`, `scripts/dump_hmac.py`, `scripts/dump_hmac.cjs`, `scripts/dump_compare.rs`, `scripts/dump_compare.py`, and `scripts/dump_compare.cjs` are used by `verify.sh`. `scripts/hmac-surface.sh` holds the HMAC log predicates. `scripts/prove-hmac-surface.sh` is the negative proof for those predicates. Do not invoke the helpers as a substitute for the full drive.
