---
name: verify-agent-receipts
description: "Use when verifying agent-receipts on a local checkout, before a push, after changing canonicalize_bytes or its Python or Node bindings, after changing files under vectors/canonicalize, or when fmt, clippy, cargo test, maturin, pytest, or napi results are in doubt."
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

A failed check is `FAIL`, not `UNSUPPORTED`. `UNSUPPORTED` is only for a surface that exists in the product and cannot run on this OS even with the toolchain present. No such surface exists on the CI targets (`ubuntu-latest`, `ubuntu-24.04-arm`).

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
| `cargo-test` | `cargo test --workspace` (includes `crates/core/tests/vectors.rs` over `vectors/canonicalize`) |
| `python-abi3` | `maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3`, install the single `*cp39-abi3*.whl`, then `python3 -m pytest bindings/python/tests` |
| `node-napi` | in `bindings/node`: `npm ci`, `npm run build`, `npm test` |
| `cross-language-agreement` | dump `canonicalize_bytes` from Rust, Python, and Node on every file in `vectors/canonicalize` and require equal bytes or equal error codes |

It then records reserved names from `docs/DECISIONS.md` that have no API yet:

- `hmac-verification`
- `authority-contract-comparison`
- `async-streaming-verifier`
- `benchmarks`

Those rows are `NOT_IMPLEMENTED` when source under `crates/core/src` and the bindings has no matching API. If that API appears, the row is `FAIL` (stale skill), never `PASS`.

Drive each mapped feature through this script. The feature file names the surface id and the log to read. Do not mark a feature passed because a different surface passed.

## Evidence

Logs live in `$VERIFY_EVIDENCE_DIR` when set, else `/tmp/agent-receipts-verify-<timestamp>-<pid>/`.

Proof for an existing surface is the command log plus a `PASS` or `FAIL` line. Proof for agreement is per-vector `ok` lines in `cross-language-agreement.log` for every `vectors/canonicalize/*.json` file. Proof for a reserved feature is a `NOT_IMPLEMENTED` line, not a skipped `PASS`.

`summary.txt` and `summary.tsv` in the evidence directory are the pass/fail table. Keep them. Cleanup must not delete that directory.

Exercise the real `cargo`, wheel, and napi paths. Do not call `canonicalize_bytes` through a test-only stub. Do not treat `cargo check` as `cargo test`.

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

`scripts/agree.py`, `scripts/dump_canonicalize.rs`, and `scripts/dump_canonicalize.cjs` are used by `verify.sh`. Do not invoke them as a substitute for the full drive.
