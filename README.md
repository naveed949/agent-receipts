# agent-receipts
Fast, portable verification of signed agent action receipts: one Rust core with Python and Node bindings

This repository publishes nothing to crates.io, PyPI, or npm.

## Test the Rust core

From the repository root, run this command.

```sh
cargo test --workspace
```

`cargo test -p agent-receipts` runs the reference vectors and the cases in `vectors/text`. `cargo test -p agent-receipts --features stream` runs the JSONL verifier.

## Test the Python binding

Use Python 3.9 or later. From the repository root, run these commands.

```sh
pip install maturin==1.16.0 pytest
maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3
pip install target/wheels/*cp39-abi3*.whl
pytest bindings/python/tests
```

The wheel filename contains `cp39-abi3`.

## Test the Node binding

Use Node.js 22. From `bindings/node`, run these commands.

```sh
npm ci
npm run build
npm test
```

## Check formatting and lints

From the repository root, run these commands.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p agent-receipts --all-targets --features stream -- -D warnings
```

The entry points are `canonical_json` and `stable_hash` in Rust and Python, and `canonicalJson` and `stableHash` in Node. JSONL audit logs use `verify_audit_receipt_lines` with feature `stream`, and `verify_stream` in Python. Audit receipts use `verify_audit_receipt` and `resign_audit_receipt` (Node: `verifyAuditReceipt`, `resignAuditReceipt`). Controlled integrity uses `verify_controlled_integrity` and `sign_controlled_integrity` (Node: `verifyControlledIntegrity`, `signControlledIntegrity`). Authority policies use `compare_authority_contracts`, `normalize_authority_policy`, `normalize_https_authority_rules`, and `is_https_authority_subset` (Node: `compareAuthorityContracts`, `normalizeAuthorityPolicy`, `normalizeHttpsAuthorityRules`, `isHttpsAuthoritySubset`). The behavior is [Canonical JSON](docs/spec/canonical-json.md), [HMAC integrity](docs/spec/hmac.md), and [Authority-contract comparison](docs/spec/authority-contracts.md). The reasons for the format are in [Decisions](docs/DECISIONS.md). Compatibility rules are in [Versioning](docs/VERSIONING.md).

CI builds the `cp39-abi3` wheel on linux x86_64 and aarch64, installs that wheel into a clean venv on CPython 3.9 and 3.13, and uploads the wheel as `agent-receipts-cp39-abi3-<arch>`.

## Measure latency

`./bench/run full` writes p50 and p95 for canonicalize, `stable_hash`, HMAC verify, and authority-contract comparison. Build the release wheel and the release Node addon first. The clock, the warmup, and how to read a row are in [Benchmarks](docs/BENCHMARKS.md).
