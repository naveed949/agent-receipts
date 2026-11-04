# agent-receipts
Fast, portable verification of signed agent action receipts: one Rust core with Python and Node bindings

This repository publishes nothing to crates.io, PyPI, or npm.

## Test the Rust core

From the repository root, run this command.

```sh
cargo test --workspace
```

`cargo test -p agent-receipts` runs the reference vectors and the cases in `vectors/text`.

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
```

The entry points are `canonical_json` and `stable_hash` in Rust and Python, and `canonicalJson` and `stableHash` in Node. The behavior is [Canonical JSON](docs/spec/canonical-json.md). The reasons for the format are in [Decisions](docs/DECISIONS.md).
