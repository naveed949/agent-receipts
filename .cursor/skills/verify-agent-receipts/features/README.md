# agent-receipts verification map

This directory is the maintained source for verifying agent-receipts. Read this index, then use the matching feature file as the recipe.

## Baseline preconditions

- Work from the repository root of this checkout.
- Run one verification job at a time in this tree. `target/` is shared.
- Put `scripts/verify.sh` on your command line as `.cursor/skills/verify-agent-receipts/scripts/verify.sh`.
- Run `scripts/verify.sh doctor` and require `RESULT=PASS`.
- Never treat a reserved feature as passed.

## Driving conventions

- Start every recipe from a doctor-ok checkout unless the feature file says otherwise.
- Run `scripts/verify.sh` for existing surfaces. Do not invent a shorter command list.
- Treat every command as literal. Keep wheel glob `*cp39-abi3*` and `maturin==1.16.0` unchanged.
- Read the evidence log named in the feature file.
- Leave proof artifacts in the evidence directory when cleanup runs.

## Proof and skip reporting

- Capture the command and the resulting status line, not only the last screen of output.
- `PASS` is allowed only for a surface the script actually ran.
- `FAIL` is required when a toolchain for an existing surface is missing.
- `NOT_IMPLEMENTED` is required for HMAC verification, authority-contract comparison, the async streaming verifier, and benchmarks, until those APIs exist.
- `UNSUPPORTED` is only for a product surface that cannot run on this OS even with the toolchain. There is no such surface on the CI targets today. Do not use it as a skip for a missing `rustfmt` or `node`.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with verify.sh` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

## Features

- [Canonical JSON bytes](./canonicalize-bytes.md) covers `canonicalize_bytes` success, error codes, and a second-pass stable rewrite.
- [Rustfmt](./rustfmt.md) covers `cargo fmt --all --check`.
- [Clippy](./clippy.md) covers `cargo clippy --workspace --all-targets -- -D warnings`.
- [Cargo tests](./cargo-test.md) covers `cargo test --workspace` and the shared files in `vectors/canonicalize`.
- [Python abi3 wheel](./python-abi3.md) covers the `cp39-abi3` wheel and pytest against that wheel.
- [Node napi binding](./node-napi.md) covers `napi build` and the Node vector tests.
- [Cross-language agreement](./cross-language-agreement.md) covers byte-identical Rust, Python, and Node results on every vector.
- [HMAC verification](./hmac-verification.md) is not yet implemented.
- [Authority-contract comparison](./authority-contract-comparison.md) is not yet implemented.
- [Async streaming verifier](./async-streaming-verifier.md) is not yet implemented.
- [Benchmarks](./benchmarks.md) are not yet implemented.
