# Rustfmt

Rustfmt checks that every workspace Rust file matches `cargo fmt --all`.

## Sub-features

- `fmt-check` fails the run when rustfmt would rewrite a file.
- `fmt-toolchain` fails closed when `rustfmt` is not installed.

## How to get to it (user POV)

- Run `cargo fmt --all --check` from the repository root.
- Run `scripts/verify.sh`, which runs that command as the `rustfmt` surface.

## Driving it with verify.sh

Preconditions:

- The working directory can see `Cargo.toml` at the repository root.

- **Doctor.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh doctor`. If rustfmt is missing, doctor exits 1.
- **Check.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `rustfmt` row is `PASS` and `rustfmt.log` is empty of rewrite diffs.
- **Missing tool.** If `rustfmt` is not on `PATH`, the row is `FAIL` with `rustfmt missing; fail closed`. It is not `UNSUPPORTED` and not `PASS`.

## Gotchas

- `cargo fmt` without `--check` rewrites files and hides a failure.
- Formatting only `crates/core` skips the binding crates. The command is `--all`.
