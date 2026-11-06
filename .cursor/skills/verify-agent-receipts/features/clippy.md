# Clippy

Clippy lints the workspace with warnings denied.

## Sub-features

- `clippy-workspace` lints every member and every target.
- `clippy-deny` treats any warning as a failed surface.
- `clippy-toolchain` fails closed when clippy is not installed.

## How to get to it (user POV)

- Run `cargo clippy --workspace --all-targets -- -D warnings` from the repository root.
- Run `scripts/verify.sh`, which runs that command as the `clippy` surface.

## Driving it with verify.sh

Preconditions:

- `rustc` 1.83 is active through `rust-toolchain.toml`.

- **Doctor.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh doctor`. If clippy is missing, doctor exits 1.
- **Lint.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `clippy` row is `PASS` and `clippy.log` ends without `error: could not compile`. The script also runs `cargo clippy -p agent-receipts --all-targets --features stream -- -D warnings` and appends that log.
- **Missing tool.** If clippy is missing, the row is `FAIL`. It is not `PASS`.

## Gotchas

- `cargo clippy` without `-D warnings` can exit 0 with warnings. That is not this surface.
- Workspace clippy does not pass `--all-features`. The script and CI also run `cargo clippy -p agent-receipts --all-targets --features stream -- -D warnings`.
- `--all-targets` is required so the core tests are linted. It is not what compiles `bindings/node/build.rs`. That file is a member build script, so Clippy compiles it when it checks the node library.
