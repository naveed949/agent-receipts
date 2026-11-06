# Async streaming verifier

`verify_audit_receipt_lines` counts `ok`, `invalid`, and `malformed` lines in a JSONL file of audit receipts. Python callers `await verify_stream(path, key)`. Node has no stream entry.

## Sub-features

- `stream-rust` is the feature-gated async function. It reuses `verify_audit_receipt_bytes` for each complete line.
- `stream-backpressure` is the cargo test whose name contains `backpressure`. A full channel stops `poll_read`.
- `stream-cancel` is the cargo test whose name contains `cancel`. Dropping the future drops the reader and returns no counts.
- `stream-python` is `verify_stream`. `test_gather_cancel_returns_no_dict` cancels `asyncio.gather` and expects `CancelledError` with no dict.

## How to get to it (user POV)

- In Rust, enable feature `stream` and call `verify_audit_receipt_lines` with a `tokio::io::AsyncRead`, a key, and `StreamLimits`.
- In Python, `await agent_receipts.verify_stream(path, key)`. `capacity` and `max_line_len` are keyword-only.
- Node stays on the synchronous verify and resign exports.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `crates/core/src` contains `async fn`.

- **Rust cases.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS`. `cargo-test.log` contains a line matching `test .*backpressure.* ... ok` and a line matching `test .*cancel.* ... ok`. The script appends `cargo test -p agent-receipts --features stream` to that log.
- **Python cases.** `python-abi3.log` contains `test_verify_stream.py::test_gather_cancel_returns_no_dict PASSED`.
- **Proof.** The `async-streaming-verifier` row is `PASS`. A checkout with no `async fn` under `crates/core/src` is `NOT_IMPLEMENTED`. A checkout that has the function and is missing one of those log lines is `FAIL`.

## Gotchas

- Workspace clippy does not pass `--all-features`. The stream lint is `cargo clippy -p agent-receipts --all-targets --features stream -- -D warnings`.
- `cargo tree -p agent-receipts-node -i tokio` does not find tokio. Node does not depend on the stream feature.
- A blocking `canonical_json` of one value is not this feature.
- The ignored million-line test is not part of `verify.sh`. It is `cargo test -p agent-receipts --features stream --release -- --ignored million_line_receipts_per_sec`.
