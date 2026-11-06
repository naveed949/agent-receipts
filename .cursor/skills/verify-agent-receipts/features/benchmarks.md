# Benchmarks

`./bench/run` reports p50, p95, p99, mean, sample count, and p95 spread for canonicalize plus `stable_hash`, HMAC verify, and authority-contract comparison. The host value already exists when the clock starts, and the clock stops after the caller reads the result. A Rust loop on an owned `Json` is printed in a separate table and is not ranked with the hosts.

## Sub-features

- `bench-smoke` runs the 23-row TypeScript vector gate, then one short process per implementation.
- `bench-parse` accepts a results file only when the live TypeScript vector gate still prints 8/8/7, the recorded `vectorsSha256` matches this checkout, each sample array matches the plan for that mode, no series is all zeros, and a file named `full.json` has mode `full`.
- `bench-tripwire` fails the row when `benches/` or `crates/core/benches` exists, or when a `[[bench]]` table exists under `crates/` or `bindings/`.

## How to get to it (user POV)

- `./bench/run full` writes `bench/results/full.json` from a clean worktree. A dirty worktree writes `bench/results/full.dirty.json` and leaves the committed file alone.
- `./bench/run smoke --out FILE --python PYTHON` writes a short results file. PYTHON is an interpreter that can import the installed wheel.
- `./bench/run parse FILE` re-runs `bench/ts-baseline/gate.ts`, checks `vectorsSha256` against `vectors/reference/vectors.json`, and then checks the schema. It does not time anything. All-zero samples, a sha256 that is not this checkout, a `full.json` whose mode is smoke, and a full-mode file with smoke sample lengths exit nonzero.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run.
- `bench/run` exists. If it does not, the row is `NOT_IMPLEMENTED`.
- The evidence interpreter can import `agent_receipts` from the wheel this drive installed, and `bindings/node/index.js` exists. `verify.sh` builds both before this row.

- **Smoke.** `verify.sh` runs `./bench/run smoke --out "$EVIDENCE/bench-results.json" --python "$PYTHON_BIN"` and writes stdout and stderr to `$EVIDENCE/benchmarks.log`.
- **Log lines.** The log contains `ts-baseline canonicalize 8 ok`, `ts-baseline hmac 8 ok`, and `ts-baseline compare 7 ok`.
- **Parse.** `./bench/run parse` exits 0 on `$EVIDENCE/bench-results.json`. When `bench/results/full.json` exists, parse also exits 0 on that file, which re-runs the vector gate against this checkout.
- **Proof.** The summary table shows `PASS`. A missing wheel, a missing addon, a failing smoke, a missing log line, or a rejected file is `FAIL`. `benches/` at the repo root, `crates/core/benches`, or `[[bench]]` under `crates/` or `bindings/` is `FAIL` and is not `PASS`. `scripts/prove-benchmarks-surface.sh` rejects an all-zero sample file and a recorded sha256 that is not this checkout.

## Gotchas

- Smoke iterations are a wiring check. Do not quote a smoke percentile as a measurement. `./bench/run full` is the measurement.
- `bench/ts-baseline` is not a product binding. Node and Python time the napi addon and the installed wheel.
- A `benchmarks` string inside `bindings/node/package-lock.json` is npm metadata. It is not this feature.
- Do not add a Cargo bench target to obtain a pass. This skill does not drive `cargo bench`.
