# Latency

`./bench/run full` measures the public calls a host makes. Those calls are canonicalize, `stable_hash`, audit-receipt verify, controlled-integrity verify, and `compare_authority_contracts`. The file stores every sample in nanoseconds. The printed p50, p95, p99, mean, and spread are computed from those samples when you print or parse the file.

## Reproduce the full run

Build the release wheel and the release Node addon, then run one command from a clean checkout.

1. Install `maturin==1.16.0`. Run `maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3`. Install the printed `cp39-abi3` wheel into a virtual environment.
2. In `bindings/node`, run `npm ci` and `npm run build`.
3. From the repository root, run `./bench/run full --python <the virtualenv python>`.

`./bench/run` is the entry. You do not pass Node's type-stripping flag yourself.

The command writes `bench/results/full.json` and prints a host table, then a Rust table. The table units are microseconds. When `git status` is dirty, the command writes `bench/results/full.dirty.json` and does not replace `bench/results/full.json`.

`./bench/run full` pins one CPU with `taskset` when that program is on `PATH` and the current mask covers more than one CPU. Pass `--allow-unpinned` to skip the pin and record the reason. If `taskset` is missing, the file records `unpinned` and the run still completes.

`./bench/run parse bench/results/full.json` checks the file. It does not time anything. Parse exits 0 only when the vector gate passed with counts 8, 8, and 7, and each sample array has the length `effort` requires for that case.

Changing warmup or the iteration counts means editing `effort` in `bench/run.ts`. The commands do not take those counts as flags.

## Run the short check

`./bench/run smoke --out FILE --python PYTHON` runs the same 23-row TypeScript vector gate, then one process per implementation. Warmup is 2 and each case runs 5 times. The command prints `bench smoke ok` after `ts-baseline canonicalize 8 ok`, `ts-baseline hmac 8 ok`, and `ts-baseline compare 7 ok`.

Smoke proves the wheel, the addon, and the Rust binary answer the same probe as the TypeScript baseline. A smoke percentile is not a measurement. The bench workflow runs smoke and does not run the full measurement. A smoke failure there does not fail the other workflow.

## What the clock includes

The runner builds the host value before the clock starts. One sample is one public call plus one read of the result.

The discarded warmup calls use the same call. The timed loop then does this.

1. Read the clock.
2. Call the public export on the value that already exists.
3. Read the string length, the boolean, or `relationship`.
4. Read the clock again.

The loop does not call a garbage collector, and it does not stringify the result. The read in step 3 is inside the interval so the result has to exist.

| Implementation | Call inside the clock | What that call includes |
| --- | --- | --- |
| `typescript` | the functions in `bench/ts-baseline` | The algorithm on a JavaScript value. No FFI. |
| `node_napi` | the same names on `bindings/node` | `Host::load`, the walk into `Json`, the Rust function, and the value returned to JavaScript. Compare also runs `JSON.parse` and `freeze_tree`, and it loads the host twice. |
| `python_abi3` | the snake_case functions on objects from the installed wheel | `read_input` under the GIL, `py.detach` around the core, then the `str` or `dict` built under the GIL. The bytes entry is not the call. |
| `rust_native` | the value functions on an owned `Json` | The core only. The `Json` was built with the public constructors before the clock. `std::hint::black_box` holds the observed value. |

`includesHostMarshalling` is true when the implementation is not `rust_native`. The host table is built only from the three host series. Nothing in the printer sorts a native series into that list.

`stable_hash` emits canonical JSON again and then hashes those bytes. Adding a `canonical_json` row to a `stable_hash` row counts the emit twice. The report does not add them.

## Warmup, clocks, and noise

Smoke uses warmup 2 and 5 iterations in one process. Full uses five processes. Each process warms up again, so the p95 spread includes JIT and process startup, not only the steady state inside one isolate.

Full iteration counts come from the canonical UTF-8 size of the case.

| Canonical UTF-8 size | Warmup | Iterations |
| --- | --- | --- |
| vector cases, and synthetic cases up to 8192 bytes | 100 | 2000 |
| synthetic cases up to 65536 bytes | 20 | 400 |
| the 524288 byte object tree | 5 | 80 |

The vector rows and the 8192 byte rows, plus compare at 4096 bytes, use the first row of that table. Compare at 32768 bytes uses the second row.

Each implementation has its own clock, and the clock call sits inside every sample.

| Implementation | Clock |
| --- | --- |
| `typescript` and `node_napi` | `process.hrtime.bigint` |
| `python_abi3` | `time.perf_counter_ns` |
| `rust_native` | `std::time::Instant` |

A native call on the small vector can take a few hundred nanoseconds. Part of that sample is the clock. A sub-microsecond cell includes the call and the timer.

The result of each call is a new string, boolean, or object. The loop does not collect on purpose. A later iteration can still hit a collection that the runtime schedules. That shows up in the spread. It is not a step of the plan. The results file records `gcInTimedRegion` as false for that reason.

Shared machines add their own noise. Other processes, frequency changes, and a wide CPU mask move p95. Full pins one CPU when `taskset` exists so the spread is process noise rather than cores competing. The committed file is one run on one machine. The bench workflow runs only smoke, on a shared runner, and a failure there does not block the other checks.

p95 spread is the max minus the min of the per-run p95. The printed p50, p95, p99, and mean come from the run whose p50 is the median p50. Samples from different processes are not pooled. When that spread is wider than 15% of the median p95, and each run has at least 400 samples, the command prints `unstable` plus the operation, the case, and the implementation. The process still exits 0. The 524288 byte rows have 80 samples, so they do not print `unstable` even when they move.

## Why the rows differ

Read a cell against the work inside the call, then stop if the number does not fit.

A small Node or Python sample pays a fixed crossing. Node runs `Host::load` on every call, and that load evaluates `isProxy` through `run_script`. Python walks the object under the GIL before `py.detach`, and it builds the returned string or dict under the GIL again. The TypeScript baseline pays neither crossing. It pays the JavaScript implementation of the whole algorithm. On a tiny value the JavaScript algorithm can be slower than a short Rust call that still had to cross. On a large tree the copy and the emit dominate, and the native algorithm should pull ahead of the JavaScript one.

Rust native has no host walk. It should sit below the host rows on the same case. If a native cell is slower than a host cell on a large input, the native number is not measuring the value function alone, and this file should say so.

Node compare does more than the other Node calls. It walks both policies, builds a JSON text, parses that text, and freezes the tree. Two `Host::load` calls happen before the compare. A small compare row can be close to two canonicalize rows plus a parse. A large compare row adds the HTTPS subset walk. The synthetic pairs are version 2 with explicit ports, because version 1 rejects `network.https`. The vector row stays the version 1 mixed case, which has no HTTPS rules.

Audit verify and controlled verify are different MAC inputs. A version 1 audit tag covers 64 hex characters, then checks every artifact hash. Growing the receipt adds artifact hashes, so verify hashes each artifact again. Controlled verify MACs the canonical body of the value. Growing the value grows that MAC input. Do not average those two rows into one HMAC number.

`stable_hash` repeats the canonicalize emit. Its row should sit above `canonical_json` for the same payload by about one hash of that byte string. The hash of a 512KiB string is real work, but it is smaller than emitting the tree.

The object tree mixes canonical index keys such as `"2"` and `"10"` with other string keys, and it stays at most 6 containers deep. The generator seed is `0xA41C`. That shape makes the numeric key branch run without hitting the depth limit.

## Checklist for the committed file

The answers below belong to `bench/results/full.json`. Smoke is not this checklist.

1. **Limiter.** Filled from a profiled run that is not the committed file. A cell with no named limiter is marked unexplained.
2. **Tuning.** The wheel, the addon, and the Rust binary are release builds. `cargoProfile` in the file is `release`.
3. **Limits.** One pinned CPU. A sample cannot do more work than one core can retire in that interval.
4. **Errors.** A probe that disagrees with the TypeScript baseline, or a verify result other than true, aborts the command before it writes the file.
5. **Spread.** Five processes per implementation. The file stores every sample. The table prints p95 spread.
6. **Does it matter.** These calls are the public API a host waits on. There is no larger request around them in this repository.
7. **Did the work happen.** The observation is inside the clock, and the probe must match before the samples are kept.
