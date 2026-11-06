# Latency

`./bench/run full` measures the public calls a host makes. Those calls are canonicalize, `stable_hash`, audit-receipt verify, controlled-integrity verify, and `compare_authority_contracts`. The file stores every sample in nanoseconds. The printed p50, p95, p99, mean, and spread are computed from those samples when you print or parse the file.

## Reproduce the full run

Build the release wheel and the release Node addon, then run one command from a clean checkout.

1. Install `maturin==1.16.0`. Run `maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3`. Install the printed `cp39-abi3` wheel into a virtual environment.
2. In `bindings/node`, run `npm ci` and `npm run build`.
3. From the repository root, run `./bench/run full --python <the virtualenv python>`.

`./bench/run` is the entry. You do not pass Node's type-stripping flag yourself.

The command writes `bench/results/full.json` and prints a host table, then a Rust table. The table units are microseconds. When `git status` is dirty, the command writes `bench/results/full.dirty.json` and does not replace `bench/results/full.json`.

`./bench/run full` records `pinned` when the process already has one CPU. If the mask covers more than one CPU, it re-execs under `taskset -c` on the lowest allowed CPU. Pass `--allow-unpinned` to skip that re-exec and record the reason. If `taskset` is missing and the mask is still wider than one CPU, the file records `unpinned` and the run still completes.

`./bench/run parse bench/results/full.json` checks the file. It does not time anything. Parse re-runs `bench/ts-baseline/gate.ts` and exits 0 only when that live gate still prints 8, 8, and 7, the recorded `vectorsSha256` matches sha256 of `vectors/reference/vectors.json` on this checkout, the file is mode `full`, no series is all zeros, and each sample array has the length `effort` requires for that case. A smoke-mode file named `full.json` is rejected. A full-mode file with smoke sample lengths is rejected.

Changing warmup or the iteration counts means editing `effort` in `bench/run.ts`. The commands do not take those counts as flags.

## Run the short check

`./bench/run smoke --out FILE --python PYTHON` runs the same 23-row TypeScript vector gate, then one process per implementation. Warmup is 2 and each case runs 5 times. The command prints `bench smoke ok` after `ts-baseline canonicalize 8 ok`, `ts-baseline hmac 8 ok`, and `ts-baseline compare 7 ok`.

Smoke proves the wheel, the addon, and the Rust binary answer the same probe as the TypeScript baseline. A smoke percentile is not a measurement. The bench workflow runs smoke and does not run the full measurement. A smoke failure there does not fail the other workflow.

## What the clock includes

The runner builds the host value before the clock starts. One sample is one public call plus one read of the result.

The discarded warmup calls use the same call. The timed loop then does this.

1. Read the clock.
2. Call the public export on the value that already exists.
3. Read the string length, the boolean, or `relationship`. TypeScript and Node also copy `widened` and `narrowed` on a compare. Python and Rust read the relationship length only.
4. Read the clock again.

The loop does not call a garbage collector, and it does not stringify the result. The read in step 3 is inside the interval so the result has to exist.

| Implementation | Call inside the clock | What that call includes |
| --- | --- | --- |
| `typescript` | the functions in `bench/ts-baseline` | The algorithm on a JavaScript value. No FFI. |
| `node_napi` | the same names on `bindings/node` | `Host::load`, the walk into `Json`, the Rust function, and the value returned to JavaScript. Compare also runs `JSON.parse` and `freeze_tree`, and it loads the host twice. |
| `python_abi3` | the snake_case functions on objects from the installed wheel | `read_input` under the GIL, `py.detach` around the core, then the `str` or `dict` built under the GIL. The bytes entry is not the call. |
| `rust_native` | the value functions on an owned `Json` | The core only. The `Json` was built with the public constructors before the clock. `std::hint::black_box` holds the observed value. |

The results file does not store an `includesHostMarshalling` field. The host table is only `typescript`, `node_napi`, and `python_abi3`. Nothing in the printer sorts a `rust_native` series into that list.

`stable_hash` emits canonical JSON again and then hashes those bytes. Adding a `canonical_json` row to a `stable_hash` row counts the emit twice. The report does not add them.

## Warmup, clocks, and noise

Smoke uses warmup 2 and 5 iterations in one process. Full uses five processes. The clock starts after that process exists, and after warmup. Each process warms up again, so the p95 spread includes JIT differences across isolates. Process startup is not inside a sample.

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

Shared machines add their own noise. Other processes, frequency changes, and a wide CPU mask move p95. Full records `pinned` when the mask is already one CPU, or when `taskset` can re-exec onto one CPU. The spread then includes a fresh process and its JIT on every repeat. The committed file is one run on one machine. The bench workflow runs only smoke, on a shared runner, and a failure there does not block the other checks.

p95 spread is the max minus the min of the per-run p95. The printed p50, p95, p99, and mean come from the run whose p50 is the median p50. Samples from different processes are not pooled. When that spread is wider than 15% of the median p95, and each run has at least 400 samples, the command prints `unstable` plus the operation, the case, and the implementation. The process still exits 0. The 524288 byte rows have 80 samples, so they do not print `unstable` even when they move.

## Why the rows differ

Read a cell against the work inside the call, then stop if the number does not fit.

A small Node or Python sample pays a fixed crossing. Node runs `Host::load` on every call, and that load evaluates `isProxy` through `run_script`. Python walks the object under the GIL before `py.detach`, and it builds the returned string or dict under the GIL again. The TypeScript baseline pays neither crossing. It pays the JavaScript implementation of the whole algorithm. On a tiny value the JavaScript algorithm can be slower than a short Rust call that still had to cross. On a large tree the copy and the emit dominate, and the native algorithm should pull ahead of the JavaScript one. TypeScript emits each string as one slice. Host validation is the same walk as before. `bench/ts-baseline/emit-repro.ts` checks `text === canonicalJson(tree)` on the 524306-byte tree.

Rust native has no host walk. It should sit below the host rows on the same case. If a native cell is slower than a host cell on a large input, the native number is not measuring the value function alone, and this file should say so.

Node compare does more than the other Node calls. It walks both policies, builds a JSON text, parses that text, and freezes the tree. Two `Host::load` calls happen before the compare. A small compare row can be close to two canonicalize rows plus a parse. A large compare row adds the HTTPS subset walk. Identifier membership is a `Set` in TypeScript and a `HashSet` in the core, so the 32768-byte pair is the subset work on a many-identifier list, not an O(n²) scan. The synthetic pairs are version 2 with explicit ports, because version 1 rejects `network.https`. The vector row stays the version 1 mixed case, which has no HTTPS rules.

Audit verify and controlled verify are different MAC inputs. A version 1 audit tag covers 64 hex characters, then checks every artifact hash. Growing the receipt adds artifact hashes, so verify hashes each artifact again. Controlled verify MACs the canonical body of the value. Growing the value grows that MAC input. Do not average those two rows into one HMAC number.

`stable_hash` repeats the canonicalize emit. Its row should sit above `canonical_json` for the same payload by about one hash of that byte string. The hash of a 512KiB string is real work, but it is smaller than emitting the tree.

The object tree mixes canonical index keys such as `"2"` and `"10"` with other string keys, and it stays at most 6 containers deep. The generator seed is `0xA41C`. That shape makes the numeric key branch run without hitting the depth limit.

## Checklist for the committed file

`bench/results/full.json` is one full run on 6 November 2026. The machine was an Intel Xeon, Linux 6.12.94+, x64, Node v22.23.4, CPython 3.12.3, rustc 1.83.0. The wheel, the addon, and `agent-receipts-bench-native` were release builds. `taskset` pinned the run to CPU 0. Git SHA `8ac4b74136ef24958c87989e436d5e5c7cb6e285`, clean worktree. Five processes per implementation. Wall time was about four minutes. Smoke is not this checklist.

1. **Limiter.** The 524288 byte canonicalize rows are tens of milliseconds on one pinned core. Native p50 is 1.27 ms. Node is 21.6 ms, Python 24.4 ms, and TypeScript 26.4 ms. Host p50 spread on that row is under 3%. Native is the emit. The host rows add the walk on that same core. TypeScript concatenates each string in one slice. Node remains ahead of TypeScript on this row; the p50 ranges do not overlap ([21.515, 22.039] ms against [26.191, 26.657] ms). The remaining gap is the rest of the TypeScript walk and emit, not a per-character join.
2. **Tuning.** `cargoProfile` is `release`. The Python module path is under `site-packages`. The Node file is the release `bindings/node/index.js`. The wheel, the addon, and the Rust binary are all release builds.
3. **Limits.** 524306 canonical bytes in 1.27 ms is about 410 MB/s of output. That is under what one core can move from memory. The host rows are slower than that, so they are not a memory-bandwidth ceiling. They are more instructions per byte on the same core. Subtracting the native emit from the Node row leaves about 20 ms, which is the walk, so the walk can account for the native-to-Node gap. It cannot make the Node row faster than the native row.
4. **Errors.** The command exits before it writes the file if a probe disagrees with the TypeScript baseline, or if verify is anything other than true. This run exited 0. The file has five runs and 68 series in each run.
5. **Spread.** Host p50 spread on the 8192, 65536, and 524288 byte canonicalize rows is at most 3.0%. Native p50 spread on the 8192 byte canonicalize row is 10%. p95 spread on several vector rows is wider than 15% of the median p95, and the command printed `unstable` for those rows. A gap smaller than that spread is not a difference.
6. **Does it matter.** These calls are the public API. This repository has no surrounding server request. The number is the call the host waits on.
7. **Did the work happen.** Samples were kept only after the probe matched. `emit-repro.ts` observed a canonical string of 524306 UTF-8 bytes and `text === canonicalJson(tree)`. Verify rows in the file are `true` on every implementation, including `rust_native`.

Cells this run does not explain.

- Vector p95 values that printed `unstable`. Those samples are a few microseconds, and the spread is the same size as the clock plus a runtime tail. Read p50 there, and treat even that p50 as the call plus the timer.
- `canonical_json` p95 at 524288 bytes for TypeScript (39.6 ms against a 26.4 ms p50). Each run has 80 samples, so the command does not print `unstable`. p50 spread on that row is 1.8%. Quote the p50.
- Host `stable_hash` minus host `canonical_json` on the 524288 byte tree is smaller than the p95 spread, so the extra hash is not visible on the host rows. It is visible on the native row. Native `stable_hash` p50 is 1.60 ms and native `canonical_json` p50 is 1.27 ms, both with p50 spread under 3%. That 0.33 ms is one SHA-256 of the canonical bytes. Do not add the two host rows.

Cross-side p50 order that this file's spreads support, because the per-run p50 ranges do not overlap:

- `canonical_json` at 8192 and 65536 bytes: TypeScript, then Node, then Python. Native sits below all three.
- `canonical_json` at 524288 bytes: Node, then Python, then TypeScript. Native sits below all three.
- `compare_authority_contracts` at 4096 and 32768 bytes: native, then TypeScript, then Python, then Node. The 32768-byte pair is the many-identifier subset walk. Python at 32768 bytes is 2.50 ms. Native is 0.699 ms. Those ranges do not overlap.
