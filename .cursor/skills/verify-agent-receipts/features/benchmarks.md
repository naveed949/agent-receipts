# Benchmarks

There is no benchmark suite in this checkout. Timing `canonical_json` by hand is not a product surface.

## Sub-features

- `bench-absent` confirms there is no `benches/` directory and no `[[bench]]` target in the crate manifests.

## How to get to it (user POV)

- There is no user entry point. README documents `cargo test`, maturin, and npm test only.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run. Doctor does not make this feature exist.

- **Record absence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `benchmarks` row is `NOT_IMPLEMENTED` with `no benches on this checkout`.
- **Stale skill.** If `benches/` or `[[bench]]` exists, the row is `FAIL` because the skill does not drive those targets. It is still not `PASS`.
- **Proof.** The summary table shows `NOT_IMPLEMENTED` or `FAIL`. Never `PASS`.

## Gotchas

- A `benchmarks` string inside `bindings/node/package-lock.json` is an npm package metadata field. It is not this feature.
- Do not add a bench target in the skill to obtain a pass.
