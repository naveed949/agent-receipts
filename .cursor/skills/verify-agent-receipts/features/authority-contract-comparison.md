# Authority-contract comparison

Authority-contract comparison is a reserved name. This checkout has no API that compares an authority contract.

## Sub-features

- `authority-absent` confirms there is no authority-contract function in the core or bindings.

## How to get to it (user POV)

- There is no user entry point. `docs/DECISIONS.md` reserves the name.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run. Doctor does not make this feature exist.

- **Record absence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `authority-contract-comparison` row is `NOT_IMPLEMENTED` with `no API on this checkout`.
- **Stale skill.** If source under `crates/core/src` or the bindings contains `authority`, the row is `FAIL` because the skill does not drive that API. It is still not `PASS`.
- **Proof.** The summary table shows `NOT_IMPLEMENTED` or `FAIL`. Never `PASS`.

## Gotchas

- Do not treat a comment or decision record as a callable feature.
- Do not mark this passed because canonical JSON tests passed.
