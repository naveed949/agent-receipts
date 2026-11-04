# Async streaming verifier

An async streaming verifier is not part of this checkout. `canonical_json` and `stable_hash` are synchronous and return one whole result.

## Sub-features

- `async-absent` confirms there is no `async fn` in `crates/core/src` or the bindings source that this skill searches.

## How to get to it (user POV)

- There is no user entry point. Callers pass a complete byte slice and receive a complete rewrite or error.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run. Doctor does not make this feature exist.

- **Record absence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `async-streaming-verifier` row is `NOT_IMPLEMENTED` with `no API on this checkout`.
- **Stale skill.** If those source trees contain `async fn`, the row is `FAIL` because the skill does not drive that API. It is still not `PASS`.
- **Proof.** The summary table shows `NOT_IMPLEMENTED` or `FAIL`. Never `PASS`.

## Gotchas

- A blocking canonicalize of a whole value is not streaming verification.
- Do not mark this passed because `canonical_json` returned.
