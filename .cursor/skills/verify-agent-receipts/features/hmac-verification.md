# HMAC verification

HMAC verification of a signed receipt is a reserved name. This checkout has no API that verifies an HMAC.

## Sub-features

- `hmac-absent` confirms there is no HMAC verify function in the core or bindings.
- `hmac-receipt` confirms `Receipt` still has no constructor.

## How to get to it (user POV)

- There is no user entry point. `docs/DECISIONS.md` reserves the name. `Receipt` is a public struct with a private field and no constructor.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` has been run. Doctor does not make this feature exist.

- **Record absence.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `hmac-verification` row is `NOT_IMPLEMENTED` with `no API on this checkout`.
- **Stale skill.** If source under `crates/core/src` or the bindings contains `hmac`, the row is `FAIL` because the skill does not drive that API. It is still not `PASS`.
- **Proof.** The summary table shows `NOT_IMPLEMENTED` or `FAIL`. Never `PASS`.

## Gotchas

- `Receipt` existing as an uninhabited struct is not HMAC verification.
- Do not invent a stub verifier in the skill to obtain a pass.
- A mention in `docs/DECISIONS.md` is documentation, not an API.
