# HMAC verification

`verify_audit_receipt` and `resign_audit_receipt` check or restamp an audit receipt. `verify_controlled_integrity` and `sign_controlled_integrity` check or write controlled-integrity evidence. Python and Node call the Rust implementations. Eight reference rows run in all three languages.

## Sub-features

- `hmac-audit-verify` returns a boolean and never raises. It covers the current MAC preimage, lowercase hex tags, artifact hashes on v1 and v2, and version linkage.
- `hmac-audit-resign` writes a new `integrity.signature` under the current preimage. A current-preimage receipt restamps to the same tag. An earlier-preimage receipt verifies only after restamp.
- `hmac-controlled` signs and verifies HMAC-SHA256 over canonical JSON bytes.
- `hmac-bindings` require the Python and Node exports to call Rust. They do not recompute HMAC.
- `hmac-vectors` requires `hmac 8 ok` from the Rust, Python, and Node reference runners, including `hmac-audit-keyid-swap`, `hmac-audit-v1-artifact-hash-mismatch`, and `hmac-audit-pre124-restamp`.

## How to get to it (user POV)

- Call `verify_audit_receipt` and `resign_audit_receipt` from Rust, or `verify_audit_receipt` and `resign_audit_receipt` from the installed Python wheel, or `verifyAuditReceipt` and `resignAuditReceipt` from the built Node addon.
- Call `verify_controlled_integrity` and `sign_controlled_integrity` (Node: `verifyControlledIntegrity`, `signControlledIntegrity`) the same way.
- Run `vectors/reference/vectors.json` through those entries. The eight HMAC and linkage rows must match.

## Driving it with verify.sh

Preconditions:

- `scripts/verify.sh doctor` prints `RESULT=PASS`.
- `vectors/reference/vectors.json` exists and has 23 rows.

- **Rust cases.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `cargo-test` row is `PASS`. `cargo-test.log` contains `test reference::reference_vectors ... ok` and `test hmac::`.
- **Python cases.** Read `python-abi3.log`. pytest exits 0 and prints a `passed` count. Pytest captures the runner's `hmac 8 ok` line; `cross-language-agreement.log` reprints it after driving the same eight rows through the installed wheel.
- **Node cases.** Read `node-napi.log`. It contains `hmac 8 ok`.
- **Proof.** The `hmac-verification` row is `PASS`. The summary table does not show `NOT_IMPLEMENTED` for this surface.

## Gotchas

- A passing canonicalize row is not this feature.
- `maturin develop` is not the Python entry. The entry is the installed `*cp39-abi3*.whl`.
- Bindings that reimplement HMAC in the host language fail this feature even if the tags match.
- Receipts signed under the earlier MAC preimage are supposed to verify as false until `resign_audit_receipt` restamps them.
- `compareAuthorityContracts` is still pending. Do not treat those seven rows as HMAC.
