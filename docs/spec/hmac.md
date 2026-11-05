# HMAC integrity

This crate verifies two HMAC-SHA256 schemes. Both write a 64-character lowercase hex tag. Both compare the decoded 32-byte tag in constant time. Verify returns a boolean and never raises.

The key is supplied by the caller. A receipt stores only a key identifier. A string key is UTF-8 encoded. The UTF-8 bytes of that string are interchangeable with a byte-array key.

A signer constructor enforces a minimum length. Verify does not. An audit signer measures a string in UTF-16 code units and a byte array in bytes, so eight `é` characters fail. A controlled-integrity signer measures UTF-8 bytes, so the same string passes. That split is inherited from the reference and is recorded in [Decisions](../DECISIONS.md).

## Audit receipts

`verify_audit_receipt` returns true only when every step below succeeds. Any other input is false.

1. `version` is `adaptive-sandbox.audit-receipt/v1` or `adaptive-sandbox.audit-receipt/v2`.
2. `integrity.algorithm` is `hmac-sha256`.
3. `integrity.keyId` is a non-empty string with no leading or trailing whitespace.
4. `integrity.signature` matches `^[a-f0-9]{64}$`. Uppercase hex is false.
5. The MAC document is the receipt with only `integrity.signature` removed. `integrity.algorithm`, `integrity.keyId`, and every other field stay in the document.
6. `stable_hash` of that document is 64 lowercase hex characters. The MAC input is those 64 ASCII bytes, not the raw digest and not the canonical JSON.
7. HMAC-SHA256 of that ASCII string under the caller key matches the offered tag.
8. Every `artifacts` entry is an object whose `hash` equals `stable_hash(value)`. This check runs for v1 and v2.
9. Version linkage holds. A correctly tagged receipt can still fail here.

`resign_audit_receipt` writes a new `integrity.signature` under the current preimage and the same key. It does not change any other field. A receipt that already uses this preimage restamps to the same tag. A receipt issued under the earlier preimage, which hashed the receipt with the whole `integrity` object removed, verifies as false until it is restamped.

Rust names: `verify_audit_receipt`, `resign_audit_receipt`. Python: `verify_audit_receipt`, `resign_audit_receipt`. Node: `verifyAuditReceipt`, `resignAuditReceipt`.

## Version linkage

The top-level `authorityPolicyVersion` field selects the rule set.

A v1 receipt omits that field. `version` must be the v1 tag. The receipt must not carry the top-level HTTPS-evidence field `gondolinHttps`. The plan envelope version, when present, is `1`. Granted authority, when it is an object, has version absent or `1`.

A v2 receipt has `authorityPolicyVersion`. The only accepted value is `2`. `version` must be the v2 tag. Policy, plan envelope, argument authority, backend, each policy layer, contract grants, and request actor authority must all be objects with version `2`. `plan.authorityHash` is 64 lowercase hex characters. Artifact hashes are checked again. Granted authority is absent, or it is an object with version `2` whose `stable_hash` equals the envelope hash. A denied v2 receipt has no granted authority and still verifies.

## Controlled integrity

`sign_controlled_integrity` and `verify_controlled_integrity` MAC the UTF-8 bytes of `canonical_json(value)` directly. That is a single hash, not the audit double hash.

Evidence is `{ integrityVersion, integrityKeyId, integrityDigest }`. `integrityVersion` is `controlled-integrity/v1`. `integrityKeyId` must equal the verifier's key id and match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` at sign time. The digest is 64 lowercase hex characters.

Python and Node call the Rust implementations. They do not recompute HMAC.

## Why the MAC covers `keyId` and `algorithm`

If those fields sit outside the MAC, an attacker who can swap `integrity.keyId` points a valid tag at a different key label (key substitution). Swapping `integrity.algorithm` while leaving the tag bytes in place is an algorithm-confusion move: a verifier that later grows a second algorithm could accept a tag computed under the old one. Binding both fields into the preimage makes those edits fail the tag check.

Receipts signed under the earlier preimage do not verify. Call `resign_audit_receipt` with the original key to restamp them.
