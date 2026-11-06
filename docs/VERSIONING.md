# Versioning

This page is the compatibility contract for `agent-receipts`. The Rust crate, the Python module, and the Node module share one workspace version in `Cargo.toml`, `bindings/python/pyproject.toml`, and `bindings/node/package.json`. A release bumps all three to the same number. This repository does not publish to crates.io, PyPI, or npm. The numbers still apply to source tags and to anyone who vendors a checkout.

`0.y.z` uses the same major, minor, and patch meanings as `1.y.z`. A breaking change increments the minor while the major stays `0`. The first stable tag is `1.0.0`. After `1.0.0`, a breaking change increments the major.

## Public API

### Rust crate `agent-receipts`

Public items are the types, constants, and functions reachable from `crates/core/src/lib.rs`. Private modules are not part of the API even when they contain `pub` items.

Types: `Receipt`, `Error`, `Wtf16`, `Json`, `SignerError`, `SigningKey`, `AuthorityError`, `AuthorityPath`, `CompareResult`, `Relationship`.

Constants: `MAX_DEPTH`, `AUDIT_RECEIPT_VERSION`, `AUDIT_RECEIPT_V2_VERSION`, `CONTROLLED_INTEGRITY_VERSION`.

Functions: `check_depth`, `canonical_json`, `stable_hash`, `canonical_json_value`, `stable_hash_value`, `compare_authority_contracts`, `compare_authority_contracts_bytes`, `is_https_authority_subset`, `is_https_authority_subset_bytes`, `normalize_authority_policy`, `normalize_authority_policy_bytes`, `normalize_https_authority_rules`, `normalize_https_authority_rules_bytes`, `audit_signing_key`, `controlled_signing_key`, `resign_audit_receipt`, `resign_audit_receipt_bytes`, `sign_controlled_integrity`, `sign_controlled_integrity_bytes`, `verify_audit_receipt`, `verify_audit_receipt_bytes`, `verify_controlled_integrity`, `verify_controlled_integrity_bytes`, `audit_mac_input_ascii`.

Public methods: `Error::code`, `Wtf16::from_units`, `Wtf16::from_str`, `Wtf16::units`, `Json::null`, `Json::bool`, `Json::number`, `Json::string`, `Json::array`, `Json::object`, `SignerError::code`, `SigningKey::utf8`, `AuthorityError::code`, `AuthorityPath::as_str`, `Relationship::as_str`.

Feature `stream` also exports `DEFAULT_STREAM_CAPACITY` (`32`), `DEFAULT_MAX_LINE_LEN` (`1048576`), `StreamLimits`, `LimitsError`, `AuditReceiptCounts`, and `verify_audit_receipt_lines`. Those names are absent unless the crate is built with `--features stream`. `LimitsError` is `ZeroCapacity` or `ZeroMaxLineLen`. It is not `Error`, and it has no `.code()`. `StreamLimits::with_capacity`, `StreamLimits::with_max_line_len`, `StreamLimits::capacity`, `StreamLimits::max_line_len`, `StreamLimits::max_retained_line_bytes`, and `AuditReceiptCounts::lines` are public. `verify_audit_receipt_lines` takes `tokio::io::AsyncRead + Unpin`, a key, and `StreamLimits`, and returns `Result<AuditReceiptCounts, std::io::Error>`. `crates/core/tests/public_api.rs` pins those items in `stream_public_items_are_pinned`, which runs under `cargo test -p agent-receipts --features stream`.

`AuthorityPath::ALL` is public. Enums are exhaustive. `Receipt` has a private field and no constructor. `Json` variants are private.

`crates/core/tests/public_api.rs` names every public function signature and every public enum variant. A changed signature or a new variant fails that test at compile time. The same file asserts the sha256 of the committed `vectors/reference/vectors.json`.

### Python module `agent_receipts`

Exported functions: `canonical_json`, `stable_hash`, `verify_audit_receipt`, `resign_audit_receipt`, `verify_controlled_integrity`, `sign_controlled_integrity`, `audit_signing_key`, `controlled_signing_key`, `compare_authority_contracts`, `normalize_authority_policy`, `normalize_https_authority_rules`, `is_https_authority_subset`, `verify_stream`.

Exported constants: `AUDIT_RECEIPT_VERSION`, `AUDIT_RECEIPT_V2_VERSION`, `CONTROLLED_INTEGRITY_VERSION`.

Exported exception: `CanonicalizeError`.

Every parameter on those functions is positional-or-keyword and has no default, except `verify_stream`. `verify_stream(path, key, *, capacity=32, max_line_len=1048576)` takes `path` and `key` as required positional-or-keyword arguments. `capacity` and `max_line_len` are keyword-only. Their defaults are `DEFAULT_STREAM_CAPACITY` and `DEFAULT_MAX_LINE_LEN`. The await returns a dict whose keys are exactly `ok`, `invalid`, and `malformed`. `malformed` is a JSON parse failure or a framing reject. `invalid` is a JSON value whose MAC or linkage check fails, including a signed receipt with an extra top-level field. Empty and whitespace-only lines are `malformed`. `AuditReceiptCounts::lines` is `ok + invalid + malformed`. `bindings/python/tests/test_public_api.py` asserts the exported names, that parameter rule, the compare result keys, and the host `.code` strings in [Error codes](#error-codes).

### Node module `agent-receipts`

Exported functions: `canonicalJson`, `stableHash`, `verifyAuditReceipt`, `resignAuditReceipt`, `verifyControlledIntegrity`, `signControlledIntegrity`, `auditSigningKey`, `controlledSigningKey`, `compareAuthorityContracts`, `normalizeAuthorityPolicy`, `normalizeHttpsAuthorityRules`, `isHttpsAuthoritySubset`.

Exported constants: `AUDIT_RECEIPT_VERSION`, `AUDIT_RECEIPT_V2_VERSION`, `CONTROLLED_INTEGRITY_VERSION`.

`bindings/node/test/public_api.test.cjs` asserts the export names, the required parameter names in generated `index.d.ts`, the compare result keys, a deep freeze of the compare result and both normalize results, and the host `.code` strings in [Error codes](#error-codes). `index.d.ts` is napi build output. It is gitignored. The test reads it after `npm run build` and compares required parameter names in order.

### Result objects

`compare_authority_contracts` returns an object whose keys are exactly `relationship`, `widened`, and `narrowed`. `widened` and `narrowed` are lists of path strings.

Node freezes that object, those lists, the `normalizeAuthorityPolicy` result, and the `normalizeHttpsAuthorityRules` result. The freeze includes nested objects and arrays. Python returns a dict and lists.

### Error codes

`Error::code` returns `not_utf8`, `invalid_json`, `too_deep`, `cycle`, or `type_error`.

Python `canonical_json` and `stable_hash` copy that string onto `CanonicalizeError.code`.

- `object()` is `type_error`.
- `b"\xff"` is `not_utf8`.
- `b"{"` is `invalid_json`.
- 129 nested lists are `too_deep`.
- A list that contains itself is `cycle`.

Node `canonicalJson` and `stableHash` copy `type_error`, `too_deep`, and `cycle` onto `error.code`. `undefined` is `type_error`. A `Buffer` is `type_error`. 129 nested arrays are `too_deep`. An object that points at itself is `cycle`. Node `canonicalJson` has no bytes parameter. `not_utf8` and `invalid_json` are Rust and Python bytes-path codes.

`AuthorityError::code` returns `invalid_input`, `not_an_object`, `cross_version`, `unsupported_version`, `unknown_field`, `https_in_v1`, `outbound_in_v2`, `invalid_scope`, `invalid_flag`, `invalid_https_host`, `invalid_https_port`, `invalid_https_method`, `invalid_https_bounds`, or `invalid_https_shape`.

`invalid_input` is a Rust-only code. `compare_authority_contracts_bytes` returns it for JSON text with a duplicate key. Python and Node authority functions take objects, so a host call does not return `invalid_input`.

Both hosts raise `TypeError` and set `.code` to the strings below when the inputs are objects. The host tests use the same objects as `vectors/reference/vectors.json` `cmp-rejections` and the tests in `crates/core/src/authority.rs`.

- `not_an_object`
- `cross_version`
- `unsupported_version`
- `unknown_field`
- `https_in_v1`
- `outbound_in_v2`
- `invalid_scope`
- `invalid_flag`
- `invalid_https_host`
- `invalid_https_port`
- `invalid_https_method`
- `invalid_https_bounds`
- `invalid_https_shape`

`compare_authority_contracts(datetime, {})` in Python and `compareAuthorityContracts(Date, {})` in Node raise `TypeError` with `.code` `type_error`. That string is `Error::code` from host conversion.

`SignerError::code` returns `short_audit_key`, `short_controlled_key`, `invalid_key_id`, or `type_error`. `short_audit_key`, `short_controlled_key`, and `invalid_key_id` are Rust-only `.code` strings.

Python `audit_signing_key` on a short key raises `TypeError` with message `audit signingKey must contain at least 16 bytes`. Python `controlled_signing_key` on a 15-byte key raises `ValueError` with message `controlled integrity signing key must contain at least 16 bytes`. Python `sign_controlled_integrity` with an empty key id raises `ValueError` with message `invalid key id`. Those exceptions leave `.code` unset.

Node `auditSigningKey` on a short key raises `Error` with `.code` `TypeError` and message `audit signingKey must contain at least 16 bytes`. Node `controlledSigningKey` on a 15-byte key raises `Error` with `.code` `RangeError` and message `controlled integrity signing key must contain at least 16 bytes`. Node `signControlledIntegrity` with an empty key id raises `Error` with `.code` `TypeError` and message `invalid key id`. Those `.code` values are the napi status strings `TypeError` and `RangeError`. The two length messages are the messages in `vectors/reference/vectors.json` under `hmac-key-encoding-and-length`.

### Canonical bytes, stableHash, and MAC input

`canonical_json` output and `stable_hash` output are public. Any change to those bytes is a major change, including a change that only appears on one language binding.

HMAC-SHA256 covers the 64 ASCII hex characters of `stable_hash` of the MAC document. Any change to that MAC input is a major change. It is a major change even when `canonical_json` of an ordinary document stays the same.

### Vector format

`vectors/reference/vectors.json` declares format `agent-receipts semantic vectors v1`. The file is generated. A change to the format name, to a required field, or to an expected `canonicalUtf8Hex` or `stableHash` value is a major change. `vectors/text` cases are part of the same byte contract for Rust and Python.

Byte stability of the committed file is guarded by that file and by the sha256 pin in `crates/core/tests/public_api.rs`. The pin is `70507a2b636c05bf9841cb99921ff91908cd5e2ab7e270b14802f32727bbb7c1`. The workspace version stays `0.0.0` until a release.

## Major, minor, and patch

### Major

- Remove or rename a public item.
- Change a public function signature, a public field, or a public enum variant.
- Add a variant to a public exhaustive enum.
- Change a documented `.code` string.
- Change canonical bytes, `stableHash` output, or MAC input.
- Change the vector format or a required expected field.
- Raise the minimum Rust version, CPython version, or Node major version in a way that rejects a previously supported toolchain.
- Remove a deprecated item after its window.

A host-only break (Python or Node) is still a major on the shared version.

### Minor

- Add a public item without changing existing signatures or output.
- Widen an accepted input in a backward-compatible way.
- Add a deprecation mark on an existing item and keep the item.
- Add a vector row that does not change existing expected bytes.

### Patch

- Fix a crash, a panic, or a wrong error path that does not change successful canonical bytes, `stableHash`, or MAC input.
- Documentation, tests, and CI-only changes.

A bug fix that changes canonical bytes or MAC input is a major, not a patch.

## Deprecation

Keep a deprecated item through at least one minor release after the mark lands. Remove it only on a major.

- Rust: `#[deprecated(since = "...", note = "...")]` on the public item.
- Python: `warnings.warn(..., DeprecationWarning, stacklevel=2)` on the exported function.
- Node: `process.emitWarning(..., "DeprecationWarning")` on the exported function.

Do not remove the item in the same release that adds the mark.

## Version mapping

`[workspace.package].version` is the product version. The Python project version and the Node package version must equal that string. A Rust-only addition, a Python-only export, or a Node-only export still bumps the shared version. Bindings do not carry a private compatibility number.

`publish = false` stays set. A version bump is a git tag and a changelog fact, not a registry publish.
