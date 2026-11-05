# Decisions

## Workspace layout

`crates/core` is the Rust library `agent-receipts`. Its dependencies are `ryu-js` 1.0.3 and `sha2` 0.10.8. Both are pinned because a later release can raise the compiler requirement. The compiler here is 1.83. `bindings/python` and `bindings/node` depend on the core by path. Every package sets `publish = false`. This repository publishes nothing to crates.io, PyPI, or npm.

## Why one abi3 wheel

The Python build produces one `cp39-abi3` wheel. That wheel loads on CPython 3.9 and later. The limited C API is the cost. The module copies a host value into an owned tree, and it copies `bytes` or `bytearray` when the caller passes a document. The limited API can do both.

## Two vector directories

`vectors/reference/vectors.json` is the file produced by the reference implementation. It is stored as generated. The file has 23 rows. Eight rows have kind `canonicalize` and must match `canonicalUtf8Hex` and `stableHash`. Eight HMAC and linkage rows run in Rust, Python, and Node. Seven rows have kind `compareAuthorityContracts` and run in Rust, Python, and Node. `vectors/reference/pending-kinds.txt` is empty.

`vectors/text` holds byte-level cases. Invalid UTF-8, duplicate keys, and a second pass over canonical bytes still belong there. Node does not read that directory. A JavaScript value cannot represent those byte strings, and Node has no bytes entry.

Compare `canonicalUtf8Hex` and `stableHash`. The escaping row contains a lone surrogate, and an ordinary string comparison can change `expected.canonical`.

## Four fail-closed defaults

Duplicate keys in JSON text are rejected, including keys that match only after a `\u` escape is decoded. The reference parser keeps the last value. This crate rejects the document.

A cycle is rejected. Nesting deeper than 128 containers is rejected. The reference implementation has no cap and overflows on a cycle. 128 is a resource limit. The walk uses a heap vector. `check_depth(128)` succeeds and `check_depth(129)` returns `too_deep`. Only containers count, including the outermost one.

Host values that are not JSON data are rejected with `type_error`. Node rejects `undefined`, a function, a symbol, a bigint, a `Date`, a `Map`, a `Set`, a class instance, a sparse array, an extra named array property, a non-enumerable own property, an own symbol key, a buffer, a typed array, a `DataView`, and an `ArrayBuffer`. Node also rejects every `Proxy`, including a transparent proxy of a dense array and a proxy of a plain object. `util.types.isProxy` is the test. A proxy is not JSON data, even when its target would have been accepted. Python rejects a `tuple`, a `set`, a `datetime`, a `memoryview`, any subclass, and an `int` that is not an exact finite float. A host NaN or infinity is `type_error`. The same non-finite spellings in JSON text are `invalid_json`. One predicate, two boundaries.

The host walk classifies the value before it counts depth. A `Date`, `Map`, buffer, or class instance inside 128 arrays is `type_error`. A string inside 128 arrays succeeds. 128 nested plain objects succeed. 129 nested containers are `too_deep`.

Underflow and precision follow the reference. Text is parsed as an IEEE-754 binary64 value before it is printed. `9007199254740993` becomes `9007199254740992`. A magnitude that underflows becomes `0`. Negative zero becomes `0`.

## Why the tree stores UTF-16

Object key order is defined on UTF-16 code units, and a lone surrogate is one unit of data. A Rust `str` cannot store that unit. UTF-8 byte order is a different order. The emoji U+1F600 is the units U+D83D and U+DE00. U+D83D sorts before U+FFFF. The UTF-8 bytes of that emoji sort after U+FFFF. The tree stores the units, so the sort and the escape walk read them directly.

`Json::object` sorts with that order and rejects a duplicate key. The emitter writes the stored order.

## Why numbers use the ECMAScript conversion

The reference implementation prints numbers with the ECMAScript Number-to-String algorithm. `1e2` prints as `100`. `1e21` prints as `1e+21`. `5e-324` stays a denormal. Negative zero prints as `0`. The formatter is `ryu-js` `format_finite`. The older emitter printed `1e2` as `100.0` and sorted keys as UTF-8 bytes. Both results disagree with the reference file.

A JSON number is a binary64 value first. That is why an integer above the 53-bit exact range rounds in text. A Python `int` is accepted only when `int(float(n))` is `n` and the float is finite. Otherwise the call returns `type_error`. Callers who want the text rule pass `bytes`.

## Canonical JSON, JCS, and CBOR

JCS (RFC 8785) also prints numbers with the ECMAScript conversion and sorts object members by UTF-16 code units. JCS sorts every key by code units alone. In JCS, `10` sorts before `2` because the code unit `1` is less than `2`. Here `2` sorts before `10` because both keys are indexes and 2 is less than 10. This crate also rejects a duplicate key, a cycle, and more than 128 nested containers. JCS leaves the depth unbounded.

CBOR canonicalization is a binary encoding. Map keys sort by their encoded bytes. Integers and floats are different types, and the preferred integer encoding is a different rule from Number-to-String. The output is CBOR bytes.

## What crosses the language boundary

Python and Node copy host data into an owned tree before the core call. Python copies `bytes` and `bytearray` into a `Vec<u8>`. A Python `str` is encoded with UTF-16 and the `surrogatepass` error handler, so a lone surrogate stays one `u16`. Node copies a string with `napi_get_value_string_utf16`, which keeps a lone surrogate.

The owned tree is what makes a later GIL release safe. Python drops the GIL around the core call only after that copy. The canonical bytes are decoded as UTF-8 at the boundary. They are UTF-8 by construction, because a lone surrogate is escaped. If they are not, the binding returns `invalid_json` instead of panicking.

Node returns a string from `canonicalJson` and `stableHash`. A buffer is `type_error`. Text that is not valid UTF-8, and text with duplicate keys, stays on the Rust and Python bytes entry.

## Receipt

`Receipt` is a public struct with a private field and no constructor. An async streaming verifier stays reserved. HMAC verification and authority-contract comparison are part of this API.

## 2026-11-05 HMAC verification

HMAC-SHA256 is the only integrity algorithm. The core crate uses `hmac` 0.12.1, pinned the same way as `sha2`, and compares tags with `verify_slice`. That path is constant time. A byte-by-byte `==` on the hex string is not.

The audit MAC is a double hash. `stable_hash` of the MAC document is 64 ASCII hex characters. HMAC then covers those 64 bytes, not the raw SHA-256 digest and not the canonical JSON. Signing the hex string keeps the MAC input a fixed-width public encoding. HMAC-SHA256 is not SHA-256, so length-extension of the inner hash does not forge a tag.

This revision binds `integrity.algorithm` and `integrity.keyId` into the MAC. The document is the receipt with only `integrity.signature` removed. The earlier construction removed the whole `integrity` object, so a verifier could not tell a swapped key label or a swapped algorithm from the original receipt. That is a key-substitution attack and an algorithm-confusion attack. Receipts issued under the earlier preimage fail `verify_audit_receipt` until `resign_audit_receipt` restamps them with the same key. The restamp is a breaking change for stored receipts. It is not a change to `canonical_json` or `stable_hash`.

Artifact hashes are rechecked for v1 and v2. A v1 receipt whose `artifacts.*.hash` does not match `stable_hash(value)` is false even when the MAC is valid.

Audit signer length is measured in host units: UTF-16 code units for a string, bytes for a byte array. Controlled-integrity signer length is measured in UTF-8 bytes. Eight `é` characters fail the audit constructor and pass the controlled constructor. Verify accepts a five-character key. The split is what the reference does. This crate does not invent a single rule.

Bindings copy the key into owned bytes, then call Rust. Python and Node do not implement HMAC. After `resign_audit_receipt` returns a `Json` tree, each binding emits canonical JSON and lets the host parser rebuild a value, because the inspectors on `Json` are crate-private.

## 2026-11-05 Authority-contract comparison

Comparison runs on a typed policy, not on JSON text. `Json` is parsed once at the crate boundary into `AuthorityPolicy`. `Relationship`, `AuthorityPath`, and `AuthorityError` are exhaustive enums. Host strings (`"widening"`, `"filesystem.read"`) are derived from those enums. The eleven paths live in `AuthorityPath::ALL`. That array is the order of `widened` and `narrowed`.

v1 cannot hold `network.https`. v2 cannot hold `network.outbound`. Cross-version compare is `CrossVersion`, not a path-by-path walk that would mix HTTPS with outbound.

HTTPS subset is per method with bounds. Protocol, host, port, resolution, and redirects must match. The covering rule must include the method and must have `maxResponseBytes` and `timeoutMs` at least as large. The fields stay on `HttpsRule` so a test can build two rules that differ in one field and prove that deleting that check fails. Parse still rejects every value except `https`, `public-only`, and `none`.

Fail-closed choices the reference file does not pin:

- A trailing-dot host (`example.com.`) is rejected. It is not folded into the undotted name.
- An empty DNS label (`a..b.com`) is rejected. `is_ldh` treats an empty label as false so a missing empty-label guard cannot panic.
- A wildcard host (`*.example.com`) is rejected.
- A Unicode IDN host is rejected. `xn--` labels are rejected.
- `protocol`, `resolution`, and `redirects` must be the fixed strings `https`, `public-only`, and `none`. Any other value is `InvalidHttpsShape`, not a comparable grant.
- Identifier scopes are exact strings. `"docs"` does not grant `"docs/a"`.
- Ports compare exactly. There is no implicit 443.
- `userinfo` is not a field. `@` in the host is an invalid host.
- `is_https_authority_subset` on invalid rules is an error, not `false`.
- A non-object policy is `NotAnObject`.
- Bound fields must be positive safe integers.

Bindings copy host values into `Json`, call Rust, and map `AuthorityError` to `TypeError`. Host conversion failures on the authority APIs are also `TypeError`, not the canonicalize exception. Node throws a real `TypeError` (`napi_create_type_error`). Both hosts set `TypeError.code` to the `AuthorityError` code, so `err.code` is `cross_version` rather than the string `"TypeError"`. They do not reimplement subset or validation. Node freezes the compare result and the normalize results. `network.https: false` is an invalid shape, not an empty grant.

The verify dump helpers are diagnostic, but they sit on the same JSON text as `compare_authority_contracts_bytes`. A last-win parse of a duplicate `filesystem.read` can report `unchanged` or `narrowing` while the bytes API returns `invalid_input`. The dumps reject duplicate keys in the input text and print `err invalid_input`. The Rust dump extracts the `previous` and `next` value spans and passes those raw bytes to `compare_authority_contracts_bytes`. It does not round-trip through `serde_json`. Node has no public bytes entry. The dump parser rejects duplicate keys in process and still calls `compareAuthorityContracts` on host objects.

Python and Node round-trip a normalized policy through canonical JSON because `Json` inspectors stay crate-private. The compare result is built from the typed `CompareResult`, not from a JSON round-trip of the policies.

## 2026-11-05 Key material lifetime

The core does not depend on `zeroize`. `audit_signing_key` and `controlled_signing_key` return `&[u8]` borrowed from the caller's buffer. Bindings copy the host key into an owned `Vec<u8>`, check the length, and hand a Python `bytes` or Node `Buffer` back to the caller. Nothing overwrites those bytes on drop. Dropping a `Vec<u8>` is not a wipe. Host-side copies stay until the language runtime reclaims them. Adding `zeroize` on the Rust `Vec` would still leave the Python and Node copies intact, so this revision documents the limit rather than adding a crate that cannot cover the host.

## 2026-11-05 Signer length split

The two constructors use different units. That is the reference rule, not a cryptographic claim.

- Audit signer: a string is measured in UTF-16 code units; a byte array is measured in bytes. Either value below 16 is `ShortAuditKey`. Eight `é` characters are 8 UTF-16 units and 16 UTF-8 bytes, so the audit constructor rejects them. Verify has no floor: a five-character key that signed a receipt still verifies that receipt.
- Controlled-integrity signer: always measured in UTF-8 bytes of the key material HMAC will use. Below 16 is `ShortControlledKey`. The same eight `é` characters pass. A 15-byte array fails.

HMAC-SHA256 consumes the UTF-8 bytes. UTF-16 length is a host-string accident. Keep the split until one unit is chosen. If the constructors are unified later, 16 UTF-8 bytes is the unit that matches the MAC.

## 2026-11-05 SemVer pins and one abi3 wheel

A stored `stableHash` or HMAC tag is a promise about bytes. Changing those bytes, or the 64 ASCII hex characters HMAC covers, is a major change even when the function names stay the same. `docs/VERSIONING.md` is the reference. `0.y.z` uses the same meanings as `1.y.z` and increments the minor for a break until `1.0.0`.

The three packages share `[workspace.package].version`. A host-only export still bumps that number. Bindings do not keep a private compatibility series.

`cargo-semver-checks` wants a published crates.io baseline. This crate is `publish = false` and `0.0.0`, so that tool has nothing to diff. `cargo public-api` wants rustdoc JSON. That dump is unstable on the pinned 1.83 toolchain. The pin is `crates/core/tests/public_api.rs`: each public function is assigned to a function pointer with the exact type, and each public enum is matched exhaustively. A renamed argument or a new variant fails at `rustc`. Python uses `inspect.signature` and the exported name set. Node uses `Object.keys` and `error.code`. Those tests need no extra binary. Adding a public item does not fail the Rust compile test until someone adds a pointer. That miss is a missed minor, not a missed major.

One `cp39-abi3` wheel is the product. Per-CPython wheels would rebuild the same limited-API module for 3.9, 3.10, 3.11, 3.12, and 3.13. The binding copies host values into an owned tree. The limited API can do that copy. The cost is the limited API, not a missing opcode. CI builds that wheel on `ubuntu-24.04` and `ubuntu-24.04-arm`, uploads `agent-receipts-cp39-abi3-${{ runner.arch }}`, then installs it into a clean venv on CPython 3.9 and again on 3.13. Those images still ship CPython 3.9 through `actions/setup-python`. `ubuntu-latest` is Ubuntu 26.04, which has no 3.9 build. Those two minors are the declared floor and a current CPython. The same pytest suite, including the shared vectors, runs in each venv. There is no PyPI upload.
