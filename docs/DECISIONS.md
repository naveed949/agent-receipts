# Decisions

## Workspace layout

`crates/core` is the Rust library `agent-receipts`. Its dependencies are `ryu-js` 1.0.3 and `sha2` 0.10.8. Both are pinned because a later release can raise the compiler requirement. The compiler here is 1.83. `bindings/python` and `bindings/node` depend on the core by path. Every package sets `publish = false`. This repository publishes nothing to crates.io, PyPI, or npm.

## Why one abi3 wheel

The Python build produces one `cp39-abi3` wheel. That wheel loads on CPython 3.9 and later. The limited C API is the cost. The module copies a host value into an owned tree, and it copies `bytes` or `bytearray` when the caller passes a document. The limited API can do both.

## Two vector directories

`vectors/reference/vectors.json` is the file produced by the reference implementation. It is stored as generated. Eight rows have kind `canonicalize` and must match `canonicalUtf8Hex` and `stableHash`. The other rows are listed once each in `vectors/reference/pending-kinds.txt`. Runners print those rows and count them. Those kinds stay unimplemented.

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

`Receipt` is a public struct with a private field and no constructor. HMAC verification, authority-contract comparison, and an async streaming verifier are names reserved for later changes. They are not part of this API.
