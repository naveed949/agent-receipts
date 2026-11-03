# Decisions

## Workspace layout

`crates/core` is the Rust library `agent-receipts`. Its only dependency is `serde_json`. `bindings/python` and `bindings/node` depend on it by path. Every package sets `publish = false`. This repository publishes nothing to crates.io, PyPI, or npm.

## Why abi3

The Python build produces one `cp39-abi3` wheel. That wheel loads on CPython 3.9 and later. The limited C API is the cost. This module only copies bytes, and the limited API can copy bytes.

## Why shared vector files

`vectors/canonicalize` is the only copy of the cases. Rust, Python, and Node tests glob that directory and compare bytes. A separate fixture file per language would drift.

## FFI ownership

`canonicalize_bytes` borrows `&[u8]` and returns a new `Vec<u8>`. Bindings copy those bytes across the language boundary. The output is a rewrite, so it cannot alias the input. A later change that releases the GIL must not borrow caller memory. Python copies the result into `bytes`. Node copies the result into a Node-owned `Buffer`.

## Provisional JSON

`canonicalize_bytes` parses and emits with `serde_json`. This emitter is provisional. RFC 8785 is a later change. Object keys sort by UTF-8 byte order, because `serde_json` stores objects in a `BTreeMap`. They do not sort by UTF-16 code units. Duplicate keys keep the last value. The number text `1e2` becomes `100.0`. These bytes are not the receipt spec.

## Receipt, HMAC, and authority

`Receipt` is a public struct with a private field and no constructor. HMAC verification and authority-contract comparison are names reserved for later changes.
