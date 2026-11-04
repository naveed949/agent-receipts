# Canonical JSON

`canonical_json` returns one JSON value in the compact form below. `stable_hash` is the lowercase hex SHA-256 of those bytes, 64 characters, with no prefix. Both functions allocate a new result. A second successful call on the canonical bytes returns the same bytes.

Rust takes the JSON text as bytes. Python takes a host value, and it takes JSON text when the argument is `bytes` or `bytearray`. A Python `str` is a JSON string. Node takes a host value. A Node buffer is rejected.

## Values

The value is `null`, `true`, `false`, a finite number, a string, an array, or an object. Arrays keep element order. Objects are written in key order, which is independent of the input order.

Tokens are packed with no whitespace. The output is UTF-8. A lone surrogate is written as an escape, so every byte of the result is UTF-8.

## Objects and keys

At every object, keys that are canonical array indexes come first, in numeric order. Every other key follows, ordered by UTF-16 code units.

A canonical array index is the decimal spelling of an integer from 0 through 4294967294. It has no leading zero, except for the one-character key `0`. It has at most 10 digits. `00`, `-1`, and the empty string are ordinary strings. `4294967295` is an ordinary string because the last index is 4294967294.

`2` sorts before `10`. A non-index sorts after every index, even when its first code unit is smaller.

Duplicate keys are rejected after `\u` escapes have been turned into code units. `a` and `\u0061` are the same key.

## Numbers

A number in text is scanned as a JSON number and then parsed as an IEEE-754 binary64 value. `9007199254740993` is the value that prints as `9007199254740992`. A magnitude that cannot be represented, including an overflow such as `1e309`, is rejected. A magnitude that underflows becomes zero.

The printed form is ECMAScript's Number-to-String conversion. Integers print without a fraction. `1e2` prints as `100`. `1e21` prints as `1e+21`. Negative zero prints as `0`.

A host number follows the same print rules. A host NaN or infinity is rejected. A Python `int` is accepted only when it is an exact finite float. Text still parses as a float first, so the same digits in a JSON document round.

## Strings

A string is a sequence of UTF-16 code units. A `\u` escape adds one code unit and does not pair surrogates by itself. A high surrogate followed by a low surrogate is one scalar and is written as raw UTF-8. A surrogate that is not part of a pair is written as `\u` and four lowercase hex digits.

`"` and `\` use the short backslash form. `/` is raw. U+0008, U+000C, U+000A, U+000D, and U+0009 use `\b`, `\f`, `\n`, `\r`, and `\t`. Every other code unit below U+0020 is `\u` and four lowercase hex digits. U+007F, U+2028, and U+2029 are raw UTF-8. Every other BMP code unit is raw UTF-8 of that scalar.

An unescaped control character inside a text string is rejected. A short or non-hex `\u` escape is rejected.

## Text input

The text must be UTF-8. A byte that is not UTF-8 is rejected before the grammar is checked. A leading BOM is rejected.

Whitespace is the space, tab, line feed, and carriage return. The input must contain one value, then only whitespace. Empty input, whitespace only, and trailing junk are rejected.

## Limits

Containers nest at most 128 deep. Only containers count, including the outermost one. 128 nested containers succeed. 129 is rejected. The host walk decides the type of a value before it counts that value toward the depth limit. A rejected host type inside 128 arrays is `type_error`, not `too_deep`. A string inside 128 arrays does not count as a container.

A host container that appears again among its ancestors is rejected. A value that is shared but is not an ancestor is written twice. The tree itself cannot contain a cycle. Node rejects every `Proxy`.

## Error codes

The code string is the contract. The message text is the same code on the Python and Node errors.

| Condition | Code |
| --- | --- |
| Text is not UTF-8 | `not_utf8` |
| Grammar, trailing junk, empty input, a duplicate key, or a non-finite number in text | `invalid_json` |
| More than 128 nested containers | `too_deep` |
| A host container is its own ancestor | `cycle` |
| A host value that this format does not store, including `undefined`, a bigint, NaN, infinity, a non-exact Python int, a date, a map, a sparse array, a function, a symbol, a class instance, or any Node `Proxy` | `type_error` |
