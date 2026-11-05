# Authority-contract comparison

`compare_authority_contracts` tells whether one authority policy grants more, less, both, or the same capabilities as another. Python uses the same snake_case names. Node uses `compareAuthorityContracts`.

Both inputs are parsed into a typed policy first. Any invalid or ambiguous field is an error. The function never returns a silent pass on bad input, and it does not panic.

The helpers `normalize_authority_policy`, `normalize_https_authority_rules`, and `is_https_authority_subset` are the same parse and subset steps. Tests call them. Comparison calls them. Python and Node call the Rust implementations. They do not reimplement the rules.

## Policy

An authority policy is a JSON object.

`version` is `"1"` or `"2"`. If the field is absent, the version is `"1"`. Any other value is an error. The two arguments must use the same version.

Known domains are `filesystem`, `network`, `git`, `environment`, `output`, and `container`. Any other top-level field is an error. Unknown fields inside a domain are an error.

A scope field is the string `"any"` or an array of identifier strings. An identifier is a non-empty string with no leading or trailing whitespace. Duplicates are dropped. Order is ignored. A boolean flag is a JSON boolean. Absent, `[]`, and `false` all mean no grant.

v1 `network` may have `outbound` as a scope. `https` on v1 is an error. v2 `network` may have `https` as an array of rules. `outbound` on v2 is an error.

A v2 HTTPS rule has exactly these eight fields:

- `protocol` must be `"https"`
- `host` must be an ASCII DNS name with at least two labels and an alphabetic TLD. The host is stored in lowercase. An IP literal, an `xn--` label, a trailing or leading dot, a wildcard, a Unicode IDN, userinfo, or a port in the host string is an error
- `port` is an integer from 1 through 65535
- `methods` is a non-empty subset of `GET HEAD POST PUT PATCH DELETE OPTIONS`
- `resolution` must be `"public-only"`
- `redirects` must be `"none"`
- `maxResponseBytes` and `timeoutMs` are positive safe integers (1 through 2^53 − 1)

During normalize, methods are sorted, exact duplicate rules are dropped, a rule covered by another rule is dropped, and the remaining rules are sorted by their canonical JSON. Empty v2 grants are omitted.

## Result

The result is:

```
{ "relationship": "widening" | "narrowing" | "mixed" | "unchanged",
  "widened": [path, ...],
  "narrowed": [path, ...] }
```

`relationship` is `mixed` when both lists are non-empty, `widening` when only `widened` is, `narrowing` when only `narrowed` is, and `unchanged` otherwise.

Both lists follow this order, never input order and never alphabetical order:

`filesystem.read`, `filesystem.sensitiveRead`, `filesystem.write`, `network.outbound`, `network.https`, `git.write`, `git.hooks`, `environment.secrets`, `environment.ambientSecrets`, `output.unrestricted`, `container.socket`

A path can appear in both lists.

## Comparison

For a scope or boolean path, equal values are unchanged. `"any"` on the next policy widens unless the previous policy is also `"any"`. `"any"` on the previous policy narrows unless the next policy is also `"any"`. Otherwise each list is a set, `true` is the set containing `"true"`, and `false` or absent is empty. Extra elements on the next side widen. Extra elements on the previous side narrow.

Identifier lists are exact strings. `"docs"` does not grant `"docs/a"`.

For `network.https`, a missing list is empty. The next side widens when its rules are not a subset of the previous rules. The previous side narrows when its rules are not a subset of the next rules.

Rule set R is a subset of C when, for every rule r in R and every method m of r, some rule c in C has the same protocol, host, port, resolution, and redirects, includes m, and has `maxResponseBytes` and `timeoutMs` at least as large as r.

Host names are compared after lowercasing. Ports are compared exactly. There is no implicit port 443.

On invalid input the host languages raise `TypeError`. The message text is not a contract. Python and Node both set `TypeError.code` to the `AuthorityError` code (`cross_version`, `invalid_input`, and the rest). JSON text with a duplicate key is `invalid_input` on the bytes entry. Diagnostic dumps must reject that text the same way and must not last-win a key.

## Why a subset check

An authority policy is a capability. Moving from a previous grant to a next grant is safe for attenuation only when every next grant was already allowed. That is a subset. Splitting one HTTPS rule into two, or merging two into one, does not change the grant if each method is still covered with at least the same bounds. Comparing JSON text, or comparing rule arrays as lists, would treat those as different policies.

Parse and normalize run before compare so case, duplicates, empty lists, and covered rules cannot hide a widening. Classic URL and host bugs live in this parse step: mixed case, a trailing dot, punycode, userinfo, and a default port that the text omitted.
