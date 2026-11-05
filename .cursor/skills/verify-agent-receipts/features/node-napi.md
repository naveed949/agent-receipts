# Node napi binding

The Node binding is a napi addon built in `bindings/node` and tested with `node --test`.

## Sub-features

- `node-install` runs `npm ci` with the locked `@napi-rs/cli`.
- `node-build` runs `napi build --platform --release`.
- `node-test` runs `node --test test/*.cjs` against the built addon. `canonicalize.test.cjs` covers the reference vectors, the v1 `gondolinHttps` ban, authority-contract comparison, and host rejects. `public_api.test.cjs` pins export names and `error.code`. Neither file reads `vectors/text`.
- `node-toolchain` fails closed when Node 22 or npm is missing.

## How to get to it (user POV)

- From `bindings/node`, run `npm ci`, `npm run build`, and `npm test`.
- Run `scripts/verify.sh`, which runs those commands as the `node-napi` surface.

## Driving it with verify.sh

Preconditions:

- `node` major version is 22.
- `scripts/verify.sh doctor` prints `RESULT=PASS`.

- **Build and test.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The `node-napi` row is `PASS`. `node-napi.log` contains `npm ci`, `napi build`, and a passing `node --test`.
- **Missing tool.** If Node 22 or npm is missing, the row is `FAIL`. It is not `UNSUPPORTED` and not `PASS`.

## Gotchas

- `index.js`, `index.d.ts`, and `*.node` are generated. They are gitignored. Tests require a successful build in this tree.
- Node major versions other than 22 fail doctor. Do not relax that pin to make the surface pass.
- The tests `require("..")`, which is the built addon, not a pure JavaScript rewrite.
