#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=benchmarks-surface.sh
. "$SCRIPT_DIR/benchmarks-surface.sh"

PROOF_DIR=${1:-/tmp/agent-receipts-bench-proof}
mkdir -p "$PROOF_DIR"
failed=0

printf '======== prove benchmarks surface ========\n'

bare=$PROOF_DIR/bare.log
printf '%s\n' 'hmac 8 ok' 'canonicalize 8 ok' 'compare 7 ok' >"$bare"
if benchmarks_log_ok "$bare"; then
  printf 'PROOF (a) FAIL: unprefixed lines were accepted\n'
  failed=1
else
  printf 'PROOF (a) PASS: unprefixed lines rejected\n'
fi

good=$PROOF_DIR/good.log
printf '%s\n' 'ts-baseline canonicalize 8 ok' 'ts-baseline hmac 8 ok' 'ts-baseline compare 7 ok' >"$good"
if benchmarks_log_ok "$good"; then
  printf 'PROOF (b) PASS: prefixed lines accepted\n'
else
  printf 'PROOF (b) FAIL: prefixed lines rejected\n'
  failed=1
fi

missing=$PROOF_DIR/missing.log
printf '%s\n' 'ts-baseline canonicalize 8 ok' 'ts-baseline hmac 8 ok' >"$missing"
if benchmarks_log_ok "$missing"; then
  printf 'PROOF (c) FAIL: log missing compare was accepted\n'
  failed=1
else
  printf 'PROOF (c) PASS: incomplete log rejected\n'
fi

SKILL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$SKILL_DIR/../../.." && pwd)
if benchmarks_entry_present "$REPO_ROOT"; then
  printf 'PROOF (d) PASS: bench/run is present\n'
else
  printf 'PROOF (d) FAIL: bench/run missing on this checkout\n'
  failed=1
fi

empty=$PROOF_DIR/empty-root
mkdir -p "$empty"
if benchmarks_entry_present "$empty"; then
  printf 'PROOF (e) FAIL: empty root reported an entry\n'
  failed=1
else
  printf 'PROOF (e) PASS: missing bench/run is not present\n'
fi

if benchmarks_tripwire_reason "$REPO_ROOT" >/dev/null; then
  printf 'PROOF (f) FAIL: this checkout tripped the bench tripwire\n'
  failed=1
else
  printf 'PROOF (f) PASS: crates and bindings have no Cargo bench target\n'
fi

fake=$PROOF_DIR/fake-root
rm -rf "$fake"
mkdir -p "$fake/benches" "$fake/crates" "$fake/bindings"
reason=$(benchmarks_tripwire_reason "$fake")
if [[ "$reason" == "benches/ exists; this skill does not drive it. Do not mark passed." ]]; then
  printf 'PROOF (g) PASS: benches/ tripwire\n'
else
  printf 'PROOF (g) FAIL: benches/ reason was %s\n' "$reason"
  failed=1
fi

manifest=$PROOF_DIR/manifest-root
rm -rf "$manifest"
mkdir -p "$manifest/crates/core" "$manifest/bindings"
printf '%s\n' '[[bench]]' 'name = "canon"' >"$manifest/crates/core/Cargo.toml"
reason=$(benchmarks_tripwire_reason "$manifest")
if [[ "$reason" == "[[bench]] exists; this skill does not drive it. Do not mark passed." ]]; then
  printf 'PROOF (h) PASS: bench table tripwire\n'
else
  printf 'PROOF (h) FAIL: bench table reason was %s\n' "$reason"
  failed=1
fi

parse_proof=$PROOF_DIR/parse-repro
if ! node --experimental-strip-types --disable-warning=ExperimentalWarning "$REPO_ROOT/bench/parse-repro.ts" "$parse_proof"; then
  printf 'PROOF (i) FAIL: parse-repro did not reject zeros, fake sha, smoke-shaped full.json, or a constant-42 full clone\n'
  failed=1
else
  printf 'PROOF (i) PASS: parse rejects zeros, fake sha, smoke-named full.json, full-mode smoke effort, and a constant-42 full clone\n'
fi

if [[ $failed -ne 0 ]]; then
  printf 'RESULT=FAIL\n'
  exit 1
fi
printf 'RESULT=PASS\n'
