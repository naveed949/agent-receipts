#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=public-api-surface.sh
. "$SCRIPT_DIR/public-api-surface.sh"

SKILL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$SKILL_DIR/../../.." && pwd)
PROOF_DIR=${1:-/tmp/agent-receipts-public-api-proof}
mkdir -p "$PROOF_DIR"
failed=0

expect_ok() {
  local label=$1
  shift
  if "$@"; then
    printf 'PROOF %s PASS\n' "$label"
  else
    printf 'PROOF %s FAIL: predicate rejected a good log\n' "$label"
    failed=1
  fi
}

expect_fail() {
  local label=$1
  shift
  if "$@"; then
    printf 'PROOF %s FAIL: planted log was accepted\n' "$label"
    failed=1
  else
    printf 'PROOF %s PASS: planted log rejected\n' "$label"
  fi
}

printf '======== prove public api surface ========\n'

cargo_good=$PROOF_DIR/cargo-good.log
: >"$cargo_good"
while IFS= read -r name; do
  printf 'test %s ... ok\n' "$name" >>"$cargo_good"
done < <(public_api_rust_test_names "$REPO_ROOT")

py_good=$PROOF_DIR/python-good.log
py_count=0
: >"$py_good"
while IFS= read -r name; do
  printf 'bindings/python/tests/test_public_api.py::%s PASSED\n' "$name" >>"$py_good"
  py_count=$((py_count + 1))
done < <(public_api_python_test_names "$REPO_ROOT")
printf '============================== %s passed in 0.02s ==============================\n' \
  "$py_count" >>"$py_good"

node_good=$PROOF_DIR/node-good.log
cat >"$node_good" <<'EOF'
ok 1 - exported names
# tests 1
# pass 1
# fail 0
# skipped 0
EOF

expect_ok '(good)' public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_good" "$node_good"
expect_ok '(good again)' public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_good" "$node_good"

cargo_miss=$PROOF_DIR/cargo-missing-signing-key.log
grep -Fv 'test signing_key_variants_are_exhaustive ... ok' "$cargo_good" >"$cargo_miss"
printf 'note test signing_key_variants_are_exhaustive ... ok\n' >>"$cargo_miss"
expect_fail '(1) cargo missing signing_key_variants_are_exhaustive' \
  public_api_policy_ok "$REPO_ROOT" "$cargo_miss" "$py_good" "$node_good"

py_skip=$PROOF_DIR/python-skipped.log
grep -v ' passed in ' "$py_good" >"$py_skip"
printf '=========================== %s passed, 1 skipped in 0.07s ============================\n' \
  "$py_count" >>"$py_skip"
expect_fail '(2) pytest passed, skipped mentioning test_public_api.py' \
  public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_skip" "$node_good"

node_later=$PROOF_DIR/node-not-ok-later.log
cat >"$node_later" <<'EOF'
ok 1 - exported names
not ok 2 - something
# fail 0
# skipped 0
EOF
expect_fail '(3) ok exported names then not ok' \
  public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_good" "$node_later"

node_not_ok=$PROOF_DIR/node-not-ok-exported-names.log
cat >"$node_not_ok" <<'EOF'
not ok 1 - exported names
# fail 0
# skipped 0
EOF
expect_fail '(4) not ok 1 - exported names' \
  public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_good" "$node_not_ok"

node_no_fail=$PROOF_DIR/node-missing-fail-0.log
cat >"$node_no_fail" <<'EOF'
ok 1 - exported names
# skipped 0
EOF
expect_fail '(5) node log missing # fail 0' \
  public_api_policy_ok "$REPO_ROOT" "$cargo_good" "$py_good" "$node_no_fail"

if [[ $failed -ne 0 ]]; then
  printf 'RESULT=FAIL\n'
  exit 1
fi
printf 'RESULT=PASS\n'
