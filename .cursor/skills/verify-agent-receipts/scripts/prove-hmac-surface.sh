#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=hmac-surface.sh
. "$SCRIPT_DIR/hmac-surface.sh"

PROOF_DIR=${1:-/tmp/agent-receipts-hmac-proof}
mkdir -p "$PROOF_DIR"
failed=0

printf '======== prove hmac surface ========\n'

fake=$PROOF_DIR/fake-python.log
cat >"$fake" <<'EOF'
=========================== 1 failed, 17 passed in 0.07s ============================
EOF
printf 'PROOF (a) input: %s\n' "$(cat "$fake")"
if python_log_hmac_ok "$fake"; then
  printf 'PROOF (a) FAIL: mixed pytest summary was accepted\n'
  failed=1
else
  printf 'PROOF (a) PASS: mixed summary rejected by hmac-surface.sh\n'
fi

SKILL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$SKILL_DIR/../../.." && pwd)
ALIEN=$PROOF_DIR/alien-target
rm -rf "$ALIEN"
mkdir -p "$ALIEN"
printf 'PROOF (b) inherited CARGO_TARGET_DIR=%s\n' "$ALIEN"
export CARGO_TARGET_DIR=$ALIEN
(
  cd "$REPO_ROOT"
  unset CARGO_TARGET_DIR
  export CARGO_TARGET_DIR="$REPO_ROOT/target"
  rm -f "$REPO_ROOT/target/wheels/"*cp39-abi3*.whl
  echo "+ after unset+override CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
  echo "+ maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3"
  out=$(maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3 2>&1)
  printf '%s\n' "$out"
  wheel=$(printf '%s\n' "$out" | grep -oE '/[^[:space:]]+cp39-abi3[^[:space:]]+\.whl' | tail -1)
  echo "+ wheel=$wheel"
  if [[ -z "$wheel" || ! -f "$wheel" ]]; then
    echo "PROOF (b) FAIL: no wheel from maturin output"
    exit 1
  fi
  case "$wheel" in
    "$ALIEN"/*)
      echo "PROOF (b) FAIL: wheel landed in alien CARGO_TARGET_DIR"
      exit 1
      ;;
  esac
  if find "$ALIEN" -name '*cp39-abi3*.whl' | grep -q .; then
    echo "PROOF (b) FAIL: alien target contains a wheel"
    exit 1
  fi
  python3 -m pip install --disable-pip-version-check --force-reinstall "$wheel"
  python3 -m pytest "$REPO_ROOT/bindings/python/tests"
)
if [[ $? -eq 0 ]]; then
  printf 'PROOF (b) PASS: inherited CARGO_TARGET_DIR=%s did not capture this checkout\n' "$ALIEN"
else
  printf 'PROOF (b) FAIL: see above\n'
  failed=1
fi

if [[ $failed -ne 0 ]]; then
  printf 'RESULT=FAIL\n'
  exit 1
fi
printf 'RESULT=PASS\n'
