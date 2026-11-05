#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SKILL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$SKILL_DIR/../../.." && pwd)
# shellcheck source=hmac-surface.sh
. "$SCRIPT_DIR/hmac-surface.sh"

unset CARGO_TARGET_DIR
export CARGO_TARGET_DIR="$REPO_ROOT/target"

MODE=run
EVIDENCE_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    doctor)
      MODE=doctor
      shift
      ;;
    --evidence-dir)
      EVIDENCE_OVERRIDE=${2:-}
      if [[ -z "$EVIDENCE_OVERRIDE" ]]; then
        echo "verify.sh: --evidence-dir needs a directory" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Drive fmt, clippy, cargo test, the Python abi3 wheel, the Node napi binding,
and Rust/Python/Node agreement on canonical JSON.

  verify.sh doctor              read-only toolchain check
  verify.sh                     full run
  verify.sh --evidence-dir DIR  full run, write logs under DIR
EOF
      exit 0
      ;;
    *)
      echo "verify.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$REPO_ROOT/Cargo.toml" || ! -f "$REPO_ROOT/vectors/reference/vectors.json" || ! -d "$REPO_ROOT/vectors/text" ]]; then
  echo "verify.sh: could not find the agent-receipts repository root from $SKILL_DIR" >&2
  exit 2
fi

RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
if [[ -n "$EVIDENCE_OVERRIDE" ]]; then
  EVIDENCE=$EVIDENCE_OVERRIDE
else
  EVIDENCE=${VERIFY_EVIDENCE_DIR:-/tmp/agent-receipts-verify-$RUN_ID}
fi
mkdir -p "$EVIDENCE"
RESULTS=$EVIDENCE/results.tsv
: >"$RESULTS"

log() { printf '%s\n' "$*"; }
log_err() { printf '%s\n' "$*" >&2; }

record() {
  local id=$1 status=$2 detail=$3
  printf '%s\t%s\t%s\n' "$id" "$status" "$detail" >>"$RESULTS"
  printf '[%s] %s %s\n' "$status" "$id" "$detail"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

DOCTOR_OK=1
doctor_check() {
  local id=$1
  shift
  local logf=$EVIDENCE/doctor-$id.log
  if "$@" >"$logf" 2>&1; then
    log "doctor $id: ok"
    return 0
  fi
  log_err "doctor $id: FAIL (see $logf)"
  DOCTOR_OK=0
  return 1
}

check_repo() {
  [[ -f "$REPO_ROOT/Cargo.toml" ]] || return 1
  grep -q 'members = \["crates/core"' "$REPO_ROOT/Cargo.toml" || return 1
  [[ -f "$REPO_ROOT/vectors/reference/vectors.json" ]] || return 1
  [[ -f "$REPO_ROOT/vectors/reference/pending-kinds.txt" ]] || return 1
  [[ -n "$(find "$REPO_ROOT/vectors/text" -name '*.json' -print -quit)" ]]
}

check_rustc() {
  have_cmd rustc || return 1
  rustc --version | grep -q 'rustc 1\.83\.'
}

check_cargo() { have_cmd cargo; }
check_rustfmt() { have_cmd rustfmt && cargo fmt --version >/dev/null; }
check_clippy() { cargo clippy --version >/dev/null; }

check_python() {
  have_cmd python3 || return 1
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'
}

check_pip() { python3 -m pip --version >/dev/null; }

check_node() {
  have_cmd node || return 1
  local major
  major=$(node -p "process.versions.node.split('.')[0]")
  [[ "$major" == "22" ]]
}

check_npm() { have_cmd npm; }

run_doctor() {
  cd "$REPO_ROOT"
  doctor_check repo check_repo
  doctor_check rustc check_rustc
  doctor_check cargo check_cargo
  doctor_check rustfmt check_rustfmt
  doctor_check clippy check_clippy
  doctor_check python check_python
  doctor_check pip check_pip
  doctor_check node check_node
  doctor_check npm check_npm
  if [[ $DOCTOR_OK -eq 1 ]]; then
    log "doctor: instance is worth driving"
    return 0
  fi
  log_err "doctor: missing toolchain; existing surfaces fail closed"
  return 1
}

run_logged() {
  local logf=$1
  shift
  "$@" >"$logf" 2>&1
}

run_existing() {
  local id=$1
  shift
  local logf=$EVIDENCE/$id.log
  if run_logged "$logf" "$@"; then
    record "$id" PASS "see $logf"
    return 0
  fi
  record "$id" FAIL "see $logf"
  return 1
}

fail_missing() {
  local id=$1 reason=$2
  record "$id" FAIL "$reason"
}

code_has() {
  local pattern=$1
  grep -RInE --include='*.rs' --include='*.py' --include='*.cjs' --include='*.js' \
    "$pattern" \
    "$REPO_ROOT/crates/core/src" \
    "$REPO_ROOT/bindings/python/src" \
    "$REPO_ROOT/bindings/python/tests" \
    "$REPO_ROOT/bindings/node/src" \
    "$REPO_ROOT/bindings/node/test" \
    >/dev/null 2>&1
}

record_reserved() {
  local id=$1 pattern=$2
  if code_has "$pattern"; then
    record "$id" FAIL "API exists in source; this skill does not drive it. Do not mark passed."
    return
  fi
  record "$id" NOT_IMPLEMENTED "no API on this checkout"
}

record_hmac() {
  local cargo_log=$EVIDENCE/cargo-test.log
  local py_log=$EVIDENCE/python-abi3.log
  local node_log=$EVIDENCE/node-napi.log
  if ! code_has 'verify_audit_receipt|verifyAuditReceipt'; then
    record hmac-verification FAIL "verify API missing"
    return
  fi
  if ! code_has 'resign_audit_receipt|resignAuditReceipt'; then
    record hmac-verification FAIL "resign API missing"
    return
  fi
  if [[ ! -f "$cargo_log" ]] || ! grep -q 'test reference::reference_vectors ... ok' "$cargo_log"; then
    record hmac-verification FAIL "rust reference_vectors not ok; see $cargo_log"
    return
  fi
  if ! python_log_hmac_ok "$py_log"; then
    record hmac-verification FAIL "python pytest did not report a zero-failure passed run; see $py_log"
    return
  fi
  if [[ ! -f "$node_log" ]] || ! grep -Eq '^#? ?hmac 8 ok$' "$node_log"; then
    record hmac-verification FAIL "node hmac 8 ok missing; see $node_log"
    return
  fi
  if ! agreement_hmac_ok "$EVIDENCE/cross-language-agreement.log"; then
    record hmac-verification FAIL "agreement missing exact hmac 8 ok; see $EVIDENCE/cross-language-agreement.log"
    return
  fi
  record hmac-verification PASS "rust python node hmac 8 ok"
}

record_pending_kinds() {
  local file="$REPO_ROOT/vectors/reference/pending-kinds.txt"
  local kind
  if [[ ! -f "$file" ]]; then
    record reference-pending-kinds FAIL "pending-kinds.txt is missing"
    return
  fi
  if ! grep -q '[^[:space:]]' "$file"; then
    record reference-pending-kinds PASS "no pending kinds"
    return
  fi
  while IFS= read -r kind || [[ -n "$kind" ]]; do
    kind="${kind#"${kind%%[![:space:]]*}"}"
    kind="${kind%"${kind##*[![:space:]]}"}"
    [[ -z "$kind" ]] && continue
    if grep -RIF --include='*.rs' --include='*.py' --include='*.cjs' --include='*.js' \
      -e "$kind" \
      "$REPO_ROOT/crates/core/src" \
      "$REPO_ROOT/bindings/python/src" \
      "$REPO_ROOT/bindings/python/tests" \
      "$REPO_ROOT/bindings/node/src" \
      "$REPO_ROOT/bindings/node/test" \
      >/dev/null 2>&1; then
      record reference-pending-kinds FAIL "pending kind is present in source; this skill does not drive it"
      return
    fi
  done <"$file"
  record reference-pending-kinds FAIL "pending kinds remain"
}

record_authority() {
  local cargo_log=$EVIDENCE/cargo-test.log
  local node_log=$EVIDENCE/node-napi.log
  if ! code_has 'compare_authority_contracts|compareAuthorityContracts'; then
    record authority-contract-comparison NOT_IMPLEMENTED "no API on this checkout"
    return
  fi
  if [[ ! -f "$cargo_log" ]] || ! grep -q 'test reference::reference_vectors ... ok' "$cargo_log"; then
    record authority-contract-comparison FAIL "rust reference_vectors not ok; see $cargo_log"
    return
  fi
  if [[ ! -f "$node_log" ]] || ! grep -Eq '^#? ?compare 7 ok$' "$node_log"; then
    record authority-contract-comparison FAIL "node compare 7 ok missing; see $node_log"
    return
  fi
  if [[ ! -f "$EVIDENCE/cross-language-agreement.log" ]] || ! grep -Fxq 'compare 7 ok' "$EVIDENCE/cross-language-agreement.log"; then
    record authority-contract-comparison FAIL "agreement missing exact compare 7 ok; see $EVIDENCE/cross-language-agreement.log"
    return
  fi
  record authority-contract-comparison PASS "rust python node compare 7 ok"
}

record_public_api() {
  local cargo_log=$EVIDENCE/cargo-test.log
  local py_log=$EVIDENCE/python-abi3.log
  local node_log=$EVIDENCE/node-napi.log
  if [[ ! -f "$cargo_log" ]] || ! grep -q 'test public_signatures_compile ... ok' "$cargo_log"; then
    record public-api-policy FAIL "rust public_signatures_compile not ok; see $cargo_log"
    return
  fi
  if [[ ! -f "$cargo_log" ]] || ! grep -q 'test public_enum_variants_are_exhaustive ... ok' "$cargo_log"; then
    record public-api-policy FAIL "rust public_enum_variants_are_exhaustive not ok; see $cargo_log"
    return
  fi
  if ! python_log_hmac_ok "$py_log"; then
    record public-api-policy FAIL "python pytest did not report a zero-failure passed run; see $py_log"
    return
  fi
  if [[ ! -f "$py_log" ]] || ! grep -q 'test_public_api.py' "$py_log"; then
    record public-api-policy FAIL "python test_public_api.py missing; see $py_log"
    return
  fi
  if [[ ! -f "$node_log" ]] || ! grep -Eq 'ok [0-9]+ - exported names' "$node_log"; then
    record public-api-policy FAIL "node exported names missing; see $node_log"
    return
  fi
  record public-api-policy PASS "rust python node public signatures pinned"
}

record_benchmarks() {
  if [[ -d "$REPO_ROOT/benches" || -d "$REPO_ROOT/crates/core/benches" ]]; then
    record benchmarks FAIL "benches/ exists; this skill does not drive it. Do not mark passed."
    return
  fi
  if grep -R --include='Cargo.toml' -n '\[\[bench\]\]' "$REPO_ROOT/crates" "$REPO_ROOT/bindings" >/dev/null 2>&1; then
    record benchmarks FAIL "[[bench]] exists; this skill does not drive it. Do not mark passed."
    return
  fi
  record benchmarks NOT_IMPLEMENTED "no benches on this checkout"
}

select_python() {
  local venv=$EVIDENCE/venv
  if python3 -m venv "$venv" >/dev/null 2>&1 && [[ -x "$venv/bin/python" ]]; then
    printf '%s\n' "$venv/bin/python"
    return 0
  fi
  rm -rf "$venv"
  printf '%s\n' "python3"
}

install_python_tools() {
  local python=$1
  local logf=$EVIDENCE/python-tools.log
  local pip_args=(install --disable-pip-version-check maturin==1.16.0 pytest)
  if [[ "$python" == "python3" ]]; then
    pip_args+=( --user )
    export PATH="${HOME}/.local/bin:${PATH}"
  fi
  if ! "$python" -m pip "${pip_args[@]}" >"$logf" 2>&1; then
    return 1
  fi
  if [[ "$python" != "python3" ]]; then
    export PATH="$(dirname "$python"):${PATH}"
  fi
  return 0
}

run_python_surface() {
  local python=$1
  local logf=$EVIDENCE/python-abi3.log
  (
    set -euo pipefail
    unset CARGO_TARGET_DIR
    export CARGO_TARGET_DIR="$REPO_ROOT/target"
    rm -f "$REPO_ROOT/target/wheels/"*cp39-abi3*.whl
    echo "+ maturin build --release --manifest-path bindings/python/Cargo.toml --interpreter python3"
    out=$(maturin build --release --manifest-path "$REPO_ROOT/bindings/python/Cargo.toml" --interpreter python3 2>&1)
    printf '%s\n' "$out"
    wheel=$(printf '%s\n' "$out" | grep -oE '/[^[:space:]]+cp39-abi3[^[:space:]]+\.whl' | tail -1)
    if [[ -z "$wheel" || ! -f "$wheel" ]]; then
      echo "maturin did not report a wheel path for this build" >&2
      exit 1
    fi
    echo "+ pip install $wheel"
    pip_install=(install --disable-pip-version-check --force-reinstall "$wheel")
    if [[ "$python" == "python3" ]]; then
      pip_install+=( --user )
    fi
    "$python" -m pip "${pip_install[@]}"
    echo "+ $python -m pytest bindings/python/tests"
    "$python" -m pytest "$REPO_ROOT/bindings/python/tests"
  ) >"$logf" 2>&1
}

run_node_surface() {
  local logf=$EVIDENCE/node-napi.log
  (
    cd "$REPO_ROOT/bindings/node"
    echo "+ npm ci"
    npm ci
    echo "+ npm run build"
    npm run build
    echo "+ npm test"
    npm test
  ) >"$logf" 2>&1
}

build_rust_dump() {
  local dump_dir=$EVIDENCE/dump-canonicalize
  local dump_bin=$dump_dir/target/debug/dump-canonicalize
  local hmac_bin=$dump_dir/target/debug/dump-hmac
  mkdir -p "$dump_dir/src"
  cat >"$dump_dir/Cargo.toml" <<EOF
[package]
name = "dump-canonicalize"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "dump-canonicalize"
path = "src/dump_canonicalize.rs"

[[bin]]
name = "dump-hmac"
path = "src/dump_hmac.rs"

[[bin]]
name = "dump-compare"
path = "src/dump_compare.rs"

[dependencies]
agent-receipts = { path = "$REPO_ROOT/crates/core" }
serde_json = "1"
EOF
  cp "$SCRIPT_DIR/dump_canonicalize.rs" "$dump_dir/src/dump_canonicalize.rs"
  cp "$SCRIPT_DIR/dump_hmac.rs" "$dump_dir/src/dump_hmac.rs"
  cp "$SCRIPT_DIR/dump_compare.rs" "$dump_dir/src/dump_compare.rs"
  rm -f "$dump_bin" "$hmac_bin" "$dump_dir/target/debug/dump-compare"
  if ! cargo build --manifest-path "$dump_dir/Cargo.toml" --target-dir "$dump_dir/target"; then
    echo "dump-canonicalize cargo build failed" >&2
    return 1
  fi
  if [[ ! -x "$dump_bin" || ! -x "$hmac_bin" || ! -x "$dump_dir/target/debug/dump-compare" ]]; then
    echo "dump binaries missing under $dump_dir/target/debug" >&2
    return 1
  fi
}

run_agreement() {
  local python=$1
  local logf=$EVIDENCE/cross-language-agreement.log
  local dump_bin=$EVIDENCE/dump-canonicalize/target/debug/dump-canonicalize
  (
    set -euo pipefail
    build_rust_dump
    if [[ ! -x "$dump_bin" ]]; then
      echo "dump-canonicalize binary missing at $dump_bin" >&2
      exit 1
    fi
    echo "+ $python $SCRIPT_DIR/agree.py"
    "$python" "$SCRIPT_DIR/agree.py" \
      --reference "$REPO_ROOT/vectors/reference" \
      --text "$REPO_ROOT/vectors/text" \
      --rust-dump "$dump_bin" \
      --node-binding "$REPO_ROOT/bindings/node" \
      --node-dump "$SCRIPT_DIR/dump_canonicalize.cjs" \
      --rust-hmac-dump "$EVIDENCE/dump-canonicalize/target/debug/dump-hmac" \
      --python-hmac-dump "$SCRIPT_DIR/dump_hmac.py" \
      --node-hmac-dump "$SCRIPT_DIR/dump_hmac.cjs" \
      --rust-compare-dump "$EVIDENCE/dump-canonicalize/target/debug/dump-compare" \
      --python-compare-dump "$SCRIPT_DIR/dump_compare.py" \
      --node-compare-dump "$SCRIPT_DIR/dump_compare.cjs"
  ) >"$logf" 2>&1
}

print_summary() {
  local passed=0 failed=0 not_impl=0 unsupported=0
  local summary=$EVIDENCE/summary.txt
  while IFS=$'\t' read -r id status detail; do
    case "$status" in
      PASS) passed=$((passed + 1)) ;;
      FAIL) failed=$((failed + 1)) ;;
      NOT_IMPLEMENTED) not_impl=$((not_impl + 1)) ;;
      UNSUPPORTED) unsupported=$((unsupported + 1)) ;;
    esac
  done <"$RESULTS"
  {
    printf '======== summary ========\n'
    printf '%-32s %-16s %s\n' "SURFACE" "STATUS" "DETAIL"
    while IFS=$'\t' read -r id status detail; do
      printf '%-32s %-16s %s\n' "$id" "$status" "$detail"
    done <"$RESULTS"
    printf '\npassed=%s failed=%s not_implemented=%s unsupported=%s\n' \
      "$passed" "$failed" "$not_impl" "$unsupported"
    printf 'evidence=%s\n' "$EVIDENCE"
    if [[ $failed -gt 0 ]]; then
      printf 'RESULT=FAIL\n'
    else
      printf 'RESULT=PASS\n'
    fi
  } >"$summary"
  cat "$summary"
  [[ $failed -eq 0 ]]
}

cleanup_scratch() {
  rm -rf "$EVIDENCE/venv" "$EVIDENCE/dump-canonicalize"
}

cd "$REPO_ROOT"
export PATH="${HOME}/.local/bin:${PATH}"

run_doctor
DOCTOR_STATUS=$?

if [[ $MODE == doctor ]]; then
  printf 'evidence=%s\n' "$EVIDENCE"
  if [[ $DOCTOR_STATUS -ne 0 ]]; then
    printf 'RESULT=FAIL\n'
    exit 1
  fi
  printf 'RESULT=PASS\n'
  exit 0
fi

if ! check_rustfmt; then
  fail_missing rustfmt "rustfmt missing; fail closed"
else
  run_existing rustfmt cargo fmt --all --check
fi

if ! check_clippy; then
  fail_missing clippy "clippy missing; fail closed"
else
  run_existing clippy cargo clippy --workspace --all-targets -- -D warnings
fi

if ! check_cargo; then
  fail_missing cargo-test "cargo missing; fail closed"
else
  run_existing cargo-test cargo test --workspace
fi

PYTHON_BIN=""
if ! check_python || ! check_pip; then
  fail_missing python-abi3 "python3 or pip missing; fail closed"
else
  PYTHON_BIN=$(select_python)
  if ! install_python_tools "$PYTHON_BIN"; then
    record python-abi3 FAIL "could not install maturin==1.16.0 and pytest; see $EVIDENCE/python-tools.log"
  elif run_python_surface "$PYTHON_BIN"; then
    record python-abi3 PASS "see $EVIDENCE/python-abi3.log"
  else
    record python-abi3 FAIL "see $EVIDENCE/python-abi3.log"
  fi
fi

if ! check_node || ! check_npm; then
  fail_missing node-napi "node 22 or npm missing; fail closed"
elif run_node_surface; then
  record node-napi PASS "see $EVIDENCE/node-napi.log"
else
  record node-napi FAIL "see $EVIDENCE/node-napi.log"
fi

PYTHON_IMPORT_OK=0
NODE_BINDING_OK=0
if [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c 'import agent_receipts' >/dev/null 2>&1; then
  PYTHON_IMPORT_OK=1
fi
if [[ -f "$REPO_ROOT/bindings/node/index.js" ]]; then
  NODE_BINDING_OK=1
fi

if [[ $PYTHON_IMPORT_OK -ne 1 ]]; then
  fail_missing cross-language-agreement "Python wheel not importable; fail closed"
elif [[ $NODE_BINDING_OK -ne 1 ]]; then
  fail_missing cross-language-agreement "Node binding not built; fail closed"
elif ! check_cargo; then
  fail_missing cross-language-agreement "cargo missing; fail closed"
elif run_agreement "$PYTHON_BIN"; then
  record cross-language-agreement PASS "see $EVIDENCE/cross-language-agreement.log"
else
  record cross-language-agreement FAIL "see $EVIDENCE/cross-language-agreement.log"
fi

record_hmac
record_authority
record_public_api
record_reserved async-streaming-verifier 'async[[:space:]]+fn'
record_benchmarks
record_pending_kinds

cp "$RESULTS" "$EVIDENCE/summary.tsv"
print_summary
SUMMARY_STATUS=$?
cleanup_scratch
if [[ -f "$EVIDENCE/summary.tsv" ]]; then
  :
else
  log_err "cleanup removed evidence"
  exit 1
fi
exit $SUMMARY_STATUS
