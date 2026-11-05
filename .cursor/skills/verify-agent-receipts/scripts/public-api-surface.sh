#!/usr/bin/env bash

public_api_policy_ok() {
  local repo=$1 cargo=$2 py=$3 node=$4
  rust_public_api_log_ok "$repo" "$cargo" \
    && python_public_api_log_ok "$repo" "$py" \
    && node_public_api_log_ok "$node"
}

public_api_rust_test_names() {
  local repo=$1
  sed -n 's/^fn \([a-z0-9_][a-z0-9_]*\)() {$/\1/p' \
    "$repo/crates/core/tests/public_api.rs"
}

public_api_python_test_names() {
  local repo=$1
  sed -n 's/^def \(test_[A-Za-z0-9_][A-Za-z0-9_]*\).*/\1/p' \
    "$repo/bindings/python/tests/test_public_api.py"
}

rust_public_api_log_ok() {
  local repo=$1
  local log=$2
  local name
  local found=0
  [[ -f "$log" ]] || return 1
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    found=1
    grep -Fxq "test ${name} ... ok" "$log" || return 1
  done < <(public_api_rust_test_names "$repo")
  [[ "$found" -eq 1 ]]
}

python_public_api_log_ok() {
  local repo=$1
  local log=$2
  local name
  local line
  local found=0
  local saw=0
  local passed_re='^=+ [1-9][0-9]* passed in [0-9.]+s =+$'
  [[ -f "$log" ]] || return 1
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    found=1
    grep -F -q "test_public_api.py::${name} PASSED" "$log" || return 1
  done < <(public_api_python_test_names "$repo")
  [[ "$found" -eq 1 ]] || return 1
  if grep -E -q 'test_public_api\.py::[^ ]* (SKIPPED|FAILED|ERROR|XFAIL)' "$log"; then
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^=+ ]] || continue
    [[ "$line" =~ =+$ ]] || continue
    [[ "$line" == *passed* || "$line" == *failed* || "$line" == *skipped* || "$line" == *error* ]] || continue
    [[ "$line" =~ $passed_re ]] || return 1
    saw=1
  done < "$log"
  [[ "$saw" -eq 1 ]]
}

node_public_api_log_ok() {
  local log=$1
  [[ -f "$log" ]] || return 1
  grep -Eq '^ok [0-9]+ - exported names$' "$log" || return 1
  if grep -Eq '^not ok' "$log"; then
    return 1
  fi
  grep -Eq '^# fail 0$' "$log" || return 1
  grep -Eq '^# (skipped|skip) 0$' "$log"
}
