#!/usr/bin/env bash

benchmarks_log_ok() {
  local log=$1
  [[ -f "$log" ]] || return 1
  grep -Fxq 'ts-baseline canonicalize 8 ok' "$log" || return 1
  grep -Fxq 'ts-baseline hmac 8 ok' "$log" || return 1
  grep -Fxq 'ts-baseline compare 7 ok' "$log" || return 1
}

benchmarks_entry_present() {
  local root=$1
  [[ -f "$root/bench/run" ]]
}

benchmarks_tripwire_reason() {
  local root=$1
  if [[ -d "$root/benches" || -d "$root/crates/core/benches" ]]; then
    printf '%s\n' "benches/ exists; this skill does not drive it. Do not mark passed."
    return 0
  fi
  if grep -R --include='Cargo.toml' -n '\[\[bench\]\]' "$root/crates" "$root/bindings" >/dev/null 2>&1; then
    printf '%s\n' "[[bench]] exists; this skill does not drive it. Do not mark passed."
    return 0
  fi
  return 1
}
