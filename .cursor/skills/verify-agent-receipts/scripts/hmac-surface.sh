#!/usr/bin/env bash
# Predicates used by verify.sh and prove-hmac-surface.sh.

python_log_hmac_ok() {
  local log=$1
  [[ -f "$log" ]] || return 1
  if grep -qE '[1-9][0-9]* failed' "$log"; then
    return 1
  fi
  grep -qE '=+ [1-9][0-9]* passed(, [0-9]+ skipped)? in [0-9.]+s' "$log"
}

agreement_hmac_ok() {
  local log=$1
  [[ -f "$log" ]] || return 1
  grep -Fxq 'hmac 8 ok' "$log"
}
