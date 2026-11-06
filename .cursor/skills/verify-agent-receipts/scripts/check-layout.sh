#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SKILL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
FEATURES=$SKILL_DIR/features
SKILL_MD=$SKILL_DIR/SKILL.md
failed=0

fail() {
  printf 'FAIL %s\n' "$1" >&2
  failed=1
}

pass() { printf 'ok %s\n' "$1"; }

if [[ ! -f "$SKILL_MD" ]]; then
  fail "missing SKILL.md"
  exit 1
fi

if ! grep -q '^name: verify-agent-receipts$' "$SKILL_MD"; then
  fail "frontmatter name must be verify-agent-receipts"
else
  pass "frontmatter name"
fi

if ! grep -qE '^description: ["'\'']?Use when' "$SKILL_MD"; then
  fail "frontmatter description must start with Use when"
else
  pass "frontmatter description"
fi

for section in Launch Doctor Drive Evidence Cleanup Helpers; do
  if ! grep -q "^## $section\$" "$SKILL_MD"; then
    fail "SKILL.md missing ## $section"
  else
    pass "section $section"
  fi
done

for script in verify.sh agree.py check-layout.sh dump_canonicalize.rs dump_canonicalize.cjs dump_hmac.rs dump_hmac.cjs dump_hmac.py dump_compare.rs dump_compare.cjs dump_compare.py hmac-surface.sh prove-hmac-surface.sh benchmarks-surface.sh prove-benchmarks-surface.sh; do
  if [[ ! -e "$SCRIPT_DIR/$script" ]]; then
    fail "missing scripts/$script"
  else
    pass "scripts/$script"
  fi
done

if [[ ! -x "$SCRIPT_DIR/verify.sh" || ! -x "$SCRIPT_DIR/agree.py" || ! -x "$SCRIPT_DIR/check-layout.sh" || ! -x "$SCRIPT_DIR/dump_hmac.py" || ! -x "$SCRIPT_DIR/dump_compare.py" || ! -x "$SCRIPT_DIR/hmac-surface.sh" || ! -x "$SCRIPT_DIR/prove-hmac-surface.sh" || ! -x "$SCRIPT_DIR/benchmarks-surface.sh" || ! -x "$SCRIPT_DIR/prove-benchmarks-surface.sh" ]]; then
  fail "verify.sh, agree.py, check-layout.sh, dump_hmac.py, dump_compare.py, hmac-surface.sh, prove-hmac-surface.sh, benchmarks-surface.sh, and prove-benchmarks-surface.sh must be executable"
else
  pass "executable bits"
fi

if [[ ! -f "$FEATURES/README.md" ]]; then
  fail "missing features/README.md"
  exit 1
fi

mapfile -t feature_files < <(find "$FEATURES" -maxdepth 1 -type f -name '*.md' ! -name 'README.md' | sort)
for file in "${feature_files[@]}"; do
  base=$(basename "$file")
  if ! grep -q "$base" "$FEATURES/README.md"; then
    fail "features/README.md does not list $base"
  fi
  for heading in '## Sub-features' '## How to get to it (user POV)' '## Driving it with verify.sh' '## Gotchas'; do
    if ! grep -q "^$heading\$" "$file"; then
      fail "$base missing $heading"
    fi
  done
done

mapfile -t readme_links < <(grep -oE '\./[A-Za-z0-9_.-]+\.md' "$FEATURES/README.md" | sort -u)
for link in "${readme_links[@]}"; do
  if [[ ! -f "$FEATURES/${link#./}" ]]; then
    fail "features/README.md links to missing $link"
  fi
done

if [[ $failed -ne 0 ]]; then
  printf 'RESULT=FAIL\n'
  exit 1
fi
printf 'RESULT=PASS\n'
