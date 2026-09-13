#!/bin/sh
# The compliance matrix's symbols must exist (Phase 10).
#
# A matrix that names functions nobody wrote is worse than no matrix, because it reads like evidence. This greps
# every backticked identifier that looks like a C symbol or macro out of docs/COMPLIANCE-MATRIX.md and fails if it
# is not in the tree -- so the document cannot drift away from the code without a check saying so.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
matrix="$root/docs/COMPLIANCE-MATRIX.md"
[ -f "$matrix" ] || { echo "matrix: $matrix is missing"; exit 1; }

# Identifiers this file's tables name, in order, deduplicated. Only `wt_`-prefixed names and ALL-CAPS macros are
# treated as symbols; a `quic/`-style path is skipped on purpose (it names a directory, which is checked by the
# build rather than by a grep).
symbols="$(grep -o '`[A-Za-z_][A-Za-z0-9_]*`' "$matrix" | tr -d '`' | sort -u | grep -E '^(wt_|WT_)' || true)"
[ -n "$symbols" ] || { echo "matrix: no symbols found, which cannot be right"; exit 1; }

missing=0
count=0
for symbol in $symbols; do
  count=$((count + 1))
  # A C symbol lives in a header or a source file; a CTest test name lives in a CMakeLists.txt or a script. Both
  # are checked, because the Evidence column names both and both can drift.
  if ! grep -rq --include='*.h' --include='*.c' -w "$symbol" "$root/include" "$root/src" "$root/apps" "$root/tests" \
     && ! grep -rq --include='CMakeLists.txt' --include='*.sh' -w "$symbol" "$root/apps" "$root/scripts" "$root/tests"; then
    echo "matrix: $symbol is named by the matrix but does not exist"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "matrix: $missing of $count named symbols are missing"
  exit 1
fi
echo "matrix: all $count named symbols exist"
