#!/bin/sh
# The compliance matrix's named symbols AND tests must exist (Phase 10).
#
# A matrix that names functions nobody wrote or tests nobody registered is worse than no matrix, because it reads
# like evidence. This walks the table's name-bearing columns, one resolution rule each:
#
#   Requirement, Implementation  a `wt_`/`WT_` name must be DECLARED in a header under include/ or src/. It used to
#                                be enough for the word to appear ANYWHERE -- a comment, a string literal, a
#                                CMakeLists or a test label -- so a deleted library symbol still passed as long as
#                                some test happened to mention it.
#   Evidence                     a test name (`test_*`, or the `wt_cli_*`/`wt_conformance_*` CTest names) must be
#                                REGISTERED by a CMakeLists or a script. The old extraction matched only `wt_` and
#                                `WT_` identifiers, so every test name in this column was dropped and the whole
#                                column went unchecked.
#
# `quic/`-style paths, `protocol-negotiation`-style slugs and `test_quic_*` globs are not identifiers and are
# skipped on purpose.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
matrix="$root/docs/COMPLIANCE-MATRIX.md"
[ -f "$matrix" ] || { echo "matrix: $matrix is missing"; exit 1; }

# The table's data rows: not the header, not the separator.
rows="$(grep '^| ' "$matrix" | grep -v '^| # ' | grep -v '^| --- ')"
[ -n "$rows" ] || { echo "matrix: no table rows found, which cannot be right"; exit 1; }

# Every backticked identifier-shaped name in column $1 of every row, deduplicated. A name with a character that
# is not part of an identifier (a slash, a hyphen, a star) does not match and is not a name this file can resolve.
column_names() {
  # The backticks are literal: the pattern matches a backtick-quoted identifier in the Markdown.
  # shellcheck disable=SC2016
  printf '%s\n' "$rows" | cut -d'|' -f"$1" | grep -o '`[A-Za-z_][A-Za-z0-9_]*`' | tr -d '`' | sort -u
}

missing=0
count=0

# The C-symbol columns (Requirement and Implementation): a declaration in a header.
for symbol in $(column_names 3) $(column_names 4); do
  case "$symbol" in
    wt_*|WT_*) ;;
    *) continue ;; # a bare prose word, such as the pre-draft protocol token `webtransport`
  esac
  count=$((count + 1))
  if ! grep -rqw --include='*.h' "$symbol" "$root/include" "$root/src"; then
    echo "matrix: $symbol is named by the matrix but is not declared in any header"
    missing=$((missing + 1))
  fi
done

# The Evidence column: a test name registered by a CMakeLists or a script.
for symbol in $(column_names 5); do
  case "$symbol" in
    test_*|wt_cli_*|wt_conformance_*) ;;
    *) continue ;;
  esac
  count=$((count + 1))
  if ! grep -rqw --include='CMakeLists.txt' --include='*.sh' "$symbol" \
       "$root/apps" "$root/tests" "$root/scripts" "$root/CMakeLists.txt"; then
    echo "matrix: $symbol is named by the Evidence column but no test registers it"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "matrix: $missing of $count named symbols/tests are missing"
  exit 1
fi
echo "matrix: all $count named symbols/tests exist"
