#!/bin/sh
# Verify the C99 tree matches the committed .clang-format (AUD-0010).
#
# The configuration is at the repository root so that it covers every C file in the tree, and
# this script applies it to exactly the files the tree owns. Two sets are excluded, and both
# are still checked elsewhere rather than left unguarded:
#
#   tests/vectors/*.h  generated from RFC text by tests/vectors/extract_*.py and compared
#                      byte for byte by scripts/check-vectors.sh. Reformatting them would
#                      break that comparison and be undone by the next regeneration, so they
#                      are excluded here and remain guarded there.
#   third_party/       vendored, and not ours to restyle.
#
# Everything else is checked, with no file excluded, no rule relaxed and no threshold set.
#
#   C99/scripts/check-format.sh

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH='' cd -- "$c99_root/.." && pwd)

if ! command -v clang-format >/dev/null 2>&1; then
  echo "error: clang-format is required by check-format.sh" >&2
  exit 1
fi

cd "$repo_root"

files=$(
  git ls-files 'C99/**/*.c' 'C99/**/*.h' |
    grep -v '^C99/tests/vectors/' |
    grep -v '^C99/third_party/' || true
)

if [ -z "$files" ]; then
  echo "error: no C sources found to check" >&2
  exit 1
fi

checked=0
failures=0
for source in $files; do
  checked=$((checked + 1))
  if ! clang-format --style=file --dry-run --Werror "$source" >/dev/null 2>&1; then
    echo "needs formatting: $source"
    failures=$((failures + 1))
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "check-format: $failures of $checked C sources differ from .clang-format" >&2
  echo "Format them with: clang-format --style=file -i <file>" >&2
  exit 1
fi

echo "check-format: all $checked C sources match .clang-format"
