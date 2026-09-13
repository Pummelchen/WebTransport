#!/bin/sh
# A second static analyser: cppcheck over the library and the tools (WT-177).
#
# `check-static-analysis.sh` runs the Clang Static Analyzer, which is path-sensitive and takes a minute and a half
# over this tree. cppcheck is a DIFFERENT engine with different heuristics -- the plan names it by hand ("static
# analysis with clang-tidy or cppcheck") -- and it finishes in seconds, which is cheap enough to put in front of
# every CI run. Two engines agreeing is evidence; one engine alone is a habit, and the findings below are what the
# second one was worth: a default mode chosen by comparing two literals in all three tools, one of those
# comparisons dead in the conformance tool, an always-false report boolean in a scenario, a duplicated `is_server`
# block in the settings builder, two conditions the surrounding checks already establish, a redundant NULL check
# and a struct member nothing read.
#
# THE STYLE CATEGORY IS DELIBERATELY OFF. cppcheck's cross-translation-unit heuristics do not see a library's own
# headers or another unit's use of a struct member, so `--enable=all` reports 63 `staticFunction` items for public
# API functions, `wt_udp_platform_acquire()` as an always-false condition (it is the platform layer's function,
# not this file's) and `entry.events` as an unread variable (the platform wait reads it) -- measured on this tree.
# The categories kept are the ones that stand on the file in front of them, and the path-sensitive class cppcheck
# would add is what the Clang Static Analyzer already covers.
#
# Usage: check-cppcheck.sh [cppcheck] [--all]   (--all adds the style category, for a look rather than a gate)
set -eu

cppcheck_bin="${1:-cppcheck}"
categories="warning,performance,portability"
if [ "${2:-}" = "--all" ]; then
  categories="all"
fi
root="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v "$cppcheck_bin" >/dev/null 2>&1; then
  echo "cppcheck: unsupported -- $cppcheck_bin is not installed, so this machine cannot run the second analyser"
  exit 0
fi

cd "$root"
# `--error-exitcode=1` is what makes this a CHECK: without it cppcheck reports and exits 0, and a report nobody
# fails on is a report nobody reads.
"$cppcheck_bin" --std=c99 --enable="$categories" --inline-suppr \
  --suppress=missingIncludeSystem --error-exitcode=1 \
  -I include -q src apps
echo "cppcheck: clean over the library and the tools ($categories)"
