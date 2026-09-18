#!/bin/sh
#
# Measures line coverage of the C99 library and its tools.
#
# The audit baseline needs a coverage number for this project, and the C99 tree had no way
# to produce one (AUD-0009): no gcovr/lcov is installed and the CMake tree had no coverage
# configuration. This uses the clang toolchain's own source-based coverage, which the
# mandated Xcode clang already carries -- `-fprofile-instr-generate -fcoverage-mapping` at
# compile time, `LLVM_PROFILE_FILE` at run time, `llvm-profdata` to merge and `llvm-cov` to
# report -- so nothing new is installed to make the metric appear.
#
# It builds in its own directory (`C99/out/coverage`), because the coverage flags change
# every object and sharing a build directory with the normal or sanitizer configurations
# would silently rebuild the tree twice per invocation.
#
# Usage: measure-coverage.sh [build-dir]
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
build="${1:-$root/out/coverage}"
profile_dir="$build/profiles"

command -v xcrun >/dev/null 2>&1 || { echo "xcrun is required (macOS toolchain)" >&2; exit 1; }
command -v cmake >/dev/null 2>&1 || { echo "cmake is required" >&2; exit 1; }

profile_flags="-fprofile-instr-generate -fcoverage-mapping"

echo "== configuring $build with source-based coverage"
cmake -S "$root" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DWEBTRANSPORT_C99_BUILD_APPS=ON \
  -DWEBTRANSPORT_C99_BUILD_TESTS=ON \
  -DCMAKE_C_FLAGS="$profile_flags" \
  -DCMAKE_EXE_LINKER_FLAGS="$profile_flags" \
  -DCMAKE_SHARED_LINKER_FLAGS="$profile_flags" \
  >/dev/null

echo "== building"
cmake --build "$build" >/dev/null

rm -rf "$profile_dir"
mkdir -p "$profile_dir"

echo "== running the suite"
# `%p` gives each process its own raw profile, so ctest's parallel and per-test processes
# never overwrite one another.
env LLVM_PROFILE_FILE="$profile_dir/%p.profraw" ctest --test-dir "$build" --output-on-failure >/dev/null

echo "== merging profiles"
xcrun llvm-profdata merge -sparse "$profile_dir"/*.profraw -o "$profile_dir/coverage.profdata"

# The report is taken from the shared library alone.
#
# `llvm-cov report` does NOT aggregate across several executables: given more than one object
# it reports the first one's view and silently ignores the rest (measured -- 89 test binaries
# produced a 94-region total, and one test binary the same). The library is also the right
# subject: every test links this one dylib, and the measurement the audit wants is the
# library's coverage rather than the tests'. Tests are excluded from the file list, because
# instrumenting the tests would inflate the figure without saying anything about the library.
dylib=$(find "$build" -maxdepth 1 -name 'libwebtransport.*.dylib' | head -1)
[ -n "$dylib" ] || { echo "no instrumented libwebtransport dylib in $build" >&2; exit 1; }

echo
xcrun llvm-cov report "$dylib" \
  -instr-profile="$profile_dir/coverage.profdata" \
  -ignore-filename-regex='tests/|third_party/' |
  tail -20
