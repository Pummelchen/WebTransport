#!/bin/sh
# Configure, build and test the C99 implementation.
#
# One script rather than a documented sequence of cmake commands, because the
# sequence has three steps that are easy to get wrong: the build directory has
# to be under out/ so that generated files stay out of the source tree, the
# tests have to be on for ctest to have anything to run, and the sanitizer build
# is a separate configuration rather than a flag on an existing one -- CMake
# caches the compiler flags, so turning sanitizers on in a directory that was
# configured without them silently does nothing.
#
# Usage:
#   scripts/build-and-test.sh              # Debug with tests
#   scripts/build-and-test.sh --release    # Release with tests
#   scripts/build-and-test.sh --sanitize   # Debug with ASan and UBSan
#   scripts/build-and-test.sh --all        # all three, in order
#
# The platform directories under platform/ are the packaging entry points; this
# is the development loop.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

# The output root is per platform so that two platforms can be built on one
# machine -- a container running Debian and this Mac, for instance -- without
# their caches colliding.
case "$(uname -s)" in
  Darwin) platform=macos26 ;;
  Linux) platform=debian ;;
  FreeBSD) platform=freebsd ;;
  *) platform=unknown ;;
esac

build_one() {
  name=$1
  shift
  build_dir="$c99_root/out/$platform/$name"
  echo "=== $name ==="
  cmake -S "$c99_root" -B "$build_dir" -G Ninja "$@" >/dev/null
  cmake --build "$build_dir"
  # The Darwin sanitizer symbolizer hangs on the reports this code can produce
  # and prints nothing useful when it does; disabling it costs stack names and
  # not the report.
  if [ "$name" = "build-sanitize" ]; then
    ASAN_OPTIONS=symbolize=0 UBSAN_OPTIONS=symbolize=0 \
      ctest --test-dir "$build_dir" --output-on-failure
  else
    ctest --test-dir "$build_dir" --output-on-failure
  fi
}

case "${1:-}" in
  --release)
    build_one build-release -DCMAKE_BUILD_TYPE=Release
    ;;
  --sanitize)
    build_one build-sanitize -DCMAKE_BUILD_TYPE=Debug \
      -DWEBTRANSPORT_C99_SANITIZE=ON
    ;;
  --all)
    build_one build -DCMAKE_BUILD_TYPE=Debug
    build_one build-release -DCMAKE_BUILD_TYPE=Release
    build_one build-sanitize -DCMAKE_BUILD_TYPE=Debug \
      -DWEBTRANSPORT_C99_SANITIZE=ON
    ;;
  "")
    build_one build -DCMAKE_BUILD_TYPE=Debug
    ;;
  *)
    echo "unknown option: $1" >&2
    exit 2
    ;;
esac
