#!/bin/sh
# Install the C99 library and build a consumer against the installed package.
#
# This is the check that the install tree is usable: it configures a separate
# CMake project that does nothing but find_package(webtransport_c99) and link,
# so a missing header, a target without its include directory, or a config file
# that exports the wrong namespace fails here rather than in a user's build.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

case "$(uname -s)" in
  Darwin) platform=macos26 ;;
  Linux) platform=debian ;;
  FreeBSD) platform=freebsd ;;
  *) platform=unknown ;;
esac

build_dir="$c99_root/out/$platform/package-check"
prefix="$build_dir/prefix"
consumer_dir="$build_dir/consumer"

rm -rf "$build_dir"

cmake -S "$c99_root" -B "$build_dir/library" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DWEBTRANSPORT_C99_BUILD_APPS=OFF \
  -DWEBTRANSPORT_C99_BUILD_TESTS=OFF >/dev/null
cmake --build "$build_dir/library" >/dev/null
cmake --install "$build_dir/library" >/dev/null

cmake -S "$c99_root/tests/package" -B "$consumer_dir" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$prefix" >/dev/null
cmake --build "$consumer_dir" >/dev/null

"$consumer_dir/consumer"
echo "webtransport-c99: the installed package builds a consumer"
