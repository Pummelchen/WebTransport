#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

if [ ! -f "$c99_root/CMakeLists.txt" ]; then
  echo "C99/CMakeLists.txt does not exist yet. Create the C99 CMake project before running this build script." >&2
  exit 2
fi

build_dir="$c99_root/out/freebsd/build"
install_dir="$c99_root/out/freebsd/install"

cmake -S "$c99_root" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$install_dir" \
  -DBUILD_SHARED_LIBS=ON \
  -DWEBTRANSPORT_C99_BUILD_APPS=ON \
  -DWEBTRANSPORT_C99_BUILD_TESTS=ON

cmake --build "$build_dir" --config Release --parallel
cmake --install "$build_dir" --config Release
