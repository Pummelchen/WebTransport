#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cpp_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

if [ ! -f "$cpp_root/CMakeLists.txt" ]; then
  echo "CPP/CMakeLists.txt does not exist yet. Create the C++ CMake project before running this build script." >&2
  exit 2
fi

build_dir="$cpp_root/out/macos26/build"
install_dir="$cpp_root/out/macos26/install"

cmake -S "$cpp_root" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$install_dir" \
  -DBUILD_SHARED_LIBS=ON \
  -DWEBTRANSPORT_BUILD_APPS=ON \
  -DWEBTRANSPORT_BUILD_TESTS=ON

cmake --build "$build_dir" --config Release --parallel
cmake --install "$build_dir" --config Release
