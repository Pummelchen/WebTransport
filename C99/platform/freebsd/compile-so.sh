#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
c99_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

if [ ! -f "$c99_root/CMakeLists.txt" ]; then
  echo "C99/CMakeLists.txt does not exist yet. Create the C99 CMake project before running this build script." >&2
  exit 2
fi

# The packaging build gets its OWN directory. `C99/scripts/build-and-test.sh`
# configures the same platform's Debug build in `out/<platform>/build` with
# Ninja, and these scripts use CMake's default generator (Makefiles), so sharing
# that directory made whichever ran second fail with "Does not match the
# generator used previously" -- a release-path failure with a confusing cause.
build_dir="$c99_root/out/freebsd/build-install"
install_dir="$c99_root/out/freebsd/install"

# Start from nothing. A version bump renames `libwebtransport.so.<version>`, and
# `cmake --install` writes the new name without removing the old one, so a second
# packaging run leaves the PREVIOUS version in the install tree and the archive
# ships both libraries. Clearing both directories makes the install tree and the
# archive a function of this source tree alone, which is what a release artifact
# has to be.
rm -rf "$build_dir" "$install_dir"

cmake -S "$c99_root" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$install_dir" \
  -DBUILD_SHARED_LIBS=ON \
  -DWEBTRANSPORT_C99_BUILD_APPS=ON \
  -DWEBTRANSPORT_C99_BUILD_TESTS=ON

cmake --build "$build_dir" --config Release --parallel
cmake --install "$build_dir" --config Release
