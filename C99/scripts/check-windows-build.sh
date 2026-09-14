#!/bin/sh
# Link the whole tree for 64-bit Windows (WT-134).
#
# `check-windows-platform.sh` compiles the tree for Windows; this goes one step further and LINKS it, which is
# the claim a Windows runner needs: every test and app becomes a PE32+ executable. It needs two things the
# compile check does not -- a mingw toolchain and a WINDOWS OpenSSL -- so a machine without them reports
# `unsupported` with the reason and the one command that would fix it, rather than a failure.
#
# What it does NOT do is RUN the binaries: PE32+ executables need Windows or Wine.
# `scripts/check-windows-wine.sh` is the sibling that runs them, so a machine with Wine gets the behaviour too;
# this script's own output says "linked, not run here" so nobody reads it as more, and nothing reads it as
# "nothing runs them".
#
# Set WT_WINDOWS_OPENSSL to a Windows OpenSSL prefix (see cmake/toolchains/mingw-w64.cmake for the MSYS2
# package that provides one). Without it the script looks in the usual places and skips if it finds nothing.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"

compiler=""
for candidate in x86_64-w64-mingw32-gcc; do
  if command -v "$candidate" >/dev/null 2>&1; then
    compiler="$candidate"
    break
  fi
done

if [ -z "$compiler" ]; then
  echo "windows build: unsupported -- no mingw cross-compiler on this machine (brew install mingw-w64,"
  echo "               or apt-get install gcc-mingw-w64-x86-64)"
  exit 0
fi

openssl_prefix="${WT_WINDOWS_OPENSSL:-}"
if [ -z "$openssl_prefix" ]; then
  for candidate in /tmp/winssl/mingw64 /opt/windows-openssl/mingw64; do
    if [ -f "$candidate/include/openssl/ssl.h" ]; then
      openssl_prefix="$candidate"
      break
    fi
  done
fi

if [ -z "$openssl_prefix" ] || [ ! -f "$openssl_prefix/include/openssl/ssl.h" ]; then
  echo "windows build: unsupported -- no Windows OpenSSL prefix (set WT_WINDOWS_OPENSSL). One is an MSYS2"
  echo "               package: curl -LO https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-openssl-<version>-any.pkg.tar.zst"
  echo "               then: zstd -d <pkg> -o openssl.tar && tar -xf openssl.tar"
  exit 0
fi

build_dir="${WT_WINDOWS_BUILD_DIR:-$root/out/windows/build}"
rm -rf "$build_dir"

cmake -S "$root" -B "$build_dir" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$root/cmake/toolchains/mingw-w64.cmake" \
  -DWT_WINDOWS_OPENSSL="$openssl_prefix" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null

cmake --build "$build_dir"

executables=$(find "$build_dir" -name '*.exe' | wc -l | tr -d ' ')
libraries=$(find "$build_dir" -maxdepth 1 -name '*.dll' | wc -l | tr -d ' ')
echo "windows build: linked $executables PE32+ executables and $libraries shared library under $compiler"
echo "               (linked, not run HERE -- scripts/check-windows-wine.sh runs them under Wine)"
