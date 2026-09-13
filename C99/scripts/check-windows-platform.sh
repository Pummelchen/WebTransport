#!/bin/sh
# Compile the Windows branch of the platform header with a cross-compiler (WT-134).
#
# The `_WIN32` branch of `src/runtime/udp_platform.h` was written from the portability inventory and marked NOT
# VERIFIED, because nothing in this repository compiled it. A cross-compiler is enough to change that much: it
# says whether the branch COMPILES, which is a smaller claim than "the port works" and a much larger one than
# "written from the inventory". It is also cheap enough to run on every CI job that can install one.
#
# No cross-compiler means "not checked here" rather than a failure: the POSIX build is what this project ships,
# and a check that fails on a machine without a Windows toolchain would teach people to ignore it. The skip is
# printed with its reason, exactly like the IPv6 scenario's.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
probe="$root/tests/windows/platform_probe.c"

compiler=""
for candidate in x86_64-w64-mingw32-gcc i686-w64-mingw32-gcc; do
  if command -v "$candidate" >/dev/null 2>&1; then
    compiler="$candidate"
    break
  fi
done

if [ -z "$compiler" ]; then
  echo "windows platform: unsupported -- no mingw cross-compiler on this machine, so the _WIN32 branch is unchecked"
  exit 0
fi

output="$(mktemp -d)"
trap 'rm -rf "$output"' EXIT

# The warnings are the point: the same set the POSIX build uses, because a branch that only compiles without
# warnings would not be evidence of much. Found this way already: FIONBIO does not fit a signed long on Windows,
# and the cross-compile said so on its first run.
"$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
  -I "$root/src/runtime" -c "$probe" -o "$output/platform_probe.o"

echo "windows platform: the _WIN32 branch of udp_platform.h compiles under $compiler (compiled, not run)"
