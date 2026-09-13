#!/bin/sh
# Compile the Windows branch of the platform header with a cross-compiler (WT-134).
#
# The `_WIN32` branch of the platform layer was written from the portability inventory and marked NOT
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
  -I "$root/src/runtime" -I "$root/include" -c "$probe" -o "$output/platform_probe.o"

# And the whole platform translation unit, which is the stronger claim: udp.c itself, with the address layer and
# the error classification inside the header. It compiles for Windows now -- and getting there found three more
# real differences the inventory had not named: `EHOSTDOWN` does not exist there, `inet_ntop` takes a `size_t`
# rather than a `socklen_t`, and `setsockopt` wants a `const char *` for its option value.
"$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
  -I "$root/include" -c "$root/src/runtime/udp.c" -o "$output/udp.o"

# And then the whole library, which is the claim a Windows port would need before a runner is worth adding. The
# OpenSSL headers are only needed to COMPILE the crypto and TLS sources; a machine without them still checks
# everything else and says how many it skipped, rather than reporting a pass it did not earn.
openssl_include=""
for candidate in /opt/homebrew/opt/openssl@3/include /opt/homebrew/include /usr/local/include /usr/include; do
  if [ -f "$candidate/openssl/ssl.h" ]; then
    openssl_include="$candidate"
    break
  fi
done

checked=0
skipped=0
for source in $(find "$root/src" -name '*.c' | sort); do
  if [ -z "$openssl_include" ] && grep -q '#include <openssl' "$source"; then
    skipped=$((skipped + 1))
    continue
  fi
  "$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
    -I "$root/include" -I "$openssl_include" -c "$source" -o "$output/library.o"
  checked=$((checked + 1))
done

# The TESTS and the APPS too, with the include paths and the one define CMake gives them: a Windows port is only
# worth a runner if the whole tree compiles, and the sweep is what makes that a measurement. The trust-fixture
# directory is a path, not a file read, so it needs no fixtures to compile.
checked_tree=0
skipped_tree=0
for source in $(find "$root/tests" "$root/apps" -name '*.c' | sort); do
  case "$source" in
    */windows/platform_probe.c) continue ;;
  esac
  if [ -z "$openssl_include" ] && grep -q '#include <openssl' "$source"; then
    skipped_tree=$((skipped_tree + 1))
    continue
  fi
  "$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
    -DWT_TRUST_FIXTURE_DIR='"'"'""'"'"' \
    -I "$root/include" -I "$openssl_include" -I "$root/tests" -I "$root/tests/unit" \
    -I "$root/tests/vectors" -I "$root/apps/support" -c "$source" -o "$output/tree.o"
  checked_tree=$((checked_tree + 1))
done

if [ "$skipped" -gt 0 ]; then
  echo "windows platform: $checked of the library's sources compile under $compiler; $skipped need OpenSSL headers this machine does not have"
else
  echo "windows platform: udp_platform.h's _WIN32 branch and all $checked of the library's sources compile under $compiler (compiled, not run)"
fi
if [ "$skipped_tree" -gt 0 ]; then
  echo "windows platform: $checked_tree of the tests' and apps' sources compile; $skipped_tree need OpenSSL headers this machine does not have"
else
  echo "windows platform: all $checked_tree of the tests' and apps' sources compile under $compiler too (compiled, not run)"
fi
