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

# The warnings are the point: a branch that only compiles without warnings would not be evidence of much. These
# four command lines use a deliberate SEVEN-FLAG SUBSET of the project's warning set
# (-Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual). The full set -- the twenty-four
# flags cmake/WTCompilerWarnings.cmake probes and applies to every target -- is what the Windows BUILD enforces,
# because scripts/check-windows-build.sh configures the tree with CMake and the mingw toolchain; docs/PORTABILITY.md
# states the same subset. The comment here used to claim this sweep used "the same set the POSIX build uses",
# which was false. Found this way already: FIONBIO does not fit a signed long on Windows, and the cross-compile
# said so on its first run.
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
#
# WHERE those headers come from matters for a cross-compile. A Windows OpenSSL (unpacked from the MSYS2
# tarball) is searched with `-I`, because it is the target's own headers. A HOST installation -- Homebrew's, or
# the distribution's `libssl-dev` -- is searched with `-idirafter` instead: `-I /usr/include` on a cross-compile
# puts the host's glibc headers in FRONT of the target's, which is exactly how this check failed on the Linux
# runner. `#include <stdint.h>` resolved to the host's copy and then wanted `bits/libc-header-start.h`, which a
# Windows target does not have. `-idirafter` searches that directory after every target directory, so the
# standard headers stay the target's and only OpenSSL's own come from the host.
openssl_flags=""
openssl_origin=""
# WT_WINDOWS_OPENSSL is the prefix `check-windows-build.sh` takes, so a CI job that has already unpacked the
# MSYS2 package points both checks at the same headers with the same variable.
for candidate in "${WT_WINDOWS_OPENSSL_INCLUDE:-}" \
                 "${WT_WINDOWS_OPENSSL:+$WT_WINDOWS_OPENSSL/include}" \
                 /tmp/windows-openssl/mingw64/include; do
  [ -n "$candidate" ] || continue
  if [ -f "$candidate/openssl/ssl.h" ]; then
    openssl_flags="-I $candidate"
    openssl_origin="$candidate (target headers)"
    break
  fi
done
if [ -z "$openssl_flags" ]; then
  for candidate in /opt/homebrew/opt/openssl@3/include /opt/homebrew/include \
                   /usr/local/include /usr/include; do
    if [ -f "$candidate/openssl/ssl.h" ]; then
      openssl_flags="-idirafter $candidate"
      openssl_origin="$candidate (host headers, searched after the target's)"
      # Debian and Ubuntu split the host's OpenSSL headers: `openssl/ssl.h` is in /usr/include and
      # `openssl/opensslconf.h` is in the multiarch directory, so both have to be searched or the host fallback
      # does not compile at all.
      for extra in /usr/include/*-linux-gnu; do
        if [ -f "$extra/openssl/opensslconf.h" ]; then
          openssl_flags="$openssl_flags -idirafter $extra"
        fi
      done
      break
    fi
  done
fi

checked=0
skipped=0
for source in $(find "$root/src" -name '*.c' | sort); do
  if [ -z "$openssl_flags" ] && grep -q '#include <openssl' "$source"; then
    skipped=$((skipped + 1))
    continue
  fi
  # shellcheck disable=SC2086 # the flags are a list on purpose: one word or two, never a path with spaces.
  "$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
    -I "$root/include" $openssl_flags -c "$source" -o "$output/library.o"
  checked=$((checked + 1))
done

# The TESTS and the APPS too, with the include paths and the one define CMake gives them: a Windows port is only
# worth a runner if the whole tree compiles, and the sweep is what makes that a measurement. The trust-fixture
# directory is a path, not a file read, so it needs no fixtures to compile. `src/runtime` is on the include path
# because the Windows datagram test includes the private platform header directly -- the same header `udp.c`
# includes -- which is what makes the `_WIN32` branch's behaviour reachable by a test and not only by the library.
checked_tree=0
skipped_tree=0
for source in $(find "$root/tests" "$root/apps" -name '*.c' | sort); do
  case "$source" in
    */windows/platform_probe.c) continue ;;
  esac
  if [ -z "$openssl_flags" ] && grep -q '#include <openssl' "$source"; then
    skipped_tree=$((skipped_tree + 1))
    continue
  fi
  # shellcheck disable=SC2086 # the flags are a list on purpose: one word or two, never a path with spaces.
  "$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
    -DWT_TRUST_FIXTURE_DIR='"'"'""'"'"' \
    -I "$root/include" $openssl_flags -I "$root/tests" -I "$root/tests/unit" \
    -I "$root/tests/vectors" -I "$root/apps/support" -I "$root/src/runtime" \
    -c "$source" -o "$output/tree.o"
  checked_tree=$((checked_tree + 1))
done

if [ -n "$openssl_origin" ]; then
  echo "windows platform: OpenSSL headers from $openssl_origin"
fi
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
