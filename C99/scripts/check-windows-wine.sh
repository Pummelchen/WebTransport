#!/bin/sh
# RUN the Windows tree under Wine (WT-134).
#
# `check-windows-build.sh` compiles and LINKS the whole tree for 64-bit Windows, which is the strongest claim
# a Linux runner can make without Windows, and says "linked, not run here" so nobody reads it as more.
# This script closes that gap where it can be closed: it RUNS every linked test executable under Wine, so the
# claim becomes "the tree executes on Windows" rather than "the tree builds for Windows".
#
# What it found is why it exists: the first run was 82 of 84, and the two failures were REAL defects in the
# `_WIN32` receive path -- a truncated datagram reported as a limit error with the sender dropped (`WT-199`), and
# a Retry path that depended on it (`WT-200`) -- plus, behind them, a `WSARecvMsg` prototype this tree had
# declared BY HAND with one parameter too many, which no cross-compile could see because the declaration was its
# own. The run is green now, and `tests/windows/test_windows_udp.c` was added so that the fallback that a working
# provider never takes is measured rather than assumed.
#
# Two things stop this working, and both cost the previous attempt a session:
#
#   * `wine64` is not on PATH on Ubuntu and Debian. The package ships no wrapper -- the binary is
#     /usr/lib/wine/wine64 -- so `wine64 --version` is "command not found" while the runtime is installed.
#   * A test executable imports TWO sets of DLLs: the target's OpenSSL, and the tree's own
#     `libwebtransport.dll`. Wine resolves a PE's imports from the executable's own directory before
#     anywhere else, so a DLL missing there is a LOAD failure -- status c0000135, whose low byte is 53,
#     which is what a first run reports as a silent `rc=53` from every test with nothing on stdout. The
#     message itself only appears on stderr under a debug channel, so it reads as the tests exiting quietly.
#
# Every run is bounded by WT_WINDOWS_WINE_TIMEOUT (default 30s). A test that hangs is reported as a hang with
# its elapsed time rather than being allowed to consume the budget: "this one binary hangs under Wine" is a
# result, and "the run never finished" is not.
#
# Set WT_WINDOWS_BUILD_DIR to the linked tree (default C99/out/windows/build). A machine without Wine, or
# without that tree, reports `unsupported` with the reason rather than failing -- the same shape as the
# compile and link checks, because a host that cannot do this is a fact about the host.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"

wine=""
for candidate in wine wine64 /usr/lib/wine/wine64 /usr/lib/wine/wine; do
  if command -v "$candidate" >/dev/null 2>&1; then
    wine="$candidate"
    break
  fi
  if [ -x "$candidate" ]; then
    wine="$candidate"
    break
  fi
done

if [ -z "$wine" ]; then
  echo "windows wine: unsupported -- no Wine on this machine (apt-get install wine64)"
  exit 0
fi

build_dir="${WT_WINDOWS_BUILD_DIR:-$root/out/windows/build}"
if [ ! -d "$build_dir" ]; then
  echo "windows wine: unsupported -- no linked Windows tree at $build_dir (run check-windows-build.sh first)"
  exit 0
fi

openssl_prefix="${WT_WINDOWS_OPENSSL:-}"
if [ -z "$openssl_prefix" ]; then
  for candidate in /tmp/windows-openssl/mingw64 /tmp/winssl/mingw64 /opt/windows-openssl/mingw64; do
    if [ -f "$candidate/include/openssl/ssl.h" ]; then
      openssl_prefix="$candidate"
      break
    fi
  done
fi

per_test_limit="${WT_WINDOWS_WINE_TIMEOUT:-30}"
export WINEPREFIX="${WINEPREFIX:-${HOME:-/root}/.wine}"
export WINEDEBUG="${WINEDEBUG:--all}"
# The console tests need no display, and Wine's tray/explorer attempts are noise in a container.
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}"

# Stage both DLL sets beside the executables, which is where Wine looks first.
if [ -d "$build_dir/tests" ]; then
  for dll in "$build_dir"/*.dll; do
    [ -f "$dll" ] && cp "$dll" "$build_dir/tests/" 2>/dev/null || true
  done
  if [ -n "$openssl_prefix" ]; then
    for dll in "$openssl_prefix"/bin/*.dll; do
      [ -f "$dll" ] && cp "$dll" "$build_dir/tests/" 2>/dev/null || true
    done
  fi
fi

# Initialize the prefix once, on its own and bounded: Wine builds it on first use, and that first-use setup
# is exactly the kind of thing that reads as a hang when it happens under a test run.
"$wine" wineboot -u >/dev/null 2>&1 || true

passed=0
failed=0
hung=0
total=0

for exe in "$build_dir"/tests/test_*.exe; do
  [ -f "$exe" ] || continue
  name=$(basename "$exe" .exe)
  total=$((total + 1))
  if timeout "$per_test_limit" "$wine" "$exe" >"/tmp/wt-wine-$name.out" 2>&1; then
    status=0
  else
    status=$?
  fi
  if [ "$status" -eq 124 ]; then
    hung=$((hung + 1))
    echo "windows wine: $name HANGS (killed at ${per_test_limit}s)"
  elif [ "$status" -eq 0 ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "windows wine: $name FAILED (exit $status)"
    tail -3 "/tmp/wt-wine-$name.out" | sed 's/^/               /'
  fi
done

if [ "$total" -eq 0 ]; then
  echo "windows wine: unsupported -- no test executables under $build_dir/tests"
  exit 0
fi

echo "windows wine: ran $total test executable(s) -- $passed passed, $failed failed, $hung hung"
[ "$failed" -eq 0 ] && [ "$hung" -eq 0 ]
