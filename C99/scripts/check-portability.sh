#!/bin/sh
# The portability inventory must stay complete (WT-134).
#
# docs/PORTABILITY.md lists what a Windows or FreeBSD build needs. A document like that rots the moment somebody
# adds a POSIX call somewhere new, so this greps the tree for the POSIX-only names the code uses and fails if one
# is used without being named in the document -- the same "check the document against the tree" pattern as the
# compliance matrix, for the same reason: an inventory that reads like a plan but is out of date is worse than
# none.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
doc="$root/docs/PORTABILITY.md"
[ -f "$doc" ] || { echo "portability: $doc is missing"; exit 1; }

# The inventory of platform-adapted calls: every name here is a call, a flag or a
# macro whose spelling or declaration differs on Windows, so each one has to be named
# in docs/PORTABILITY.md. The list is the check's source of truth; a new platform call
# added to src/runtime/udp_platform.h or src/runtime/udp.c must be added here AND to
# the document, which is what makes the document and the tree fail together when one
# of them drifts. The list used to hold nine names while the library also called
# inet_ntop, setsockopt, getsockopt, socket and bind, so those five could never fail
# the check (F-26).
#
# THE LIST IS THE LIMIT, AND IT IS A HAND-MAINTAINED ONE. This check cannot see a
# platform-only call whose name nobody has added here: `getpid()` -- a POSIX call MSVC
# does not have -- passes it, which was demonstrated rather than assumed (AUD-0019).
# What catches that case is the Windows half of the matrix: `msvc`, `clang-cl` and
# `windows-native` in c99-ci.yml all configure, build and ctest the library, so a call
# that does not exist on Windows fails the build. This check keeps the DOCUMENT honest;
# those builds are what keep the CODE honest. Saying so here is the point -- a reader
# who took the old success line ("every POSIX-only name the library uses is in the
# inventory") for a universal claim was reading a stronger statement than the mechanism
# could make. Widening this list is cheap and was done again here: the library was
# calling `htons`, `ntohs` and `clock_gettime` without any of them being checked.
posix_names="close fcntl O_NONBLOCK poll errno recvmsg sendmsg MSG_PEEK MSG_TRUNC sendto recvfrom snprintf inet_pton inet_ntop setsockopt getsockopt socket bind htons ntohs clock_gettime"
missing=0
for name in $posix_names; do
  # Where the name is USED, in the library and the apps (a test may use it freely; the library is what ships).
  used="$(grep -rlw "$name" "$root/src" "$root/include" 2>/dev/null || true)"
  [ -n "$used" ] || continue
  if ! grep -qw "$name" "$doc"; then
    echo "portability: $name is used in the library but is not in the inventory"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "portability: $missing POSIX-only name(s) missing from the inventory"
  exit 1
fi
echo "portability: every name on the checker's list that the library uses is in the inventory"
echo "portability: a POSIX-only name NOT on that list is caught by the Windows builds, which compile"
echo "portability: the library for MSVC, clang-cl and MSYS2 (c99-ci.yml); this check covers the list."
