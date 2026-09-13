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

posix_names="fcntl poll recvmsg sendmsg inet_pton recvfrom sendto close O_NONBLOCK"
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
echo "portability: every POSIX-only name the library uses is in the inventory"
