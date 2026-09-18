#!/bin/sh
#
# WT-262: prove that resolving a server identity needs no unlocked keychain.
#
# macOS's `SecPKCS12Import` files the identity into the DEFAULT KEYCHAIN unless it is
# given `kSecImportToMemoryOnly`, so on a normal machine -- where the login keychain is
# unlocked -- the broken and the fixed code both pass and a CI runner would not tell them
# apart. This check gives the process the state that failed: a default keychain that
# exists and is LOCKED, which is what a headless server and a CI job with no login session
# have. The PKCS#12 suites must pass anyway.
#
# It changes the user's default keychain for the duration and restores it on every exit
# path, including a signal. Run it where that is acceptable: CI, or a machine whose
# keychain may point at a temporary one for the length of one `swift test --skip-build`.
#
# The build happens BEFORE the keychain is locked: it has no reason to depend on the
# keychain, and if it did, the failure would be blamed on this check rather than on the
# build.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

command -v security >/dev/null 2>&1 || {
  echo "security(1) is required; this check is macOS-only" >&2
  exit 1
}

original_default=$(security default-keychain -d user | tr -d ' "')
[ -n "$original_default" ] || {
  echo "no default keychain found to restore afterwards; refusing to run" >&2
  exit 1
}

# Canonical, because macOS reports the same directory as /var/... from mktemp and as
# /private/var/... from security(1), and the check below compares the two spellings.
work=$(CDPATH= cd -- "$(mktemp -d "${TMPDIR:-/tmp}/wt-pkcs12-keychain.XXXXXX")" && pwd -P)
locked="$work/locked.keychain-db"
restored=0
restore() {
  [ "$restored" -eq 1 ] && return 0
  restored=1
  security default-keychain -s "$original_default" >/dev/null 2>&1 || true
  security delete-keychain "$locked" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== building the tests while the keychain is still usable"
swift build --build-tests

echo "== making a locked keychain the default: $locked"
security create-keychain -p "$(uuidgen)" "$locked"
security lock-keychain "$locked"
security default-keychain -s "$locked" >/dev/null

current=$(security default-keychain -d user | tr -d ' "')
[ "$current" = "$locked" ] || {
  echo "could not make the locked keychain the default (default is '$current')" >&2
  exit 1
}

# Every name below resolves a PKCS#12 bundle. If the import files the identity into the
# default keychain, this is where it fails with OSStatus -26276: the bundle is decoded and
# then the locked keychain refuses it. With the memory-only import it never gets that far.
swift test --skip-build --filter pkcs12

echo
echo "== pkcs12 identity resolution needs no unlocked keychain"
