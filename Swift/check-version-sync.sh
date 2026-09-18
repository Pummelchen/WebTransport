#!/bin/bash
#
# Verifies that the three declarations of the library version agree.
#
# The version is single-sourced from the repository-root `VERSION` file. C has no
# way to read a file at compile time, and SwiftPM has no way to pull a sibling
# file into a target as a constant, so the value is MIRRORED in two build-time
# declarations:
#
#   VERSION                                                   authoritative
#   C99/include/webtransport/version.h   WT_VERSION_*          mirror
#   Swift/Sources/WebTransport/WebTransportVersion.swift       mirror
#
# The two libraries ship together and must carry the same number, because a
# caller pairing a Swift client with a C99 server has no other way to know the
# pair is compatible. Nothing reads one of these on its own, so without this
# check a bump that updated one file and missed another would ship silently --
# which is the drift this exists to prevent.
#
# `WT_ABI_VERSION` (and its Swift mirror) is deliberately NOT compared: it moves
# only for a breaking layout or signature change, which a version bump does not
# imply. Comparing it would force a bug-fix release to claim a new ABI, which is
# the opposite of what that number is for.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION_FILE="VERSION"
C99_HEADER="C99/include/webtransport/version.h"
SWIFT_SOURCE="Swift/Sources/WebTransport/WebTransportVersion.swift"

fail() { echo "error: $*" >&2; exit 1; }

read_macro() {  # <file> <MACRO>
    sed -n "s/^#define $2[[:space:]]*\([0-9][0-9]*\).*/\1/p" "$1" | head -n1
}

# --- the authoritative value -------------------------------------------------
[ -f "$VERSION_FILE" ] || fail "$VERSION_FILE is missing; it is the single source of the library version"
version="$(head -n1 "$VERSION_FILE" | tr -d '[:space:]')"
# Releases are MAJOR.MINOR. A third component is still accepted so the existing
# 1.5.2 line keeps validating, but a release must not introduce one: the C99 side
# prints no patch when it is 0, so a three-part release would ship a version
# string that disagrees with the tag.
printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+(\.[0-9]+)?$' \
    || fail "$VERSION_FILE must be MAJOR.MINOR (got '$version')"

major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"
case "$rest" in
    *.*) patch="${rest#*.}" ;;
    *) patch=0 ;;
esac

# `--write` propagates VERSION into the two mirrors, so a release needs one edit
# (VERSION) plus one command -- not three careful edits and a hope. It runs
# before the comparison and then falls through to it, so a write that did not
# take is caught here rather than at the next release.
if [ "${1:-}" = "--write" ]; then
    tmp_c="$(mktemp "${TMPDIR:-/tmp}/wt-version-c.XXXXXX")"
    tmp_s="$(mktemp "${TMPDIR:-/tmp}/wt-version-s.XXXXXX")"
    trap 'rm -f "$tmp_c" "$tmp_s"' EXIT

    sed -e "s/^\(#define WT_VERSION_MAJOR[[:space:]]*\)[0-9][0-9]*/\1$major/" \
        -e "s/^\(#define WT_VERSION_MINOR[[:space:]]*\)[0-9][0-9]*/\1$minor/" \
        -e "s/^\(#define WT_VERSION_PATCH[[:space:]]*\)[0-9][0-9]*/\1$patch/" \
        "$C99_HEADER" > "$tmp_c" || fail "could not rewrite $C99_HEADER"
    sed -e "s/\(public static let library = \"\)[0-9][0-9.]*\(\"\)/\1$version\2/" \
        "$SWIFT_SOURCE" > "$tmp_s" || fail "could not rewrite $SWIFT_SOURCE"

    cmp -s "$tmp_c" "$C99_HEADER" || { mv "$tmp_c" "$C99_HEADER"; echo "wrote $version into $C99_HEADER"; }
    cmp -s "$tmp_s" "$SWIFT_SOURCE" || { mv "$tmp_s" "$SWIFT_SOURCE"; echo "wrote $version into $SWIFT_SOURCE"; }
fi

# --- the C99 mirror ----------------------------------------------------------
[ -f "$C99_HEADER" ] || fail "$C99_HEADER is missing"
c_major="$(read_macro "$C99_HEADER" WT_VERSION_MAJOR)"
c_minor="$(read_macro "$C99_HEADER" WT_VERSION_MINOR)"
c_patch="$(read_macro "$C99_HEADER" WT_VERSION_PATCH)"
[ -n "$c_major" ] && [ -n "$c_minor" ] && [ -n "$c_patch" ] \
    || fail "$C99_HEADER: could not read WT_VERSION_MAJOR/MINOR/PATCH"

# The mirror is read back the way wt_version_string() prints it: a zero patch is
# omitted, so a release at 1.6 is compared as "1.6" and not "1.6.0". Without this
# the write below succeeds and the comparison immediately rejects its own output.
c_version="$c_major.$c_minor"
[ "$c_patch" = "0" ] || c_version="$c_version.$c_patch"

# --- the Swift mirror --------------------------------------------------------
[ -f "$SWIFT_SOURCE" ] || fail "$SWIFT_SOURCE is missing"
s_version="$(sed -n 's/.*public static let library = "\([0-9][0-9.]*\)".*/\1/p' "$SWIFT_SOURCE" | head -n1)"
[ -n "$s_version" ] || fail "$SWIFT_SOURCE: could not read 'public static let library'"

# --- the ABI mirror ----------------------------------------------------------
# The two libraries must carry the SAME ABI version on a release, even though the
# ABI is a separate axis from the library version: a caller pairing them checks one
# number, so a disagreement is the same class of defect as a version mismatch.
c_abi="$(read_macro "$C99_HEADER" WT_ABI_VERSION)"
s_abi="$(sed -n 's/.*public static let abi = \([0-9][0-9]*\).*/\1/p' "$SWIFT_SOURCE" | head -n1)"
[ -n "$c_abi" ] || fail "$C99_HEADER: could not read WT_ABI_VERSION"
[ -n "$s_abi" ] || fail "$SWIFT_SOURCE: could not read 'public static let abi'"

# --- they must all say the same thing ----------------------------------------
status=0
if [ "$c_abi" != "$s_abi" ]; then
    echo "error: ABI versions disagree: $C99_HEADER declares $c_abi, $SWIFT_SOURCE declares $s_abi; they must be identical on a release" >&2
    status=1
fi
if [ "$c_version" != "$version" ]; then
    echo "error: $C99_HEADER declares $c_version, but $VERSION_FILE says $version" >&2
    status=1
fi
if [ "$s_version" != "$version" ]; then
    echo "error: $SWIFT_SOURCE declares $s_version, but $VERSION_FILE says $version" >&2
    status=1
fi
[ "$status" -eq 0 ] \
    || fail "the two libraries would ship at different versions; bump all three together"

echo "version $version agrees across $VERSION_FILE, $C99_HEADER and $SWIFT_SOURCE"
