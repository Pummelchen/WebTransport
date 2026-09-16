#!/bin/sh
#
# Cut a macOS release of this repository: both libraries, one version, one tag.
#
# RELEASE.md is the standard this implements. It is a two-library repository --
# the Swift package and, under C99/, a separate CMake C99 library -- and Part 2 is
# explicit that they carry the SAME version and that the C99 library "joins this
# tag and these notes rather than getting its own". So this produces one release
# with one artifact per library, not a Swift release with a C99 afterthought:
#
#   WebTransport-swift-<version>-macos-arm64.tar.gz   the two Swift CLI products
#   WebTransport-c99-<version>-macos-arm64.tar.gz     the C99 library, headers,
#                                                     CMake package and tools
#
# and the source of both is on the same Release through GitHub's own source
# archives for the tag (Source code (tar.gz) / Source code (zip)).
#
# Usage:
#   ./release-macos-arm64.sh               # dry run: build, package, checksum
#   ./release-macos-arm64.sh --dry-run     # the same, explicitly
#   ./release-macos-arm64.sh --publish     # also create the Release (clean, pushed
#                                          # HEAD; gh as the owner)
#   ./release-macos-arm64.sh --republish   # correct an existing Release: edit its
#                                          # title/notes and re-upload the assets
#
# What it asserts, and why each one is a check rather than a hope:
#
#   - `lipo -archs` is exactly `arm64` for every shipped Mach-O: both Swift
#     products, the C99 dylib, the C99 static library and the three C99 tools
#     (Part 1 §1.2.1-2: Apple Silicon only, asserted).
#   - The C99 library's identity is observable from the artifact alone: the install
#     tree must contain `libwebtransport.<version>.dylib`, so a build whose
#     filename and whose `VERSION` disagree cannot be packed (Part 1 §1.3).
#   - Each archive is named `<project>-<library>-<version>-macos-arm64.tar.gz`, the
#     library segment present because this is a two-library repository and the two
#     artifacts of one release have to be distinguishable (Part 1 §1.6).
#   - Each archive carries a `README-binaries.txt` stating the platform floor, that
#     the build is Apple-Silicon-only, and that the binaries are ad-hoc signed and
#     NOT notarized, with the quarantine command; the C99 one additionally names
#     the OpenSSL 3 runtime dependency the dylib is linked against (Part 1 §1.6).
#   - A `.sha256` is written beside each archive (Part 1 §1.2.5).
#   - `--publish` refuses unless the notes carry the pending placeholders or
#     already quote the real digests, substitutes the real digests and byte counts
#     into the published body only, and never copies a size or digest out of a dry
#     run (Part 1 §1.8).
#   - `--republish` exists because a published Release may need correcting (this
#     one did: it was first cut as "WebTransport Swift 1.4.0" with only the Swift
#     artifact). It edits the title and notes and re-uploads with --clobber, so the
#     tag and the URL stay and nothing is silently deleted.
#
# No resource bundles are shipped: the only `.bundle` in the tree belongs to a test
# product, not to a release artifact. Checked, not assumed (Part 1 §1.6).
#
# Nothing here fetches a dependency to make a gate pass (Part 1 §1.2.7). The two
# build scripts it calls use only the local toolchain and the system OpenSSL 3.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

mode=dry-run
case "${1:-}" in
  ""|--dry-run) mode=dry-run ;;
  --publish) mode=publish ;;
  --republish) mode=republish ;;
  *) echo "usage: $0 [--dry-run|--publish|--republish]" >&2; exit 2 ;;
esac

# --- identity, from the single source (Part 1 §1.3) ---------------------------
[ -f VERSION ] || { echo "VERSION is missing; it is the single source of the version" >&2; exit 1; }
version=$(head -n1 VERSION | tr -d '[:space:]')
printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || { echo "VERSION must be MAJOR.MINOR.PATCH (got '$version')" >&2; exit 1; }
./Swift/check-version-sync.sh >/dev/null \
  || { echo "the version mirrors disagree; run ./Swift/check-version-sync.sh --write" >&2; exit 1; }

tag="$version"
notes="docs/release-notes-v$version.md"
swift_archive="WebTransport-swift-$version-macos-arm64.tar.gz"
c99_archive="WebTransport-c99-$version-macos-arm64.tar.gz"
dist="$root/dist"

echo "== WebTransport $version (macOS arm64, both libraries)"
echo "   notes:   $notes"
echo "   output:  $dist/$swift_archive"
echo "            $dist/$c99_archive"
case "$mode" in
  dry-run)   echo "   mode:    dry run (nothing is uploaded, no tag is created)" ;;
  publish)   echo "   mode:    PUBLISH (creates the tag and the Release)" ;;
  republish) echo "   mode:    REPUBLISH (edits the existing Release in place)" ;;
esac

assert_arm64() {  # <path> <description>
  [ -e "$1" ] || { echo "missing release artifact: $1" >&2; exit 1; }
  archs=$(lipo -archs "$1")
  [ "$archs" = "arm64" ] || { echo "$2 is not arm64-only: lipo -archs says '$archs'" >&2; exit 1; }
  echo "   arm64: $2"
}

# --- the Swift products (the rigorous build, unchanged) -----------------------
"$root/Swift/build-release-apple-silicon.sh"

swift_artifacts="$root/Swift/.build/release-artifacts"
for product in WebTransportClient WebTransportServer; do
  assert_arm64 "$swift_artifacts/$product" "$product"
done

# --- the C99 library, headers, CMake package and tools ------------------------
"$root/C99/platform/macos26/compile-dylib.sh" >/dev/null

c99_install="$root/C99/out/macos26/install"
c99_dylib="$c99_install/lib/libwebtransport.$version.dylib"
[ -f "$c99_dylib" ] || {
  echo "the C99 install tree has no libwebtransport.$version.dylib;" >&2
  echo "its filenames and VERSION disagree, so the artifact cannot name itself (Part 1 §1.3)." >&2
  exit 1
}
assert_arm64 "$c99_dylib" "libwebtransport.$version.dylib"
assert_arm64 "$c99_install/lib/libwebtransport.a" "libwebtransport.a"
for tool in wt-client-c99 wt-server-c99 wt-conformance-c99; do
  assert_arm64 "$c99_install/bin/$tool" "$tool"
done

# --- stage the Swift archive (Part 1 §1.6) ------------------------------------
swift_stage=$(mktemp -d "${TMPDIR:-/tmp}/webtransport-swift-stage.XXXXXX")
c99_stage=$(mktemp -d "${TMPDIR:-/tmp}/webtransport-c99-stage.XXXXXX")
trap 'rm -rf "$swift_stage" "$c99_stage"' EXIT

for product in WebTransportClient WebTransportServer; do
  cp "$swift_artifacts/$product" "$swift_stage/$product"
  chmod 755 "$swift_stage/$product"
done
cp "$swift_artifacts/SHA256SUMS" "$swift_stage/SHA256SUMS"
cp LICENSE "$swift_stage/LICENSE"
cp THIRD_PARTY_NOTICES.md "$swift_stage/THIRD_PARTY_NOTICES.md"

cat > "$swift_stage/README-binaries.txt" <<EOF
WebTransport Swift $version -- macOS prebuilt binaries
======================================================

Library: the Swift package (WebTransport). The C99 library is the archive
WebTransport-c99-$version-macos-arm64.tar.gz of this same release; both carry
the version $version, and the repository's source for both is on this Release as
Source code (tar.gz) / Source code (zip).

Platform floor
  macOS 26 or later, Apple Silicon (arm64) only: M1, M2, M3, M4, M5, M6.
  These are thin arm64 Mach-O executables. There is no x86_64 build and no
  universal binary; \`lipo -archs\` reports exactly \`arm64\` for each one.

Contents
  WebTransportClient   the client CLI
  WebTransportServer   the server CLI
  SHA256SUMS           the digest of each binary above
  LICENSE              Apache License 2.0
  THIRD_PARTY_NOTICES.md  the licence of every third-party component

Not signed, not notarized
  These binaries are ad-hoc signed, NOT Developer ID signed, and NOT notarized.
  Gatekeeper therefore quarantines a downloaded copy on first run. After
  verifying the digest, clear the flag and run them:

    shasum -a 256 -c SHA256SUMS
    chmod +x WebTransportClient WebTransportServer
    xattr -dr com.apple.quarantine WebTransportClient WebTransportServer
    ./WebTransportServer --scenario all

  A downloaded release does not carry a file's mode, which is why the chmod is
  there as well. This is not a notarized build and must not be described as one.
EOF

# --- stage the C99 archive (Part 1 §1.6) --------------------------------------
cp -R "$c99_install/lib" "$c99_stage/lib"
cp -R "$c99_install/include" "$c99_stage/include"
cp -R "$c99_install/bin" "$c99_stage/bin"
mkdir -p "$c99_stage/share/doc/webtransport_c99"
cp "$c99_install/share/doc/webtransport_c99/THIRD_PARTY_NOTICES.md" "$c99_stage/share/doc/webtransport_c99/"
cp LICENSE "$c99_stage/LICENSE"

# What the dylib is linked against is a fact a user has to know before the library
# will load, so it is measured here rather than asserted from memory.
openssl_dep=$(otool -L "$c99_dylib" | awk '/libcrypto|libssl/ {print $1; exit}')
[ -n "$openssl_dep" ] || openssl_dep="(none)"

cat > "$c99_stage/README-binaries.txt" <<EOF
WebTransport C99 $version -- macOS prebuilt library
===================================================

Library: the portable C99 implementation. The Swift package is the archive
WebTransport-swift-$version-macos-arm64.tar.gz of this same release; both carry
the version $version, and the repository's source for both is on this Release as
Source code (tar.gz) / Source code (zip).

Platform floor
  macOS 26 or later, Apple Silicon (arm64) only: M1, M2, M3, M4, M5, M6.
  Everything here is thin arm64: \`lipo -archs\` reports exactly \`arm64\` for the
  dylib, the static library and each tool. There is no x86_64 build.

Runtime dependency: OpenSSL 3
  The dylib links the platform's OpenSSL 3 (\`find_package(OpenSSL 3.0 REQUIRED)\`)
  and is NOT bundled with it -- the project's documented decision is that this
  dependency comes from the platform, so security fixes arrive through the
  distributor's package updates. This build resolves it at:

    $openssl_dep

  macOS itself ships LibreSSL, not OpenSSL 3, so a machine without OpenSSL 3 in
  that location cannot load the dylib. Install it with \`brew install openssl@3\`
  (the same package this archive's build used), or link the static library
  \`lib/libwebtransport.a\` into your program together with your own OpenSSL 3.
  The three tools in \`bin/\` are not linked against the dylib's rpath; they need
  the same OpenSSL 3 present.

Contents
  lib/libwebtransport.$version.dylib   the shared library (with its .1.dylib and
                                       .dylib symlinks)
  lib/libwebtransport.a                the static library
  lib/cmake/webtransport_c99/          a CMake package: find_package(webtransport_c99)
  include/webtransport/                the public headers
  bin/wt-client-c99                    the client CLI
  bin/wt-server-c99                    the server CLI
  bin/wt-conformance-c99               the conformance CLI
  share/doc/webtransport_c99/THIRD_PARTY_NOTICES.md
  LICENSE                              Apache License 2.0

The library reports its own version: \`wt_version_string()\` returns "$version"
and \`wt_abi_version()\` returns the ABI version, which is a separate axis from the
library version and does not move with it.

Not signed, not notarized
  These are ad-hoc signed, NOT Developer ID signed, and NOT notarized. Gatekeeper
  therefore quarantines a downloaded copy on first run. After verifying the
  digest, clear the flag:

    xattr -dr com.apple.quarantine lib include bin
EOF

# --- archives + digests (Part 1 §1.2.5, §1.6) --------------------------------
rm -rf "$dist"
mkdir -p "$dist"
tar -czf "$dist/$swift_archive" -C "$swift_stage" .
tar -czf "$dist/$c99_archive" -C "$c99_stage" .
( cd "$dist" && shasum -a 256 "$swift_archive" > "$swift_archive.sha256" )
( cd "$dist" && shasum -a 256 "$c99_archive" > "$c99_archive.sha256" )

swift_digest=$(awk '{print $1}' "$dist/$swift_archive.sha256")
swift_bytes=$(wc -c < "$dist/$swift_archive" | tr -d ' ')
c99_digest=$(awk '{print $1}' "$dist/$c99_archive.sha256")
c99_bytes=$(wc -c < "$dist/$c99_archive" | tr -d ' ')

echo
echo "== staged"
printf '   %s\n     sha256 %s\n     bytes  %s\n' "$swift_archive" "$swift_digest" "$swift_bytes"
printf '   %s\n     sha256 %s\n     bytes  %s\n' "$c99_archive" "$c99_digest" "$c99_bytes"
( cd "$dist" && shasum -a 256 -c "$swift_archive.sha256" && shasum -a 256 -c "$c99_archive.sha256" )

# --- publish (Part 1 §1.7, §1.8) ---------------------------------------------
if [ "$mode" = dry-run ]; then
  echo
  echo "== dry run complete. Nothing was published, and no tag was created."
  echo "   Do not copy these digests or sizes into the notes: publishing rebuilds."
  exit 0
fi

[ -f "$notes" ] || { echo "release notes not found: $notes" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the tree is not clean; commit before publishing" >&2; exit 1; }
head_sha=$(git rev-parse HEAD)
upstream_sha=$(git rev-parse "@{upstream}" 2>/dev/null || true)
[ "$head_sha" = "$upstream_sha" ] || { echo "HEAD is not pushed (HEAD $head_sha, upstream ${upstream_sha:-none}); push before publishing" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated; the owner's account is required" >&2; exit 1; }

exists=0
if gh release view "$tag" --repo "Pummelchen/WebTransport" >/dev/null 2>&1; then exists=1; fi
if [ "$mode" = publish ] && [ "$exists" -eq 1 ]; then
  echo "release $tag already exists; use --republish to correct it, or bump VERSION for a new release" >&2
  exit 1
fi
if [ "$mode" = republish ] && [ "$exists" -eq 0 ]; then
  echo "release $tag does not exist; use --publish" >&2
  exit 1
fi
if [ "$mode" = republish ]; then
  # The tag must point at the tree the artifacts were built from, or the release
  # would ship binaries its own tag cannot reproduce. When a correction changes the
  # SOURCE (as this one did: the C99 install rpath and the gate that runs an
  # installed tool), the tag has to move with it. That is done here, loudly, and
  # only under --republish: HEAD is already known to be pushed, so nothing is lost.
  tag_sha=$(git rev-list -n1 "$tag")
  if [ "$tag_sha" != "$head_sha" ]; then
    echo "   NOTE: tag $tag is at $tag_sha but HEAD is $head_sha."
    echo "         The correction changed the released source, so the tag moves:"
    echo "           $tag_sha -> $head_sha"
    git tag -f -a "$tag" -m "WebTransport $version"
    git push --force origin "$tag"
  fi
fi

# The notes must carry the placeholders or the real digests (Part 1 §1.8): a
# release that quotes the wrong digest is worse than one that quotes none.
#
# ORDER MATTERS, and the first version of this got it wrong: `SHA256_PENDING` is a
# SUBSTRING of `C99_SHA256_PENDING`, so substituting the short token first rewrote
# the C99 line into `C99_<swift digest>` and left the C99 substitution with nothing
# to match. The published 1.4.0 body said exactly that, which is the failure this
# rule exists to prevent. The C99 tokens are substituted FIRST, and the result is
# then checked rather than trusted: no placeholder may survive, and each real digest
# must appear exactly once.
published_notes=$(mktemp "${TMPDIR:-/tmp}/webtransport-notes.XXXXXX")
trap 'rm -rf "$swift_stage" "$c99_stage" "$published_notes"' EXIT
if grep -q 'SHA256_PENDING' "$notes" || grep -q 'C99_SHA256_PENDING' "$notes"; then
  sed -e "s/C99_SHA256_PENDING/$c99_digest/" \
      -e "s/C99_ARCHIVE_BYTES_PENDING/$c99_bytes/" \
      -e "s/SHA256_PENDING/$swift_digest/" \
      -e "s/ARCHIVE_BYTES_PENDING/$swift_bytes/" "$notes" > "$published_notes"
elif grep -q "$swift_digest" "$notes" && grep -q "$c99_digest" "$notes"; then
  cp "$notes" "$published_notes"
else
  echo "$notes carries neither the placeholders nor both real digests; refusing to publish" >&2
  exit 1
fi

if grep -q 'PENDING' "$published_notes"; then
  echo "a placeholder survived substitution in the published notes; refusing to publish" >&2
  grep -n 'PENDING' "$published_notes" >&2
  exit 1
fi
for pair in "$swift_digest swift" "$c99_digest c99"; do
  digest=${pair%% *}
  which=${pair##* }
  count=$(grep -c "$digest" "$published_notes" || true)
  if [ "$count" -ne 1 ]; then
    echo "the $which digest appears $count time(s) in the published notes, expected exactly 1" >&2
    echo "  digest: $digest" >&2
    grep -n 'SHA256:' "$published_notes" >&2
    exit 1
  fi
done

if [ "$mode" = publish ]; then
  git tag -a "$tag" -m "WebTransport $version"
  git push origin "$tag"
  gh release create "$tag" \
    "$dist/$swift_archive" "$dist/$swift_archive.sha256" \
    "$dist/$c99_archive" "$dist/$c99_archive.sha256" \
    --repo "Pummelchen/WebTransport" --title "WebTransport $version" \
    --notes-file "$published_notes" --latest
  echo
  echo "== published $tag with both artifacts."
else
  gh release edit "$tag" --repo "Pummelchen/WebTransport" \
    --title "WebTransport $version" --notes-file "$published_notes" --latest
  gh release upload "$tag" \
    "$dist/$swift_archive" "$dist/$swift_archive.sha256" \
    "$dist/$c99_archive" "$dist/$c99_archive.sha256" \
    --repo "Pummelchen/WebTransport" --clobber
  echo
  echo "== republished $tag: title, notes and both artifacts updated in place."
fi

echo "   Verify it yourself:"
echo "     gh release view $tag --repo Pummelchen/WebTransport"
echo "     the body must quote $swift_digest and $c99_digest, and the assets must be"
echo "     the two archives with a .sha256 beside each"
