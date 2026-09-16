#!/bin/sh
#
# Cut a macOS release of the Swift products: build, package, checksum, and -- only
# with --publish -- create the GitHub Release.
#
# RELEASE.md is the standard this implements (Part 1 §1.2-§1.9, and Part 2's
# "WebTransport -- Swift and C99, semantic version, 11 releases"). It ships only the
# Swift products today; the C99 library is built and tested but not released, so the
# notes must say which library is not built, and this script prints that too.
#
# Usage:
#   Swift/release-macos-arm64.sh              # dry run: build, package, checksum
#   Swift/release-macos-arm64.sh --dry-run    # the same, explicitly
#   Swift/release-macos-arm64.sh --publish    # also create the Release (needs a clean,
#                                             # pushed HEAD and gh as the owner)
#
# What it asserts, and why each one is a check rather than a hope:
#
#   - `lipo -archs` is exactly `arm64` for every shipped binary (Part 1 §1.2.1-2:
#     Apple Silicon only, asserted rather than assumed). A fat binary is a release
#     defect, not an option, and this fails on one.
#   - The archive is named `WebTransport-swift-<version>-macos-arm64.tar.gz`, the
#     library segment present because this is a two-library repository and the two
#     artifacts of one release have to be distinguishable (Part 1 §1.6).
#   - The archive carries the binaries, LICENSE, THIRD_PARTY_NOTICES.md and a
#     `README-binaries.txt` that states the platform floor, that the build is
#     Apple-Silicon-only, and that the binaries are ad-hoc signed and NOT notarized,
#     with the quarantine command (Part 1 §1.6).
#   - A `.sha256` is written beside the archive, because a binary with no digest
#     beside it is not a release asset (Part 1 §1.2.5).
#   - `--publish` refuses unless the notes carry `SHA256_PENDING` /
#     `ARCHIVE_BYTES_PENDING` or already quote the real values, substitutes the real
#     ones into the published body only, and never copies a size or digest out of a
#     dry run (Part 1 §1.8).
#   - No resource bundles are shipped because these two products produce none: a
#     `.bundle` in the tree belongs to a test product (`WebTransportNetworkRuntimeTests`),
#     which is not a release artifact. That was checked, not assumed (Part 1 §1.6
#     names the failure mode: a Swift binary without its `.bundle` fails at runtime).
#
# Nothing here fetches a dependency to make a gate pass (Part 1 §1.2.7). The build
# script it calls has no network use at all.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$root"

publish=0
case "${1:-}" in
  ""|--dry-run) publish=0 ;;
  --publish) publish=1 ;;
  *) echo "usage: $0 [--dry-run|--publish]" >&2; exit 2 ;;
esac

# --- identity, from the single source (Part 1 §1.3) ---------------------------
[ -f VERSION ] || { echo "VERSION is missing; it is the single source of the version" >&2; exit 1; }
version=$(head -n1 VERSION | tr -d '[:space:]')
printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || { echo "VERSION must be MAJOR.MINOR.PATCH (got '$version')" >&2; exit 1; }
./Swift/check-version-sync.sh >/dev/null || { echo "the version mirrors disagree; run ./Swift/check-version-sync.sh --write" >&2; exit 1; }

tag="$version"
project="WebTransport"
library="swift"
archive_name="$project-$library-$version-macos-arm64.tar.gz"
notes="docs/release-notes-v$version.md"
artifacts="$script_dir/.build/release-artifacts"
dist="$root/dist"

echo "== $project $library $version (macOS arm64)"
echo "   notes:   $notes"
echo "   output:  $dist/$archive_name"
[ "$publish" -eq 1 ] && echo "   mode:    PUBLISH" || echo "   mode:    dry run (nothing is uploaded)"

# --- build the binaries (the rigorous build, unchanged) -----------------------
"$script_dir/build-release-apple-silicon.sh"

# --- assert the architecture on every shipped binary (Part 1 §1.2.2) ----------
for product in WebTransportClient WebTransportServer; do
  [ -x "$artifacts/$product" ] || { echo "missing release binary: $artifacts/$product" >&2; exit 1; }
  archs=$(lipo -archs "$artifacts/$product")
  [ "$archs" = "arm64" ] || { echo "$product is not arm64-only: lipo -archs says '$archs'" >&2; exit 1; }
  echo "   $product: arm64"
done

# --- stage the archive contents (Part 1 §1.6) --------------------------------
stage=$(mktemp -d "${TMPDIR:-/tmp}/webtransport-release-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

for product in WebTransportClient WebTransportServer; do
  cp "$artifacts/$product" "$stage/$product"
  chmod 755 "$stage/$product"
done
cp "$artifacts/SHA256SUMS" "$stage/SHA256SUMS"
cp LICENSE "$stage/LICENSE"
cp THIRD_PARTY_NOTICES.md "$stage/THIRD_PARTY_NOTICES.md"

cat > "$stage/README-binaries.txt" <<EOF
$project $version -- macOS prebuilt binaries
====================================================

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

The C99 library is not in this archive
  This repository also carries a portable C99 implementation (\`C99/\`). It is
  built and tested on every push, but it is not released yet, so no C99 artifact
  is attached to this release. When it joins, it joins this tag and these notes.
EOF

# --- archive + digest (Part 1 §1.2.5, §1.6) ----------------------------------
rm -rf "$dist"
mkdir -p "$dist"
tar -czf "$dist/$archive_name" -C "$stage" .
( cd "$dist" && shasum -a 256 "$archive_name" > "$archive_name.sha256" )
digest=$(awk '{print $1}' "$dist/$archive_name.sha256")
bytes=$(wc -c < "$dist/$archive_name" | tr -d ' ')

echo
echo "== staged"
echo "   archive: $archive_name"
echo "   sha256:  $digest"
echo "   bytes:   $bytes"
( cd "$dist" && shasum -a 256 -c "$archive_name.sha256" )

# --- publish (Part 1 §1.7, §1.8) ---------------------------------------------
if [ "$publish" -eq 0 ]; then
  echo
  echo "== dry run complete. Nothing was published, and no tag was created."
  echo "   Do not copy the digest or size above into the notes: publishing rebuilds."
  exit 0
fi

[ -f "$notes" ] || { echo "release notes not found: $notes" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the tree is not clean; commit before publishing" >&2; exit 1; }
head_sha=$(git rev-parse HEAD)
upstream_sha=$(git rev-parse "@{upstream}" 2>/dev/null || true)
[ "$head_sha" = "$upstream_sha" ] || { echo "HEAD is not pushed (HEAD $head_sha, upstream ${upstream_sha:-none}); push before publishing" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated; the owner's account is required" >&2; exit 1; }
if gh release view "$tag" --repo "Pummelchen/$project" >/dev/null 2>&1; then
  echo "release $tag already exists; refusing to overwrite it" >&2
  exit 1
fi

# The notes must carry the placeholders (or the real values already): a release that
# quotes the wrong digest is worse than one that quotes none (Part 1 §1.8).
published_notes=$(mktemp "${TMPDIR:-/tmp}/webtransport-notes.XXXXXX")
trap 'rm -rf "$stage" "$published_notes"' EXIT
if grep -q 'SHA256_PENDING' "$notes" || grep -q 'ARCHIVE_BYTES_PENDING' "$notes"; then
  sed -e "s/SHA256_PENDING/$digest/" -e "s/ARCHIVE_BYTES_PENDING/$bytes/" "$notes" > "$published_notes"
elif grep -q "$digest" "$notes"; then
  cp "$notes" "$published_notes"
else
  echo "$notes carries neither the placeholders nor the real digest; refusing to publish" >&2
  exit 1
fi

git tag -a "$tag" -m "$project $version"
git push origin "$tag"
gh release create "$tag" "$dist/$archive_name" "$dist/$archive_name.sha256" \
  --repo "Pummelchen/$project" --title "$project Swift $version" \
  --notes-file "$published_notes" --latest

echo
echo "== published $tag. Verify it yourself:"
echo "   gh release view $tag --repo Pummelchen/$project"
echo "   the body must quote $digest, and the assets must be the archive and its .sha256"
