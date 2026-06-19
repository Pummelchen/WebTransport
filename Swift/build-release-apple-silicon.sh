#!/bin/sh
set -eu

cd "$(dirname "$0")"

export SOURCE_DATE_EPOCH=0
export SWIFT_DETERMINISTIC_HASHING=1
export ZERO_AR_DATE=1

products="WebTransportClient WebTransportServer"
spikes="AppleQUICSpike NativeQUICCoreSpike"
artifacts_dir=".build/release-artifacts"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/webtransport-release.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

normalized_macho_hash() {
  python3 - "$1" <<'PY'
import hashlib
import struct
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
if len(data) < 32:
    raise SystemExit("input is too short to be a Mach-O binary")

magic = struct.unpack_from("<I", data, 0)[0]
if magic != 0xfeedfacf:
    raise SystemExit("expected little-endian 64-bit Mach-O binary")

ncmds = struct.unpack_from("<I", data, 16)[0]
offset = 32
for _ in range(ncmds):
    if offset + 8 > len(data):
        raise SystemExit("truncated Mach-O load command")
    cmd, cmdsize = struct.unpack_from("<II", data, offset)
    if cmdsize < 8 or offset + cmdsize > len(data):
        raise SystemExit("invalid Mach-O load command size")
    if cmd == 0x1B and cmdsize >= 24:  # LC_UUID
        data[offset + 8:offset + 24] = b"\0" * 16
    offset += cmdsize

print(hashlib.sha256(data).hexdigest())
PY
}

build_pass() {
  pass_dir="$1"
  rm -rf .build/arm64-apple-macosx/release .build/release "$pass_dir"
  mkdir -p "$pass_dir"

  for product in $products; do
    swift build \
      -c release \
      --arch arm64 \
      --product "$product"

    binary=".build/arm64-apple-macosx/release/$product"
    if [ ! -x "$binary" ]; then
      binary=".build/release/$product"
    fi

    if [ ! -x "$binary" ]; then
      echo "Expected release binary for $product" >&2
      exit 1
    fi

    archs="$(lipo -archs "$binary")"
    if [ "$archs" != "arm64" ]; then
      echo "Expected arm64-only binary for $product, got: $archs" >&2
      exit 1
    fi

    cp "$binary" "$pass_dir/$product"
    shasum -a 256 "$pass_dir/$product" | awk '{print $1}' > "$pass_dir/$product.sha256"
    normalized_macho_hash "$pass_dir/$product" > "$pass_dir/$product.normalized.sha256"
    file "$pass_dir/$product"
  done

  for spike in $spikes; do
    if [ -e ".build/arm64-apple-macosx/release/$spike" ] || [ -e ".build/release/$spike" ]; then
      echo "Unexpected spike binary in production release output: $spike" >&2
      exit 1
    fi
  done
}

echo "Building production release pass 1..."
build_pass "$workdir/pass1"
echo "Building production release pass 2 for reproducibility check..."
build_pass "$workdir/pass2"

for product in $products; do
  if ! cmp -s "$workdir/pass1/$product.normalized.sha256" "$workdir/pass2/$product.normalized.sha256"; then
    echo "Release artifact is not reproducible for $product" >&2
    echo "pass1 normalized $(cat "$workdir/pass1/$product.normalized.sha256")" >&2
    echo "pass2 normalized $(cat "$workdir/pass2/$product.normalized.sha256")" >&2
    exit 1
  fi
done

rm -rf "$artifacts_dir"
mkdir -p "$artifacts_dir"
: > "$artifacts_dir/SHA256SUMS"

for product in $products; do
  cp "$workdir/pass2/$product" "$artifacts_dir/$product"
  chmod 755 "$artifacts_dir/$product"
  hash="$(cat "$workdir/pass2/$product.sha256")"
  printf '%s  %s\n' "$hash" "$product" >> "$artifacts_dir/SHA256SUMS"
done

echo "Release artifacts are reproducible. Checksums:"
cat "$artifacts_dir/SHA256SUMS"
