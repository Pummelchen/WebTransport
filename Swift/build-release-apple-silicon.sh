#!/bin/sh
set -eu

cd "$(dirname "$0")"

swift build -c release --arch arm64

for product in AppleQUICSpike NativeQUICCoreSpike; do
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

  file "$binary"
done
