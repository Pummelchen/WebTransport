#!/bin/sh
set -eu

cd "$(dirname "$0")"

rm -rf .build/arm64-apple-macosx/release .build/release

for product in WebTransportClient WebTransportServer; do
  swift build -c release --arch arm64 --product "$product"

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

for spike in AppleQUICSpike NativeQUICCoreSpike; do
  if [ -e ".build/arm64-apple-macosx/release/$spike" ] || [ -e ".build/release/$spike" ]; then
    echo "Unexpected spike binary in production release output: $spike" >&2
    exit 1
  fi
done
