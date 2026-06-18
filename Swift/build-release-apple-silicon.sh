#!/bin/sh
set -eu

cd "$(dirname "$0")"

swift build -c release --arch arm64

binary=".build/arm64-apple-macosx/release/AppleQUICSpike"
if [ ! -x "$binary" ]; then
  binary=".build/release/AppleQUICSpike"
fi

archs="$(lipo -archs "$binary")"
if [ "$archs" != "arm64" ]; then
  echo "Expected arm64-only binary, got: $archs" >&2
  exit 1
fi

file "$binary"
