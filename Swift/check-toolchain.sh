#!/bin/sh
set -eu

minimum_swift="6.3.3"
minimum_xcode="26.6"

version_at_least() {
    awk -v current="$1" -v minimum="$2" 'BEGIN {
        current_count = split(current, current_parts, ".")
        minimum_count = split(minimum, minimum_parts, ".")
        count = current_count > minimum_count ? current_count : minimum_count
        for (part_index = 1; part_index <= count; part_index++) {
            current_part = current_parts[part_index] + 0
            minimum_part = minimum_parts[part_index] + 0
            if (current_part > minimum_part) exit 0
            if (current_part < minimum_part) exit 1
        }
        exit 0
    }'
}

swift_output="$(swift --version 2>&1)"
swift_version="$(printf '%s\n' "$swift_output" | sed -nE 's/.*Swift version ([0-9]+(\.[0-9]+)+).*/\1/p' | head -n 1)"
if [ -z "$swift_version" ]; then
    printf 'Unable to determine Swift version from:\n%s\n' "$swift_output" >&2
    exit 1
fi
if ! version_at_least "$swift_version" "$minimum_swift"; then
    printf 'Swift %s or later is required; found %s.\n' "$minimum_swift" "$swift_version" >&2
    exit 1
fi

xcode_output="$(xcodebuild -version)"
xcode_version="$(printf '%s\n' "$xcode_output" | awk '/^Xcode / { print $2; exit }')"
if [ -z "$xcode_version" ]; then
    printf 'Unable to determine Xcode version from:\n%s\n' "$xcode_output" >&2
    exit 1
fi
if ! version_at_least "$xcode_version" "$minimum_xcode"; then
    printf 'Xcode %s or later is required; found %s.\n' "$minimum_xcode" "$xcode_version" >&2
    exit 1
fi

printf 'Toolchain baseline satisfied: Xcode %s, Swift %s.\n' "$xcode_version" "$swift_version"
