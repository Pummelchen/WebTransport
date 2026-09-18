#!/bin/bash
#
# Refuses a package that uses unsafe build flags.
#
# `.unsafeFlags` needs no justification to the compiler and is invisible in a build log,
# but it makes the package unusable to every caller who depends on it by version: SwiftPM
# refuses such a product outright. The API-compatibility check cannot catch it, because
# that check consumes the package by PATH, and SwiftPM allows unsafe flags for path
# dependencies. That gap is what this gate closes (AUD-0017).
#
# It reads `swift package dump-package`, so it sees what SwiftPM actually resolved rather
# than what the manifest text happens to look like.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required by check-unsafe-flags.sh" >&2
    exit 1
fi

status=0

for manifest in "." "Swift"; do
    dumped="$(swift package --package-path "$manifest" dump-package)"
    offenders="$(
        printf '%s' "$dumped" | jq -r '
            [.targets[] as $target
             | ($target.settings // [])[]
             | select(.kind.unsafeFlags != null)
             | "  \($target.name): \((.kind.unsafeFlags._0 // []) | join(" "))"]
            | .[]'
    )"
    if [ -n "$offenders" ]; then
        echo "error: the $manifest manifest uses unsafe build flags." >&2
        echo "These stop the package being usable as a versioned dependency:" >&2
        printf '%s\n' "$offenders" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "check-unsafe-flags: neither manifest uses unsafe build flags"
fi

exit "$status"
