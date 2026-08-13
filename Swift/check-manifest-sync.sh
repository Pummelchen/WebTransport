#!/bin/bash
#
# Verifies that targets shared by the two package manifests stay in sync.
#
# The repository root manifest and Swift/Package.swift intentionally expose
# different product sets: the nested manifest adds smoke executables and shared
# test support. What must NOT diverge is any target defined in both — its source
# path and its dependency list. That invariant was previously maintained by hand
# and by review only, so drift could ship silently.
#
# Comparison runs against `swift package dump-package` rather than the manifest
# text, so formatting and declaration order do not produce false failures.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required by check-manifest-sync.sh" >&2
    exit 1
fi

# Normalizes one manifest into {targetName: {path, type, dependencies[]}}.
#
# Two differences are conventions rather than drift, and are normalized away:
#   * Root paths are relative to the repository root ("Swift/Sources/..."),
#     while the nested manifest's are relative to Swift/. The prefix is stripped.
#   * The nested manifest omits `path:` entirely and relies on SwiftPM's default
#     layout, which dumps as null. Null is resolved to that same default so an
#     implicit path compares equal to the explicit one naming the same directory.
normalize() {
    local strip_prefix="$1"
    jq -S --arg strip "$strip_prefix" '
        [ .targets[]
          | { name,
              type,
              path: (
                  (if .path == null
                   then (if .type == "test" then "Tests/" else "Sources/" end) + .name
                   else .path end)
                  | if $strip != "" and startswith($strip) then ltrimstr($strip) else . end
              ),
              dependencies: [
                  .dependencies[]?
                  | (.byName[0]? // .target[0]? // .product[0]?)
                  | select(. != null)
              ] | sort
            }
        ] | INDEX(.name)
    '
}

root_targets="$(swift package dump-package | normalize "Swift/")"
nested_targets="$(swift package --package-path Swift dump-package | normalize "")"

mismatches="$(jq -n \
    --argjson root "$root_targets" \
    --argjson nested "$nested_targets" '
    [ ($root | keys[]) as $name
      | select($nested[$name] != null)
      | select(
            ($root[$name].path         != $nested[$name].path) or
            ($root[$name].type         != $nested[$name].type) or
            ($root[$name].dependencies != $nested[$name].dependencies)
        )
      | { target: $name,
          root:   { path: $root[$name].path,   type: $root[$name].type,   dependencies: $root[$name].dependencies },
          nested: { path: $nested[$name].path, type: $nested[$name].type, dependencies: $nested[$name].dependencies } }
    ]
')"

shared_count="$(jq -n --argjson r "$root_targets" --argjson n "$nested_targets" \
    '[($r | keys[]) as $k | select($n[$k] != null) | $k] | length')"

if [ "$(jq -n --argjson m "$mismatches" '$m | length')" -ne 0 ]; then
    echo "error: shared targets diverge between Package.swift and Swift/Package.swift" >&2
    echo "$mismatches" | jq . >&2
    exit 1
fi

echo "manifest sync OK: $shared_count shared targets agree on path, type, and dependencies"
