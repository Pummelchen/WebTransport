#!/bin/bash
#
# Verifies that every module a target imports is covered by that target's
# declared dependencies in the manifest that builds it.
#
# Why this exists: check-manifest-sync.sh compares the two manifests with each
# other, so a dependency both manifests omit stays invisible to every check in
# the repository. Three test targets imported `WebTransportTLSCore` without
# declaring it, and nothing failed until Swift 6.4's linker refused to produce
# the test bundle (A-0001) -- the root manifest built green on the older
# toolchains because the missing module happened to be available transitively.
# A per-target import/dependency check catches that class at the manifest, before
# the link step, for both package entry points.
#
# Both manifests point at the same source directories, so each target is checked
# against the manifest that declares it; a target only the nested manifest
# declares (the smoke executables and the shared test support) is checked there.
#
# Comparison runs against `swift package dump-package`, so declaration syntax and
# formatting do not matter. The Apple/system modules listed below come from the
# SDK or the toolchain and are never declared in a manifest.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required by check-target-imports.sh" >&2
    exit 1
fi

# Modules the platform / toolchain provides. Extend this list only for modules
# that genuinely ship with the SDK or the Swift toolchain; a module from this
# repository belongs in the target's `dependencies` instead.
system_modules="
CommonCrypto
CoreFoundation
CryptoKit
Darwin
Dispatch
Foundation
Network
Security
Synchronization
Testing
XCTest
_Concurrency
os
"
system_modules=" $(printf '%s ' $system_modules) "

failures=0
checked_targets=0
covered_imports=0

# Checks one package entry point: $1 is its root, $2 the label used in errors.
check_package() {
    local package_root="$1"
    local package_label="$2"
    local manifest

    manifest="$(cd "$package_root" && swift package dump-package)"

    # One row per target: name, type, manifest path (or `null`), declared
    # dependencies. `dependencies` entries are `byName`, `target` or `product`;
    # all three name a module this target may import.
    while IFS=$'\t' read -r name type path declared; do
        [ -n "$name" ] || continue

        local source_dir
        if [ -n "$path" ] && [ "$path" != "null" ]; then
            source_dir="$package_root/$path"
        elif [ "$type" = "test" ]; then
            source_dir="$package_root/Tests/$name"
        else
            source_dir="$package_root/Sources/$name"
        fi
        [ -d "$source_dir" ] || continue
        checked_targets=$((checked_targets + 1))

        # Every module named by an `import` line in this target's sources,
        # including `@testable import` and `import struct Module.Member`.
        local imports
        imports="$(
            grep -rhoE \
                '^[[:space:]]*(@testable[[:space:]]+)?import[[:space:]]+(struct[[:space:]]+|class[[:space:]]+|enum[[:space:]]+|protocol[[:space:]]+|func[[:space:]]+|var[[:space:]]+|let[[:space:]]+|typealias[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*' \
                "$source_dir" --include='*.swift' 2>/dev/null \
                | sed -E 's/.*import[[:space:]]+//; s/^(struct|class|enum|protocol|func|var|let|typealias)[[:space:]]+//' \
                | sort -u || true
        )"

        local module
        while IFS= read -r module; do
            [ -n "$module" ] || continue
            # A target cannot import itself.
            if [ "$module" = "$name" ]; then
                continue
            fi
            case "$system_modules" in
                *" $module "*) continue ;;
            esac
            case ",$declared," in
                *",$module,"*) continue ;;
            esac
            printf 'error: %s target "%s" imports "%s", which it does not declare in its dependencies\n' \
                "$package_label" "$name" "$module" >&2
            printf '       declared: %s\n' "${declared:-<none>}" >&2
            failures=$((failures + 1))
        done <<<"$imports"

        local count
        count="$(printf '%s\n' "$imports" | grep -c . || true)"
        covered_imports=$((covered_imports + count))
    done < <(
        printf '%s' "$manifest" | jq -r '
            .targets[]
            | [
                .name,
                .type,
                (.path // "null"),
                ((.dependencies // [])
                 | map(.byName[0]? // .target[0]? // .product[0]?)
                 | map(select(. != null))
                 | join(","))
              ]
            | @tsv
        '
    )
}

check_package "." "Package.swift"
check_package "Swift" "Swift/Package.swift"

if [ "$failures" -ne 0 ]; then
    echo "error: $failures undeclared target import(s); declare the module in the target's dependencies" >&2
    exit 1
fi

echo "target imports OK: $checked_targets targets agree with their imports ($covered_imports imports covered by declared dependencies)"
