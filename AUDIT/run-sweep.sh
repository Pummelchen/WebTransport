#!/bin/sh
# Run every audit gate and report one line per gate (AUDIT/convergence.md is its log).
#
# This exists because "we fixed everything" is only meaningful if the same sweep can be run
# again and produce the same answer. Each entry below is the command the corresponding CI
# workflow runs, so a green sweep here means the tree is green against the gates that matter,
# not against a remembered subset of them.
#
#   AUDIT/run-sweep.sh              the gates that fit in a normal working session
#   SWEEP_HEAVY=1 AUDIT/run-sweep.sh   adds the expensive ones (release build, DocC,
#                                    conformance suites, sanitizers). On the primary host
#                                    (8 GB) these are serialised deliberately: one heavy
#                                    build at a time, which is why this is a list and not a
#                                    parallel fan-out.
#
# Exits non-zero if any gate fails, so it can be used as a single CI step as well.

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$repo_root"

heavy=${SWEEP_HEAVY:-0}
failed=0
ran=0

# Runs one gate: name, then the command as the remaining arguments.
gate() {
  name=$1
  shift
  ran=$((ran + 1))
  if "$@" >/dev/null 2>&1; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n' "$name"
    failed=$((failed + 1))
  fi
}

printf '=== Swift ===\n'
gate "toolchain pinned (Swift 6.4 / Xcode 27)" ./Swift/check-toolchain.sh 6.4 27.0
gate "manifests agree on shared targets" ./Swift/check-manifest-sync.sh
gate "no unsafe build flags" ./Swift/check-unsafe-flags.sh
gate "the two libraries report the same version" ./Swift/check-version-sync.sh
gate "target imports declared as dependencies" ./Swift/check-target-imports.sh
gate "swift-format lint --strict" swift format lint --strict --recursive Swift/Sources Swift/Tests Package.swift Swift/Package.swift
gate "swiftlint lint --strict" swiftlint lint --strict --quiet Swift/Sources Swift/Tests
gate "swift build with safety diagnostics" swift build \
  -Xswiftc -warnings-as-errors \
  -Xswiftc -strict-concurrency=complete \
  -Xswiftc -require-explicit-sendable
gate "public API compatibility sample" ./Swift/check-api-compatibility.sh
gate "package tests" swift test -Xswiftc -warnings-as-errors -Xswiftc -strict-concurrency=complete -Xswiftc -require-explicit-sendable
gate "PKCS#12 resolution is keychain-free" ./Swift/check-pkcs12-keychain-free.sh
gate "nested manifest test target" swift test --package-path Swift --filter WebTransportTestSupportTests
gate "library smoke pair" ./Swift/run-library-smoke.sh

printf '=== C99 ===\n'
gate "build, warnings-as-errors, ctest" ./C99/scripts/build-and-test.sh
gate "RFC vectors match the documents" ./C99/scripts/check-vectors.sh
gate "installed package consumer" ./C99/scripts/check-package.sh
gate "compliance matrix against the tree" ./C99/scripts/check-matrix.sh
gate "portability inventory against the tree" ./C99/scripts/check-portability.sh
gate "tree matches .clang-format" ./C99/scripts/check-format.sh
gate "cppcheck" ./C99/scripts/check-cppcheck.sh
gate "Clang Static Analyzer" ./C99/scripts/check-static-analysis.sh
gate "workflow files parse" python3 C99/scripts/check-workflows.py

printf '=== Security ===\n'
# trivy needs an empty docker config on this host: the user's ~/.docker/config.json names a
# credential helper that is not installed, and trivy fails to fetch its database through it.
gate "gitleaks over full history" env GITLEAKS_CONFIG=.gitleaks.toml gitleaks git --no-banner --redact .
gate "trivy filesystem scan" env DOCKER_CONFIG=/tmp/audit-docker-empty trivy fs --config .trivy.yaml .

if [ "$heavy" = "1" ]; then
  printf '=== Heavy (SWEEP_HEAVY=1) ===\n'
  gate "release artifacts reproducible (arm64)" ./Swift/build-release-apple-silicon.sh
  gate "client CLI conformance" swift run WebTransportClient --scenario all
  gate "server CLI conformance" swift run WebTransportServer --scenario all
  gate "peer-input fuzz under AddressSanitizer" swift test --sanitize=address --filter 'peerFacingParsers|huffmanDecoder'
  gate "tests under Thread Sanitizer" swift test --sanitize=thread --skip CLIProcess --skip ReleaseArtifacts
  gate "C99 sanitizer build and tests" ./C99/scripts/build-and-test.sh --sanitize
fi

printf '\n%d gates ran, %d failed\n' "$ran" "$failed"
[ "$failed" -eq 0 ]
