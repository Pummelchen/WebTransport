<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 742358be03922065f4aca3af823d36df5993204d
Last generated: 2026-06-26T15:16:55+02:00
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Playbooks

## Public API

Read `Swift/Sources/WebTransport/WebTransport.swift`, DocC, public API tests, and `Swift/check-api-compatibility.sh`. Validate with build, tests, and API compatibility.

## CLI behavior

Read `Swift/Sources/WebTransportClient/main.swift`, `Swift/Sources/WebTransportServer/main.swift`, and `Swift/Sources/WebTransportCLIConformance/`. Validate with process tests and both scenario suites.

## Runtime and trust

Read `Swift/Sources/WebTransportNetworkRuntime/` and `.ai/SECURITY.md`. Preserve packet-only real sessions, system trust default, and explicit loopback-only local self-signed trust. Validate with build, tests, and loopback checks.

## HTTP/3 and WebTransport core

Read `Swift/Sources/WebTransportHTTP3Core/`, especially `WebTransportSession.swift`. Validate with HTTP3Core tests and CLI conformance.

## QUIC, TLS, crypto, UDP

Read the matching module under `Swift/Sources/` and tests under `Swift/Tests/`. Preserve parser hardening, bounded buffers, and loopback-only UDP behavior.

## CI, release, interop

Read `.github/workflows/swift-ci.yml` and scripts under `Swift/`. Update README and `.ai/COMMANDS.md` when commands change.

## C99 and C++ plans

Use current Swift source as the reference. Keep C99/CPP READMEs clear that these are planned skeletons until implementation files and build systems exist.

## AI onboarding refresh

Re-scan source, manifests, CI, README, and tests. Update `.ai/MANIFEST.json`. Preserve valid human edits. Keep the files vendor-neutral.
