# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning.

## Unreleased

- Raised the development baseline to Xcode 26.6 and Swift 6.3.3, enabled strict memory-safety checking for every SwiftPM target, and made complete concurrency and explicit `Sendable` diagnostics CI gates.
- Audited Apple socket, Security, CommonCrypto, CryptoKit, and Network.framework boundaries; removed avoidable C formatting, byte-copy, and standard-I/O calls in favor of Swift-native APIs.
- Reworked the repository and Wiki documentation around a concise Swift reference-implementation narrative, current requirements, validation evidence, and explicit limitations.

## [1.1.0] - 2026-08-11

- Updated the Swift protocol target to `draft-ietf-webtrans-http3-16`.
- Added draft-16 flow-control negotiation, directional accounting, strict limit updates, prohibited-capsule handling, and excessive-session rejection.
- Added optimistic CONNECT capsule support, 1024-byte UTF-8 close-message enforcement, and the `EXPORTER-WebTransport` TLS exporter binding.
- Removed obsolete protocol-revision compatibility aliases and the legacy settings-validation spelling.
- Hardened Swift runtime endpoint reporting, local self-signed trust handling, and `@unchecked Sendable` documentation.
- Restricted the Swift UDP packet-probe helper to explicit loopback use and added IPv6 loopback coverage.

## [1.0.0] - 2026-06-20

- Swift implementation exposed as a repository-root SwiftPM package.
- Swift WebTransport compatibility documented against the protocol target used for the initial release.
- Swift interop validated against `pywebtransport`/`aioquic`, `web-transport-quinn`, and `web-transport-quiche`.
- Added a Debian 13 VPS interop runner covering five third-party implementations: `pywebtransport`/`aioquic`, `web-transport-quinn`, `web-transport-quiche`, `hyperium/h3-webtransport`, and `erlang-webtransport`.
- MIT license added.
- Security reporting policy added.
- DocC catalog added for the public Swift API.
