# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning.

## Unreleased

## [1.3.0] - 2026-08-15

The code audit for this release was performed by Claude Opus 5.

Added:

- `WebTransportServerIdentity` supplies a listener's TLS certificate as a PKCS#12 bundle or an explicit DER chain with a matching private key, and reports certificate expiry so rotation can be scheduled.
- `WebTransportAdmissionPolicy` and `WebTransportTransportLimits` cap concurrent connections, optionally rate-limit newly accepted ones before the handshake is driven, and bound what an unauthenticated peer can make the server commit.
- Graceful shutdown signals live sessions and drains in-flight work within a bounded grace period.
- Certificate rotation replaces a listener without restarting the process.
- `settingsValidation: .interoperable` accepts browsers, which send `:protocol = webtransport` rather than the draft-16 `webtransport-h3` token and omit `SETTINGS_WT_ENABLE_WEBTRANSPORT`. The draft-16 token is still what this implementation sends.
- A seeded fuzz corpus for every parser that consumes peer bytes, a containerized third-party interop matrix, a connection-churn soak, and CI jobs for manifest agreement, AddressSanitizer fuzzing, and ThreadSanitizer.

Fixed:

- Inbound QUIC streams arriving before a handler was attached were discarded, most often the peer's HTTP/3 control stream, leaving both ends waiting until they timed out. Loopback session establishment went from 16 failures in 300 to 3 in 500.
- A timed-out wait for a stream left its claim in the waiter list, so the next stream to arrive was handed to a caller that had already given up. `acceptBidirectionalStream` polls with a timeout and could therefore lose a stream the peer had opened.
- Two HTTP/3 critical streams were released after reading, which a peer sees as closing them and answers with `H3_CLOSED_CRITICAL_STREAM`. This is what prevented browsers from connecting.
- Terminated session and stream state was retained without bound, letting a peer grow server memory by opening and closing sessions on one connection.
- Advertised and enforced datagram ceilings disagreed, rejecting a peer sending exactly what it had been told it could send.
- Malformed `wt-protocol` and `wt-available-protocols` headers were downgraded to absent instead of rejected, leaving the ends disagreeing about the subprotocol in force.
- Certificate generation now fails instead of degrading when the CSPRNG fails.
- Three busy-wait loops replaced with event-driven waits.

Changed, not backwards compatible:

- The built-in development certificate is refused on any non-loopback bind address. A server that previously bound `0.0.0.0` with default settings started and was unreachable by every real client; it now fails at startup with an error naming the fix.

Known limitation:

- Roughly 0.6% of loopback sessions still fail to establish and end in a timeout. Two causes are known, both predating this release's fixes, and neither is resolved. Treat a connect timeout as retryable. See the Wiki's Known Limitations page.

## [1.2.0] - 2026-08-11

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
