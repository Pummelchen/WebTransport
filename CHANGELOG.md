# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning.

## Unreleased

## [1.3.3] - 2026-08-16

Added:

- `WebTransportNetworkRuntimeError.peerControlStreamNotDelivered` distinguishes a lost HTTP/3 control stream from a generic timeout. The condition is not recoverable on the affected connection, so the error says to establish a new one rather than wait longer.

Fixed:

- `QUICAckTracker` retained every packet number it had ever seen, so the set grew for the life of a connection and each `makeAckFrame` sorted the whole of it. Tracking is now bounded to a window that doubles as the replay boundary. Reachable by embedders of `WebTransportQUICCore`; this repository's own client and server use Network.framework's QUIC and never construct it.

Known limitation, now attributed:

- Session establishment failures under heavy CPU load are caused by Network.framework dropping an inbound QUIC stream, not by this package. A standalone harness — `NetworkListener<QUIC>` and `NetworkConnection<QUIC>`, no HTTP/3 — loses one of three peer-opened streams on a saturated receiver in 13 of 1600 connections, matching the rate seen here. When the lost stream is the peer's control stream, both ends wait until they time out. The stream is never resent, so raising the deadline does not help: 6 second and 60 second timeouts fail at the same rate. Reported to Apple as FB24354509, with a standalone reproducer attached.

## [1.3.1] - 2026-08-15

Fixed:

- An inbound QUIC stream delivered twice by the transport was processed twice. A QUIC stream identifier is unique for the life of a connection and never reused, so a repeat is a re-delivery of a stream already handed out, and acting on it is always wrong. Delivered to the WebTransport stream path it was rejected as `unknown WebTransport stream marker: 0`; that failure has not been observed since the guard was added.

  This is a correctness fix, not a reliability improvement. An earlier draft of these notes claimed a measured drop in session establishment failures. That measurement was taken on a heavily loaded development machine and does not reproduce: on four otherwise idle Macs, 1.3.0 and 1.3.1 both completed 4000 loopback sessions without a failure, and under saturating load both failed at roughly 1%, with no difference between them.

Known limitation:

- Session establishment is load-sensitive. On an unsaturated machine no failures were observed in 4000 sessions per release. With every core saturated, roughly 1% failed to establish and ended in a timeout rather than an error. (The cause was unknown at this release and was attributed in 1.3.3: Network.framework drops an inbound QUIC stream on a saturated host.)

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

- Inbound QUIC streams arriving before a handler was attached were discarded, most often the peer's HTTP/3 control stream, leaving both ends waiting until they timed out. The loss was confirmed by logging every delivery: the peer's later streams arrived while the first never did. (The failure-rate figures originally given here were measured on a loaded development machine and have been withdrawn; see 1.3.1.)
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

- Session establishment is load-sensitive. On an unsaturated machine no failures were observed in 4000 loopback sessions; with every core saturated, roughly 1% fail to establish and end in a timeout. Treat a connect timeout as retryable whenever the host may be under load. See the Wiki's Known Limitations page.

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
