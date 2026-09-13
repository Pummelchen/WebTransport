# Changelog

All notable changes to this project will be documented here.

The project uses semantic versioning.

## [Unreleased]

Fixed:

- A connection the transport failed to establish is reported as `WebTransportNetworkRuntimeError.connectionEstablishmentFailed(role:domain:code:)` rather than as the framework's own error. `NetworkConnection.State.failed` was rethrown verbatim, so a caller saw a bare `POSIXErrorCode` — on a loaded runner `ENETDOWN` (50) and, in another run, `ENOTCONN` (57) — with nothing to say whether the endpoint was wrong or the local stack was momentarily unavailable. The case names the condition, keeps the framework's domain and code for diagnosis, and `isTransientEstablishmentFailure` answers whether a fresh connection can clear it. This is the error `listenerServesMoreSequentialSessionsThanTheDefaultCeiling` was failing on under Thread Sanitizer; that test now retries only the named transient condition, bounded, so a listener that has genuinely stopped accepting — issue #23, which presents as a timeout — still fails it (WT-185).
- The conformance runner counts a scenario it could not attempt as `skipped` with its reason instead of as a failure. The two `Release` scenarios read the source tree, so outside a checkout the suite now reports `passed=38 failed=0 skipped=2` and exits `3` ("nothing failed, something was not attempted") rather than `passed=38 failed=2`, which read as a broken binary rather than an incomplete run. The human summary gained a `skipped=` count, `--json` gained a top-level `skipped` and a per-scenario `status`, and `--help` documents the exit statuses (WT-186).

Added:

- `WebTransportNetworkRuntimeError.connectionEstablishmentFailed(role:domain:code:)` and its `isTransientEstablishmentFailure` predicate. Retrying on that predicate must be bounded: it answers whether a fresh connection *could* clear the condition, and some of the codes it covers also describe a route or an address that will never come back.
- `WebTransportCLIConformanceStatus` and `WebTransportCLIConformanceResult.status`. `result.passed` is still the question most callers ask, but it is now a read-only derived property (`status == .passed`) rather than a stored one, and it is false for a skipped scenario — so a caller that needs the third state reads `status`.
- `WebTransportErrorSurface.publicDescription(for:)` now names `WebTransportNetworkRuntimeError` conditions instead of collapsing every one of them into "WebTransport operation failed". It deliberately omits the stream and connection numbers those cases carry, because that surface exists to keep transport identifiers out of user-visible text.

Changed:

- Adding a case to the public enum `WebTransportNetworkRuntimeError` means an embedder's exhaustive `switch` over it needs a branch for the new case, and `WebTransportCLIConformanceResult.passed` is no longer settable. The conformance tools gained exit status `3`; `0` and `1` keep their meanings.

## [1.3.8] - 2026-09-13

A defect-fix release. There are no wire-format changes and nothing is added to or
removed from the public API; the release makes one peer behaviour legible that was
previously reported as an internal error.

Fixed:

- A peer that ends a stream before sending the bytes that stream has to begin with is now reported as such, instead of as `QUICCodecError.truncated(needed: 1, available: 0)`. The runtime read the first chunk of a stream and dropped the `endOfStream` flag, so the codec's empty-buffer refusal was what a caller saw for a peer that FINed an inbound stream without writing to it — a message that reads like an internal truncation rather than a peer that is not following the protocol. The new `WebTransportNetworkRuntimeError.peerClosedStreamWithoutData(streamID:)` names the stream and the cause, and it is raised on the request stream, an inbound WebTransport stream, the peer's HTTP/3 control stream and a CONNECT response. A read that returns no bytes while the stream is still open is now waited out rather than returned, so "nothing yet" and "the peer is done" cannot be confused. Reported in issue #24.

## [1.3.7] - 2026-09-13

A defect-fix release. There are no wire-format changes and nothing is added to or
removed from the public API; the release restores behaviour the documentation already
promised. It follows the report in issue #23 and was reproduced before it was changed.

Fixed:

- A listener no longer stops accepting forever once it has served `maxConcurrentConnections` sessions. The value was passed to `NetworkListener.newConnectionLimit`, which on macOS 26 counts connections over the listener's whole life rather than at one time: measured with a minimal listener, a limit of 2 hands two connections to the handler and never a third, even after both have ended, and a connection that ends does not return its slot. A long-lived server therefore died permanently after `maxConcurrentConnections` total sessions — the default of 16 is low enough to be reached in normal operation — while every other transport it served kept working and each new WebTransport session timed out instead. The runtime now runs its listeners without that limit and counts in-flight connections itself: a connection is admitted only while fewer than the ceiling are being served, and the slot is returned when a session closes, when the peer closes it, when a session is released without being closed, and on every failed accept. Reported in issue #23.
  Refusal behaves as before: a connection over the ceiling is dropped before its handshake is driven. Regression tests cover both halves — more sequential sessions than the ceiling are all accepted, and a connection that arrives while the ceiling is held by a live session is still refused.

## [1.3.6] - 2026-09-12

A defect-fix release. There are no wire-format changes and nothing is removed from
the public API; the additions are one new validation entry point and one new error
case. Every item was found by an adversarial audit of the codecs, the runtime and the
command-line tools, and each was reproduced before being changed. The 1.3 series code
audits were performed by Claude Opus 5.

Fixed:

- A PKCS#12 bundle whose certificate carries explicit elliptic-curve parameters — which is what the macOS system `openssl` (LibreSSL 3.3.6) emits for an EC key — no longer terminates the process. `SecPKCS12Import` raises an Objective-C `NSInvalidArgumentException` in that case rather than returning a status, and because Swift cannot catch Objective-C exceptions the failure escaped every `do`/`catch` and aborted the host application. The import now runs behind an exception boundary in a new `WebTransportSecurityShim` target, so `listen(on:)` throws a `WebTransportNetworkRuntimeError` naming the cause instead of killing the process. Reported in issue #20. Named-curve EC identities and RSA identities are unaffected; a bundle that previously crashed now reports: regenerate the certificate against a named curve, or use RSA.
- `ServerIdentityResolver` now refuses an identity whose private key cannot be read, with the reason attached, rather than handing it to Network.framework and deferring the failure to the first peer handshake.
- `.certificateChain(chainDER:privateKeyDER:keyKind:)` reports why a private key was rejected. The parameter must hold the representation `SecKeyCopyExternalRepresentation` returns for the private key, not the DER that `openssl` writes and not the public point: 97 bytes for P-256, 145 for P-384, and 199 for P-521. The previous failure was a bare `OSStatus -50` that said nothing about the encoding; the error now names the expected form and length. The required encoding is documented on the case and on `makePrivateKey`, with a worked example in the wiki (issue #21).
- The PKCS#12 import error no longer repeats Security.framework's raw exception reason. It is a fixed framework string that carries nothing a caller can act on, and the project's trust rules keep framework-supplied text out of public errors. The exception name is still reported, because it is stable and useful.
- `makeFromPKCS12` reads the imported identity through a type-identifier check rather than a forced cast.
Added:
- The repository's first non-Swift target, `WebTransportSecurityShim`, which exists only to give `SecPKCS12Import` an Objective-C frame where its exception can be converted into a status code. It is an internal target and is not part of the public product surface.
- Regression fixtures and tests for the PKCS#12 import path, using bundles generated by the macOS system `openssl`. See `Swift/Tests/WebTransportNetworkRuntimeTests/Resources/README.md`.

- The CRYPTO reassembly ceiling now bounds bytes waiting for a gap rather than every byte the connection has carried. Consumed bytes are retained so a conflicting retransmission is still detected, and counting them against the ceiling made it a lifetime cap: a peer that completed a large handshake could no longer deliver a legitimate post-handshake message such as a NewSessionTicket or KeyUpdate, and was disconnected instead. The count is computed once per frame and incremented locally from there, so a large frame stays linear.
- An accept that times out no longer consumes the next connection. `acceptSession` bounds its wait on the connection queue with a timeout, and a cancelled `CheckedContinuation` is never resumed, so the abandoned waiter stayed at the head of the queue and was handed the next accepted connection — which was then dropped. Reachable from the documented accept loop, `while true { try await acceptSession() }`, whose one-second default plants an abandoned waiter on every idle timeout; once connections arrive slower than that, every connection is lost. The queue now tags each waiter so a caller that stops waiting removes its own entry and resumes it, which lets the abandoned task unwind; dropping the continuation instead would leak it. A cancelled accept also releases a connection that arrives after it gave up.
- Shutdown now wakes a parked accept with a shutdown error instead of leaving it to block for its full timeout. That timeout was how the abandoned waiters above were created, so the two defects compounded.
- `connectSession` cancels its inbound handler task on every failure path, not only when the peer rejects the session. The handler strongly retains the connection and Network.framework exposes no `cancel()`, so a task left running kept the connection and its socket alive. `acceptSession` already did this.
- DATAGRAM and PING frames are no longer classified as retransmittable. RFC 9221 section 5.2 states DATAGRAM frames are not retransmitted on loss detection, and RFC 9000 section 13.3 notes a lost PING needs no repair; a caller resending everything in `retransmittableFrames` re-sent an unreliable datagram and delivered it twice.
- `NEW_CONNECTION_ID` rejects a zero-length connection ID. RFC 9000 section 19.15 makes anything outside 1...20 a `FRAME_ENCODING_ERROR`, and only the upper bound was checked, so an empty connection ID was accepted and stored as a usable identity. The encoder enforces the same range, so the library can no longer produce a frame it would refuse to read.
- `HKDF-Expand` is capped at `255 * HashLen` (8,160 bytes for SHA-256) as RFC 5869 section 2.3 requires. The guard allowed up to `UInt16.max`, so a larger request wrapped the block counter to zero and returned bytes that look well-formed but are not the RFC's stream.
- An explicit `maxConcurrentConnections` now overrides a supplied admission policy instead of being silently ignored. The override was gated on `admission == .default`, so a caller passing both a policy and an explicit limit had the limit dropped with no diagnostic, and an out-of-range limit was neither applied nor refused. It is now tied to the default argument value and validated on the same terms as the policy's own field.
- Long-header packets with a cleared Fixed Bit or non-zero reserved bits are rejected. RFC 9000 section 17.2 requires such packets be discarded and RFC 9001 section 5.4 requires the reserved bits to be zero; the short-header decoder enforced the Fixed Bit but the long-header path enforced neither. The Retry decoder, which is also a long header, now applies the same two checks and rejects a zero-length Retry token, which RFC 9000 section 17.2.5 requires a client to discard.
- An oversized datagram is reported instead of being silently truncated. The UDP receive path used `recvfrom`, which on this platform returns a short payload with a valid source and no indication that anything was lost — a QUIC parser would then read a packet that was never sent. It now uses `recvmsg` and rejects the datagram when the kernel sets `MSG_TRUNC`, which is the only form that reports truncation here. Note that passing `MSG_TRUNC` to `recvfrom` does not work: macOS documents the flag as "data discarded before delivery", and it is set on output rather than honoured on input.
- `QUICTransportParameters.validated()` enforces the value rules of RFC 9000 section 18.2, which nothing did before: `max_udp_payload_size` below 1200, `ack_delay_exponent` above 20, `max_ack_delay` at or above 2^14, `active_connection_id_limit` below 2, a `stateless_reset_token` that is not 16 bytes, and `original_destination_connection_id` outside 1...20 are now rejected. A zero-length `initial_source_connection_id` or `retry_source_connection_id` is accepted, because RFC 9000 section 7.3 defines that as the encoding for a selected zero-length connection ID, and an explicit zero `max_datagram_frame_size` is accepted because RFC 9221 section 3 defines it as the default. It is opt-in rather than folded into `decode`, because `decode` is also the TLS-extension parser and must keep accepting parameters this build does not model.
- `--max-sessions` is bounded at 65,536. The value sizes an array of tasks, so `--max-sessions=1000000` committed memory proportional to the request until the process was killed; the parser accepted any positive integer. The bound stops that abuse and is deliberately well clear of `Swift/run-soak.sh`, which passes `CONNECTIONS + 10`.
- `--listen` exits non-zero when it served no sessions. It previously exited zero after every session attempt failed, which a script or CI job reads as success.

## [1.3.5] - 2026-08-16

No behaviour change. The substance of this release is verification rather than code.

Verified:

- The remote interoperability matrix passes all 7 proofs across all 5 independent implementations for the first time: pywebtransport/aioquic (stream), web-transport-quinn (stream and datagram), web-transport-quiche (stream), hyperium/h3-webtransport (datagram), and erlang-webtransport (stream and datagram). Unlike the containerized matrix, these run with platform system trust against a CA-issued certificate over a routable network path, so they exercise certificate validation. The two peers previously recorded as "not deployed" since June were built and deployed for this run.

Changed:

- The tree was reformatted in one mechanical pass and the formatter is now a blocking CI gate rather than an advisory notice. No behaviour change: the full test suite and both conformance suites pass unchanged across the reformat. Run `swift format --recursive --in-place Swift/Sources Swift/Tests` before pushing.
- Two `try!` calls in a test helper now throw, so a failure there fails the calling test instead of trapping and taking the suite process down with it.

## [1.3.4] - 2026-08-16

Changed, wire format:

- The QPACK Required Insert Count is now encoded as RFC 9204 section 4.5.1.1 specifies — modulo twice the table size and offset by one — rather than as the raw value. The raw form was self-consistent, so nothing here could see it, but it disagrees with a conforming peer by at least one as soon as a dynamic reference appears. It remains unreachable in practice: no table capacity is advertised, so a conforming peer may not use the dynamic table and always sends zero. Deriving the window needs the negotiated capacity, so both directions now take it from the dynamic table they are given, and a non-zero count without an advertised capacity is refused rather than encoded into something a peer would misread.

Fixed:

- `TLSCryptoStreamReassembler` had no ceiling on what it would hold. CRYPTO frames carry an arbitrary offset and are processed before the handshake has authenticated anything, so a peer could scatter single bytes across the offset space, never complete a message, and make the receiver retain all of them. RFC 9000 section 7.5 requires a limit and defines CRYPTO_BUFFER_EXCEEDED to report it. Bounded at 64 KB by default; retransmitted bytes do not count against the ceiling, so an honest peer resending a lost frame is not refused. Reachable by embedders of `WebTransportTLSCore`; this repository's own client and server use Network.framework's TLS and never construct it.

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
