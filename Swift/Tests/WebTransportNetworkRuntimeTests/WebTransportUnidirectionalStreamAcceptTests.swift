import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportLoopbackTestSupport
@testable import WebTransportNetworkRuntime

/// F-swift-line-security-05b: after the session is established the runtime must
/// have a consumer for a peer-initiated unidirectional WebTransport stream, and
/// the public API must expose it as receive-only.
///
/// The runtime serves exactly one WebTransport session per connection
/// (F-swift-architecture-08), so the demultiplex is by direction plus the session
/// ID in the stream prefix: a unidirectional stream naming this session is
/// delivered to `acceptUnidirectionalStream`; one naming another session is
/// refused with `WT_SESSION_GONE` before the session manager sees it.
@Suite("Unidirectional stream accept")
struct WebTransportUnidirectionalStreamAcceptTests {
    @Test
    func runtimeAcceptsPeerInitiatedUnidirectionalStreamAndDeliversBytes() async throws {
        try await WebTransportLoopbackTestLock.withLockAsync(label: #function) {
            let server = try WebTransportQUICServer(
                endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
                authority: "localhost",
                localOnly: false
            )
            let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
            defer { server.shutdown() }

            let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
            let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
            async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
            let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
            let clientSession = try await connecting

            let payload = Data("peer-initiated-unidirectional".utf8)
            let producer = try await clientSession.openUnidirectionalStreamForTesting(
                firstPayload: payload,
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )

            let inbound = try await serverSession.acceptUnidirectionalStream(timeoutMilliseconds: 15_000)
            #expect(inbound.streamID == producer.streamID)

            // The first chunk carried the prefix and the payload, so the payload
            // is the accepted stream's buffered initial bytes. Reading it proves
            // the bytes survived the prefix strip and the manager registration.
            let received = try await inbound.receive(timeoutMilliseconds: 15_000)
            #expect(received == payload)

            // A peer-initiated unidirectional stream belongs to the client, so
            // this endpoint owns only the receive half.
            let streamID = inbound.streamID
            #expect(streamID % 4 == 2, "expected a client-initiated unidirectional stream ID")
        }
    }

    @Test
    func runtimeRefusesUnidirectionalStreamNamingAForeignSession() async throws {
        try await WebTransportLoopbackTestLock.withLockAsync(label: #function) {
            let server = try WebTransportQUICServer(
                endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
                authority: "localhost",
                localOnly: false
            )
            let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
            defer { server.shutdown() }

            let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
            let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
            async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
            let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
            let clientSession = try await connecting

            // Another client-initiated bidirectional request stream ID is a valid
            // WebTransport session ID this connection does not serve.
            let foreignSessionID = clientSession.sessionID &+ 4
            _ = try await clientSession.openUnidirectionalStreamForTesting(
                writingSessionID: foreignSessionID,
                firstPayload: Data("foreign".utf8),
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )

            // The prefix is classified before the session manager can register or
            // buffer the stream, and the refusal names the session-gone condition
            // rather than a generic frame error.
            do {
                _ = try await serverSession.acceptUnidirectionalStream(timeoutMilliseconds: 15_000)
                Issue.record("a unidirectional stream naming a foreign session must be refused")
            } catch let error as WebTransportDraft16Error {
                #expect(error.kind == .sessionGone)
            }

            // The refusal is per stream: a stream naming the served session still
            // arrives on the same connection, so nothing was poisoned or consumed
            // in its place.
            let payload = Data("still-served".utf8)
            _ = try await clientSession.openUnidirectionalStreamForTesting(
                firstPayload: payload,
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )
            let inbound = try await serverSession.acceptUnidirectionalStream(timeoutMilliseconds: 15_000)
            #expect(try await inbound.receive(timeoutMilliseconds: 15_000) == payload)
        }
    }

    /// RFC 9114 section 6.2: a unidirectional stream whose type this endpoint does
    /// not serve — including the reserved types section 6.2.3 carves out
    /// (`0x1f * N + 0x21`) — must be discarded, never reported as a connection
    /// error. Before the fix the accept path answered the reserved type `0x21`
    /// with `unexpectedFrame`, so a peer exercising exactly the stream type the
    /// RFC reserves for private use failed the session instead of being ignored.
    @Test
    func runtimeIgnoresUnidirectionalStreamsWithReservedTypes() async throws {
        try await WebTransportLoopbackTestLock.withLockAsync(label: #function) {
            let server = try WebTransportQUICServer(
                endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
                authority: "localhost",
                localOnly: false
            )
            let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
            defer { server.shutdown() }

            let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
            let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
            async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
            let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
            let clientSession = try await connecting

            // `0x21` is the first reserved stream type, and the RFC explicitly
            // allows a peer to send it. The payload after it is opaque bytes.
            let reservedTypeBytes = Data([0x21, 0xde, 0xad, 0xbe, 0xef])
            _ = try await clientSession.openUnframedUnidirectionalStreamForTesting(
                firstPayload: reservedTypeBytes,
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )
            // Let the reserved stream reach the server first, so the accept path
            // meets it before the WebTransport stream: the failure this guards
            // against is a *session-level* report, which happens regardless of
            // what arrives later.
            try await Task.sleep(for: .milliseconds(300))

            let payload = Data("served-after-reserved-type".utf8)
            _ = try await clientSession.openUnidirectionalStreamForTesting(
                firstPayload: payload,
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )

            // The reserved stream must not be handed to the application, and it
            // must not fail the accept: the WebTransport stream behind it is
            // still served on the same connection.
            let inbound = try await serverSession.acceptUnidirectionalStream(timeoutMilliseconds: 15_000)
            #expect(try await inbound.receive(timeoutMilliseconds: 15_000) == payload)
        }
    }

    /// RFC 9114 section 6.2.1 makes a second HTTP/3 control stream a connection
    /// error of type H3_STREAM_CREATION_ERROR (RFC 9204 section 4.2 says the same
    /// for a second QPACK encoder or decoder stream). Establishment already reads
    /// and retains the peer's one control stream, so a second one is peer
    /// misbehaviour; before the fix the accept path retained it silently, leaving
    /// both ends waiting until the accept deadline and permanently spending one
    /// unit of the peer's unidirectional-stream credit.
    @Test
    func runtimeRejectsASecondHTTP3ControlStream() async throws {
        try await WebTransportLoopbackTestLock.withLockAsync(label: #function) {
            let server = try WebTransportQUICServer(
                endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
                authority: "localhost",
                localOnly: false
            )
            let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
            defer { server.shutdown() }

            let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
            let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
            async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
            let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
            let clientSession = try await connecting

            // HTTP/3 stream type 0x00, then a zero-length SETTINGS frame: the
            // smallest well-formed shape of a second control stream.
            _ = try await clientSession.openUnframedUnidirectionalStreamForTesting(
                firstPayload: Data([0x00, 0x04, 0x00]),
                endOfStream: true,
                timeoutMilliseconds: 15_000
            )

            do {
                _ = try await serverSession.acceptUnidirectionalStream(timeoutMilliseconds: 5_000)
                Issue.record("a second HTTP/3 control stream must be a connection error")
            } catch let error as HTTP3ConnectionError {
                #expect(error.code == .streamCreationError)
            }
        }
    }

    /// The caller's `timeoutMilliseconds` is the whole budget for the accept, not
    /// a per-await allowance. A stream that arrives late spends most of the
    /// budget inside `inboundStreams.next`; the read for its first bytes must use
    /// only what is left, so the call cannot wait twice its deadline.
    @Test
    func acceptUnidirectionalStreamHonoursOneDeadlineAcrossItsAwaits() async throws {
        try await WebTransportLoopbackTestLock.withLockAsync(label: #function) {
            let server = try WebTransportQUICServer(
                endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
                authority: "localhost",
                localOnly: false
            )
            let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
            defer { server.shutdown() }

            let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
            let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
            async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
            let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
            let clientSession = try await connecting

            let timeoutMilliseconds: Int32 = 1_000
            let openedAfterMilliseconds = 800
            let started = Date()
            async let accepting = serverSession.acceptUnidirectionalStream(
                timeoutMilliseconds: timeoutMilliseconds
            )
            // Open the stream with no bytes on it, late enough that `next` has
            // already spent most of the budget waiting for it. The stream has
            // nothing to read, so only the remaining budget may be spent on the
            // first-chunk read.
            try await Task.sleep(for: .milliseconds(openedAfterMilliseconds))
            _ = try await clientSession.openUnframedUnidirectionalStreamForTesting(
                firstPayload: Data(),
                endOfStream: false,
                timeoutMilliseconds: 5_000
            )
            do {
                _ = try await accepting
                Issue.record("an empty stream cannot be accepted as a WebTransport stream")
            } catch {
                // Expected: the accept runs out of budget.
            }
            let elapsed = Date().timeIntervalSince(started)
            #expect(
                elapsed < Double(timeoutMilliseconds) / 1_000 * 1.6,
                "the accept waited \(elapsed)s for a \(timeoutMilliseconds)ms budget"
            )
        }
    }

    /// F-swift-line-security-03 still holds when nobody accepts: the per-direction
    /// inbound ceiling refuses the stream that does not fit instead of retaining
    /// it. The caller is told exactly which refusal happened, because that is the
    /// value the runtime turns into the peer-visible `WT_BUFFERED_STREAM_REJECTED`.
    @Test
    func unidirectionalStreamsBeyondTheCeilingAreRefusedWhenNobodyAccepts() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        let direction = InteroperableQUICHelpers.unidirectionalStreamDirection
        let limit = WebTransportTransportLimits.default.initialMaxUnidirectionalStreams
        #expect(limit > 0)

        for index in 0..<limit {
            let disposition = await queue.enqueue(
                index,
                direction: direction,
                streamID: UInt64(index)
            )
            #expect(disposition == .accepted)
        }

        // The queue holds its ceiling now. A peer that opens one more stream is
        // refused rather than having it retained behind the others.
        let refused = await queue.enqueue(
            limit,
            direction: direction,
            streamID: UInt64(limit)
        )
        #expect(refused == .refusedQueueFull(limit: limit))
    }
}
