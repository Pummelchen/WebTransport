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
