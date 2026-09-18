import Foundation
import CryptoKit
import Network
import Security
import Synchronization
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

/// The steps a server takes between accepting a connection and having a session on it: opening the
/// control streams, reading the request, exchanging control streams, delivering the decision and
/// collecting the inbound one, plus the timeout wrapper they share.
///
/// They take everything they need as arguments and read no server state, so they live here rather
/// than on `WebTransportQUICServer`, whose file is about the listener and the session lifecycle.
enum WebTransportServerSessionSetup {
    /// Everything the handshake produces, ready to become a session.
    struct ServerHandshakeOutcome {
        let connection: NetworkConnection<QUIC>
        let inboundStreams: InteroperableQUICInboundStreamCollector
        let inboundTask: Task<Void, Never>
        let lease: InteroperableQUICConnectionLease?
        let manager: WebTransportSessionManager
        let decision: WebTransportServerSessionDecision
        let localControlStream: QUIC.Stream<QUICStream>
        let requestStream: QUIC.Stream<QUICStream>
        let qpackStreams: [QUIC.Stream<QUICStream>]
        let useDatagrams: Bool
        let optimisticCapsuleBytes: Data
        let timeoutMilliseconds: Int32
    }

    /// A rejected session ends here: the inbound handler is cancelled and the rejection is
    /// what the caller sees.
    static func refuseRejectedSession(
        _ decision: WebTransportServerSessionDecision,
        inboundTask: Task<Void, Never>
    ) throws {
        guard let rejectionError = decision.rejectionError else {
            return
        }
        inboundTask.cancel()
        throw rejectionError
    }
    /// Hands the CONNECT request to the session manager, sends whatever it decided, and
    /// returns the decision.
    static func performConnectExchange(
        manager: inout WebTransportSessionManager,
        requestStream: QUIC.Stream<QUICStream>,
        request: WebTransportServerRequestHandling.DecodedSessionRequest,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws -> WebTransportServerSessionDecision {
        let decision: WebTransportServerSessionDecision
        do {
            decision = try manager.receiveClientSessionRequest(
                streamID: requestStream.streamID,
                frame: request.frame,
                policy: request.policy
            )
        } catch {
            // Without this the reason a peer's CONNECT was refused is lost: the
            // throw propagates as a transport error once the peer has already
            // gone, which is what makes browser handshake failures opaque.
            InteroperableQUICDebug.log("server CONNECT rejected before response: \(error)")
            throw error
        }
        try await WebTransportServerRequestHandling.deliverSessionDecision(
            decision,
            on: requestStream,
            remainingTimeout: remainingTimeout,
            totalTimeoutMilliseconds: totalTimeoutMilliseconds
        )
        return decision
    }
    /// The session object the handshake produced.
    static func makeSession(_ outcome: ServerHandshakeOutcome, localEndpoint: WebTransportNetworkEndpoint) -> WebTransportNetworkSession {
        WebTransportNetworkSession(
            connection: outcome.connection,
            inboundStreams: outcome.inboundStreams,
            inboundTask: outcome.inboundTask,
            lease: outcome.lease,
            manager: outcome.manager,
            sessionID: outcome.decision.session.id,
            selectedProtocol: outcome.decision.session.selectedProtocol,
            localControlStream: outcome.localControlStream,
            connectStream: outcome.requestStream,
            qpackStreams: outcome.qpackStreams,
            localEndpoint: localEndpoint,
            remoteEndpoint: InteroperableQUICRuntime.networkEndpoint(
                from: outcome.connection.remoteEndpoint,
                fallback: WebTransportNetworkEndpoint(host: "unknown", port: 0)
            ),
            datagramsAvailable: outcome.useDatagrams,
            timeoutMilliseconds: outcome.timeoutMilliseconds,
            initialConnectCapsuleBytes: outcome.optimisticCapsuleBytes
        )
    }
    /// The remaining-timeout gate every awaited step in `acceptSession` runs through.
    private static func withCheckedTimeout<T: Sendable>(
        _ remaining: Int32,
        totalTimeoutMilliseconds: Int32,
        _ operation: @Sendable @escaping () async throws -> T
    ) async throws -> T {
        guard remaining > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        return try await InteroperableQUICHelpers.withTimeout(remaining, operation)
    }
    /// The peer's CONNECT request stream and its first chunk, sharing one deadline.
    static func nextRequestStreamAndFirstChunk(
        inboundStreams: InteroperableQUICInboundStreamCollector,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws -> (stream: QUIC.Stream<QUICStream>, payload: Data) {
        let streamTimeout = remainingTimeout()
        guard streamTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        let stream = try await InteroperableQUICHelpers.withTimeout(streamTimeout) {
            try await inboundStreams.next(
                direction: InteroperableQUICHelpers.bidirectionalStreamDirection,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server got request stream \(stream.streamID)")
        let payloadTimeout = remainingTimeout()
        guard payloadTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        let payload = try await InteroperableQUICHelpers.withTimeout(payloadTimeout) {
            try await InteroperableQUICHelpers.readFirstChunk(
                stream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server request payload bytes=\(payload.count)")
        return (stream, payload)
    }
    /// Opens the server's local control stream, sends its SETTINGS, and opens the QPACK
    /// streams. Each step samples the remaining deadline rather than reusing a value taken
    /// before the previous one.
    static func openServerControlStreams(
        connection: NetworkConnection<QUIC>,
        http3: HTTP3ConnectionState,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws -> (control: QUIC.Stream<QUICStream>, qpack: [QUIC.Stream<QUICStream>]) {
        let localControlPayload = try http3.localControlStreamBytes()
        let openTimeout = remainingTimeout()
        guard openTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        let localControlStream = try await InteroperableQUICHelpers.withTimeout(openTimeout) {
            try await connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("server opened local control stream \(localControlStream.streamID)")
        let sendTimeout = remainingTimeout()
        guard sendTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        try await InteroperableQUICHelpers.withTimeout(sendTimeout) {
            try await localControlStream.send(localControlPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("server sent local control payload")
        let qpackStreams = try await InteroperableQUICHelpers.openQPACKStreams(
            on: connection,
            role: "server",
            timeoutMilliseconds: remainingTimeout()
        )
        return (localControlStream, qpackStreams)
    }
    /// The inbound collector for one accepted connection, with its handler already
    /// registered and waited for.
    static func startInboundCollection(
        connection: NetworkConnection<QUIC>,
        advertisedStreamLimits: WebTransportTransportLimits
    ) async -> (streams: InteroperableQUICInboundStreamCollector, task: Task<Void, Never>) {
        let inboundStreams = InteroperableQUICInboundStreamCollector(
            bidirectionalLimit: advertisedStreamLimits.initialMaxBidirectionalStreams,
            unidirectionalLimit: advertisedStreamLimits.initialMaxUnidirectionalStreams
        )
        let inboundRegistration = InteroperableQUICInboundRegistration()
        let inboundTask = Task {
            do {
                await inboundRegistration.markEntered()
                try await connection.inboundStreams { stream in
                    await InteroperableQUICHelpers.enqueueInboundStream(
                        stream,
                        into: inboundStreams,
                        role: "server"
                    )
                }
            } catch {
                await inboundRegistration.markEntered()
                await inboundStreams.fail(error, role: "server")
            }
        }
        await inboundRegistration.waitUntilEntered()
        return (inboundStreams, inboundTask)
    }
}
