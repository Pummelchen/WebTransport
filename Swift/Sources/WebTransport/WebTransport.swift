import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore

/// Client-side options for the in-process Swift concurrency WebTransport facade.
///
/// This facade is intentionally small: it exercises the package's HTTP/3
/// WebTransport session machinery without exposing low-level QUIC/TLS state.
public struct WebTransportClientConfiguration: Equatable, Sendable {
    /// The expected `:authority` value on the extended CONNECT request.
    public var authority: String
    /// The expected `:path` value on the extended CONNECT request.
    public var path: String
    /// Optional origin header value for server-side origin policy checks.
    public var origin: String?
    /// Client-offered WebTransport subprotocol tokens.
    public var availableProtocols: [String]

    public init(
        authority: String,
        path: String,
        origin: String? = nil,
        availableProtocols: [String] = []
    ) {
        self.authority = authority
        self.path = path
        self.origin = origin
        self.availableProtocols = availableProtocols
    }
}

/// Server-side options for the in-process Swift concurrency WebTransport facade.
public struct WebTransportServerConfiguration: Equatable, Sendable {
    /// Allowed CONNECT authority.
    public var authority: String
    /// Allowed CONNECT path.
    public var path: String
    /// Optional required origin value.
    public var origin: String?
    /// Server-supported WebTransport subprotocol tokens.
    public var supportedProtocols: [String]

    public init(
        authority: String = "localhost",
        path: String = "/wt",
        origin: String? = nil,
        supportedProtocols: [String] = []
    ) {
        self.authority = authority
        self.path = path
        self.origin = origin
        self.supportedProtocols = supportedProtocols
    }
}

/// Sanitized production log event emitted by the high-level WebTransport facade.
///
/// Events intentionally avoid TLS secrets, certificate material, QUIC connection
/// IDs, raw session IDs, packet bytes, datagram payloads, and close reason text.
public enum WebTransportLogEvent: Equatable, Sendable, CustomStringConvertible {
    case clientControlExchanged
    case serverControlAccepted
    case sessionEstablished(role: String)
    case datagramSent(byteCount: Int)
    case datagramReceived(byteCount: Int)
    case sessionClosed(applicationErrorCode: UInt32, reasonByteCount: Int)

    public var description: String {
        switch self {
        case .clientControlExchanged:
            return "webtransport.client_control_exchanged"
        case .serverControlAccepted:
            return "webtransport.server_control_accepted"
        case .sessionEstablished(let role):
            return "webtransport.session_established role=\(role)"
        case .datagramSent(let byteCount):
            return "webtransport.datagram_sent bytes=\(byteCount)"
        case .datagramReceived(let byteCount):
            return "webtransport.datagram_received bytes=\(byteCount)"
        case .sessionClosed(let applicationErrorCode, let reasonByteCount):
            return "webtransport.session_closed code=\(applicationErrorCode) reason_bytes=\(reasonByteCount)"
        }
    }
}

/// Opt-in sink for sanitized production log events.
public struct WebTransportLogger: Sendable {
    public typealias Sink = @Sendable (WebTransportLogEvent) -> Void

    /// Logger that drops all events.
    public static let disabled = WebTransportLogger()

    private let sink: Sink?

    public init(_ sink: Sink? = nil) {
        self.sink = sink
    }

    func record(_ event: WebTransportLogEvent) {
        sink?(event)
    }
}

/// Public error text helper for production surfaces.
///
/// Use this for user-visible/logged error text when the original error might
/// carry peer input, close messages, packet bytes, or transport identifiers.
public enum WebTransportErrorSurface {
    public static func publicDescription(for error: Error) -> String {
        if let draftError = error as? WebTransportDraft15Error {
            switch draftError.kind {
            case .sessionGone:
                return "WebTransport session is gone"
            case .bufferedStreamRejected:
                return "WebTransport buffered stream was rejected"
            case .flowControl:
                return "WebTransport flow-control violation"
            case .requirementsNotMet:
                return "WebTransport peer requirements were not met"
            case .alpn:
                return "WebTransport ALPN negotiation failed"
            case .h3ID:
                return "WebTransport session identifier was invalid"
            }
        }
        if error is QUICCodecError {
            return "WebTransport protocol codec rejected malformed input"
        }
        return "WebTransport operation failed"
    }
}

/// Minimal async session contract for sending datagrams, receiving datagrams,
/// and closing a WebTransport session.
public protocol WebTransportSession: Sendable {
    /// Draft session identifier. Treat as protocol state, not as log-safe user data.
    var id: WebTransportSessionID { get }

    /// Sends one datagram payload on this session.
    func sendDatagram(_ data: Data) async throws

    /// Returns an async datagram stream for this session.
    func receiveDatagrams() -> AsyncThrowingStream<Data, Error>

    /// Closes the session with a 32-bit application code and optional reason.
    func close(code: UInt32, reason: String?) async throws
}

/// Placeholder value type for future bidirectional stream facade APIs.
public struct WebTransportBidirectionalStream: Equatable, Sendable {
    public var id: UInt64
}

/// Placeholder value type for future send stream facade APIs.
public struct WebTransportSendStream: Equatable, Sendable {
    public var id: UInt64
}

/// Placeholder value type for future receive stream facade APIs.
public struct WebTransportReceiveStream: Equatable, Sendable {
    public var id: UInt64
}

/// In-process client facade backed by the package's HTTP/3 WebTransport core.
public actor WebTransportClient {
    public let configuration: WebTransportClientConfiguration
    private let logger: WebTransportLogger
    private var http3: HTTP3ConnectionState
    private var manager: WebTransportSessionManager?
    private var nextRequestStreamID: UInt64

    public init(configuration: WebTransportClientConfiguration, logger: WebTransportLogger = .disabled) {
        self.configuration = configuration
        self.logger = logger
        self.http3 = HTTP3ConnectionState(role: .client)
        self.manager = nil
        self.nextRequestStreamID = 0
    }

    /// Establishes a WebTransport session against the paired in-process server.
    public func connect(to server: WebTransportServer) async throws -> WebTransportClientSession {
        let serverControl = try await server.receiveClientControl(http3.localControlStreamBytes())
        _ = try http3.receivePeerControlStream(serverControl)
        logger.record(.clientControlExchanged)
        if manager == nil {
            manager = WebTransportSessionManager(http3: http3)
        }

        let streamID = nextRequestStreamID
        nextRequestStreamID += 4
        let request = try WebTransportSessionRequest(
            authority: configuration.authority,
            path: configuration.path,
            origin: configuration.origin,
            availableProtocols: configuration.availableProtocols
        )
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport client manager was not initialized")
        }
        let requestFrame = try manager.makeClientSessionRequest(streamID: streamID, request: request)
        let decision = try await server.receiveClientSessionRequest(streamID: streamID, frame: requestFrame)
        let session = try manager.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
        self.manager = manager
        logger.record(.sessionEstablished(role: "client"))

        let datagrams = WebTransportDatagramChannel()
        await server.registerDatagramChannel(datagrams, for: session.id)
        return WebTransportClientSession(id: session.id, client: self, server: server, datagrams: datagrams)
    }

    fileprivate func makeDatagramFrame(sessionID: WebTransportSessionID, payload: Data) throws -> QUICFrame {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport client is not connected")
        }
        let frame = try manager.makeDatagramFrame(sessionID: sessionID, payload: payload)
        self.manager = manager
        logger.record(.datagramSent(byteCount: payload.count))
        return frame
    }

    fileprivate func close(sessionID: WebTransportSessionID, code: UInt32, reason: String?) throws -> Data {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport client is not connected")
        }
        let capsule = try manager.makeCloseSessionCapsule(
            sessionID: sessionID,
            applicationErrorCode: code,
            message: reason ?? ""
        )
        self.manager = manager
        logger.record(.sessionClosed(
            applicationErrorCode: code,
            reasonByteCount: Data((reason ?? "").utf8).count
        ))
        return capsule
    }
}

/// In-process server facade backed by the package's HTTP/3 WebTransport core.
public actor WebTransportServer {
    public let configuration: WebTransportServerConfiguration
    private let logger: WebTransportLogger
    private var http3: HTTP3ConnectionState
    private var manager: WebTransportSessionManager?
    private var datagramChannels: [WebTransportSessionID: WebTransportDatagramChannel]

    public init(configuration: WebTransportServerConfiguration, logger: WebTransportLogger = .disabled) {
        self.configuration = configuration
        self.logger = logger
        self.http3 = HTTP3ConnectionState(role: .server)
        self.manager = nil
        self.datagramChannels = [:]
    }

    fileprivate func receiveClientControl(_ bytes: Data) throws -> Data {
        _ = try http3.receivePeerControlStream(bytes)
        manager = WebTransportSessionManager(http3: http3)
        logger.record(.serverControlAccepted)
        return try http3.localControlStreamBytes()
    }

    fileprivate func receiveClientSessionRequest(
        streamID: UInt64,
        frame: HTTP3Frame
    ) throws -> WebTransportServerSessionDecision {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport server manager was not initialized")
        }
        let policy = try WebTransportServerSessionPolicy(
            allowedAuthorities: [configuration.authority],
            allowedPaths: [configuration.path],
            allowedOrigins: configuration.origin.map { [$0] },
            supportedProtocols: configuration.supportedProtocols,
            requireProtocolSelection: !configuration.supportedProtocols.isEmpty
        )
        let decision = try manager.receiveClientSessionRequest(
            streamID: streamID,
            frame: frame,
            policy: policy
        )
        self.manager = manager
        if decision.rejectionError == nil {
            logger.record(.sessionEstablished(role: "server"))
        }
        return decision
    }

    fileprivate func registerDatagramChannel(
        _ channel: WebTransportDatagramChannel,
        for sessionID: WebTransportSessionID
    ) {
        datagramChannels[sessionID] = channel
    }

    fileprivate func receiveDatagram(_ frame: QUICFrame) async throws {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport server is not connected")
        }
        let sessionID = try manager.receiveDatagramFrame(frame)
        let payload = manager.popDatagramPayload(sessionID: sessionID)
        self.manager = manager
        if let payload, let channel = datagramChannels[sessionID] {
            logger.record(.datagramReceived(byteCount: payload.count))
            await channel.yield(payload)
        }
    }

    fileprivate func receiveClose(sessionID: WebTransportSessionID, capsule: Data) throws {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport server is not connected")
        }
        let received = try manager.receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: capsule)
        self.manager = manager
        if case .closeSession(let applicationErrorCode, let message) = received.capsule {
            logger.record(.sessionClosed(
                applicationErrorCode: applicationErrorCode,
                reasonByteCount: Data(message.utf8).count
            ))
        }
    }
}

/// Client-side session returned by `WebTransportClient.connect(to:)`.
public struct WebTransportClientSession: WebTransportSession {
    public let id: WebTransportSessionID
    private let client: WebTransportClient
    private let server: WebTransportServer
    private let datagrams: WebTransportDatagramChannel

    fileprivate init(
        id: WebTransportSessionID,
        client: WebTransportClient,
        server: WebTransportServer,
        datagrams: WebTransportDatagramChannel
    ) {
        self.id = id
        self.client = client
        self.server = server
        self.datagrams = datagrams
    }

    public func sendDatagram(_ data: Data) async throws {
        let frame = try await client.makeDatagramFrame(sessionID: id, payload: data)
        try await server.receiveDatagram(frame)
    }

    public func receiveDatagrams() -> AsyncThrowingStream<Data, Error> {
        AsyncThrowingStream { continuation in
            Task {
                await datagrams.attach(continuation)
            }
        }
    }

    public func close(code: UInt32, reason: String?) async throws {
        let capsule = try await client.close(sessionID: id, code: code, reason: reason)
        try await server.receiveClose(sessionID: id, capsule: capsule)
        await datagrams.finish()
    }
}

/// Async in-memory datagram fan-out used by the high-level facade.
public actor WebTransportDatagramChannel {
    private var continuations: [UUID: AsyncThrowingStream<Data, Error>.Continuation] = [:]
    private var pending: [Data] = []

    func attach(_ continuation: AsyncThrowingStream<Data, Error>.Continuation) {
        let id = UUID()
        continuations[id] = continuation
        for item in pending {
            continuation.yield(item)
        }
        pending.removeAll()
        continuation.onTermination = { [weak self] _ in
            Task { await self?.remove(id) }
        }
    }

    func yield(_ data: Data) {
        guard !continuations.isEmpty else {
            pending.append(data)
            return
        }
        for continuation in continuations.values {
            continuation.yield(data)
        }
    }

    func finish() {
        for continuation in continuations.values {
            continuation.finish()
        }
        continuations.removeAll()
    }

    private func remove(_ id: UUID) {
        continuations.removeValue(forKey: id)
    }
}
