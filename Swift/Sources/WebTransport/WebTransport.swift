import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore

public struct WebTransportClientConfiguration: Equatable, Sendable {
    public var authority: String
    public var path: String
    public var origin: String?
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

public struct WebTransportServerConfiguration: Equatable, Sendable {
    public var authority: String
    public var path: String
    public var origin: String?
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

public protocol WebTransportSession: Sendable {
    var id: WebTransportSessionID { get }
    func sendDatagram(_ data: Data) async throws
    func receiveDatagrams() -> AsyncThrowingStream<Data, Error>
    func close(code: UInt32, reason: String?) async throws
}

public struct WebTransportBidirectionalStream: Equatable, Sendable {
    public var id: UInt64
}

public struct WebTransportSendStream: Equatable, Sendable {
    public var id: UInt64
}

public struct WebTransportReceiveStream: Equatable, Sendable {
    public var id: UInt64
}

public actor WebTransportClient {
    public let configuration: WebTransportClientConfiguration
    private var http3: HTTP3ConnectionState
    private var manager: WebTransportSessionManager?
    private var nextRequestStreamID: UInt64

    public init(configuration: WebTransportClientConfiguration) {
        self.configuration = configuration
        self.http3 = HTTP3ConnectionState(role: .client)
        self.manager = nil
        self.nextRequestStreamID = 0
    }

    public func connect(to server: WebTransportServer) async throws -> WebTransportClientSession {
        let serverControl = try await server.receiveClientControl(http3.localControlStreamBytes())
        _ = try http3.receivePeerControlStream(serverControl)
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
        return capsule
    }
}

public actor WebTransportServer {
    public let configuration: WebTransportServerConfiguration
    private var http3: HTTP3ConnectionState
    private var manager: WebTransportSessionManager?
    private var datagramChannels: [WebTransportSessionID: WebTransportDatagramChannel]

    public init(configuration: WebTransportServerConfiguration) {
        self.configuration = configuration
        self.http3 = HTTP3ConnectionState(role: .server)
        self.manager = nil
        self.datagramChannels = [:]
    }

    fileprivate func receiveClientControl(_ bytes: Data) throws -> Data {
        _ = try http3.receivePeerControlStream(bytes)
        manager = WebTransportSessionManager(http3: http3)
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
            await channel.yield(payload)
        }
    }

    fileprivate func receiveClose(sessionID: WebTransportSessionID, capsule: Data) throws {
        guard var manager else {
            throw QUICCodecError.malformed("WebTransport server is not connected")
        }
        _ = try manager.receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: capsule)
        self.manager = manager
    }
}

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
