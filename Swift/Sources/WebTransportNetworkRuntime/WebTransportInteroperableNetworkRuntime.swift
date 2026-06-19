import Foundation
import CryptoKit
import Network
import Security

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

private enum InteroperableQUICDebug {
    static let enabled = ProcessInfo.processInfo.environment["WEBTRANSPORT_INTEROP_DEBUG"] == "1"

    static func log(_ message: @autoclosure () -> String) {
        guard enabled else {
            return
        }
        let text = "[interoperable-quic] \(message())\n"
        if let data = text.data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
}

public enum WebTransportQUICPeerTrustPolicy: Equatable, Sendable {
    /// Use Network.framework's default platform certificate validation.
    case systemTrust
    /// Test-only trust bypass for generated localhost identities.
    ///
    /// This mode is rejected for non-loopback endpoints before any network
    /// connection is attempted.
    case localDevelopmentSelfSigned

    public static func parse(_ value: String) throws -> WebTransportQUICPeerTrustPolicy {
        switch value {
        case "system":
            return .systemTrust
        case "local-self-signed":
            return .localDevelopmentSelfSigned
        default:
            throw WebTransportNetworkRuntimeError.invalidTransport("unknown trust policy: \(value)")
        }
    }

    func validate(endpoint: WebTransportNetworkEndpoint) throws {
        switch self {
        case .systemTrust:
            return
        case .localDevelopmentSelfSigned:
            guard Self.isLoopbackHost(endpoint.host) else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "local-self-signed trust is restricted to localhost, 127.0.0.1, and ::1"
                )
            }
        }
    }

    private static func isLoopbackHost(_ host: String) -> Bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1"
    }
}

public struct WebTransportQUICClient: Sendable {
    public var localPort: UInt16
    public var trustPolicy: WebTransportQUICPeerTrustPolicy

    public init(
        localPort: UInt16 = 0,
        trustPolicy: WebTransportQUICPeerTrustPolicy = .systemTrust
    ) {
        self.localPort = localPort
        self.trustPolicy = trustPolicy
    }

    @discardableResult
    public func connectSession(
        to endpoint: WebTransportNetworkEndpoint,
        authority: String? = nil,
        path: String = "/wt",
        origin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        timeoutMilliseconds: Int32 = 1_000
    ) async throws -> WebTransportNetworkSession {
        try trustPolicy.validate(endpoint: endpoint)
        let host = InteroperableQUICRuntime.host(for: endpoint.host)
        let destination = NWEndpoint.hostPort(
            host: host,
            port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any
        )
        InteroperableQUICDebug.log("client connecting to \(endpoint.host):\(endpoint.port)")
        let connection = NetworkConnection(to: destination) {
            InteroperableQUICRuntime.makeClientQUIC(trustPolicy: trustPolicy)
        }
        InteroperableQUICDebug.log("client state before start: \(connection.state)")
        InteroperableQUICDebug.log("client started")

        let started = Date()
        func remainingTimeout() -> Int32 {
            InteroperableQUICHelpers.remainingTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                started: started
            )
        }
        func runWithTimeout(_ operation: @Sendable @escaping () async throws -> Void) async throws {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        try await InteroperableQUICHelpers.waitForReady(
            connection: connection,
            role: "client",
            start: { _ = connection.start() },
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client ready")

        let inboundStreams = InteroperableQUICInboundStreamCollector()
        let inboundTask = Task {
            do {
                try await connection.inboundStreams { stream in
                    await inboundStreams.enqueue(stream, direction: InteroperableQUICHelpers.streamDirectionKey(stream.directionality))
                }
            } catch {
                await inboundStreams.fail(error)
            }
        }

        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(connection)
        InteroperableQUICDebug.log("client datagrams usable=\(useDatagrams)")

        var http3 = HTTP3ConnectionState(
            role: .client,
            localSettings: settingsValidation.localSettings
        )
        let localControlPayload = try http3.localControlStreamBytes()
        let localControlStream = try await InteroperableQUICHelpers.withTimeout(
            remainingTimeout()
        ) {
            try await connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("client opened local control stream \(localControlStream.streamID)")
        try await runWithTimeout {
            try await localControlStream.send(localControlPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent local control payload")

        let peerControlBytes = try await InteroperableQUICHelpers.readPeerControlStream(
            from: inboundStreams,
            role: "client",
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client peer control bytes=\(peerControlBytes.count)")
        _ = try http3.receivePeerControlStream(
            peerControlBytes,
            settingsValidation: settingsValidation
        )
        var manager = WebTransportSessionManager(
            http3: http3,
            settingsValidation: settingsValidation
        )

        let requestStream = try await InteroperableQUICHelpers.withTimeout(
            remainingTimeout()
        ) {
            try await connection.openStream(directionality: .bidirectional)
        }
        let requestStreamID = requestStream.streamID
        InteroperableQUICDebug.log("client opened request stream \(requestStreamID)")
        let request = try WebTransportSessionRequest(
            authority: authority ?? endpoint.host,
            path: path,
            origin: origin,
            availableProtocols: protocols
        )
        let requestFrame = try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
        let connectPayload = try InteroperableQUICHelpers.makeRequestStreamPayload(
            streamID: requestStreamID,
            requestFrame: requestFrame
        )
        try await runWithTimeout {
            try await requestStream.send(connectPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent connect payload")

        let responseData = try await InteroperableQUICHelpers.readStream(
            requestStream,
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client got response bytes=\(responseData.count)")
        let responseFrames = try HTTP3Frame.decodeFrames(responseData)
        guard let responseFrame = responseFrames.first(where: { $0.type == HTTP3FrameType.headers }) else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        let session = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responseFrame)
        guard session.state == .accepted else {
            inboundTask.cancel()
            throw WebTransportDraft15Error(
                kind: .requirementsNotMet,
                message: "WebTransport session was rejected"
            )
        }
        let sessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)

        return WebTransportNetworkSession(
            connection: connection,
            inboundStreams: inboundStreams,
            inboundTask: inboundTask,
            manager: manager,
            sessionID: sessionID,
            selectedProtocol: session.selectedProtocol,
            localControlStream: localControlStream,
            connectStream: requestStream,
            localEndpoint: WebTransportNetworkEndpoint(host: endpoint.host, port: endpoint.port),
            remoteEndpoint: endpoint,
            datagramsAvailable: useDatagrams,
            timeoutMilliseconds: timeoutMilliseconds
        )
    }

    @discardableResult
    public func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        authority: String? = nil,
        path: String = "/wt",
        origin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        timeoutMilliseconds: Int32 = 1_000
    ) async throws -> WebTransportNetworkSessionResult {
        let session = try await connectSession(
            to: endpoint,
            authority: authority,
            path: path,
            origin: origin,
            protocols: protocols,
            settingsValidation: settingsValidation,
            timeoutMilliseconds: timeoutMilliseconds
        )

        let responseMessage: String
        let preferStreams = settingsValidation == .pywebtransportStreamInterop
        if session.datagramsAvailable && !preferStreams {
            InteroperableQUICDebug.log("client using datagram path")
            try await session.sendDatagram(Data(message.utf8), timeoutMilliseconds: timeoutMilliseconds)
            InteroperableQUICDebug.log("client sent datagram")
            let responsePayload = try await session.receiveDatagram(timeoutMilliseconds: timeoutMilliseconds)
            guard let responseMessageValue = String(data: responsePayload, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            responseMessage = responseMessageValue
        } else {
            InteroperableQUICDebug.log("client using stream fallback path")
            let fallbackStream = try await session.openBidirectionalStream(timeoutMilliseconds: timeoutMilliseconds)
            try await fallbackStream.send(Data(message.utf8), endOfStream: true, timeoutMilliseconds: timeoutMilliseconds)
            let fallbackResponse = try await fallbackStream.receive(timeoutMilliseconds: timeoutMilliseconds)
            guard let responseMessageValue = String(data: fallbackResponse, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            responseMessage = responseMessageValue
        }

        return WebTransportNetworkSessionResult(
            localEndpoint: session.localEndpoint,
            remoteEndpoint: session.remoteEndpoint,
            message: responseMessage,
            transport: .packet,
            sessionEstablished: true
        )
    }
}

public final class WebTransportNetworkBidirectionalStream: @unchecked Sendable {
    public let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let prefix: Data?
    private let state: WebTransportNetworkStreamState

    init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        prefix: Data? = nil,
        initialPayload: Data = Data()
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.prefix = prefix
        self.state = WebTransportNetworkStreamState(prefix: prefix, initialPayload: initialPayload)
    }

    public func send(
        _ data: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        var mutablePayload = Data()
        if let prefix = await state.consumeOutboundPrefix() {
            mutablePayload.append(prefix)
        }
        mutablePayload.append(data)
        let payload = mutablePayload
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.stream.send(payload, endOfStream: endOfStream)
        }
    }

    public func receive(
        maximumBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
        if let initialPayload = await state.consumeInitialPayload(), !initialPayload.isEmpty {
            return initialPayload
        }
        return try await InteroperableQUICHelpers.readStream(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumBytes
        )
    }
}

public final class WebTransportNetworkSession: @unchecked Sendable {
    public let localEndpoint: WebTransportNetworkEndpoint
    public let remoteEndpoint: WebTransportNetworkEndpoint
    public let sessionID: UInt64
    public let selectedProtocol: String?
    public let datagramsAvailable: Bool
    public let transport: WebTransportNetworkTransport = .packet

    private let connection: NetworkConnection<QUIC>
    private let inboundStreams: InteroperableQUICInboundStreamCollector
    private let inboundTask: Task<Void, Never>
    private let manager: WebTransportNetworkSessionManagerState
    private let localControlStream: QUIC.Stream<QUICStream>
    private let connectStream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32

    fileprivate init(
        connection: NetworkConnection<QUIC>,
        inboundStreams: InteroperableQUICInboundStreamCollector,
        inboundTask: Task<Void, Never>,
        manager: WebTransportSessionManager,
        sessionID: WebTransportSessionID,
        selectedProtocol: String?,
        localControlStream: QUIC.Stream<QUICStream>,
        connectStream: QUIC.Stream<QUICStream>,
        localEndpoint: WebTransportNetworkEndpoint,
        remoteEndpoint: WebTransportNetworkEndpoint,
        datagramsAvailable: Bool,
        timeoutMilliseconds: Int32
    ) {
        self.connection = connection
        self.inboundStreams = inboundStreams
        self.inboundTask = inboundTask
        self.manager = WebTransportNetworkSessionManagerState(manager: manager)
        self.sessionID = sessionID.rawValue
        self.selectedProtocol = selectedProtocol
        self.localControlStream = localControlStream
        self.connectStream = connectStream
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.datagramsAvailable = datagramsAvailable
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    deinit {
        inboundTask.cancel()
    }

    public func openBidirectionalStream(
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> WebTransportNetworkBidirectionalStream {
        let timeout = overrideTimeoutMilliseconds ?? timeoutMilliseconds
        let started = Date()
        var lastError: Error?
        while true {
            do {
                let stream = try await InteroperableQUICHelpers.withTimeout(
                    InteroperableQUICHelpers.remainingTimeout(
                        timeoutMilliseconds: timeout,
                        started: started
                    )
                ) {
                    try await self.connection.openStream(directionality: .bidirectional)
                }
                let prefix = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: sessionID)
                return WebTransportNetworkBidirectionalStream(
                    stream: stream,
                    timeoutMilliseconds: timeout,
                    prefix: prefix
                )
            } catch {
                guard InteroperableQUICHelpers.isTransientNotConnected(error) else {
                    throw error
                }
                lastError = error
                let remaining = InteroperableQUICHelpers.remainingTimeout(
                    timeoutMilliseconds: timeout,
                    started: started
                )
                guard remaining > 100 else {
                    throw lastError ?? error
                }
                try await Task.sleep(for: .milliseconds(50))
            }
        }
    }

    public func acceptBidirectionalStream(
        maximumInitialBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> WebTransportNetworkBidirectionalStream {
        let stream = try await inboundStreams.next(
            direction: InteroperableQUICHelpers.bidirectionalStreamDirection,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds
        )
        let firstChunk = try await InteroperableQUICHelpers.readStream(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumInitialBytes
        )
        let prefix = try WebTransportStreamSignaling.parsePrefix(firstChunk)
        guard prefix.form == .bidirectional, prefix.sessionID.rawValue == sessionID else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        return WebTransportNetworkBidirectionalStream(
            stream: stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            initialPayload: prefix.remainingPayload
        )
    }

    public func sendDatagram(
        _ data: Data,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        guard datagramsAvailable else {
            throw WebTransportNetworkRuntimeError.invalidTransport("QUIC DATAGRAM is not available on this connection")
        }
        let datagrams = try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connection.datagrams
        }
        let frame = try await manager.withManager { manager in
            try manager.makeDatagramFrame(sessionID: WebTransportSessionID(rawValue: self.sessionID), payload: data)
        }
        guard case .datagram(let payload) = frame else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await datagrams.send(payload)
        }
    }

    public func receiveDatagram(
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
        guard datagramsAvailable else {
            throw WebTransportNetworkRuntimeError.invalidTransport("QUIC DATAGRAM is not available on this connection")
        }
        let datagrams = try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connection.datagrams
        }
        let receivedDatagram = try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await datagrams.receive().content
        }
        return try await manager.withManager { manager in
            let responseSessionID = try manager.receiveDatagramFrame(.datagram(receivedDatagram))
            guard responseSessionID.rawValue == self.sessionID,
                  let payload = manager.popDatagramPayload(sessionID: responseSessionID) else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            return payload
        }
    }

    public func drain(timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil) async throws {
        let capsule = try await manager.withManager { manager in
            try manager.makeDrainSessionCapsule(sessionID: WebTransportSessionID(rawValue: self.sessionID))
        }
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connectStream.send(capsule, endOfStream: false)
        }
    }

    public func close(
        applicationErrorCode: UInt32,
        reason: String = "",
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        let capsule = try await manager.withManager { manager in
            try manager.makeCloseSessionCapsule(
                sessionID: WebTransportSessionID(rawValue: self.sessionID),
                applicationErrorCode: applicationErrorCode,
                message: reason
            )
        }
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connectStream.send(capsule, endOfStream: true)
        }
    }
}

private actor WebTransportNetworkStreamState {
    private var outboundPrefix: Data?
    private var initialPayload: Data?

    init(prefix: Data?, initialPayload: Data) {
        self.outboundPrefix = prefix
        self.initialPayload = initialPayload
    }

    func consumeOutboundPrefix() -> Data? {
        let value = outboundPrefix
        outboundPrefix = nil
        return value
    }

    func consumeInitialPayload() -> Data? {
        let value = initialPayload
        initialPayload = nil
        return value
    }
}

private actor WebTransportNetworkSessionManagerState {
    private var manager: WebTransportSessionManager

    init(manager: WebTransportSessionManager) {
        self.manager = manager
    }

    func withManager<T: Sendable>(_ body: @Sendable (inout WebTransportSessionManager) throws -> T) rethrows -> T {
        try body(&manager)
    }
}

public final class WebTransportQUICServer: @unchecked Sendable {
    public private(set) var localEndpoint: WebTransportNetworkEndpoint
    public let certificateSHA256: Data

    private let listener: NetworkListener<QUIC>
    private let acceptedConnections: InteroperableQUICConnectionQueue
    private let listenerTask: Task<Void, Never>
    private let authority: String
    private let path: String
    private let allowedOrigin: String?
    private let protocols: [String]
    private let settingsValidation: HTTP3WebTransportSettingsValidation

    public convenience init(
        bindPort: UInt16,
        maxConcurrentConnections: Int = 16,
        authority: String = "localhost",
        path: String = "/wt",
        allowedOrigin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        localOnly: Bool = false
    ) throws {
        try self.init(
            endpoint: WebTransportNetworkEndpoint(port: bindPort),
            maxConcurrentConnections: maxConcurrentConnections,
            authority: authority,
            path: path,
            allowedOrigin: allowedOrigin,
            protocols: protocols,
            settingsValidation: settingsValidation,
            localOnly: localOnly
        )
    }

    public init(
        endpoint: WebTransportNetworkEndpoint,
        maxConcurrentConnections: Int = 16,
        authority: String = "localhost",
        path: String = "/wt",
        allowedOrigin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        localOnly: Bool = false
    ) throws {
        InteroperableQUICDebug.log("server init endpoint=\(endpoint.commandLineValue)")
        let identity = try InteroperableTLSIdentity.create()
        certificateSHA256 = Data(SHA256.hash(data: identity.certificateDER))
        let baseParameters = NWParametersBuilder(auto: {
            InteroperableQUICRuntime.makeServerQUIC(identity: identity.networkIdentity)
        })
        .localEndpoint(
            .hostPort(
                host: InteroperableQUICRuntime.host(for: endpoint.host),
                port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any
            )
        )
        let parameters = localOnly ? baseParameters.localOnly(true) : baseParameters

        listener = try NetworkListener<QUIC>(using: parameters)
            .newConnectionLimit(max(1, max(16, maxConcurrentConnections * 2)))
        acceptedConnections = InteroperableQUICConnectionQueue()
        localEndpoint = endpoint
        self.authority = authority
        self.path = path
        self.allowedOrigin = allowedOrigin
        self.protocols = protocols
        self.settingsValidation = settingsValidation
        listener.onStateUpdate { _, state in
            InteroperableQUICDebug.log("server listener state update: \(state)")
        }

        let listener = self.listener
        let acceptedConnections = self.acceptedConnections
        listenerTask = Task {
            do {
                try await listener.run { connection in
                    InteroperableQUICDebug.log("server accepted connection")
                    _ = connection.start()
                    await acceptedConnections.enqueue(connection)
                }
            } catch {
                await acceptedConnections.fail(error)
            }
        }
    }

    public func waitForListening(timeoutMilliseconds: Int32 = 5_000) async throws -> WebTransportNetworkEndpoint {
        let port = try await Self.resolveListenerPort(
            self.listener,
            timeoutMilliseconds: timeoutMilliseconds
        )
        localEndpoint = WebTransportNetworkEndpoint(host: localEndpoint.host, port: port.rawValue)
        return localEndpoint
    }

    public func shutdown() {
        listenerTask.cancel()
    }

    deinit {
        shutdown()
    }

    public func acceptSession(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSession {
        let connection = try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await self.acceptedConnections.dequeue()
        }
        InteroperableQUICDebug.log("server acceptSession dequeued")
        InteroperableQUICDebug.log("server acceptSession connection state before wait: \(connection.state)")
        connection.onStateUpdate { _, state in
            InteroperableQUICDebug.log("server connection state update: \(state)")
        }

        do {
            try await InteroperableQUICHelpers.waitForReady(
                connection: connection,
                role: "server",
                allowSetupProceed: true,
                timeoutMilliseconds: timeoutMilliseconds
            )
        } catch {
            _ = connection.state
            throw error
        }

        return try await acceptSession(
            on: connection,
            timeoutMilliseconds: timeoutMilliseconds
        )
    }

    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSessionResult {
        let session = try await acceptSession(timeoutMilliseconds: timeoutMilliseconds)
        let echoed: Data
        if session.datagramsAvailable {
            echoed = try await session.receiveDatagram(timeoutMilliseconds: timeoutMilliseconds)
            try await session.sendDatagram(echoed, timeoutMilliseconds: timeoutMilliseconds)
        } else {
            let stream = try await session.acceptBidirectionalStream(timeoutMilliseconds: timeoutMilliseconds)
            echoed = try await stream.receive(timeoutMilliseconds: timeoutMilliseconds)
            try await stream.send(echoed, endOfStream: true, timeoutMilliseconds: timeoutMilliseconds)
        }
        guard let echoedMessage = String(data: echoed, encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return WebTransportNetworkSessionResult(
            localEndpoint: session.localEndpoint,
            remoteEndpoint: session.remoteEndpoint,
            message: echoedMessage,
            transport: session.transport,
            sessionEstablished: true
        )
    }

    private func acceptSession(
        on connection: NetworkConnection<QUIC>,
        timeoutMilliseconds: Int32
    ) async throws -> WebTransportNetworkSession {
        let started = Date()
        let remainingTimeout: @Sendable () -> Int32 = { [timeoutMilliseconds] () -> Int32 in
            InteroperableQUICHelpers.remainingTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                started: started
            )
        }

        func runWithTimeout(_ operation: @Sendable @escaping () async throws -> Void) async throws {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        func runWithTimeout<T: Sendable>(_ operation: @Sendable @escaping () async throws -> T) async throws -> T {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            return try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        InteroperableQUICDebug.log("server serveSession start")
        let inboundStreams = InteroperableQUICInboundStreamCollector()
        let inboundTask = Task {
            do {
                try await connection.inboundStreams { stream in
                    InteroperableQUICDebug.log("server inbound stream direction=\(stream.directionality) id=\(stream.streamID)")
                    await inboundStreams.enqueue(
                        stream,
                        direction: InteroperableQUICHelpers.streamDirectionKey(stream.directionality)
                    )
                }
            } catch {
                await inboundStreams.fail(error)
            }
        }

        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(connection)
        InteroperableQUICDebug.log("server datagrams usable=\(useDatagrams)")

        var http3 = HTTP3ConnectionState(
            role: .server,
            localSettings: settingsValidation.localSettings
        )
        let localControlPayload = try http3.localControlStreamBytes()
        let localControlStream = try await runWithTimeout {
            try await connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("server opened local control stream \(localControlStream.streamID)")
        try await runWithTimeout {
            try await localControlStream.send(localControlPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("server sent local control payload")

        let controlPayload = try await runWithTimeout {
            try await InteroperableQUICHelpers.readPeerControlStream(
                from: inboundStreams,
                role: "server",
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server control payload bytes=\(controlPayload.count)")
        _ = try http3.receivePeerControlStream(
            controlPayload,
            settingsValidation: settingsValidation
        )
        var manager = WebTransportSessionManager(
            http3: http3,
            settingsValidation: settingsValidation
        )

        let requestStream = try await runWithTimeout {
            try await inboundStreams.next(
                direction: InteroperableQUICHelpers.bidirectionalStreamDirection,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server got request stream \(requestStream.streamID)")
        let requestPayload = try await runWithTimeout {
            try await InteroperableQUICHelpers.readStream(
                requestStream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server request payload bytes=\(requestPayload.count)")
        let requestFramePayload: Data
        if let prefixed = try? WebTransportStreamSignaling.parsePrefix(requestPayload),
           prefixed.form == .bidirectional {
            requestFramePayload = prefixed.remainingPayload
        } else {
            requestFramePayload = requestPayload
        }
        let requestFrames = try HTTP3Frame.decodeFrames(requestFramePayload)
        guard let requestFrame = requestFrames.first(where: { $0.type == HTTP3FrameType.headers }) else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        var allowedAuthorities = Set([authority])
        allowedAuthorities.insert("\(authority):\(localEndpoint.port)")
        allowedAuthorities.insert(localEndpoint.host)
        allowedAuthorities.insert("\(localEndpoint.host):\(localEndpoint.port)")
        let policy = try WebTransportServerSessionPolicy(
            allowedAuthorities: allowedAuthorities,
            allowedPaths: [path],
            allowedOrigins: allowedOrigin.map { [$0] },
            supportedProtocols: protocols,
            requireProtocolSelection: !protocols.isEmpty
        )

        let decision = try manager.receiveClientSessionRequest(
            streamID: requestStream.streamID,
            frame: requestFrame,
            policy: policy
        )
        let responsePayload = try decision.responseFrame.encode()
        try await runWithTimeout {
            try await requestStream.send(responsePayload, endOfStream: false)
        }
        if let rejectionError = decision.rejectionError {
            inboundTask.cancel()
            throw rejectionError
        }

        return WebTransportNetworkSession(
            connection: connection,
            inboundStreams: inboundStreams,
            inboundTask: inboundTask,
            manager: manager,
            sessionID: decision.session.id,
            selectedProtocol: decision.session.selectedProtocol,
            localControlStream: localControlStream,
            connectStream: requestStream,
            localEndpoint: localEndpoint,
            remoteEndpoint: localEndpoint,
            datagramsAvailable: useDatagrams,
            timeoutMilliseconds: timeoutMilliseconds
        )
    }

    private static func resolveListenerPort(
        _ listener: NetworkListener<QUIC>,
        timeoutMilliseconds: Int32
    ) async throws -> NWEndpoint.Port {
        let start = Date()
        let timeoutSeconds = TimeInterval(max(1, timeoutMilliseconds)) / 1_000
        while (listener.port == nil || listener.port?.rawValue == 0) && Date().timeIntervalSince(start) < timeoutSeconds {
            try await Task.sleep(for: .milliseconds(10))
        }
        guard let port = listener.port, port.rawValue != 0 else {
            throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
        }
        return port
    }
}

private enum InteroperableQUICRuntime {
    static let defaultAuthority = "localhost"
    static let defaultPath = "/wt"
    static let defaultOrigin = "https://localhost"
    static let defaultProtocol = "demo.v1"

    static func host(for value: String) -> NWEndpoint.Host {
        switch value {
        case "127.0.0.1", "localhost":
            return .ipv4(.loopback)
        case "::1":
            return .ipv6(.loopback)
        default:
            return .init(value)
        }
    }

    static func makeBaseQUIC() -> QUIC {
        QUIC(alpn: ["h3"]) {
            UDP()
        }
        .idleTimeout(30_000)
        .initialMaxData(1_048_576)
        .initialMaxStreamDataBidirectionalLocal(262_144)
        .initialMaxStreamDataBidirectionalRemote(262_144)
        .initialMaxStreamDataUnidirectional(262_144)
        .initialMaxBidirectionalStreams(16)
        .initialMaxUnidirectionalStreams(16)
        .maxDatagramFrameSize(65_535)
    }

    static func makeClientQUIC(trustPolicy: WebTransportQUICPeerTrustPolicy) -> QUIC {
        switch trustPolicy {
        case .systemTrust:
            return makeBaseQUIC()
        case .localDevelopmentSelfSigned:
            return makeBaseQUIC().tls.peerAuthentication(.none)
        }
    }

    static func makeServerQUIC(identity: sec_identity_t) -> QUIC {
        makeBaseQUIC()
            .tls.localIdentity(identity)
    }
}

private enum InteroperableQUICHelpers {
    static let bidirectionalStreamDirection = 0
    static let unidirectionalStreamDirection = 1

    static func streamDirectionKey(_ direction: QUICStream.Directionality) -> Int {
        switch direction {
        case .unidirectional:
            return unidirectionalStreamDirection
        case .bidirectional:
            return bidirectionalStreamDirection
        @unknown default:
            return bidirectionalStreamDirection
        }
    }

    static func makeRequestStreamPayload(streamID: UInt64, requestFrame: HTTP3Frame) throws -> Data {
        try requestFrame.encode()
    }

    static func waitForReady(
        connection: NetworkConnection<QUIC>,
        role: String = "client",
        start: (@Sendable () -> Void)? = nil,
        allowSetupProceed: Bool = false,
        timeoutMilliseconds: Int32
    ) async throws {
        if connection.state == .ready {
            InteroperableQUICDebug.log("\(role) connection already ready")
            return
        }
        if allowSetupProceed, case .setup = connection.state {
            InteroperableQUICDebug.log("\(role) connection in setup state; proceeding to stream negotiation")
            return
        }
        if case .failed(let error) = connection.state {
            InteroperableQUICDebug.log("\(role) connection already failed: \(error)")
            throw error
        }
        if case .cancelled = connection.state {
            InteroperableQUICDebug.log("\(role) connection already cancelled")
            throw WebTransportNetworkRuntimeError.timeout(0)
        }

        try await withTimeout(timeoutMilliseconds) {
            try await withCheckedThrowingContinuation { continuation in
                let completion = OneShotContinuation()
                let handleState: @Sendable (NetworkConnection<QUIC>.State) -> Void = { state in
                    InteroperableQUICDebug.log("\(role) connection state observed: \(state)")
                    switch state {
                    case .ready:
                        Task {
                            await completion.complete {
                                InteroperableQUICDebug.log("\(role) connection became ready")
                                continuation.resume()
                            }
                        }
                    case .failed(let error):
                        Task {
                            await completion.complete {
                                InteroperableQUICDebug.log("\(role) connection failed: \(error)")
                                continuation.resume(throwing: error)
                            }
                        }
                    case .cancelled:
                        Task {
                            await completion.complete {
                                InteroperableQUICDebug.log("\(role) connection cancelled")
                                continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                            }
                        }
                    default:
                        break
                    }
                }

                InteroperableQUICDebug.log("\(role) connection state monitor start=\(connection.state)")
                handleState(connection.state)
                connection.onStateUpdate { _, state in
                    InteroperableQUICDebug.log("connection state update: \(state)")
                    handleState(state)
                }

                if let start {
                    InteroperableQUICDebug.log("\(role) connection start requested")
                    start()
                }

                Task {
                    while true {
                        try? await Task.sleep(for: .milliseconds(50))
                        let polled = connection.state
                        InteroperableQUICDebug.log("\(role) connection state poll: \(polled)")
                        switch polled {
                        case .ready:
                            await completion.complete {
                                continuation.resume()
                            }
                            return
                        case .failed(let error):
                            await completion.complete {
                                continuation.resume(throwing: error)
                            }
                            return
                        case .cancelled:
                            await completion.complete {
                                continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                            }
                            return
                        default:
                            break
                        }
                    }
                }
            }
        }
    }

    static func datagramsUsable(_ connection: NetworkConnection<QUIC>) -> Bool {
        connection.usableDatagramFrameSize > 0
    }

    static func readStream(
        _ stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        maxBytes: Int = 8_192
    ) async throws -> Data {
        try await withTimeout(timeoutMilliseconds) {
            let chunk = try await stream.receive(atMost: maxBytes)
            return chunk.content
        }
    }

    static func readPeerControlStream(
        from inboundStreams: InteroperableQUICInboundStreamCollector,
        role: String,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        while true {
            let stream = try await inboundStreams.next(
                direction: unidirectionalStreamDirection,
                timeoutMilliseconds: timeoutMilliseconds
            )
            InteroperableQUICDebug.log("\(role) got peer unidirectional stream \(stream.streamID)")
            let bytes = try await readStream(stream, timeoutMilliseconds: timeoutMilliseconds)
            let prefix = try HTTP3StreamTypeParser.parsePrefix(bytes)
            switch prefix.type {
            case HTTP3StreamType.control:
                return bytes
            case HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
                InteroperableQUICDebug.log("\(role) ignoring peer QPACK stream type=\(prefix.type)")
                continue
            default:
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            }
        }
    }

    static func remainingTimeout(timeoutMilliseconds: Int32, started: Date) -> Int32 {
        let elapsedMilliseconds = Int32(max(0.0, Date().timeIntervalSince(started) * 1_000.0))
        return max(0, timeoutMilliseconds - elapsedMilliseconds)
    }

    static func withTimeout<T: Sendable>(
        _ timeoutMilliseconds: Int32,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard timeoutMilliseconds > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
        }

        return try await withCheckedThrowingContinuation { continuation in
            let gate = TimeoutCompletion()
            let operationTask = Task { @Sendable in
                do {
                    let value = try await operation()
                    if await gate.tryFinish() {
                        continuation.resume(returning: value)
                    }
                } catch {
                    if await gate.tryFinish() {
                        continuation.resume(throwing: error)
                    }
                }
            }

            let timeoutTask = Task { @Sendable in
                let nanoseconds = UInt64(max(1, timeoutMilliseconds)) * 1_000_000
                try? await Task.sleep(for: .nanoseconds(nanoseconds))
                if await gate.tryFinish() {
                    operationTask.cancel()
                    continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                }
            }

            Task { @Sendable in
                await gate.waitUntilFinished()
                operationTask.cancel()
                timeoutTask.cancel()
            }
        }
    }

    static func isTransientNotConnected(_ error: Error) -> Bool {
        if let posix = error as? POSIXError {
            return posix.code == .ENOTCONN
        }
        let nsError = error as NSError
        return nsError.domain == NSPOSIXErrorDomain && nsError.code == Int(ENOTCONN)
    }
}

private actor TimeoutCompletion {
    private var completed = false

    func tryFinish() -> Bool {
        if completed {
            return false
        }
        completed = true
        return true
    }

    func waitUntilFinished() async {
        while !completed {
            try? await Task.sleep(for: .milliseconds(1))
        }
    }
}

private actor InteroperableQUICConnectionQueue {
    private var queue: [NetworkConnection<QUIC>] = []
    private var waiters: [CheckedContinuation<NetworkConnection<QUIC>, Error>] = []
    private var failure: Error?

    func enqueue(_ connection: NetworkConnection<QUIC>) {
        guard failure == nil else {
            return
        }
        if let continuation = waiters.first {
            waiters.removeFirst()
            continuation.resume(returning: connection)
        } else {
            queue.append(connection)
        }
    }

    func dequeue() async throws -> NetworkConnection<QUIC> {
        if let failure {
            throw failure
        }
        if let connection = queue.first {
            queue.removeFirst()
            return connection
        }
        return try await withCheckedThrowingContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func fail(_ error: Error) {
        failure = error
        let waiters = self.waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.resume(throwing: error)
        }
    }
}

private actor InteroperableQUICInboundStreamCollector {
    private var queued: [Int: [QUIC.Stream<QUICStream>]] = [:]
    private var waiting: [Int: [CheckedContinuation<QUIC.Stream<QUICStream>, Error>]] = [:]
    private var failure: Error?

    func enqueue(_ stream: QUIC.Stream<QUICStream>, direction: Int) {
        guard failure == nil else {
            return
        }
        if var continuations = waiting[direction], !continuations.isEmpty {
            let continuation = continuations.removeFirst()
            if continuations.isEmpty {
                waiting.removeValue(forKey: direction)
            } else {
                waiting[direction] = continuations
            }
            continuation.resume(returning: stream)
            return
        }
        queued[direction, default: []].append(stream)
    }

    func next(direction: Int, timeoutMilliseconds: Int32) async throws -> QUIC.Stream<QUICStream> {
        if let failure {
            throw failure
        }

        if var streams = queued[direction], let stream = streams.first {
            streams.removeFirst()
            if streams.isEmpty {
                queued.removeValue(forKey: direction)
            } else {
                queued[direction] = streams
            }
            return stream
        }

        return try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await self.waitFor(direction: direction)
        }
    }

    func fail(_ error: Error) {
        failure = error
        let waitingByDirection = waiting
        waiting.removeAll()
        for (_, waiters) in waitingByDirection {
            for waiter in waiters {
                waiter.resume(throwing: error)
            }
        }
    }

    private func waitFor(direction: Int) async throws -> QUIC.Stream<QUICStream> {
        return try await withCheckedThrowingContinuation { continuation in
            if let failure {
                continuation.resume(throwing: failure)
                return
            }
            waiting[direction, default: []].append(continuation)
        }
    }
}

private actor OneShotContinuation {
    private var resumed = false

    func complete(_ operation: () -> Void) async {
        guard !resumed else {
            return
        }
        resumed = true
        operation()
    }
}

private struct InteroperableTLSIdentity {
    var networkIdentity: sec_identity_t
    var certificateDER: Data

    static func create() throws -> InteroperableTLSIdentity {
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrIsPermanent: false
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server key generation failed")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key extraction failed")
        }
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key export failed")
        }

        let certificateDER = try SelfSignedCertificate.make(
            privateKey: privateKey,
            p256PublicKeyDER: publicKeyData
        )
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server certificate generation produced invalid DER")
        }
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server identity creation failed")
        }
        guard let networkIdentity = sec_identity_create_with_certificates(identity, [certificate] as CFArray) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server QUIC identity conversion failed")
        }
        return InteroperableTLSIdentity(
            networkIdentity: networkIdentity,
            certificateDER: certificateDER
        )
    }
}

private enum SelfSignedCertificate {
    static func make(privateKey: SecKey, p256PublicKeyDER: Data) throws -> Data {
        let signatureAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 10045, 4, 3, 2])
        ])
        let ecPublicKeyAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 10045, 2, 1]),
            try DER.objectIdentifier([1, 2, 840, 10045, 3, 1, 7])
        ])
        let name = DER.sequence([
            DER.set([
                DER.sequence([
                    try DER.objectIdentifier([2, 5, 4, 3]),
                    DER.utf8String("localhost")
                ])
            ])
        ])
        let validity = DER.sequence([
            DER.utcTime(Date(timeIntervalSinceNow: -60)),
            DER.utcTime(Date(timeIntervalSinceNow: 86_400))
        ])
        let subjectPublicKeyInfo = DER.sequence([
            ecPublicKeyAlgorithm,
            DER.bitString(p256PublicKeyDER)
        ])
        let extensions = DER.explicit(3, DER.sequence([
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 19]),
                DER.boolean(true),
                DER.octetString(DER.sequence([DER.boolean(false)]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 15]),
                DER.boolean(true),
                DER.octetString(DER.bitString(Data([0x80]), unusedBits: 7))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 37]),
                DER.octetString(DER.sequence([
                    try DER.objectIdentifier([1, 3, 6, 1, 5, 5, 7, 3, 1])
                ]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 17]),
                DER.octetString(DER.sequence([
                    DER.contextSpecificPrimitive(2, Data("localhost".utf8)),
                    DER.contextSpecificPrimitive(7, Data([127, 0, 0, 1]))
                ]))
            ])
        ]))

        let tbsCertificate = DER.sequence([
            DER.explicit(0, DER.integer(Data([0x02]))),
            DER.integer(randomSerial()),
            signatureAlgorithm,
            name,
            validity,
            name,
            subjectPublicKeyInfo,
            extensions
        ])

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbsCertificate as CFData,
            &signError
        ) as Data? else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }

        return DER.sequence([
            tbsCertificate,
            signatureAlgorithm,
            DER.bitString(signature)
        ])
    }

    private static func randomSerial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            bytes = Array(UUID().uuidString.utf8.prefix(16))
        }
        bytes[0] &= 0x7f
        if bytes.allSatisfy({ $0 == 0 }) {
            bytes[0] = 1
        }
        return Data(bytes)
    }
}

private enum DER {
    static func sequence(_ parts: [Data]) -> Data {
        tagged(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: [Data]) -> Data {
        tagged(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func explicit(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0xa0 + tag, content)
    }

    static func contextSpecificPrimitive(_ tag: UInt8, _ value: Data) -> Data {
        tagged(0x80 + tag, value)
    }

    static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tagged(0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func objectIdentifier(_ components: [UInt64]) throws -> Data {
        guard components.count >= 2 else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let firstTwo = components[0] * 40 + components[1]
        var bytes = [UInt8(firstTwo)]
        for component in components.dropFirst(2) {
            var section = [UInt8(component & 0x7f)]
            var remaining = component >> 7
            while remaining > 0 {
                section.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
                remaining >>= 7
            }
            bytes.append(contentsOf: section)
        }
        return tagged(0x06, Data(bytes))
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func utcTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tagged(0x17, Data(formatter.string(from: value).utf8))
    }

    fileprivate static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + encodeLength(content.count) + content
    }

    private static func encodeLength(_ value: Int) -> Data {
        if value < 128 {
            return Data([UInt8(value)])
        }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
