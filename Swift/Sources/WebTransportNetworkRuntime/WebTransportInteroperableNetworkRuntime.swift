import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

/// Opt-in diagnostic channel for interoperability debugging.
///
/// This is **not** covered by the redaction guarantees that `WebTransportLogger`
/// enforces. It emits transport identifiers — stream IDs, connection states, and
/// bound endpoints — which the project's public logging policy excludes. It does
/// not emit secrets, key material, packet or datagram payloads, or peer close
/// text, and it is disabled unless `WEBTRANSPORT_INTEROP_DEBUG=1` is set.
///
/// Enabling it announces itself once on stderr so an operator who turns it on in
/// a deployed process is told that the output is unredacted rather than having
/// to infer it.
private enum InteroperableQUICDebug {
    static let enabled = ProcessInfo.processInfo.environment["WEBTRANSPORT_INTEROP_DEBUG"] == "1"

    private static let announceOnce: Void = {
        write(
            "[interoperable-quic] diagnostic logging is enabled and is NOT redacted; "
                + "it emits transport identifiers and must not be used in production\n"
        )
    }()

    static func log(_ message: @autoclosure () -> String) {
        guard enabled else {
            return
        }
        _ = announceOnce
        write("[interoperable-quic] \(message())\n")
    }

    private static func write(_ text: String) {
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

    fileprivate func runtimeConfiguration(endpoint: WebTransportNetworkEndpoint) throws -> InteroperableQUICTrustConfiguration {
        switch self {
        case .systemTrust:
            return .systemTrust
        case .localDevelopmentSelfSigned:
            guard Self.isLoopbackHost(endpoint.host) else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "local-self-signed trust is restricted to localhost, 127.0.0.1, and ::1"
                )
            }
            return .localLoopbackDevelopmentSelfSigned
        }
    }

    private static func isLoopbackHost(_ host: String) -> Bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1"
    }
}

private enum InteroperableQUICTrustConfiguration: Sendable {
    case systemTrust
    case localLoopbackDevelopmentSelfSigned
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

    /// Renders HTTP/3 SETTINGS as sorted `0xid=value` pairs for the diagnostic
    /// channel. Setting identifiers and counts only — no peer payload.
    private static func renderSettings(_ settings: HTTP3Settings) -> String {
        settings.entries
            .sorted { $0.key < $1.key }
            .map { "0x\(String($0.key, radix: 16))=\($0.value)" }
            .joined(separator: " ")
    }

    @discardableResult
    public func connectSession(
        to endpoint: WebTransportNetworkEndpoint,
        authority: String? = nil,
        path: String = "/wt",
        origin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        optimisticCapsules: [WebTransportFlowCapsule] = [],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict,
        timeoutMilliseconds: Int32 = 1_000
    ) async throws -> WebTransportNetworkSession {
        let trustConfiguration = try trustPolicy.runtimeConfiguration(endpoint: endpoint)
        let host = InteroperableQUICRuntime.host(for: endpoint.host)
        let destination = NWEndpoint.hostPort(
            host: host,
            port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any
        )
        InteroperableQUICDebug.log("client connecting to \(endpoint.host):\(endpoint.port)")
        let connection = NetworkConnection(to: destination) {
            InteroperableQUICRuntime.makeClientQUIC(trustConfiguration: trustConfiguration)
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

        // Registered before the connection is started, not after it is ready.
        // The peer opens its control stream the instant its own side completes
        // the handshake, so a handler installed after `start()` races that
        // stream and loses it outright — see `InteroperableQUICInboundRegistration`.
        let inboundStreams = InteroperableQUICInboundStreamCollector()
        let inboundRegistration = InteroperableQUICInboundRegistration()
        let inboundTask = Task {
            do {
                await inboundRegistration.markEntered()
                try await connection.inboundStreams { stream in
                    await InteroperableQUICHelpers.enqueueInboundStream(
                        stream,
                        into: inboundStreams,
                        role: "client"
                    )
                }
            } catch {
                await inboundRegistration.markEntered()
                await inboundStreams.fail(error)
            }
        }
        await inboundRegistration.waitUntilEntered()

        // Cancel the inbound handler on every failure path, not only the
        // rejected-session one below. The handler task strongly retains the connection,
        // and Network.framework exposes no `cancel()` — only `deinit` — so a task left
        // running keeps the connection and its socket alive for the process lifetime.
        // `acceptSession` already does this on its error paths; `defer` keeps it out of
        // the body and clear of the rest of this function's indentation.
        var handedBackSession = false
        defer {
            if !handedBackSession {
                inboundTask.cancel()
            }
        }

        try await InteroperableQUICHelpers.waitForReady(
            connection: connection,
            role: "client",
            start: { _ = connection.start() },
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client ready")

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
        let qpackStreams = try await InteroperableQUICHelpers.openQPACKStreams(
            on: connection,
            role: "client",
            timeoutMilliseconds: remainingTimeout()
        )

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
        InteroperableQUICDebug.log("client local settings: \(Self.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("client peer settings: \(Self.renderSettings(peerSettings))")
        }
        // Datagram availability is a property of the negotiated SETTINGS, so it
        // is answered after the control-stream exchange rather than assumed.
        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(
            localSettings: http3.localSettings,
            remoteSettings: http3.remoteSettings
        )
        InteroperableQUICDebug.log("client datagrams usable=\(useDatagrams)")
        var manager = WebTransportSessionManager(
            http3: http3,
            // makeClientQUIC advertises the default limits, so enforce the same
            // ceiling here rather than the manager's smaller built-in default.
            maxDatagramFrameSize: WebTransportTransportLimits.default.maxDatagramFrameSize,
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
        var connectPayload = try InteroperableQUICHelpers.makeRequestStreamPayload(
            streamID: requestStreamID,
            requestFrame: requestFrame
        )
        let pendingSessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)
        for capsule in optimisticCapsules {
            connectPayload.append(
                try manager.makeOptimisticConnectStreamCapsule(
                    sessionID: pendingSessionID,
                    capsule: capsule
                ))
        }
        let requestPayload = connectPayload
        try await runWithTimeout {
            try await requestStream.send(requestPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent connect payload")

        // The server's response is the first thing on this stream: a peer that ends it
        // without writing anything has not answered the request.
        let responseData = try await InteroperableQUICHelpers.readFirstChunk(
            requestStream,
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client got response bytes=\(responseData.count)")
        let responsePrefix = try HTTP3Frame.decodePrefix(responseData)
        guard responsePrefix.frame.type == HTTP3FrameType.headers else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        let session = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responsePrefix.frame)
        guard session.state == .accepted else {
            inboundTask.cancel()
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport session was rejected"
            )
        }
        let sessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)

        handedBackSession = true
        return WebTransportNetworkSession(
            connection: connection,
            inboundStreams: inboundStreams,
            inboundTask: inboundTask,
            manager: manager,
            sessionID: sessionID,
            selectedProtocol: session.selectedProtocol,
            localControlStream: localControlStream,
            connectStream: requestStream,
            qpackStreams: qpackStreams,
            localEndpoint: InteroperableQUICRuntime.networkEndpoint(
                from: connection.localEndpoint,
                fallback: WebTransportNetworkEndpoint(host: "unknown", port: 0)
            ),
            remoteEndpoint: InteroperableQUICRuntime.networkEndpoint(from: connection.remoteEndpoint, fallback: endpoint),
            datagramsAvailable: useDatagrams,
            timeoutMilliseconds: timeoutMilliseconds,
            initialConnectCapsuleBytes: Data(responseData.dropFirst(responsePrefix.bytesConsumed))
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
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict,
        exchangeMode: WebTransportNetworkExchangeMode = .auto,
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
        let useDatagrams: Bool
        switch exchangeMode {
        case .auto:
            useDatagrams = session.datagramsAvailable && !preferStreams
        case .stream:
            useDatagrams = false
        case .datagram:
            useDatagrams = true
        }

        if useDatagrams {
            InteroperableQUICDebug.log("client using datagram path")
            try await session.sendDatagram(
                Data(message.utf8),
                requireAvailability: exchangeMode != .datagram,
                timeoutMilliseconds: timeoutMilliseconds
            )
            InteroperableQUICDebug.log("client sent datagram")
            let responsePayload = try await session.receiveDatagram(
                requireAvailability: exchangeMode != .datagram,
                timeoutMilliseconds: timeoutMilliseconds
            )
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

// SAFETY: The wrapper is immutable after initialization. Prefix and initial
// payload state are isolated in `WebTransportNetworkStreamState`; the stored
// Network.framework stream handle is used only through async send/receive calls.
public final class WebTransportNetworkBidirectionalStream: @unchecked Sendable {
    public let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let prefix: Data?
    private let state: WebTransportNetworkStreamState
    private let manager: WebTransportNetworkSessionManagerState?

    fileprivate init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        prefix: Data? = nil,
        initialPayload: Data = Data(),
        manager: WebTransportNetworkSessionManagerState? = nil
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.prefix = prefix
        self.state = WebTransportNetworkStreamState(prefix: prefix, initialPayload: initialPayload)
        self.manager = manager
    }

    public func send(
        _ data: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        if let manager {
            _ = try await manager.withManager { manager in
                try manager.sendStreamPayload(
                    streamID: self.streamID,
                    payload: data,
                    fin: endOfStream
                )
            }
        }
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
        // A stream accepted from the wire carries the prefix-stripped remainder of
        // its first chunk. That buffer is served first, and it is a read like any
        // other: it must return at most `maximumBytes` and keep the unread
        // remainder for the next call, or the bound the caller asked for is only
        // honoured on the network path.
        if let initialPayload = await state.consumeInitialPayload(maximumBytes: maximumBytes) {
            if !initialPayload.isEmpty, let manager {
                _ = await manager.withManager { manager in
                    manager.popStreamPayload(streamID: self.streamID)
                }
            }
            return initialPayload
        }
        let payload = try await InteroperableQUICHelpers.readStream(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumBytes
        )
        if let manager {
            return try await manager.withManager { manager in
                try manager.receiveStreamPayload(streamID: self.streamID, payload: payload)
                return manager.popStreamPayload(streamID: self.streamID) ?? Data()
            }
        }
        return payload
    }
}

// SAFETY: Endpoint/session metadata are immutable. Mutable WebTransport state is
// isolated in `WebTransportNetworkSessionManagerState`; inbound stream queues are
// actors; the Network.framework connection is only accessed through async APIs.
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
    /// The listener's concurrency slot for this session's connection, when a
    /// listener accepted it. Released as soon as the session is closed or dropped;
    /// see ``InteroperableQUICConnectionLease``.
    private let lease: InteroperableQUICConnectionLease?
    private let manager: WebTransportNetworkSessionManagerState
    private let localControlStream: QUIC.Stream<QUICStream>
    private let connectStream: QUIC.Stream<QUICStream>
    /// Held only to keep the QPACK critical streams open; never read or written
    /// after their type prefix. Releasing them would FIN a critical stream.
    private let qpackStreams: [QUIC.Stream<QUICStream>]
    private let timeoutMilliseconds: Int32
    private let connectCapsuleTask: Task<Void, Never>

    fileprivate init(
        connection: NetworkConnection<QUIC>,
        inboundStreams: InteroperableQUICInboundStreamCollector,
        inboundTask: Task<Void, Never>,
        lease: InteroperableQUICConnectionLease? = nil,
        manager: WebTransportSessionManager,
        sessionID: WebTransportSessionID,
        selectedProtocol: String?,
        localControlStream: QUIC.Stream<QUICStream>,
        connectStream: QUIC.Stream<QUICStream>,
        qpackStreams: [QUIC.Stream<QUICStream>],
        localEndpoint: WebTransportNetworkEndpoint,
        remoteEndpoint: WebTransportNetworkEndpoint,
        datagramsAvailable: Bool,
        timeoutMilliseconds: Int32,
        initialConnectCapsuleBytes: Data = Data()
    ) {
        self.connection = connection
        self.inboundStreams = inboundStreams
        self.inboundTask = inboundTask
        self.lease = lease
        let managerState = WebTransportNetworkSessionManagerState(manager: manager)
        self.manager = managerState
        self.sessionID = sessionID.rawValue
        self.selectedProtocol = selectedProtocol
        self.localControlStream = localControlStream
        self.connectStream = connectStream
        self.qpackStreams = qpackStreams
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.datagramsAvailable = datagramsAvailable
        self.timeoutMilliseconds = timeoutMilliseconds
        // Lifecycle markers for the diagnostic channel. Session leaks are the
        // failure this runtime is most exposed to — abandoned work can hold a
        // session past its connection — and resident memory cannot answer the
        // question, because a freed session's pages are not returned to the OS.
        // Counting these two lines can.
        InteroperableQUICDebug.log("session established")
        self.connectCapsuleTask = Task {
            await Self.receiveConnectCapsules(
                from: connectStream,
                manager: managerState,
                streamID: sessionID.rawValue,
                initialBytes: initialConnectCapsuleBytes
            )
        }
    }

    deinit {
        InteroperableQUICDebug.log("session released")
        connectCapsuleTask.cancel()
        inboundTask.cancel()
        // A session the application dropped without closing still has to hand its
        // listener slot back, or the slot leaks for the lifetime of the process.
        lease?.release()
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
                let prefix = try await manager.withManager { manager in
                    try manager.openBidirectionalStream(
                        streamID: stream.streamID,
                        sessionID: WebTransportSessionID(rawValue: self.sessionID)
                    )
                }
                return WebTransportNetworkBidirectionalStream(
                    stream: stream,
                    timeoutMilliseconds: timeout,
                    prefix: prefix,
                    manager: manager
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
        // A WebTransport stream begins with its prefix, so a stream that ends without
        // one is a peer that closed it before writing: `readFirstChunk` names that case
        // rather than letting the codec report an empty buffer as a truncation.
        let firstChunk = try await InteroperableQUICHelpers.readFirstChunk(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumInitialBytes
        )
        let accepted = try await manager.withManager { manager in
            try manager.acceptBidirectionalStreamWithActions(
                streamID: stream.streamID,
                firstBytes: firstChunk
            )
        }
        guard let prefix = accepted.prefix,
            accepted.rejectionFrame == nil,
            prefix.form == .bidirectional,
            prefix.sessionID.rawValue == sessionID
        else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        return WebTransportNetworkBidirectionalStream(
            stream: stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            initialPayload: prefix.remainingPayload,
            manager: manager
        )
    }

    public func sendDatagram(
        _ data: Data,
        requireAvailability: Bool = true,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        guard datagramsAvailable || !requireAvailability else {
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
        requireAvailability: Bool = true,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
        guard datagramsAvailable || !requireAvailability else {
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
                let payload = manager.popDatagramPayload(sessionID: responseSessionID)
            else {
                throw WebTransportNetworkRuntimeError.invalidPayload
            }
            return payload
        }
    }

    public func exportKeyingMaterial(
        applicationLabel: Data,
        applicationContext: Data = Data(),
        outputByteCount: Int
    ) throws -> Data {
        guard outputByteCount >= 0 else {
            throw QUICCodecError.valueOutOfRange("negative WebTransport exporter output length")
        }
        let context = try WebTransportExporter.context(
            sessionID: WebTransportSessionID(rawValue: sessionID),
            applicationLabel: applicationLabel,
            applicationContext: applicationContext
        )
        let contextBytes = context.isEmpty ? [UInt8(0)] : [UInt8](context)
        let labelBytes = Array(WebTransportExporter.tlsLabel.utf8CString)
        // SAFETY: Both arrays remain alive for the synchronous Security call.
        // The UTF-8 label includes a terminator excluded from its byte count;
        // the context pointer is nonnil even when its declared length is zero.
        let exported = labelBytes.withUnsafeBufferPointer { labelBuffer in
            contextBytes.withUnsafeBufferPointer { contextBuffer in
                unsafe sec_protocol_metadata_create_secret_with_context(
                    connection.securityProtocolMetadata,
                    labelBytes.count - 1,
                    labelBuffer.baseAddress!,
                    context.count,
                    contextBuffer.baseAddress!,
                    outputByteCount
                )
            }
        }
        guard let exported else {
            throw WebTransportNetworkRuntimeError.exporterUnavailable
        }
        return Data(exported as DispatchData)
    }

    /// Tells the peer this endpoint is going away, without tearing the session down.
    ///
    /// Sends HTTP/3 GOAWAY on the control stream, then WT_DRAIN_SESSION on the
    /// CONNECT stream. The peer learns no new sessions or requests will be
    /// accepted while in-flight work continues, which is what lets a deploy
    /// finish serving instead of severing every live connection.
    ///
    /// The GOAWAY identifier is the next client-initiated bidirectional stream
    /// after this session's CONNECT stream: everything already accepted is still
    /// honoured, nothing beyond it is.
    public func beginGracefulShutdown(
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        let timeout = overrideTimeoutMilliseconds ?? timeoutMilliseconds
        // Client-initiated bidirectional stream IDs advance by four.
        let firstUnservedStreamID = connectStream.streamID &+ 4
        let goawayPayload = try await manager.withManager { manager in
            try manager.makeGoawayFrame(streamID: firstUnservedStreamID).encode()
        }
        try await InteroperableQUICHelpers.withTimeout(timeout) {
            try await self.localControlStream.send(goawayPayload, endOfStream: false)
        }
        try await drain(timeoutMilliseconds: timeout)
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
        // The session ends here whether or not the capsule reaches the peer, so the
        // listener's slot goes back now rather than when the caller happens to drop
        // this object: an application that keeps a closed session around must not
        // hold the listener's connection budget down. Network.framework keeps the
        // QUIC connection itself until the peer closes it or it idles out — the
        // framework exposes no way to cancel a started `NetworkConnection`.
        defer { lease?.release() }
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

    fileprivate func waitForPeerClosure(timeoutMilliseconds: Int32) async {
        let started = Date()
        while InteroperableQUICHelpers.remainingTimeout(
            timeoutMilliseconds: timeoutMilliseconds,
            started: started
        ) > 0 {
            let isClosed = await manager.withManager { manager in
                guard let state = manager.sessionsByID[WebTransportSessionID(rawValue: self.sessionID)]?.state else {
                    return true
                }
                if case .closed = state {
                    return true
                }
                return false
            }
            if isClosed {
                // The peer ended the session, so this connection is no longer the
                // runtime's to serve even if the application still holds the object.
                lease?.release()
                return
            }
            do {
                try await Task.sleep(for: .milliseconds(5))
            } catch {
                // Cancelled: stop waiting rather than polling out the full
                // deadline. `try?` here would swallow cancellation and keep the
                // loop running after the caller has gone away.
                return
            }
        }
    }

    /// The largest CONNECT-stream capsule payload permitted by
    /// draft-ietf-webtrans-http3-16, in bytes.
    ///
    /// The only CONNECT-stream capsule whose payload is neither empty nor a
    /// single QUIC varint is WT_CLOSE_SESSION: it carries a 32-bit application
    /// error code followed by a UTF-8 message that the draft (Section 6) caps
    /// at `wtCloseSessionMaxMessageBytes` (1024) bytes. Flow-control capsules
    /// carry one varint and WT_DRAIN_SESSION is empty, so a conforming peer
    /// can never declare a larger payload. The reader rejects a declared
    /// length above this bound on the capsule header alone — before waiting
    /// for, and therefore before buffering, the payload — so a peer cannot
    /// pin unbounded memory by announcing a huge capsule and then stalling.
    static let maximumConnectStreamCapsulePayloadBytes =
        WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 4

    private static func receiveConnectCapsules(
        from stream: QUIC.Stream<QUICStream>,
        manager: WebTransportNetworkSessionManagerState,
        streamID: UInt64,
        initialBytes: Data
    ) async {
        var buffered = initialBytes
        do {
            while !Task.isCancelled {
                while let capsule = try popCompleteCapsule(from: &buffered) {
                    let result = try await manager.withManager { manager in
                        try manager.receiveConnectStreamCapsulesWithActions(
                            streamID: streamID,
                            bytes: capsule
                        )
                    }
                    if result.connectResetFrame != nil {
                        stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
                        try? await stream.send(Data(), endOfStream: true)
                        return
                    }
                }

                let received = try await stream.receive(atMost: 8_192)
                buffered.append(received.content)
                if received.metadata.endOfStream {
                    if !buffered.isEmpty {
                        stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
                        try? await stream.send(Data(), endOfStream: true)
                    } else {
                        _ = try? await manager.withManager { manager in
                            try manager.finishConnectStream(streamID: streamID)
                        }
                    }
                    return
                }
            }
        } catch is CancellationError {
            return
        } catch {
            stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
            try? await stream.send(Data(), endOfStream: true)
        }
    }

    /// Internal rather than private so the draft-16 capsule-size bound can be
    /// regression-tested directly: `receiveConnectCapsules` needs a live
    /// `Network.framework` `QUIC.Stream` that a unit test cannot fabricate.
    static func popCompleteCapsule(from buffer: inout Data) throws -> Data? {
        guard !buffer.isEmpty else {
            return nil
        }
        var cursor = QUICByteCursor(buffer)
        do {
            _ = try QUICVarInt.decode(from: &cursor)
            let payloadLength = try QUICVarInt.decode(from: &cursor)
            guard payloadLength <= UInt64(Int.max) else {
                throw QUICCodecError.valueOutOfRange("CONNECT capsule length exceeds Int.max")
            }
            // Reject an over-long declaration on the header alone. Waiting for
            // the announced payload would let a peer keep this loop buffering
            // (and re-opening flow-control credit) without bound.
            guard payloadLength <= UInt64(Self.maximumConnectStreamCapsulePayloadBytes) else {
                throw QUICCodecError.valueOutOfRange(
                    "CONNECT capsule payload length \(payloadLength) exceeds the draft-16 maximum of "
                        + "\(Self.maximumConnectStreamCapsulePayloadBytes) bytes"
                )
            }
            let headerLength = buffer.count - cursor.remaining
            let (capsuleLength, overflow) = headerLength.addingReportingOverflow(Int(payloadLength))
            guard !overflow else {
                throw QUICCodecError.valueOutOfRange("CONNECT capsule length overflow")
            }
            guard buffer.count >= capsuleLength else {
                return nil
            }
            let capsule = Data(buffer.prefix(capsuleLength))
            buffer.removeFirst(capsuleLength)
            return capsule
        } catch QUICCodecError.truncated {
            return nil
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

    func consumeInitialPayload(maximumBytes: Int) -> Data? {
        guard let buffered = initialPayload, !buffered.isEmpty else {
            return nil
        }
        let limit = max(0, maximumBytes)
        guard buffered.count > limit else {
            initialPayload = nil
            return buffered
        }
        let returned = Data(buffered.prefix(limit))
        let remainder = Data(buffered.dropFirst(limit))
        initialPayload = remainder.isEmpty ? nil : remainder
        return returned
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

// SAFETY: Every stored property is immutable after initialization except the
// bound endpoint, which is held in a `Mutex` because `waitForListening` may
// rewrite it concurrently with readers on the accept path. Accepted connections
// are handed through an actor queue, and shutdown only cancels the listener task.
/// Weak handle to a served session.
///
/// Weak so the registry never keeps a session alive past the application's own
/// reference to it; shutdown simply skips entries the application already let go.
private struct WeakSessionRef {
    weak var session: WebTransportNetworkSession?
}

public final class WebTransportQUICServer: @unchecked Sendable {
    private let localEndpointStorage: Mutex<WebTransportNetworkEndpoint>

    /// Sessions handed to the application, so `shutdown(gracePeriodMilliseconds:)`
    /// can signal them. Without this the listener can stop accepting but has no
    /// way to tell live peers that it is going away.
    private let servedSessions = Mutex<[WeakSessionRef]>([])

    /// Cleared once shutdown begins, so accept calls fail immediately with a
    /// clear error instead of blocking until their timeout expires.
    private let accepting = Mutex<Bool>(true)

    private let admission: WebTransportAdmissionPolicy
    /// nil when the policy sets no rate limit.
    private let rateLimiter: ConnectionRateLimiter?
    /// Kept so the session manager enforces the same datagram ceiling the QUIC
    /// layer advertised. Advertising one number and enforcing a smaller one
    /// rejects peers that are honouring what we told them.
    private let transportLimits: WebTransportTransportLimits

    /// The endpoint the listener is bound to.
    ///
    /// Reads are synchronized: the port is not known until the listener binds,
    /// so `waitForListening` rewrites this after construction and callers on the
    /// accept path may observe it from another thread.
    public var localEndpoint: WebTransportNetworkEndpoint {
        localEndpointStorage.withLock { $0 }
    }

    /// The admission policy this listener actually enforces.
    ///
    /// `maxConcurrentConnections` predates ``WebTransportAdmissionPolicy`` and is
    /// folded into it at construction. Exposing the result lets tests assert the
    /// precedence between the two without opening as many connections as the
    /// limit.
    var effectiveAdmissionPolicy: WebTransportAdmissionPolicy {
        admission
    }

    public let certificateSHA256: Data

    /// Expiry of the certificate this listener presents, when it could be read.
    ///
    /// Network.framework fixes the identity in the listener's parameters at
    /// construction — measured: the parameters are built once per listener, not
    /// once per connection — so the certificate cannot be replaced on a live
    /// listener. Rotation means standing up a new listener, which an operator
    /// has to schedule against this date.
    public let certificateNotAfter: Date?

    /// True when the listener is presenting the ephemeral development
    /// certificate rather than an injected, CA-issued identity.
    ///
    /// The development certificate is regenerated per construction, so
    /// ``certificateSHA256`` is not stable across restarts when this is true.
    public let usesDevelopmentCertificate: Bool

    private let listener: NetworkListener<QUIC>
    private let acceptedConnections: InteroperableQUICConnectionQueue
    private let listenerTask: Task<Void, Never>
    private let authority: String
    private let path: String
    private let allowedOrigin: String?
    private let protocols: [String]
    private let settingsValidation: HTTP3WebTransportSettingsValidation

    /// Ceiling on connections this listener serves at one time.
    ///
    /// Enforced by the runtime, not by `NetworkListener.newConnectionLimit`:
    /// measured on macOS 26.6.2, a listener built with a limit of 2 accepts exactly
    /// two connections and never a third, however long ago the first two ended, so
    /// that limit is a budget for the listener's whole life rather than a
    /// concurrency cap. Passing `maxConcurrentConnections` through to it made a
    /// listener stop accepting permanently once it had served that many sessions in
    /// total (issue #23).
    private let connectionBudget: InteroperableQUICConnectionBudget

    public convenience init(
        bindPort: UInt16,
        maxConcurrentConnections: Int? = nil,
        authority: String = "localhost",
        path: String = "/wt",
        allowedOrigin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict,
        localOnly: Bool = false,
        identity: WebTransportServerIdentity = .developmentSelfSigned,
        admission: WebTransportAdmissionPolicy = .default,
        transportLimits: WebTransportTransportLimits = .default
    ) throws {
        try self.init(
            endpoint: WebTransportNetworkEndpoint(port: bindPort),
            maxConcurrentConnections: maxConcurrentConnections,
            authority: authority,
            path: path,
            allowedOrigin: allowedOrigin,
            protocols: protocols,
            settingsValidation: settingsValidation,
            localOnly: localOnly,
            identity: identity,
            admission: admission,
            transportLimits: transportLimits
        )
    }

    public init(
        endpoint: WebTransportNetworkEndpoint,
        maxConcurrentConnections: Int? = nil,
        authority: String = "localhost",
        path: String = "/wt",
        allowedOrigin: String? = "https://localhost",
        protocols: [String] = ["demo.v1"],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict,
        localOnly: Bool = false,
        identity: WebTransportServerIdentity = .developmentSelfSigned,
        admission: WebTransportAdmissionPolicy = .default,
        transportLimits: WebTransportTransportLimits = .default
    ) throws {
        InteroperableQUICDebug.log("server init endpoint=\(endpoint.commandLineValue)")
        // `maxConcurrentConnections` predates the admission policy. An explicit value
        // overrides whatever the policy carries, and `nil` (the argument not being
        // supplied) leaves the policy's own limit alone.
        //
        // The override used to be tied to the default argument `16`, so an operator
        // who explicitly asked for 16 while supplying another policy got the policy's
        // number instead — 256 for `.publicFacing`. Representing "not supplied" as
        // `nil` rather than as a valid value is what makes the two distinguishable.
        // The value is validated on the same terms as the policy field so an
        // out-of-range override is refused rather than accepted here and rejected
        // elsewhere.
        var admission = try admission.validated()
        if let maxConcurrentConnections {
            guard maxConcurrentConnections > 0 else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "maxConcurrentConnections must be positive"
                )
            }
            admission.maxConcurrentConnections = maxConcurrentConnections
        }
        let transportLimits = try transportLimits.validated()
        self.admission = admission
        self.rateLimiter = ConnectionRateLimiter(policy: admission)
        self.connectionBudget = InteroperableQUICConnectionBudget(
            limit: max(1, admission.maxConcurrentConnections)
        )
        self.transportLimits = transportLimits
        let resolvedIdentity = try ServerIdentityResolver.resolve(
            identity,
            endpoint: endpoint,
            authority: authority,
            localOnly: localOnly
        )
        certificateSHA256 = resolvedIdentity.certificateSHA256
        certificateNotAfter = resolvedIdentity.notAfter
        usesDevelopmentCertificate = identity.isDevelopmentSelfSigned
        let baseParameters = NWParametersBuilder(auto: {
            InteroperableQUICRuntime.makeServerQUIC(
                identity: resolvedIdentity.networkIdentity,
                limits: transportLimits
            )
        })
        .localEndpoint(
            .hostPort(
                host: InteroperableQUICRuntime.host(for: endpoint.host),
                port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any
            )
        )
        let parameters = localOnly ? baseParameters.localOnly(true) : baseParameters

        // The listener runs without a `newConnectionLimit`, which would cap its
        // whole life rather than its concurrency; `admitConnection()` applies the
        // policy's ceiling instead.
        listener = try NetworkListener<QUIC>(using: parameters)
        acceptedConnections = InteroperableQUICConnectionQueue()
        localEndpointStorage = Mutex(endpoint)
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
        let rateLimiter = self.rateLimiter
        let connectionBudget = self.connectionBudget
        // The listener task must not retain the server to read these, and each
        // accepted connection builds its own collector from them.
        let advertisedStreamLimits = transportLimits
        listenerTask = Task {
            do {
                try await listener.run { connection in
                    // Refuse over-rate connections here, before the handshake is
                    // driven, so a peer cycling connections cannot make the
                    // server do unbounded work. The connection is neither
                    // started nor queued, so it is released on return and the
                    // refusal costs nothing beyond the accept itself.
                    if let rateLimiter, !rateLimiter.allow() {
                        InteroperableQUICDebug.log("server refused connection: rate limit")
                        return
                    }
                    // Refuse over-budget connections before the handshake is
                    // driven. Returning from the accept handler without starting
                    // the connection is what hands it back to Network.framework.
                    guard let lease = connectionBudget.admit() else {
                        InteroperableQUICDebug.log(
                            "server refused connection: concurrency limit \(connectionBudget.limit)"
                        )
                        return
                    }
                    InteroperableQUICDebug.log("server accepted connection")
                    // Attach the stream handler before starting the connection.
                    // The peer opens its control stream as soon as the handshake
                    // completes, which is typically while this connection is
                    // still queued and long before anything calls `serveOne`.
                    // The collector's per-direction ceiling is the stream count
                    // this listener advertised: retaining more would hold stream
                    // objects the peer was never allowed to open, and fewer would
                    // refuse streams the advertisement promised.
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
                            await inboundStreams.fail(error)
                        }
                    }
                    await inboundRegistration.waitUntilEntered()
                    _ = connection.start()
                    await acceptedConnections.enqueue(
                        InteroperableQUICAcceptedConnection(
                            connection: connection,
                            inboundStreams: inboundStreams,
                            inboundTask: inboundTask,
                            lease: lease
                        )
                    )
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
        return localEndpointStorage.withLock { endpoint in
            endpoint = WebTransportNetworkEndpoint(host: endpoint.host, port: port.rawValue)
            return endpoint
        }
    }

    /// Stops the listener immediately, without telling live peers anything.
    ///
    /// Sessions already handed to the application are unaffected and their peers
    /// learn nothing until the connection times out. Prefer
    /// ``shutdown(gracePeriodMilliseconds:)`` for a deploy or restart.
    public func shutdown() {
        accepting.withLock { $0 = false }
        listenerTask.cancel()
        let queue = acceptedConnections
        Task {
            await queue.cancelQueued()
        }
    }

    /// Stops accepting, tells every live session the server is going away, and
    /// gives in-flight work a bounded window to finish.
    ///
    /// Ordering matters: acceptance is closed *before* peers are signalled, so a
    /// peer cannot open a session in the window between being told to drain and
    /// the listener actually stopping.
    ///
    /// Signalling is best effort by design. A peer that has already vanished
    /// cannot be told anything, and one unreachable peer must not prevent the
    /// rest from being drained, so per-session failures are logged and skipped
    /// rather than thrown. Returns once every session has been signalled or the
    /// grace period expires.
    public func shutdown(gracePeriodMilliseconds: Int32) async {
        accepting.withLock { $0 = false }

        let sessions = servedSessions.withLock { registry -> [WebTransportNetworkSession] in
            let live = registry.compactMap(\.session)
            registry.removeAll()
            return live
        }
        InteroperableQUICDebug.log("server graceful shutdown: signalling \(sessions.count) session(s)")

        if !sessions.isEmpty, gracePeriodMilliseconds > 0 {
            let perSession = max(1, gracePeriodMilliseconds / Int32(sessions.count))
            await withTaskGroup(of: Void.self) { group in
                for session in sessions {
                    group.addTask {
                        do {
                            try await session.beginGracefulShutdown(timeoutMilliseconds: perSession)
                        } catch {
                            InteroperableQUICDebug.log("server graceful shutdown: session signal failed: \(error)")
                        }
                    }
                }
            }
        }

        listenerTask.cancel()
        await acceptedConnections.cancelQueued()
        InteroperableQUICDebug.log("server graceful shutdown complete")
    }

    deinit {
        shutdown()
    }

    public func acceptSession(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSession {
        guard accepting.withLock({ $0 }) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("listener is shutting down")
        }
        let accepted = try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await self.acceptedConnections.dequeue()
        }
        let connection = accepted.connection
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
            // This connection is being abandoned, so nothing will ever drain the
            // handler attached to it at accept time.
            accepted.inboundTask.cancel()
            _ = connection.state
            throw error
        }

        let session: WebTransportNetworkSession
        do {
            session = try await acceptSession(
                on: accepted,
                timeoutMilliseconds: timeoutMilliseconds
            )
        } catch {
            accepted.inboundTask.cancel()
            throw error
        }
        register(session)
        return session
    }

    /// Records a served session and drops entries the application has released.
    ///
    /// Compaction happens here rather than on a timer so the registry cannot
    /// grow without bound on a long-lived listener.
    private func register(_ session: WebTransportNetworkSession) {
        servedSessions.withLock { sessions in
            sessions.removeAll { $0.session == nil }
            sessions.append(WeakSessionRef(session: session))
        }
    }

    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSessionResult {
        let session = try await acceptSession(timeoutMilliseconds: timeoutMilliseconds)

        // The peer picks the transport, so the server cannot. `datagramsAvailable`
        // now states whether `SETTINGS_H3_DATAGRAM` was negotiated, but a peer that
        // negotiated it can still open a stream, and a browser that did not is
        // stream-only from the start. Waiting only for a datagram hung on a peer
        // that had already opened a stream, so when datagrams are negotiated this
        // waits for both and echoes on whichever the peer actually used.
        // Racing means one entrant loses and is abandoned, and an abandoned
        // entrant keeps the session alive until its own wait expires. Handing it
        // the caller's full timeout makes that window arbitrarily long: with a
        // ten-minute timeout under sustained churn, sessions accumulate at the
        // churn rate for ten minutes. Measured as resident growth that scales
        // with the configured timeout and vanishes at short ones.
        //
        // The wait is therefore capped. A peer that has established a session
        // and then sent nothing for this long is not mid-exchange, so the cap
        // costs nothing real while bounding what an abandoned entrant can hold.
        let echoed: Data
        if session.datagramsAvailable {
            let raceTimeout = min(timeoutMilliseconds, Self.firstMessageWaitMilliseconds)
            echoed = try await InteroperableQUICHelpers.raceFirstSuccess([
                { try await Self.echoOneDatagram(on: session, timeoutMilliseconds: raceTimeout) },
                { try await Self.echoOneStream(on: session, timeoutMilliseconds: raceTimeout) },
            ])
        } else {
            echoed = try await Self.echoOneStream(on: session, timeoutMilliseconds: timeoutMilliseconds)
        }
        await session.waitForPeerClosure(timeoutMilliseconds: min(timeoutMilliseconds, 250))
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

    /// Longest the sample echo server waits for a peer's first message.
    ///
    /// Bounds how long an abandoned race entrant can keep a session alive,
    /// independently of how generous the caller's session timeout is.
    static let firstMessageWaitMilliseconds: Int32 = 15_000

    /// Receives one datagram and echoes it back verbatim.
    private static func echoOneDatagram(
        on session: WebTransportNetworkSession,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        let payload = try await session.receiveDatagram(timeoutMilliseconds: timeoutMilliseconds)
        try await session.sendDatagram(payload, timeoutMilliseconds: timeoutMilliseconds)
        return payload
    }

    /// Accepts one bidirectional stream and echoes its payload back verbatim.
    private static func echoOneStream(
        on session: WebTransportNetworkSession,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        let stream = try await session.acceptBidirectionalStream(timeoutMilliseconds: timeoutMilliseconds)
        let payload = try await stream.receive(timeoutMilliseconds: timeoutMilliseconds)
        try await stream.send(payload, endOfStream: true, timeoutMilliseconds: timeoutMilliseconds)
        return payload
    }

    private func acceptSession(
        on accepted: InteroperableQUICAcceptedConnection,
        timeoutMilliseconds: Int32
    ) async throws -> WebTransportNetworkSession {
        let connection = accepted.connection
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

        let datagramFrameSizeLimit = transportLimits.maxDatagramFrameSize
        InteroperableQUICDebug.log("server serveSession start")
        // Attached at accept time, before the connection was started, so streams
        // the peer opened during the handshake are already collected here.
        let inboundStreams = accepted.inboundStreams
        let inboundTask = accepted.inboundTask

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
        let qpackStreams = try await InteroperableQUICHelpers.openQPACKStreams(
            on: connection,
            role: "server",
            timeoutMilliseconds: remainingTimeout()
        )

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
        // Peer SETTINGS identify which WebTransport revision the client speaks.
        // Logging the decoded ids is what makes a "handshake failed" from an
        // opaque peer such as a browser diagnosable at all.
        InteroperableQUICDebug.log("server local settings: \(Self.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("server peer settings: \(Self.renderSettings(peerSettings))")
        }
        // Datagram availability is a property of the negotiated SETTINGS, so it
        // is answered after the control-stream exchange rather than assumed.
        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(
            localSettings: http3.localSettings,
            remoteSettings: http3.remoteSettings
        )
        InteroperableQUICDebug.log("server datagrams usable=\(useDatagrams)")
        var manager = WebTransportSessionManager(
            http3: http3,
            // Accept what the QUIC layer advertised to the peer. Leaving this at
            // the manager's own smaller default rejects a peer that is sending
            // exactly what it was told it could send.
            maxDatagramFrameSize: datagramFrameSizeLimit,
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
            try await InteroperableQUICHelpers.readFirstChunk(
                requestStream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server request payload bytes=\(requestPayload.count)")
        let requestFramePayload: Data
        if WebTransportStreamSignaling.hasStreamPrefix(requestPayload) {
            // The peer asserted a WebTransport stream prefix, so a malformed one
            // is a protocol violation and must propagate. Swallowing it here
            // would silently reinterpret invalid bytes as an unprefixed CONNECT
            // request and continue.
            let prefixed = try WebTransportStreamSignaling.parsePrefix(requestPayload)
            guard prefixed.form == .bidirectional else {
                throw WebTransportDraft16Error(
                    kind: .h3ID,
                    message: "WebTransport CONNECT request stream carried a unidirectional stream marker"
                )
            }
            requestFramePayload = prefixed.remainingPayload
        } else {
            // No marker: an ordinary HTTP/3 extended CONNECT request stream.
            requestFramePayload = requestPayload
        }
        let requestPrefix = try HTTP3Frame.decodePrefix(requestFramePayload)
        guard requestPrefix.frame.type == HTTP3FrameType.headers else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        let optimisticCapsuleBytes = Data(requestFramePayload.dropFirst(requestPrefix.bytesConsumed))

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

        let decision: WebTransportServerSessionDecision
        do {
            decision = try manager.receiveClientSessionRequest(
                streamID: requestStream.streamID,
                frame: requestPrefix.frame,
                policy: policy
            )
        } catch {
            // Without this the reason a peer's CONNECT was refused is lost: the
            // throw propagates as a transport error once the peer has already
            // gone, which is what makes browser handshake failures opaque.
            InteroperableQUICDebug.log("server CONNECT rejected before response: \(error)")
            throw error
        }
        InteroperableQUICDebug.log(
            "server CONNECT decision: session=\(decision.session.id) "
                + "protocol=\(decision.session.selectedProtocol ?? "none") "
                + "rejection=\(decision.rejectionError.map { "\($0)" } ?? "none")"
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
            lease: accepted.lease,
            manager: manager,
            sessionID: decision.session.id,
            selectedProtocol: decision.session.selectedProtocol,
            localControlStream: localControlStream,
            connectStream: requestStream,
            qpackStreams: qpackStreams,
            localEndpoint: localEndpoint,
            remoteEndpoint: InteroperableQUICRuntime.networkEndpoint(
                from: connection.remoteEndpoint,
                fallback: WebTransportNetworkEndpoint(host: "unknown", port: 0)
            ),
            datagramsAvailable: useDatagrams,
            timeoutMilliseconds: timeoutMilliseconds,
            initialConnectCapsuleBytes: optimisticCapsuleBytes
        )
    }

    /// Renders HTTP/3 SETTINGS as sorted `0xid=value` pairs for the diagnostic
    /// channel. Setting identifiers and counts only — no peer payload.
    private static func renderSettings(_ settings: HTTP3Settings) -> String {
        settings.entries
            .sorted { $0.key < $1.key }
            .map { "0x\(String($0.key, radix: 16))=\($0.value)" }
            .joined(separator: " ")
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

    static func networkEndpoint(
        from endpoint: NWEndpoint?,
        fallback: WebTransportNetworkEndpoint
    ) -> WebTransportNetworkEndpoint {
        guard let endpoint,
            case .hostPort(let host, let port) = endpoint
        else {
            return fallback
        }
        return WebTransportNetworkEndpoint(host: host.debugDescription, port: port.rawValue)
    }

    static func makeBaseQUIC(limits: WebTransportTransportLimits = .default) -> QUIC {
        QUIC(alpn: ["h3"]) {
            UDP()
        }
        .idleTimeout(limits.idleTimeoutMilliseconds)
        .initialMaxData(limits.initialMaxData)
        .initialMaxStreamDataBidirectionalLocal(limits.initialMaxStreamDataBidirectionalLocal)
        .initialMaxStreamDataBidirectionalRemote(limits.initialMaxStreamDataBidirectionalRemote)
        .initialMaxStreamDataUnidirectional(limits.initialMaxStreamDataUnidirectional)
        .initialMaxBidirectionalStreams(limits.initialMaxBidirectionalStreams)
        .initialMaxUnidirectionalStreams(limits.initialMaxUnidirectionalStreams)
        .maxDatagramFrameSize(limits.maxDatagramFrameSize)
    }

    static func makeClientQUIC(trustConfiguration: InteroperableQUICTrustConfiguration) -> QUIC {
        switch trustConfiguration {
        case .systemTrust:
            return makeBaseQUIC()
        case .localLoopbackDevelopmentSelfSigned:
            return makeBaseQUIC().tls.peerAuthentication(.none)
        }
    }

    static func makeServerQUIC(
        identity: sec_identity_t,
        limits: WebTransportTransportLimits = .default
    ) -> QUIC {
        makeBaseQUIC(limits: limits)
            .tls.localIdentity(identity)
    }
}

/// Internal rather than private so the stream-read policy below can be tested directly: a
/// `QUIC.Stream` cannot be constructed in a test, so the decision that turns a chunk into
/// bytes, a wait, or a named error is what the tests can pin.
enum InteroperableQUICHelpers {
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

    /// Hands an inbound stream to its connection's collector, refusing it at the
    /// transport when the collector will not retain it.
    ///
    /// The collector bounds how many streams it holds per direction so a peer
    /// cannot make this endpoint retain stream objects, and the buffers behind
    /// them, for the connection's whole life. A stream the collector declines is
    /// not merely dropped: the peer still believes it is open and keeps writing
    /// into it. RFC 9000 section 3.5 gives a receiver STOP_SENDING for exactly
    /// this, and the WebTransport draft's `WT_BUFFERED_STREAM_REJECTED` is the
    /// refusal code the session layer already uses for an over-limit buffered
    /// stream.
    ///
    /// Network.framework exposes neither stop-sending nor a per-stream reset, but
    /// documents enough for both halves of the refusal: the application error
    /// code set on the stream is the one sent to the peer when the stream is
    /// closed, and releasing the last handle lets the transport cancel the
    /// receive side — which the peer observes as STOP_SENDING. The refusal is
    /// therefore to set the code and return without retaining the stream.
    @discardableResult
    static func enqueueInboundStream(
        _ stream: QUIC.Stream<QUICStream>,
        into inboundStreams: InteroperableQUICStreamQueue<QUIC.Stream<QUICStream>>,
        role: String
    ) async -> InteroperableQUICInboundStreamDisposition {
        let direction = streamDirectionKey(stream.directionality)
        let disposition = await inboundStreams.enqueue(
            stream,
            direction: direction,
            streamID: UInt64(stream.streamID)
        )
        switch disposition {
        case .accepted:
            InteroperableQUICDebug.log(
                "\(role) inbound stream direction=\(stream.directionality) id=\(stream.streamID)"
            )
        case .refusedQueueFull(let limit):
            InteroperableQUICDebug.log(
                "\(role) refusing inbound stream id=\(stream.streamID): "
                    + "direction \(direction) already holds its \(limit)-stream ceiling"
            )
            stream.streamApplicationErrorCode =
                WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError
        case .refusedInboundDeliveryFailed:
            InteroperableQUICDebug.log(
                "\(role) refusing inbound stream id=\(stream.streamID): inbound delivery has already failed"
            )
            stream.streamApplicationErrorCode =
                WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError
        }
        return disposition
    }

    static func makeRequestStreamPayload(streamID: UInt64, requestFrame: HTTP3Frame) throws -> Data {
        try requestFrame.encode()
    }

    /// Opens this endpoint's QPACK encoder and decoder streams.
    ///
    /// RFC 9204 §4.2 gives each endpoint at most one encoder and one decoder
    /// stream, and peers that intend to use the dynamic table expect them to
    /// exist. This implementation encodes field sections without the dynamic
    /// table, but omitting the streams entirely leaves a peer with no channel on
    /// which to receive decoder acknowledgements, and deployed peers treat their
    /// absence as a broken HTTP/3 connection.
    ///
    /// Only the stream type prefix is written; no instructions follow, which is
    /// valid for an endpoint that never populates a dynamic table.
    /// The returned streams MUST be retained for the lifetime of the
    /// connection. QPACK encoder and decoder streams are critical streams: RFC
    /// 9204 section 4.2 forbids either peer from closing them, and a peer that
    /// observes a FIN on one closes the connection with H3_CLOSED_CRITICAL_STREAM.
    /// Dropping the handle lets the transport finish the stream, which is
    /// indistinguishable from closing it on purpose.
    @discardableResult
    static func openQPACKStreams(
        on connection: NetworkConnection<QUIC>,
        role: String,
        timeoutMilliseconds: Int32
    ) async throws -> [QUIC.Stream<QUICStream>] {
        var opened: [QUIC.Stream<QUICStream>] = []
        for (label, type) in [
            ("encoder", HTTP3StreamType.qpackEncoder),
            ("decoder", HTTP3StreamType.qpackDecoder),
        ] {
            let stream = try await withTimeout(timeoutMilliseconds) {
                try await connection.openStream(directionality: .unidirectional)
            }
            let prefix = try QUICVarInt.encode(type)
            try await withTimeout(timeoutMilliseconds) {
                try await stream.send(prefix, endOfStream: false)
            }
            InteroperableQUICDebug.log("\(role) opened QPACK \(label) stream \(stream.streamID)")
            opened.append(stream)
        }
        return opened
    }

    /// Names a connection the transport failed to establish (WT-185).
    ///
    /// `NetworkConnection.State.failed` carries the framework's own error, and on a
    /// loaded host that is a transient POSIX condition rather than anything about the
    /// endpoint. Translating it here rather than rethrowing it verbatim is what stops
    /// *this* path's framework error from reaching a caller as a bare `POSIXErrorCode`:
    /// the caller gets a case it can recognise and act on, and the framework's error is
    /// kept for diagnosis.
    ///
    /// It does not make raw framework errors unreachable everywhere — an inbound stream
    /// or a queued connection that fails still surfaces the framework's error through
    /// `InteroperableQUICInboundStreamCollector.next` and
    /// `InteroperableQUICConnectionQueue.dequeue`. Establishment is the one path on which
    /// the condition is recognisable enough to be worth naming.
    ///
    /// **A POSIX condition is recognised from the error itself, not from its `NSError`
    /// domain.** Measured rather than assumed: `NWError.posix(.ENETDOWN)` bridges to
    /// `NSError` under the domain `"Network.NWError"` — *not* `NSPOSIXErrorDomain` — so a
    /// predicate reading the bridged domain would never match a real failure. That is the
    /// trap `isTransientNotConnected` below fell into, and it is why this unwraps the
    /// `NWError` case and reports the condition under the POSIX domain it actually is.
    static func establishmentFailure(role: String, error: Error) -> WebTransportNetworkRuntimeError {
        if let networkError = error as? NWError, case .posix(let posixCode) = networkError {
            return .connectionEstablishmentFailed(
                role: role,
                domain: NSPOSIXErrorDomain,
                code: Int(posixCode.rawValue)
            )
        }
        let nsError = error as NSError
        return .connectionEstablishmentFailed(role: role, domain: nsError.domain, code: nsError.code)
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
            throw establishmentFailure(role: role, error: error)
        }
        if case .cancelled = connection.state {
            InteroperableQUICDebug.log("\(role) connection already cancelled")
            throw WebTransportNetworkRuntimeError.timeout(0)
        }

        try await withTimeout(timeoutMilliseconds) {
            let gate = InteroperableQUICWaitGate()
            let handleState: @Sendable (NetworkConnection<QUIC>.State) -> Void = { state in
                InteroperableQUICDebug.log("\(role) connection state observed: \(state)")
                switch state {
                case .ready:
                    InteroperableQUICDebug.log("\(role) connection became ready")
                    gate.resolveReady()
                case .failed(let error):
                    InteroperableQUICDebug.log("\(role) connection failed: \(error)")
                    gate.resolveFailure(establishmentFailure(role: role, error: error))
                case .cancelled:
                    InteroperableQUICDebug.log("\(role) connection cancelled")
                    gate.resolveFailure(WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                default:
                    break
                }
            }

            // `withCheckedThrowingContinuation` does not observe task cancellation,
            // and `withTimeout` abandons (rather than drains) the operation when its
            // deadline fires. Without this handler the timeout path cancelled the
            // task but never resumed the inner continuation, so the abandoned task —
            // and the observer and `start` closure it held — stayed suspended until
            // the connection independently reached `.failed`/`.cancelled`, or for the
            // life of the process if it never did. `gate` makes the observer's resume
            // and the cancellation's resume mutually exclusive and exactly-once,
            // including when the cancellation arrives before the wait has parked.
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    gate.park(continuation)
                    InteroperableQUICDebug.log("\(role) connection state monitor start=\(connection.state)")

                    // Register the observer before sampling the current state. A
                    // transition that lands between the two is then delivered twice
                    // rather than missed, and `gate` is one-shot so the duplicate is
                    // discarded. Sampling first would leave a window where a terminal
                    // transition is observed by nobody.
                    connection.onStateUpdate { _, state in
                        InteroperableQUICDebug.log("connection state update: \(state)")
                        handleState(state)
                    }
                    handleState(connection.state)

                    if let start {
                        InteroperableQUICDebug.log("\(role) connection start requested")
                        start()
                    }
                }
            } onCancel: {
                InteroperableQUICDebug.log("\(role) wait for ready cancelled")
                gate.resolveFailure(WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
            }
        }
    }

    /// Whether H3 DATAGRAM was negotiated with the peer.
    ///
    /// Network.framework does not expose the peer's `max_datagram_frame_size`
    /// before the datagram channel is first used — measured: `usableDatagramFrameSize`
    /// reports 0 on an established connection even when both peers advertised it —
    /// so the honest pre-use answer is the HTTP/3 one. Draft-16 carries datagrams
    /// inside HTTP/3 DATAGRAM frames, so both endpoints must have advertised
    /// `SETTINGS_H3_DATAGRAM = 1` for the capability to be real. The framework
    /// remains the authority for a send or receive that is actually attempted.
    static func datagramsUsable(localSettings: HTTP3Settings, remoteSettings: HTTP3Settings?) -> Bool {
        let identifier = WebTransportHTTP3DraftConstants.current.settingsH3Datagram
        guard localSettings[identifier] == 1 else {
            return false
        }
        guard let remoteSettings, remoteSettings[identifier] == 1 else {
            return false
        }
        return true
    }

    /// What one chunk of a stream means to a reader waiting for its first bytes.
    enum FirstChunkDecision: Equatable {
        case bytes(Data)
        case keepWaiting
        case peerClosed
    }

    /// Classify a chunk from a stream the caller is waiting to read.
    ///
    /// `receive(atMost:)` defaults to `atLeast: 1`, so an empty chunk with the stream
    /// still open is the one case the framework does not promise; waiting rather than
    /// returning it is what keeps "no bytes yet" from reaching a caller that cannot tell
    /// it apart from "the stream is over". An empty chunk at end of stream is the peer
    /// having ended the stream without writing to it. Measured against the real
    /// framework (WebTransport issue #24): a stream opened without data is not delivered
    /// at all until its first byte arrives, and a stream finished with no bytes reads as
    /// empty with `endOfStream` set.
    static func decideFirstChunk(_ content: Data, endOfStream: Bool) -> FirstChunkDecision {
        if !content.isEmpty {
            return .bytes(content)
        }
        return endOfStream ? .peerClosed : .keepWaiting
    }

    static func readStream(
        _ stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        maxBytes: Int = 8_192
    ) async throws -> Data {
        try await withTimeout(timeoutMilliseconds) {
            while true {
                let chunk = try await stream.receive(atMost: maxBytes)
                switch decideFirstChunk(chunk.content, endOfStream: chunk.metadata.endOfStream) {
                case .bytes(let bytes):
                    return bytes
                case .keepWaiting:
                    continue
                case .peerClosed:
                    // A payload read is allowed to see the end of the stream: an empty
                    // result with nothing behind it is how a reader learns the peer is
                    // done. The callers that need bytes use `readFirstChunk`.
                    return Data()
                }
            }
        }
    }

    /// The first bytes of a stream whose protocol requires data, refusing a peer that
    /// ended the stream before writing any.
    ///
    /// The codecs report that emptiness as `QUICCodecError.truncated(needed: 1,
    /// available: 0)`, which is a true statement about the bytes and a misleading one
    /// about the cause, so the runtime names it here instead (issue #24).
    static func readFirstChunk(
        _ stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        maxBytes: Int = 8_192
    ) async throws -> Data {
        let bytes = try await readStream(
            stream,
            timeoutMilliseconds: timeoutMilliseconds,
            maxBytes: maxBytes
        )
        guard !bytes.isEmpty else {
            throw WebTransportNetworkRuntimeError.peerClosedStreamWithoutData(streamID: stream.streamID)
        }
        return bytes
    }

    fileprivate static func readPeerControlStream(
        from inboundStreams: InteroperableQUICInboundStreamCollector,
        role: String,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        while true {
            let stream: QUIC.Stream<QUICStream>
            do {
                stream = try await inboundStreams.next(
                    direction: unidirectionalStreamDirection,
                    timeoutMilliseconds: timeoutMilliseconds
                )
            } catch let error as WebTransportNetworkRuntimeError {
                // Name what actually happened. Waiting here and running out of
                // time means the peer's control stream never arrived, which the
                // transport can cause by dropping an inbound stream on a busy
                // host. Reporting it as a generic timeout sent every previous
                // investigation looking for a slow peer instead.
                guard case .timeout = error else {
                    throw error
                }
                throw WebTransportNetworkRuntimeError.peerControlStreamNotDelivered(
                    role: role,
                    timeoutMilliseconds: timeoutMilliseconds
                )
            }
            InteroperableQUICDebug.log("\(role) got peer unidirectional stream \(stream.streamID)")
            let bytes = try await readFirstChunk(stream, timeoutMilliseconds: timeoutMilliseconds)
            let prefix = try HTTP3StreamTypeParser.parsePrefix(bytes)
            switch prefix.type {
            case HTTP3StreamType.control:
                await inboundStreams.retainCritical(stream)
                return bytes
            case HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
                InteroperableQUICDebug.log("\(role) ignoring peer QPACK stream type=\(prefix.type)")
                await inboundStreams.retainCritical(stream)
                Task {
                    await drainPeerCriticalStream(stream)
                }
                continue
            default:
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            }
        }
    }

    private static func drainPeerCriticalStream(_ stream: QUIC.Stream<QUICStream>) async {
        do {
            while !Task.isCancelled {
                let received = try await stream.receive(atMost: 8_192)
                if received.metadata.endOfStream {
                    return
                }
            }
        } catch {
            return
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

        // Deliberately unstructured. Several operations wrapped here bottom out
        // in Network.framework calls that do not observe cancellation, so a
        // structured group would block on draining a stuck child after the
        // deadline fired. This races the work against the timer and abandons
        // the loser; `gate` guarantees the continuation resumes exactly once.
        return try await withCheckedThrowingContinuation { continuation in
            let gate = OneShotContinuation()
            let timer = PendingTimer()

            let operationTask = Task { @Sendable in
                do {
                    let value = try await operation()
                    await gate.complete { continuation.resume(returning: value) }
                } catch {
                    await gate.complete { continuation.resume(throwing: error) }
                }
                // Retire the timer as soon as the work is done. Letting it sleep
                // out the full timeout is not free: it holds its captures for
                // the whole window, and with a long configured timeout and many
                // timed operations per connection those sleeping tasks
                // accumulate into real memory growth under sustained churn.
                timer.operationFinished()
            }

            let timeoutTask = Task { @Sendable in
                try? await Task.sleep(for: .milliseconds(Int(timeoutMilliseconds)))
                await gate.complete {
                    operationTask.cancel()
                    continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                }
            }
            // The operation can finish before this assignment, so handing the
            // task over has to cancel it immediately in that case.
            timer.arm(timeoutTask)
        }
    }

    /// Runs `operations` concurrently and returns the first one to succeed.
    ///
    /// An operation that fails does not end the race; the error surfaces only if
    /// every operation fails, in which case the first error is thrown. Losers are
    /// cancelled but never awaited, for the same reason `withTimeout` abandons
    /// rather than drains: these operations bottom out in Network.framework calls
    /// that may not observe cancellation. Each is independently bounded by its
    /// own timeout, so an abandoned loser retires on its own.
    static func raceFirstSuccess<T: Sendable>(
        _ operations: [@Sendable () async throws -> T]
    ) async throws -> T {
        guard !operations.isEmpty else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let total = operations.count
        return try await withCheckedThrowingContinuation { continuation in
            let state = RaceCompletion()
            let tasks = Mutex<[Task<Void, Never>]>([])
            for operation in operations {
                let task = Task { @Sendable in
                    do {
                        let value = try await operation()
                        let won = await state.succeed()
                        if won {
                            continuation.resume(returning: value)
                            tasks.withLock { $0.forEach { $0.cancel() } }
                        }
                    } catch {
                        if let final = await state.fail(error, total: total) {
                            continuation.resume(throwing: final)
                        }
                    }
                }
                tasks.withLock { $0.append(task) }
            }
        }
    }

    /// Whether a failed stream operation failed because the connection was not connected
    /// yet, which a retry can clear.
    ///
    /// **This predicate was dead for the errors the runtime actually sees.** `NWError.posix`
    /// bridges to `NSError` under the domain `"Network.NWError"`, not under
    /// `NSPOSIXErrorDomain`, so the bridged-domain test below never matched a real
    /// framework error; nor does `error as? POSIXError` succeed for one. The connection's
    /// own `ENOTCONN` therefore never took the retry branch in `openBidirectionalStream`.
    /// It unwraps the `NWError` case first, which is the only form that identifies the
    /// condition. Found while fixing `WT-185`, which is the same misunderstanding.
    static func isTransientNotConnected(_ error: Error) -> Bool {
        if let networkError = error as? NWError, case .posix(let posixCode) = networkError {
            return posixCode == .ENOTCONN
        }
        if let posix = error as? POSIXError {
            return posix.code == .ENOTCONN
        }
        let nsError = error as NSError
        return nsError.domain == NSPOSIXErrorDomain && nsError.code == Int(ENOTCONN)
    }
}

/// An accepted connection together with the stream handler already attached to it.
///
/// The handler cannot be attached later by whoever eventually serves the
/// connection: the peer starts opening streams as soon as the handshake
/// completes, which happens while the connection is still sitting in the accept
/// queue. Attaching it before `start()` and carrying it along is what keeps the
/// peer's control stream from being delivered to nothing.
/// The listener's concurrency budget.
///
/// Held apart from the listener so the accept handler can be built before the
/// listener's own stored properties are initialized, and so releasing a slot does
/// not reach back into the listener.
private final class InteroperableQUICConnectionBudget: @unchecked Sendable {
    let limit: Int
    private let live = Mutex(0)

    init(limit: Int) {
        self.limit = limit
    }

    /// Take one slot in the budget, or `nil` when it is full.
    func admit() -> InteroperableQUICConnectionLease? {
        let admitted = live.withLock { live -> Bool in
            guard live < limit else {
                return false
            }
            live += 1
            return true
        }
        guard admitted else {
            return nil
        }
        return InteroperableQUICConnectionLease { [self] in
            live.withLock { live in
                live = max(0, live - 1)
            }
        }
    }
}

/// One accepted connection's slot in a listener's concurrency budget.
///
/// Network.framework's `NetworkListener.newConnectionLimit` is a lifetime cap, not a
/// concurrency cap: measured on macOS 26.6.2, a listener built with a limit of 2
/// hands exactly two connections to its handler and never a third, even after both
/// have ended, and a connection that ends does not return its slot. The runtime
/// therefore runs its listeners without that limit and counts live connections
/// itself. A lease is taken when a connection is admitted and released when the
/// runtime is done with it.
///
/// The release is one-shot because a connection has several endings — clean close,
/// peer close, refused accept, dropped queue entry, released session — and no path
/// may return the same slot twice. Dropping the lease releases it, so a connection
/// abandoned between admission and a session cannot strand a slot.
private final class InteroperableQUICConnectionLease: @unchecked Sendable {
    private let releaseSlot: @Sendable () -> Void
    private let released = Mutex(false)

    init(releaseSlot: @escaping @Sendable () -> Void) {
        self.releaseSlot = releaseSlot
    }

    deinit {
        release()
    }

    func release() {
        let alreadyReleased = released.withLock { released -> Bool in
            guard !released else {
                return true
            }
            released = true
            return false
        }
        guard !alreadyReleased else {
            return
        }
        releaseSlot()
    }
}

private struct InteroperableQUICAcceptedConnection: Sendable {
    let connection: NetworkConnection<QUIC>
    let inboundStreams: InteroperableQUICInboundStreamCollector
    let inboundTask: Task<Void, Never>
    /// Held for as long as the connection is the runtime's to serve.
    let lease: InteroperableQUICConnectionLease
}

private actor InteroperableQUICConnectionQueue {
    /// A parked accept, tagged so its own caller can take it back out.
    ///
    /// `acceptSession` bounds the wait with a timeout, and a continuation that is only
    /// cancelled is never resumed. Untagged, such an abandoned waiter stays at the head
    /// of the queue, is handed the next accepted connection, and drops it, so the live
    /// accept behind it never sees a connection.
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<InteroperableQUICAcceptedConnection, Error>
    }

    private var queue: [InteroperableQUICAcceptedConnection] = []
    private var waiters: [Waiter] = []
    private var nextWaiterID: UInt64 = 0
    private var failure: Error?

    /// Delivered to parked accepts when the listener stops accepting.
    static var listenerStopped: WebTransportNetworkRuntimeError {
        .invalidTransport("listener is shutting down")
    }

    func enqueue(_ accepted: InteroperableQUICAcceptedConnection) {
        guard failure == nil else {
            // The listener has already failed, so nothing will ever serve this
            // connection. Its handler task would otherwise run for the lifetime
            // of the process.
            accepted.inboundTask.cancel()
            return
        }
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.continuation.resume(returning: accepted)
        } else {
            queue.append(accepted)
        }
    }

    func dequeue() async throws -> InteroperableQUICAcceptedConnection {
        if let failure {
            throw failure
        }
        if let accepted = queue.first {
            queue.removeFirst()
            return try releaseIfAbandoned(accepted)
        }
        let id = nextWaiterID
        nextWaiterID += 1
        let accepted = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiters.append(Waiter(id: id, continuation: continuation))
            }
        } onCancel: {
            Task { await self.removeWaiter(id) }
        }
        return try releaseIfAbandoned(accepted)
    }

    /// Hands a connection back if the task waiting for it has already been abandoned.
    ///
    /// `withTimeout` runs this `dequeue` in a separate unstructured task and, on expiry,
    /// cancels *that* task and throws to its own caller. Removing the parked waiter is an
    /// asynchronous actor hop, so an `enqueue` can win the race and resume the abandoned
    /// waiter with a connection. The value is then discarded, and without this the
    /// connection's handler task would keep the connection and its socket alive with
    /// nothing left to serve them. The check has to happen here, in the task that
    /// observes the cancellation — the caller's task is never cancelled.
    private func releaseIfAbandoned(
        _ accepted: InteroperableQUICAcceptedConnection
    ) throws -> InteroperableQUICAcceptedConnection {
        if Task.isCancelled {
            accepted.inboundTask.cancel()
            throw CancellationError()
        }
        return accepted
    }

    /// Detaches a waiter whose caller has stopped waiting, and lets it unwind.
    ///
    /// The continuation must be resumed, not merely dropped. `withTimeout` abandons
    /// the operation task rather than awaiting it, so that task is still suspended on
    /// this continuation: dropping the reference leaves it suspended for the process
    /// lifetime and the Swift runtime reports a leaked continuation. Resuming with an
    /// error lets it unwind; the caller has already stopped waiting, so the value is
    /// discarded by its one-shot gate.
    ///
    /// This cannot resume twice: an entry is only ever resumed after it has been
    /// removed from `waiters`, and ids are unique.
    func removeWaiter(_ id: UInt64) {
        let removed = waiters.filter { $0.id == id }
        guard !removed.isEmpty else {
            return
        }
        waiters.removeAll { $0.id == id }
        for waiter in removed {
            waiter.continuation.resume(throwing: CancellationError())
        }
    }

    func fail(_ error: Error) {
        failure = error
        let waiters = self.waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume(throwing: error)
        }
        cancelQueued()
    }

    /// Releases connections that were accepted but will never be served.
    ///
    /// Each carries a handler task that is parked in `inboundStreams` and holds
    /// the connection alive, so dropping the queue alone would not end them.
    func cancelQueued() {
        let abandoned = queue
        queue.removeAll()
        for accepted in abandoned {
            accepted.inboundTask.cancel()
        }
        // Parked accepts have to be woken as well. Shutdown previously left them
        // blocking for their whole timeout, and each one that then expired became
        // exactly the abandoned waiter described above.
        let parked = waiters
        waiters.removeAll()
        for waiter in parked {
            waiter.continuation.resume(throwing: Self.listenerStopped)
        }
    }
}

/// Holds a connection back until its inbound-stream handler is on the scheduler.
///
/// `connection.inboundStreams` can only be entered from inside a task, and a
/// freshly spawned task does not run at the point it is created. Starting the
/// connection first therefore opens a window in which the peer completes its
/// handshake, opens its HTTP/3 control stream, and has it delivered to a handler
/// that does not exist yet. Network.framework does not replay those streams, so
/// the control stream is lost and both ends wait for each other until the
/// operation times out.
///
/// The window is small and the loss is total, which is what made this present as
/// an occasional hang rather than a reproducible failure. Waiting here costs one
/// scheduling hop on a path that is about to perform a network handshake.
private actor InteroperableQUICInboundRegistration {
    private var entered = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func markEntered() {
        guard !entered else {
            return
        }
        entered = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume()
        }
    }

    func waitUntilEntered() async {
        guard !entered else {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

/// What the inbound-stream collector did with a stream offered to it.
///
/// Spelled out rather than returned as a `Bool` so a caller cannot ignore a
/// refusal by accident. A stream the collector did not retain is one the peer
/// still believes is open, so the caller has to refuse it at the transport; see
/// ``InteroperableQUICStreamQueue/enqueue(_:direction:streamID:)``.
enum InteroperableQUICInboundStreamDisposition: Equatable, Sendable {
    /// The stream was handed to a parked caller, queued for the next one, or
    /// recognised as a repeat of a stream already delivered. In every one of
    /// those cases the caller must leave the stream alone — a duplicate is the
    /// live stream, not a new one, so refusing it would signal an error on a
    /// stream a reader is using.
    case accepted
    /// The per-direction ceiling is already reached, so nothing was retained.
    case refusedQueueFull(limit: Int)
    /// Inbound delivery for this connection has already failed, so nothing more
    /// can be retained.
    case refusedInboundDeliveryFailed
}

private typealias InteroperableQUICInboundStreamCollector = InteroperableQUICStreamQueue<QUIC.Stream<QUICStream>>

/// Delivers inbound streams to whoever is waiting for one of that direction.
///
/// Generic over the element purely so the delivery and timeout semantics can be
/// tested without a live QUIC connection; the runtime only ever uses the
/// `InteroperableQUICInboundStreamCollector` specialization below.
actor InteroperableQUICStreamQueue<Element: Sendable> {
    /// A parked caller. The identifier lets a timeout fail exactly its own
    /// waiter, so a stream delivered a moment earlier is never discarded.
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<Element, Error>
    }

    /// One inbound stream, identified so a repeat delivery can be recognised.
    private struct DeliveredStream: Hashable {
        let direction: Int
        let streamID: UInt64
    }

    private var queued: [Int: [Element]] = [:]
    private var waiting: [Int: [Waiter]] = [:]
    private var nextWaiterID: UInt64 = 0
    private let maxRememberedDeliveries = 4096
    private var deliveredKeys: Set<DeliveredStream> = []
    private var deliveryOrder: [DeliveredStream] = []
    private var failure: Error?

    /// Ceiling on streams held at once for one direction.
    ///
    /// Taken from the transport limits this endpoint advertised, because that is
    /// the number of streams the peer was told it may have open. It is a
    /// *retention* bound rather than an enforcement of the advertisement — QUIC
    /// enforces that itself — so each entry keeps at least one slot: the CONNECT
    /// request stream and the peer's control stream can both arrive before a
    /// reader parks, and refusing those because an operator advertised zero
    /// streams would break the connection instead of bounding it.
    private let ceilingByDirection: [Int: Int]

    init(
        bidirectionalLimit: Int = WebTransportTransportLimits.default.initialMaxBidirectionalStreams,
        unidirectionalLimit: Int = WebTransportTransportLimits.default.initialMaxUnidirectionalStreams
    ) {
        ceilingByDirection = [
            InteroperableQUICHelpers.bidirectionalStreamDirection: max(1, bidirectionalLimit),
            InteroperableQUICHelpers.unidirectionalStreamDirection: max(1, unidirectionalLimit),
        ]
    }

    private func ceiling(for direction: Int) -> Int {
        ceilingByDirection[direction]
            ?? max(1, WebTransportTransportLimits.default.initialMaxBidirectionalStreams)
    }

    /// Peer control and QPACK streams, held for the lifetime of the connection.
    ///
    /// These are critical streams: RFC 9114 section 6.2.1 and RFC 9204 section
    /// 4.2 forbid closing them, and a peer that receives STOP_SENDING on one
    /// closes the connection with H3_CLOSED_CRITICAL_STREAM. Releasing the
    /// handle after reading lets the transport cancel the receive side, which
    /// the peer sees as exactly that. This collector is owned by the session, so
    /// anything parked here lives as long as the connection does.
    private var retainedCriticalStreams: [Element] = []

    func retainCritical(_ stream: Element) {
        retainedCriticalStreams.append(stream)
    }

    /// Accepts an inbound stream, ignoring one that has already been delivered.
    ///
    /// A QUIC stream identifier is unique for the life of a connection and is
    /// never reused, so the same identifier arriving twice on the same collector
    /// is a repeat of a stream already handed out, not a new one. Passing it on
    /// is actively harmful: the peer's CONNECT request stream gets delivered a
    /// second time after the session is established, is taken for a new
    /// WebTransport stream, and fails the session with a stream-marker error
    /// against bytes the peer never framed that way.
    ///
    /// Only recent identifiers are remembered. A duplicate observed in practice
    /// follows its original almost immediately, and a connection is free to open
    /// unboundedly many streams over its lifetime, so retaining every identifier
    /// would trade this defect for unbounded growth.
    ///
    /// ## Retention bound and refusal
    ///
    /// At most ``ceiling(for:)`` streams are held per direction. RFC 9000
    /// section 4.6 stops counting a stream against `initial_max_streams_*` once
    /// it is closed, and a stream the peer FINs is closed whether or not the
    /// application read it, so the advertised stream limit does not bound how
    /// many stream objects a long-lived connection accumulates. Without a
    /// ceiling, a peer that opens streams this endpoint has no consumer for —
    /// post-establishment unidirectional streams in particular — makes the
    /// runtime retain each one, and the buffers behind it, until the connection
    /// ends.
    ///
    /// A stream that does not fit is **not** retained and is reported as
    /// ``InteroperableQUICInboundStreamDisposition/refusedQueueFull(limit:)``.
    /// The caller owns refusing it: dropping the handle alone tells the peer
    /// nothing, and the peer keeps writing into a stream this endpoint has
    /// forgotten. ``InteroperableQUICHelpers/enqueueInboundStream(_:into:role:)``
    /// is that caller for the runtime and performs the transport-level refusal.
    @discardableResult
    func enqueue(
        _ stream: Element,
        direction: Int,
        streamID: UInt64
    ) -> InteroperableQUICInboundStreamDisposition {
        guard failure == nil else {
            return .refusedInboundDeliveryFailed
        }
        let key = DeliveredStream(direction: direction, streamID: streamID)
        guard !deliveredKeys.contains(key) else {
            InteroperableQUICDebug.log("ignoring duplicate inbound stream delivery id=\(streamID)")
            return .accepted
        }
        deliveredKeys.insert(key)
        deliveryOrder.append(key)
        if deliveryOrder.count > maxRememberedDeliveries {
            deliveredKeys.remove(deliveryOrder.removeFirst())
        }
        if var waiters = waiting[direction], !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            if waiters.isEmpty {
                waiting.removeValue(forKey: direction)
            } else {
                waiting[direction] = waiters
            }
            waiter.continuation.resume(returning: stream)
            return .accepted
        }
        let limit = ceiling(for: direction)
        guard (queued[direction]?.count ?? 0) < limit else {
            return .refusedQueueFull(limit: limit)
        }
        queued[direction, default: []].append(stream)
        return .accepted
    }

    /// Removes and returns the oldest queued stream for `direction`.
    private func takeQueued(direction: Int) -> Element? {
        guard var streams = queued[direction], !streams.isEmpty else {
            return nil
        }
        let stream = streams.removeFirst()
        if streams.isEmpty {
            queued.removeValue(forKey: direction)
        } else {
            queued[direction] = streams
        }
        return stream
    }

    /// Waits for the next stream in `direction`, giving up after the timeout.
    ///
    /// The timeout is run as a task that resumes the waiter through the actor
    /// rather than by racing and abandoning the wait. Abandoning is what the
    /// general-purpose `withTimeout` does, and it is wrong here for two reasons:
    /// the abandoned waiter stays parked and a later stream is handed to a caller
    /// that already gave up — silently swallowing it — and the wait had to be
    /// entered from a separate task, which is a suspension point during which a
    /// stream can be queued and then never noticed. Here the waiter is resumed
    /// exactly once, by whichever of the two arrives first, and both run on the
    /// actor so neither can interleave with the other.
    func next(direction: Int, timeoutMilliseconds: Int32) async throws -> Element {
        if let failure {
            throw failure
        }
        if let stream = takeQueued(direction: direction) {
            return stream
        }
        guard timeoutMilliseconds > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
        }

        let id = nextWaiterID
        nextWaiterID &+= 1
        let timer = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(Int(timeoutMilliseconds)))
            await self?.expire(direction: direction, id: id, timeoutMilliseconds: timeoutMilliseconds)
        }
        defer {
            timer.cancel()
        }
        return try await waitFor(direction: direction, id: id)
    }

    func fail(_ error: Error) {
        failure = error
        let waitingByDirection = waiting
        waiting.removeAll()
        // A failed collector can never deliver what it still holds: every later
        // `next` throws `error` before reaching the queue. Keeping the queued
        // streams would only pin the peer's stream objects and their buffers for
        // the remaining life of the connection.
        queued.removeAll()
        for (_, waiters) in waitingByDirection {
            for waiter in waiters {
                waiter.continuation.resume(throwing: error)
            }
        }
    }

    /// Fails one specific waiter, identified so a stream that arrived first wins.
    private func expire(direction: Int, id: UInt64, timeoutMilliseconds: Int32) {
        guard var waiters = waiting[direction],
            let index = waiters.firstIndex(where: { $0.id == id })
        else {
            // Already resumed with a stream; the timeout lost the race.
            return
        }
        let waiter = waiters.remove(at: index)
        if waiters.isEmpty {
            waiting.removeValue(forKey: direction)
        } else {
            waiting[direction] = waiters
        }
        waiter.continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
    }

    private func waitFor(direction: Int, id: UInt64) async throws -> Element {
        return try await withCheckedThrowingContinuation { continuation in
            if let failure {
                continuation.resume(throwing: failure)
                return
            }
            // Re-check under the same actor step that parks: `next` may have
            // suspended between its own check and here.
            if let stream = takeQueued(direction: direction) {
                continuation.resume(returning: stream)
                return
            }
            waiting[direction, default: []].append(Waiter(id: id, continuation: continuation))
        }
    }
}

/// Tracks a race between several ways of receiving the same thing.
///
/// Distinct from ``OneShotContinuation`` because a loss is not a result: only the
/// first success resumes the caller, and an error is surfaced solely when every
/// entrant has failed.
private actor RaceCompletion {
    private var finished = false
    private var failures = 0
    private var firstError: Error?

    func succeed() -> Bool {
        guard !finished else {
            return false
        }
        finished = true
        return true
    }

    /// Returns the error to surface when this failure was the last one, and nil
    /// while another entrant could still win.
    func fail(_ error: Error, total: Int) -> Error? {
        guard !finished else {
            return nil
        }
        failures += 1
        if firstError == nil {
            firstError = error
        }
        guard failures >= total else {
            return nil
        }
        finished = true
        return firstError
    }
}

/// Owns a timeout task so it can be retired the moment its work completes.
///
/// The two events race: the operation can finish before the timer task has even
/// been handed over. Both paths funnel through one lock so the timer is
/// cancelled exactly once, whichever happens first, and never survives its
/// operation.
private final class PendingTimer: @unchecked Sendable {
    private let state = Mutex<(task: Task<Void, Never>?, finished: Bool)>((nil, false))

    /// Hands the timer over. Cancels immediately if the work already finished.
    func arm(_ task: Task<Void, Never>) {
        let alreadyFinished = state.withLock { state -> Bool in
            state.task = task
            return state.finished
        }
        if alreadyFinished {
            task.cancel()
        }
    }

    /// Marks the work complete and cancels the timer if it has been armed.
    func operationFinished() {
        let task = state.withLock { state -> Task<Void, Never>? in
            state.finished = true
            return state.task
        }
        task?.cancel()
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

/// Parks one checked continuation and resumes it exactly once.
///
/// `withCheckedThrowingContinuation` does not observe task cancellation, so a
/// timeout has to resume the wait explicitly, while a state observer may resume
/// it at the same moment. This gate makes those two resumes mutually exclusive
/// and also survives the cancellation arriving before the wait has parked its
/// continuation: the later `park` sees the earlier resolution and resumes
/// immediately, so no caller is left suspended.
private final class InteroperableQUICWaitGate: @unchecked Sendable {
    private enum Resolution {
        case pending
        case ready
        case failure(any Error)
    }

    private let state = Mutex<(resolution: Resolution, continuation: CheckedContinuation<Void, any Error>?)>(
        (.pending, nil)
    )

    func park(_ continuation: CheckedContinuation<Void, any Error>) {
        let resolution = state.withLock { state -> Resolution? in
            guard case .pending = state.resolution else {
                let resolution = state.resolution
                state.resolution = .pending
                return resolution
            }
            state.continuation = continuation
            return nil
        }
        if let resolution {
            Self.resume(continuation, with: resolution)
        }
    }

    func resolveReady() {
        resolve(.ready)
    }

    func resolveFailure(_ error: any Error) {
        resolve(.failure(error))
    }

    private func resolve(_ resolution: Resolution) {
        let continuation = state.withLock { state -> CheckedContinuation<Void, any Error>? in
            guard case .pending = state.resolution else {
                return nil
            }
            state.resolution = resolution
            let continuation = state.continuation
            state.continuation = nil
            return continuation
        }
        guard let continuation else {
            return
        }
        Self.resume(continuation, with: resolution)
    }

    private static func resume(
        _ continuation: CheckedContinuation<Void, any Error>,
        with resolution: Resolution
    ) {
        switch resolution {
        case .pending:
            break
        case .ready:
            continuation.resume()
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}
