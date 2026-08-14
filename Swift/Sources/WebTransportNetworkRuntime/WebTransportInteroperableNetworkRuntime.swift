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
        var connectPayload = try InteroperableQUICHelpers.makeRequestStreamPayload(
            streamID: requestStreamID,
            requestFrame: requestFrame
        )
        let pendingSessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)
        for capsule in optimisticCapsules {
            connectPayload.append(try manager.makeOptimisticConnectStreamCapsule(
                sessionID: pendingSessionID,
                capsule: capsule
            ))
        }
        let requestPayload = connectPayload
        try await runWithTimeout {
            try await requestStream.send(requestPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent connect payload")

        let responseData = try await InteroperableQUICHelpers.readStream(
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
        if let initialPayload = await state.consumeInitialPayload(), !initialPayload.isEmpty {
            if let manager {
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
        let firstChunk = try await InteroperableQUICHelpers.readStream(
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
              prefix.sessionID.rawValue == sessionID else {
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
                  let payload = manager.popDatagramPayload(sessionID: responseSessionID) else {
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
        let exported = unsafe labelBytes.withUnsafeBufferPointer { labelBuffer in
            unsafe contextBytes.withUnsafeBufferPointer { contextBuffer in
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

    private static func popCompleteCapsule(from buffer: inout Data) throws -> Data? {
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

    /// The endpoint the listener is bound to.
    ///
    /// Reads are synchronized: the port is not known until the listener binds,
    /// so `waitForListening` rewrites this after construction and callers on the
    /// accept path may observe it from another thread.
    public var localEndpoint: WebTransportNetworkEndpoint {
        localEndpointStorage.withLock { $0 }
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

    public convenience init(
        bindPort: UInt16,
        maxConcurrentConnections: Int = 16,
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
        maxConcurrentConnections: Int = 16,
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
        // `maxConcurrentConnections` predates the admission policy. When a caller
        // supplies a policy its value wins; otherwise the legacy argument is
        // honoured so existing call sites behave identically.
        var admission = try admission.validated()
        if admission == .default, maxConcurrentConnections != 16 {
            admission.maxConcurrentConnections = maxConcurrentConnections
        }
        let transportLimits = try transportLimits.validated()
        self.admission = admission
        self.rateLimiter = ConnectionRateLimiter(policy: admission)
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

        listener = try NetworkListener<QUIC>(using: parameters)
            .newConnectionLimit(max(1, admission.maxConcurrentConnections))
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
        InteroperableQUICDebug.log("server graceful shutdown complete")
    }

    deinit {
        shutdown()
    }

    public func acceptSession(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSession {
        guard accepting.withLock({ $0 }) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("listener is shutting down")
        }
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

        let session = try await acceptSession(
            on: connection,
            timeoutMilliseconds: timeoutMilliseconds
        )
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
        // is reported optimistically — Network.framework does not confirm datagram
        // support until the channel is first used, so the runtime always answers
        // true — which meant this waited for a datagram even when the peer had
        // opened a stream. A browser opens a stream by default, so it hung here
        // after a successful handshake. Wait for both and echo on whichever the
        // peer actually used.
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
                { try await Self.echoOneStream(on: session, timeoutMilliseconds: raceTimeout) }
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
              case .hostPort(let host, let port) = endpoint else {
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
            ("decoder", HTTP3StreamType.qpackDecoder)
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

                // Register the observer before sampling the current state. A
                // transition that lands between the two is then delivered twice
                // rather than missed, and `completion` is one-shot so the
                // duplicate is discarded. Sampling first would leave a window
                // where a terminal transition is observed by nobody.
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
        }
    }

    static func datagramsUsable(_: NetworkConnection<QUIC>) -> Bool {
        // Network.framework can report 0 here until the datagram channel is
        // first used, even when both peers negotiated QUIC DATAGRAM support.
        // The runtime config always advertises max_datagram_frame_size; the
        // actual datagram channel send/receive calls remain the authoritative
        // failure point for non-compliant peers.
        return true
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

    static func isTransientNotConnected(_ error: Error) -> Bool {
        if let posix = error as? POSIXError {
            return posix.code == .ENOTCONN
        }
        let nsError = error as NSError
        return nsError.domain == NSPOSIXErrorDomain && nsError.code == Int(ENOTCONN)
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

    /// Peer control and QPACK streams, held for the lifetime of the connection.
    ///
    /// These are critical streams: RFC 9114 section 6.2.1 and RFC 9204 section
    /// 4.2 forbid closing them, and a peer that receives STOP_SENDING on one
    /// closes the connection with H3_CLOSED_CRITICAL_STREAM. Releasing the
    /// handle after reading lets the transport cancel the receive side, which
    /// the peer sees as exactly that. This collector is owned by the session, so
    /// anything parked here lives as long as the connection does.
    private var retainedCriticalStreams: [QUIC.Stream<QUICStream>] = []

    func retainCritical(_ stream: QUIC.Stream<QUICStream>) {
        retainedCriticalStreams.append(stream)
    }

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
