// The interoperable runtime's client half: the public client entry point, its
// trust policy, and the QUIC configuration it builds.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

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

    /// The name the server's certificate must be valid for, or `nil` when the framework's own validation — against
    /// the address the connection is opened with — is already the right one.
    ///
    /// A certificate proves a NAME, and `authority` is the name the caller asked for ("The expected `:authority`
    /// value on the extended CONNECT request"); the endpoint is where that name happens to be reachable. When the
    /// two agree there is nothing to override, and when they differ the certificate has to be checked against the
    /// NAME — that is the difference between dialling an address (an IP, a load balancer, a tailnet name) and being
    /// told which name to expect, and without it such a connection fails the handshake with `bad_certificate`
    /// (WT-261). This is a pure function so the decision itself is testable; the verification it feeds is
    /// `InteroperableQUICCertificateVerification`, which changes only the name and leaves the trust anchors alone.
    internal func certificateName(
        endpoint: WebTransportNetworkEndpoint,
        authority: String?
    ) -> String? {
        guard self == .systemTrust else {
            // The local development bypass has no verification to name.
            return nil
        }
        let requested = InteroperableQUICAuthority.host(of: authority ?? endpoint.host)
        // Both sides are reduced the same way, so `example.com:443` and `example.com` agree rather than looking
        // like two different names that happen to reach the same server.
        let dialled = InteroperableQUICAuthority.host(of: endpoint.host)
        guard !requested.isEmpty, requested.caseInsensitiveCompare(dialled) != .orderedSame else {
            return nil
        }
        return requested
    }

    func runtimeConfiguration(
        endpoint: WebTransportNetworkEndpoint,
        authority: String?
    ) throws -> InteroperableQUICTrustConfiguration {
        switch self {
        case .systemTrust:
            guard let name = certificateName(endpoint: endpoint, authority: authority) else {
                return .systemTrust
            }
            return .systemTrustForName(name)
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

enum InteroperableQUICTrustConfiguration: Sendable {
    case systemTrust
    /// Verify the platform's trust chain against this name rather than against the address dialled (WT-261).
    case systemTrustForName(String)
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
        let trustConfiguration = try trustPolicy.runtimeConfiguration(endpoint: endpoint, authority: authority)
        let connection = makeClientConnection(endpoint: endpoint, trustConfiguration: trustConfiguration)
        let started = Date()
        let remainingTimeout: @Sendable () -> Int32 = { [timeoutMilliseconds] () -> Int32 in
            InteroperableQUICHelpers.remainingTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                started: started
            )
        }
        let (inboundStreams, inboundTask) = await startInboundCollection(connection: connection)
        let prelude = ClientSessionPrelude(
            connection: connection,
            endpoint: endpoint,
            authority: authority,
            path: path,
            origin: origin,
            protocols: protocols,
            optimisticCapsules: optimisticCapsules,
            settingsValidation: settingsValidation,
            timeoutMilliseconds: timeoutMilliseconds,
            remainingTimeout: remainingTimeout,
            inboundStreams: inboundStreams,
            inboundTask: inboundTask
        )
        let outcome = try await performClientHandshake(prelude)
        return makeSession(prelude: prelude, outcome: outcome)
    }
}

extension WebTransportQUICClient {
    /// The values every phase of the client handshake needs.
    private struct ClientSessionPrelude {
        let connection: NetworkConnection<QUIC>
        let endpoint: WebTransportNetworkEndpoint
        let authority: String?
        let path: String
        let origin: String?
        let protocols: [String]
        let optimisticCapsules: [WebTransportFlowCapsule]
        let settingsValidation: HTTP3WebTransportSettingsValidation
        let timeoutMilliseconds: Int32
        let remainingTimeout: @Sendable () -> Int32
        let inboundStreams: InteroperableQUICInboundStreamCollector
        let inboundTask: Task<Void, Never>
    }

    /// Everything the client handshake produces, ready to become a session.
    private struct ClientHandshakeOutcome {
        let localControlStream: QUIC.Stream<QUICStream>
        let requestStream: QUIC.Stream<QUICStream>
        let qpackStreams: [QUIC.Stream<QUICStream>]
        let manager: WebTransportSessionManager
        let sessionID: WebTransportSessionID
        let selectedProtocol: String?
        let useDatagrams: Bool
        let initialConnectCapsuleBytes: Data
    }

    /// The server's first chunk, decoded as far as its frame prefix.
    private struct ServerResponse {
        let frame: HTTP3Frame
        let bytesConsumed: Int
        let data: Data
    }

    /// The connection itself, with the transport trust policy already applied.
    private func makeClientConnection(
        endpoint: WebTransportNetworkEndpoint,
        trustConfiguration: InteroperableQUICTrustConfiguration
    ) -> NetworkConnection<QUIC> {
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
        return connection
    }

    /// The client half of the handshake: control streams, SETTINGS, the CONNECT request, and
    /// the server's answer.
    private func performClientHandshake(_ prelude: ClientSessionPrelude) async throws -> ClientHandshakeOutcome {
        // Cancel the inbound handler on every failure path, not only the rejected-session
        // one. The handler task strongly retains the connection, and Network.framework
        // exposes no `cancel()` — only `deinit` — so a task left running keeps the connection
        // and its socket alive for the process lifetime.
        var handedBackSession = false
        defer {
            if !handedBackSession {
                prelude.inboundTask.cancel()
            }
        }

        try await InteroperableQUICHelpers.waitForReady(
            connection: prelude.connection,
            role: "client",
            start: { _ = prelude.connection.start() },
            timeoutMilliseconds: prelude.remainingTimeout()
        )
        InteroperableQUICDebug.log("client ready")

        var http3 = HTTP3ConnectionState(
            role: .client,
            localSettings: prelude.settingsValidation.localSettings
        )
        let (localControlStream, qpackStreams) = try await openClientControlStreams(prelude: prelude, http3: http3)
        let useDatagrams = try await exchangeControlStreams(
            http3: &http3,
            inboundStreams: prelude.inboundStreams,
            settingsValidation: prelude.settingsValidation,
            timeoutMilliseconds: prelude.remainingTimeout()
        )
        var manager = WebTransportSessionManager(
            http3: http3,
            // makeClientQUIC advertises the default limits, so enforce the same ceiling here
            // rather than the manager's smaller built-in default.
            maxDatagramFrameSize: WebTransportTransportLimits.default.maxDatagramFrameSize,
            settingsValidation: prelude.settingsValidation
        )
        let (requestStream, requestStreamID) = try await openAndSendSessionRequest(prelude: prelude, manager: &manager)
        let response = try await awaitServerResponse(prelude: prelude, requestStream: requestStream)
        let session = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: response.frame)
        guard session.state == .accepted else {
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport session was rejected"
            )
        }

        handedBackSession = true
        return ClientHandshakeOutcome(
            localControlStream: localControlStream,
            requestStream: requestStream,
            qpackStreams: qpackStreams,
            manager: manager,
            sessionID: try WebTransportSessionID.fromRequestStreamID(requestStreamID),
            selectedProtocol: session.selectedProtocol,
            useDatagrams: useDatagrams,
            initialConnectCapsuleBytes: Data(response.data.dropFirst(response.bytesConsumed))
        )
    }

    /// Opens the client's local control stream, sends its SETTINGS, and opens the QPACK
    /// streams. Each step samples the remaining deadline.
    private func openClientControlStreams(
        prelude: ClientSessionPrelude,
        http3: HTTP3ConnectionState
    ) async throws -> (control: QUIC.Stream<QUICStream>, qpack: [QUIC.Stream<QUICStream>]) {
        let localControlPayload = try http3.localControlStreamBytes()
        let openTimeout = prelude.remainingTimeout()
        guard openTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(prelude.timeoutMilliseconds)
        }
        let localControlStream = try await InteroperableQUICHelpers.withTimeout(openTimeout) {
            try await prelude.connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("client opened local control stream \(localControlStream.streamID)")
        let sendTimeout = prelude.remainingTimeout()
        guard sendTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(prelude.timeoutMilliseconds)
        }
        try await InteroperableQUICHelpers.withTimeout(sendTimeout) {
            try await localControlStream.send(localControlPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent local control payload")
        let qpackStreams = try await InteroperableQUICHelpers.openQPACKStreams(
            on: prelude.connection,
            role: "client",
            timeoutMilliseconds: prelude.remainingTimeout()
        )
        return (localControlStream, qpackStreams)
    }

    /// Opens the CONNECT stream, builds the request with any optimistic capsules, and sends it.
    private func openAndSendSessionRequest(
        prelude: ClientSessionPrelude,
        manager: inout WebTransportSessionManager
    ) async throws -> (stream: QUIC.Stream<QUICStream>, streamID: UInt64) {
        let openTimeout = prelude.remainingTimeout()
        guard openTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(prelude.timeoutMilliseconds)
        }
        let requestStream = try await InteroperableQUICHelpers.withTimeout(openTimeout) {
            try await prelude.connection.openStream(directionality: .bidirectional)
        }
        let requestStreamID = requestStream.streamID
        InteroperableQUICDebug.log("client opened request stream \(requestStreamID)")
        let request = try WebTransportSessionRequest(
            authority: prelude.authority ?? prelude.endpoint.host,
            path: prelude.path,
            origin: prelude.origin,
            availableProtocols: prelude.protocols
        )
        let requestFrame = try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
        var connectPayload = try InteroperableQUICHelpers.makeRequestStreamPayload(requestFrame: requestFrame)
        let pendingSessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)
        for capsule in prelude.optimisticCapsules {
            connectPayload.append(
                try InteroperableCONNECTCapsuleFraming.wrap(
                    manager.makeOptimisticConnectStreamCapsule(
                        sessionID: pendingSessionID,
                        capsule: capsule
                    )))
        }
        let sendTimeout = prelude.remainingTimeout()
        guard sendTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(prelude.timeoutMilliseconds)
        }
        // Bound to a `let` first: the send closure is @Sendable, and a captured `var` is a
        // strict-concurrency error. The original had this line for the same reason.
        let requestPayload = connectPayload
        try await InteroperableQUICHelpers.withTimeout(sendTimeout) {
            try await requestStream.send(requestPayload, endOfStream: false)
        }
        InteroperableQUICDebug.log("client sent connect payload")
        return (requestStream, requestStreamID)
    }

    /// The server's answer, which must be a HEADERS frame: a peer that ends the CONNECT
    /// stream without writing anything has not answered the request.
    private func awaitServerResponse(
        prelude: ClientSessionPrelude,
        requestStream: QUIC.Stream<QUICStream>
    ) async throws -> ServerResponse {
        let readTimeout = prelude.remainingTimeout()
        guard readTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(prelude.timeoutMilliseconds)
        }
        let responseData = try await InteroperableQUICHelpers.withTimeout(readTimeout) {
            try await InteroperableQUICHelpers.readFirstChunk(
                requestStream,
                timeoutMilliseconds: prelude.remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("client got response bytes=\(responseData.count)")
        let responsePrefix = try HTTP3Frame.decodePrefix(responseData)
        guard responsePrefix.frame.type == HTTP3FrameType.headers else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        return ServerResponse(
            frame: responsePrefix.frame,
            bytesConsumed: responsePrefix.bytesConsumed,
            data: responseData
        )
    }

    /// The session object the handshake produced.
    private func makeSession(
        prelude: ClientSessionPrelude,
        outcome: ClientHandshakeOutcome
    ) -> WebTransportNetworkSession {
        WebTransportNetworkSession(
            connection: prelude.connection,
            inboundStreams: prelude.inboundStreams,
            inboundTask: prelude.inboundTask,
            manager: outcome.manager,
            sessionID: outcome.sessionID,
            selectedProtocol: outcome.selectedProtocol,
            localControlStream: outcome.localControlStream,
            connectStream: outcome.requestStream,
            qpackStreams: outcome.qpackStreams,
            localEndpoint: InteroperableQUICRuntime.networkEndpoint(
                from: prelude.connection.localEndpoint,
                fallback: WebTransportNetworkEndpoint(host: "unknown", port: 0)
            ),
            remoteEndpoint: InteroperableQUICRuntime.networkEndpoint(
                from: prelude.connection.remoteEndpoint,
                fallback: prelude.endpoint
            ),
            datagramsAvailable: outcome.useDatagrams,
            timeoutMilliseconds: prelude.timeoutMilliseconds,
            initialConnectCapsuleBytes: outcome.initialConnectCapsuleBytes
        )
    }
}

// `makeClientQUIC` stays in this file because it is the client's own construction
// site, next to the policies whose selection it implements. Its parameter type is
// internal rather than private so the tests can pin that selection.
extension InteroperableQUICRuntime {
    fileprivate static func makeClientQUIC(trustConfiguration: InteroperableQUICTrustConfiguration) -> QUIC {
        switch trustConfiguration {
        case .systemTrust:
            return makeBaseQUIC()
        case .systemTrustForName(let name):
            // The framework would verify the address it dialled; this verifies the name the caller asked for, with
            // the platform's own anchors and its own SSL policy (WT-261).
            //
            // `peerAuthentication` is deliberately NOT set here. Security.framework's own
            // `sec_protocol_options_set_peer_authentication_required` documents that "clients default to true,
            // whereas servers default to false", so a client already requires a peer certificate, and installing a
            // validator neither narrows that nor relaxes it: a server that presents no certificate is still
            // refused. The local development bypass below is the only place that turns the requirement off, and it
            // does so explicitly.
            return makeBaseQUIC().tls.certificateValidator { _, trust in
                InteroperableQUICCertificateVerification.isValid(trust, forName: name)
            }
        case .localLoopbackDevelopmentSelfSigned:
            return makeBaseQUIC().tls.peerAuthentication(.none)
        }
    }
}

extension WebTransportQUICClient {
    @discardableResult

    /// Starts the inbound-stream handler and waits until it is registered.
    ///
    /// Registered before the connection is started, not after it is ready. The peer opens
    /// its control stream the instant its own side completes the handshake, so a handler
    /// installed after `start()` races that stream and loses it outright — see
    /// `InteroperableQUICInboundRegistration`.
    private func startInboundCollection(
        connection: NetworkConnection<QUIC>
    ) async -> (streams: InteroperableQUICInboundStreamCollector, task: Task<Void, Never>) {
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
                await inboundStreams.fail(error, role: "client")
            }
        }
        await inboundRegistration.waitUntilEntered()
        return (inboundStreams, inboundTask)
    }

    /// Reads the peer's control stream and answers whether datagrams are usable.
    ///
    /// Datagram availability is a property of the negotiated SETTINGS, so it is answered
    /// after the control-stream exchange rather than assumed.
    private func exchangeControlStreams(
        http3: inout HTTP3ConnectionState,
        inboundStreams: InteroperableQUICInboundStreamCollector,
        settingsValidation: HTTP3WebTransportSettingsValidation,
        timeoutMilliseconds: Int32
    ) async throws -> Bool {
        let peerControlBytes = try await InteroperableQUICHelpers.readPeerControlStream(
            from: inboundStreams,
            role: "client",
            timeoutMilliseconds: timeoutMilliseconds
        )
        InteroperableQUICDebug.log("client peer control bytes=\(peerControlBytes.count)")
        _ = try http3.receivePeerControlStream(
            peerControlBytes,
            settingsValidation: settingsValidation
        )
        InteroperableQUICDebug.log("client local settings: \(InteroperableQUICRuntime.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("client peer settings: \(InteroperableQUICRuntime.renderSettings(peerSettings))")
        }
        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(
            localSettings: http3.localSettings,
            remoteSettings: http3.remoteSettings
        )
        InteroperableQUICDebug.log("client datagrams usable=\(useDatagrams)")
        return useDatagrams
    }

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

        let responseMessage =
            if useDatagrams {
                try await exchangeOverDatagram(
                    session: session,
                    message: message,
                    exchangeMode: exchangeMode,
                    timeoutMilliseconds: timeoutMilliseconds
                )
            } else {
                try await exchangeOverStream(
                    session: session,
                    message: message,
                    timeoutMilliseconds: timeoutMilliseconds
                )
            }

        return WebTransportNetworkSessionResult(
            localEndpoint: session.localEndpoint,
            remoteEndpoint: session.remoteEndpoint,
            message: responseMessage,
            transport: .packet,
            sessionEstablished: true
        )
    }
    /// The datagram exchange, including the two availability checks the exchange mode sets.
    private func exchangeOverDatagram(
        session: WebTransportNetworkSession,
        message: String,
        exchangeMode: WebTransportNetworkExchangeMode,
        timeoutMilliseconds: Int32
    ) async throws -> String {
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
        guard let response = String(data: responsePayload, encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return response
    }

    /// The bidirectional-stream exchange, used when datagrams are unavailable or the peer
    /// asked for the stream interop profile.
    private func exchangeOverStream(
        session: WebTransportNetworkSession,
        message: String,
        timeoutMilliseconds: Int32
    ) async throws -> String {
        InteroperableQUICDebug.log("client using stream fallback path")
        let stream = try await session.openBidirectionalStream(timeoutMilliseconds: timeoutMilliseconds)
        try await stream.send(Data(message.utf8), endOfStream: true, timeoutMilliseconds: timeoutMilliseconds)
        let response = try await stream.receive(timeoutMilliseconds: timeoutMilliseconds)
        guard let responseMessage = String(data: response, encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return responseMessage
    }
}
