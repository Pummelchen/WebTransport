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
                await inboundStreams.fail(error, role: "client")
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
        InteroperableQUICDebug.log("client local settings: \(InteroperableQUICRuntime.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("client peer settings: \(InteroperableQUICRuntime.renderSettings(peerSettings))")
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
            requestFrame: requestFrame
        )
        let pendingSessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)
        for capsule in optimisticCapsules {
            connectPayload.append(
                try InteroperableCONNECTCapsuleFraming.wrap(
                    manager.makeOptimisticConnectStreamCapsule(
                        sessionID: pendingSessionID,
                        capsule: capsule
                    )))
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
            return makeBaseQUIC().tls.certificateValidator { _, trust in
                InteroperableQUICCertificateVerification.isValid(trust, forName: name)
            }
        case .localLoopbackDevelopmentSelfSigned:
            return makeBaseQUIC().tls.peerAuthentication(.none)
        }
    }
}
