// The interoperable runtime's server half: the listener, the connections it accepts,
// and the sessions it serves.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

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
    private let acceptedConnections: InteroperableQUICConnectionQueue<InteroperableQUICAcceptedConnection>
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
        let admission = try Self.resolvedAdmission(admission, maxConcurrentConnections: maxConcurrentConnections)
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
        acceptedConnections = InteroperableQUICConnectionQueue(release: { $0.inboundTask.cancel() })
        localEndpointStorage = Mutex(endpoint)
        self.authority = authority
        self.path = path
        self.allowedOrigin = allowedOrigin
        self.protocols = protocols
        self.settingsValidation = settingsValidation
        listener.onStateUpdate { _, state in
            InteroperableQUICDebug.log("server listener state update: \(state)")
        }

        listenerTask = Self.makeListenerTask(
            listener: listener,
            acceptedConnections: acceptedConnections,
            rateLimiter: rateLimiter,
            connectionBudget: connectionBudget,
            advertisedStreamLimits: transportLimits
        )
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

}

extension WebTransportQUICServer {
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
}

extension WebTransportQUICServer {
    private func acceptSession(
        on accepted: InteroperableQUICAcceptedConnection,
        timeoutMilliseconds: Int32
    ) async throws -> WebTransportNetworkSession {
        makeSession(try await performServerHandshake(on: accepted, timeoutMilliseconds: timeoutMilliseconds))
    }

    /// The values every phase of the handshake needs, taken from the accepted connection once.
    private struct SessionPrelude {
        let connection: NetworkConnection<QUIC>
        let remainingTimeout: @Sendable () -> Int32
        let datagramFrameSizeLimit: Int
        let inboundStreams: InteroperableQUICInboundStreamCollector
        let inboundTask: Task<Void, Never>
    }

    /// Everything the handshake produces, ready to become a session.
    private struct ServerHandshakeOutcome {
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

    private func makeSessionPrelude(
        accepted: InteroperableQUICAcceptedConnection,
        timeoutMilliseconds: Int32
    ) -> SessionPrelude {
        let started = Date()
        InteroperableQUICDebug.log("server serveSession start")
        return SessionPrelude(
            connection: accepted.connection,
            remainingTimeout: { [timeoutMilliseconds] () -> Int32 in
                InteroperableQUICHelpers.remainingTimeout(
                    timeoutMilliseconds: timeoutMilliseconds,
                    started: started
                )
            },
            datagramFrameSizeLimit: transportLimits.maxDatagramFrameSize,
            // Attached at accept time, before the connection was started, so streams the peer
            // opened during the handshake are already collected here.
            inboundStreams: accepted.inboundStreams,
            inboundTask: accepted.inboundTask
        )
    }

    /// The server half of the handshake: control streams, SETTINGS, the CONNECT request and
    /// the decision. Split from `acceptSession` so each phase is named and the entry point is
    /// one line.
    private func performServerHandshake(
        on accepted: InteroperableQUICAcceptedConnection,
        timeoutMilliseconds: Int32
    ) async throws -> ServerHandshakeOutcome {
        let prelude = makeSessionPrelude(accepted: accepted, timeoutMilliseconds: timeoutMilliseconds)
        var http3 = HTTP3ConnectionState(
            role: .server,
            localSettings: settingsValidation.localSettings
        )
        let (localControlStream, qpackStreams) = try await openServerControlStreams(
            connection: prelude.connection,
            http3: http3,
            remainingTimeout: prelude.remainingTimeout,
            totalTimeoutMilliseconds: timeoutMilliseconds
        )
        let useDatagrams = try await exchangeServerControlStreams(
            http3: &http3,
            inboundStreams: prelude.inboundStreams,
            settingsValidation: settingsValidation,
            remainingTimeout: prelude.remainingTimeout,
            totalTimeoutMilliseconds: timeoutMilliseconds
        )
        var manager = makeSessionManager(
            http3: http3,
            datagramFrameSizeLimit: prelude.datagramFrameSizeLimit
        )
        let (requestStream, requestPayload) = try await nextRequestStreamAndFirstChunk(
            inboundStreams: prelude.inboundStreams,
            remainingTimeout: prelude.remainingTimeout,
            totalTimeoutMilliseconds: timeoutMilliseconds
        )
        let request = try decodeRequestAndPolicy(requestPayload: requestPayload)
        let decision = try await performConnectExchange(
            manager: &manager,
            requestStream: requestStream,
            request: request,
            remainingTimeout: prelude.remainingTimeout,
            totalTimeoutMilliseconds: timeoutMilliseconds
        )
        try refuseRejectedSession(decision, inboundTask: prelude.inboundTask)
        return ServerHandshakeOutcome(
            connection: prelude.connection,
            inboundStreams: prelude.inboundStreams,
            inboundTask: prelude.inboundTask,
            lease: accepted.lease,
            manager: manager,
            decision: decision,
            localControlStream: localControlStream,
            requestStream: requestStream,
            qpackStreams: qpackStreams,
            useDatagrams: useDatagrams,
            optimisticCapsuleBytes: request.optimisticCapsuleBytes,
            timeoutMilliseconds: timeoutMilliseconds
        )
    }

    /// A rejected session ends here: the inbound handler is cancelled and the rejection is
    /// what the caller sees.
    private func refuseRejectedSession(
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
    private func performConnectExchange(
        manager: inout WebTransportSessionManager,
        requestStream: QUIC.Stream<QUICStream>,
        request: DecodedSessionRequest,
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
        try await Self.deliverSessionDecision(
            decision,
            on: requestStream,
            remainingTimeout: remainingTimeout,
            totalTimeoutMilliseconds: totalTimeoutMilliseconds
        )
        return decision
    }

    /// The session object the handshake produced.
    private func makeSession(_ outcome: ServerHandshakeOutcome) -> WebTransportNetworkSession {
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

extension WebTransportQUICServer {
    /// The session manager for a fresh server connection.
    ///
    /// The datagram frame size is what the QUIC layer advertised to the peer: leaving it at
    /// the manager's own smaller default rejects a peer that is sending exactly what it was
    /// told it could send.
    private func makeSessionManager(
        http3: HTTP3ConnectionState,
        datagramFrameSizeLimit: Int
    ) -> WebTransportSessionManager {
        WebTransportSessionManager(
            http3: http3,
            maxDatagramFrameSize: datagramFrameSizeLimit,
            settingsValidation: settingsValidation
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

    /// Reads the peer's control stream and answers whether datagrams are usable.
    ///
    /// Peer SETTINGS identify which WebTransport revision the client speaks, so logging the
    /// decoded ids is what makes a "handshake failed" from an opaque peer such as a browser
    /// diagnosable at all. Datagram availability is a property of the negotiated SETTINGS,
    /// so it is answered after the exchange rather than assumed.
    private func exchangeServerControlStreams(
        http3: inout HTTP3ConnectionState,
        inboundStreams: InteroperableQUICInboundStreamCollector,
        settingsValidation: HTTP3WebTransportSettingsValidation,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws -> Bool {
        let readTimeout = remainingTimeout()
        guard readTimeout > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        let controlPayload = try await InteroperableQUICHelpers.withTimeout(readTimeout) {
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
        InteroperableQUICDebug.log("server local settings: \(InteroperableQUICRuntime.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("server peer settings: \(InteroperableQUICRuntime.renderSettings(peerSettings))")
        }
        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(
            localSettings: http3.localSettings,
            remoteSettings: http3.remoteSettings
        )
        InteroperableQUICDebug.log("server datagrams usable=\(useDatagrams)")
        return useDatagrams
    }

    /// The peer's CONNECT request stream and its first chunk, sharing one deadline.
    private func nextRequestStreamAndFirstChunk(
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
    private func openServerControlStreams(
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

    /// Logs and sends the server's decision.
    ///
    /// Without the log line the reason a peer's CONNECT was refused is lost: the throw
    /// propagates as a transport error once the peer has already gone, which is what makes
    /// browser handshake failures opaque.
    private static func deliverSessionDecision(
        _ decision: WebTransportServerSessionDecision,
        on requestStream: QUIC.Stream<QUICStream>,
        remainingTimeout: @escaping @Sendable () -> Int32,
        totalTimeoutMilliseconds: Int32
    ) async throws {
        InteroperableQUICDebug.log(
            "server CONNECT decision: session=\(decision.session.id) "
                + "protocol=\(decision.session.selectedProtocol ?? "none") "
                + "rejection=\(decision.rejectionError.map { "\($0)" } ?? "none")"
        )
        let responsePayload = try decision.responseFrame.encode()
        let remaining = remainingTimeout()
        guard remaining > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(totalTimeoutMilliseconds)
        }
        try await InteroperableQUICHelpers.withTimeout(remaining) {
            try await requestStream.send(responsePayload, endOfStream: false)
        }
    }

    /// A decoded CONNECT request: its HEADERS frame, any optimistic capsule bytes behind it,
    /// and the policy this server applies to it.
    private struct DecodedSessionRequest {
        let frame: HTTP3Frame
        let optimisticCapsuleBytes: Data
        let policy: WebTransportServerSessionPolicy
    }

    /// The CONNECT request's HEADERS frame, any optimistic capsule bytes behind it, and the
    /// policy this server applies to it.
    ///
    /// The authorities are the four spellings a client may use for this listener: the
    /// configured authority, that authority with the port, the host, and the host with the
    /// port. A peer that asserted a WebTransport stream prefix but sent a malformed one is a
    /// protocol violation and must propagate: swallowing it would silently reinterpret
    /// invalid bytes as an unprefixed CONNECT request and continue.
    private func decodeRequestAndPolicy(requestPayload: Data) throws -> DecodedSessionRequest {
        let requestFramePayload: Data
        if WebTransportStreamSignaling.hasStreamPrefix(requestPayload) {
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
        return DecodedSessionRequest(
            frame: requestPrefix.frame,
            optimisticCapsuleBytes: Data(requestFramePayload.dropFirst(requestPrefix.bytesConsumed)),
            policy: policy
        )
    }

    /// The inbound collector for one accepted connection, with its handler already
    /// registered and waited for.
    private static func startInboundCollection(
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

    /// The accept loop, built so that it captures the values it needs rather than the server.
    ///
    /// A connection refused by rate or budget is neither started nor queued, so returning
    /// from the accept handler is what hands it back to Network.framework and the refusal
    /// costs nothing beyond the accept itself. The stream handler is attached before the
    /// connection is started, because the peer opens its control stream as soon as the
    /// handshake completes — typically while this connection is still queued and long before
    /// anything calls `serveOne`. The collector's per-direction ceiling is the stream count
    /// this listener advertised: retaining more would hold stream objects the peer was never
    /// allowed to open, and fewer would refuse streams the advertisement promised.
    private static func makeListenerTask(
        listener: NetworkListener<QUIC>,
        acceptedConnections: InteroperableQUICConnectionQueue<InteroperableQUICAcceptedConnection>,
        rateLimiter: ConnectionRateLimiter?,
        connectionBudget: InteroperableQUICConnectionBudget,
        advertisedStreamLimits: WebTransportTransportLimits
    ) -> Task<Void, Never> {
        // The listener task must not retain the server to read these, and each accepted
        // connection builds its own collector from them.
        let listener = listener
        let acceptedConnections = acceptedConnections
        let rateLimiter = rateLimiter
        let connectionBudget = connectionBudget
        let advertisedStreamLimits = advertisedStreamLimits
        return Task {
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
                    let (inboundStreams, inboundTask) = await Self.startInboundCollection(
                        connection: connection,
                        advertisedStreamLimits: advertisedStreamLimits
                    )
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
                await acceptedConnections.fail(error, role: "server")
            }
        }
    }

    /// The admission policy with the legacy `maxConcurrentConnections` override applied.
    ///
    /// `maxConcurrentConnections` predates the admission policy. An explicit value overrides
    /// whatever the policy carries, and `nil` (the argument not being supplied) leaves the
    /// policy's own limit alone.
    ///
    /// The override used to be tied to the default argument `16`, so an operator who
    /// explicitly asked for 16 while supplying another policy got the policy's number
    /// instead — 256 for `.publicFacing`. Representing "not supplied" as `nil` rather than as
    /// a valid value is what makes the two distinguishable. The value is validated on the
    /// same terms as the policy field, so an out-of-range override is refused rather than
    /// accepted here and rejected elsewhere.
    private static func resolvedAdmission(
        _ admission: WebTransportAdmissionPolicy,
        maxConcurrentConnections: Int?
    ) throws -> WebTransportAdmissionPolicy {
        var resolved = try admission.validated()
        if let maxConcurrentConnections {
            guard maxConcurrentConnections > 0 else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "maxConcurrentConnections must be positive"
                )
            }
            resolved.maxConcurrentConnections = maxConcurrentConnections
        }
        return resolved
    }
}
