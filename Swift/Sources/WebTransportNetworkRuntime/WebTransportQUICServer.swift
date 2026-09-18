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
        InteroperableQUICDebug.log("server local settings: \(InteroperableQUICRuntime.renderSettings(http3.localSettings))")
        if let peerSettings = http3.remoteSettings {
            InteroperableQUICDebug.log("server peer settings: \(InteroperableQUICRuntime.renderSettings(peerSettings))")
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
}

extension WebTransportQUICServer {
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
