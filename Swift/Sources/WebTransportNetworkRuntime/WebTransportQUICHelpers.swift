// Shared helpers for the interoperable runtime: the diagnostic channel, the QUIC
// configuration factory, and the stream and capsule read policy.

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
enum InteroperableQUICDebug {
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

enum InteroperableQUICRuntime {
    /// The ALPN identifiers every QUIC connection this runtime builds offers.
    ///
    /// The HTTP/3 token comes from ``WebTransportALPNPolicy`` rather than a
    /// literal so the offer and the negotiated-ALPN validation cannot drift
    /// apart: a change to the policy moves the offer with it, and a test pins the
    /// two together.
    static let alpnProtocols = [WebTransportALPNPolicy.requiredHTTP3Protocol]

    /// Renders HTTP/3 SETTINGS as sorted `0xid=value` pairs for the diagnostic
    /// channel. Setting identifiers and counts only — no peer payload.
    ///
    /// Shared by the client and server halves: the two used to carry
    /// byte-identical private copies.
    static func renderSettings(_ settings: HTTP3Settings) -> String {
        settings.entries
            .sorted { $0.key < $1.key }
            .map { "0x\(String($0.key, radix: 16))=\($0.value)" }
            .joined(separator: " ")
    }

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
        QUIC(alpn: alpnProtocols) {
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
    ) async -> InboundStreamDisposition {
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

    /// The session a peer-prefixed stream names, when that session is not the one
    /// this connection serves.
    ///
    /// A WebTransport stream starts with a marker and a session ID. The runtime
    /// serves exactly one session per connection, so a prefix naming any other
    /// session is a peer error the draft requires be refused at the stream level.
    /// The bytes have already been consumed from the transport by the time the
    /// prefix is available, so the stream cannot be handed back; it must be reset
    /// rather than silently dropped. A caller that sees `nil` leaves the bytes to
    /// `WebTransportSessionManager`, which owns the prefix grammar and reports the
    /// appropriate protocol error for a missing, malformed, or wrong-form prefix.
    ///
    /// `form` is the direction the caller accepted the stream on. A prefix whose
    /// form does not match is a grammar error owned by the session manager, not a
    /// foreign-session report, so it is deliberately left alone: only a
    /// well-formed prefix of the expected form naming another session is foreign.
    static func foreignSessionID(
        inPrefixedStream firstBytes: Data,
        expectedSessionID: UInt64,
        form: WebTransportStreamForm = .bidirectional
    ) -> UInt64? {
        guard WebTransportStreamSignaling.hasStreamPrefix(firstBytes),
            let prefix = try? WebTransportStreamSignaling.parsePrefix(firstBytes),
            prefix.form == form
        else {
            return nil
        }
        let namedSessionID = prefix.sessionID.rawValue
        guard namedSessionID != expectedSessionID else {
            return nil
        }
        return namedSessionID
    }

    /// The session a WebTransport datagram names, when that session is not the
    /// one this connection serves.
    ///
    /// The QUIC datagram channel is connection-scoped: a datagram read from it
    /// cannot be put back, so the session ID in its prefix has to be checked
    /// before the session manager can retain the payload for a session this
    /// connection never serves. The runtime serves exactly one session per
    /// connection, so a datagram naming any other session is a peer error that
    /// must be named rather than reported as an invalid payload and discarded.
    /// A malformed datagram prefix throws the `.h3ID` error the session manager
    /// reports for the same bytes, so a caller propagates it unchanged.
    static func foreignDatagramSessionID(
        inDatagram payload: Data,
        expectedSessionID: UInt64
    ) throws -> UInt64? {
        let parsed: WebTransportDatagramPrefix
        do {
            parsed = try WebTransportDatagramSignaling.parse(payload)
        } catch {
            throw WebTransportDraft16Error(kind: .h3ID, message: "invalid WebTransport datagram session ID")
        }
        let namedSessionID = parsed.sessionID.rawValue
        guard namedSessionID != expectedSessionID else {
            return nil
        }
        return namedSessionID
    }

    static func makeRequestStreamPayload(requestFrame: HTTP3Frame) throws -> Data {
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
    /// The queues that serve an accepted connection name their failures the same way, but
    /// as ``connectionTransportFailed(role:domain:code:)``: they are also used after
    /// establishment, so calling theirs an establishment failure would be false. See
    /// ``connectionQueueFailure(role:error:)``.
    static func establishmentFailure(role: String, error: Error) -> WebTransportNetworkRuntimeError {
        let components =
            frameworkFailureComponents(error)
            ?? {
                let nsError = error as NSError
                return (domain: nsError.domain, code: nsError.code)
            }()
        return .connectionEstablishmentFailed(
            role: role,
            domain: components.domain,
            code: components.code
        )
    }

    /// The framework's own domain and code for `error`, or `nil` when the error is not a
    /// framework transport error.
    ///
    /// **A POSIX condition is recognised from the error itself, not from its bridged
    /// `NSError` domain.** Measured rather than assumed: `NWError.posix(.ENETDOWN)`
    /// bridges under `"Network.NWError"` — *not* `NSPOSIXErrorDomain` — so a predicate that
    /// read the bridged domain would never match a real failure. The `NWError` case is
    /// unwrapped and reported under the POSIX domain the condition actually is; an
    /// `NWError` of any other kind keeps the framework's domain and code.
    ///
    /// A framework error can also arrive already flattened into `NSError`, because the
    /// runtime does not control which layer hands it on, so the two framework domains are
    /// recognised by name as well as by type. Everything else — the runtime's own named
    /// errors, `CancellationError`, a caller's error — returns `nil`, which is what keeps
    /// the translation below from rewrapping a cause the caller can already act on.
    static func frameworkFailureComponents(_ error: Error) -> (domain: String, code: Int)? {
        if let networkError = error as? NWError {
            if case .posix(let posixCode) = networkError {
                return (NSPOSIXErrorDomain, Int(posixCode.rawValue))
            }
            let nsError = networkError as NSError
            return (nsError.domain, nsError.code)
        }
        if let posix = error as? POSIXError {
            return (NSPOSIXErrorDomain, Int(posix.code.rawValue))
        }
        let nsError = error as NSError
        guard nsError.domain == NSPOSIXErrorDomain || nsError.domain == "Network.NWError" else {
            return nil
        }
        return (nsError.domain, nsError.code)
    }

    /// Names a failure a connection queue is about to deliver (WT-197).
    ///
    /// `InteroperableQUICConnectionQueue.dequeue` and
    /// `InteroperableQUICInboundStreamCollector.next` are used after establishment as well
    /// as during it: the connection queue serves every session a listener accepts, and the
    /// inbound-stream collector only fails once the connection is carrying streams. Naming
    /// their failures ``connectionEstablishmentFailed(role:domain:code:)`` would be false,
    /// and it would make ``WebTransportNetworkRuntimeError/isTransientEstablishmentFailure``
    /// retry a session that may already have carried data. They are named
    /// ``connectionTransportFailed(role:domain:code:)`` instead — "the transport failed
    /// while the runtime was using the connection" is true of both sites.
    ///
    /// The translation runs where the queue records the failure, not only where it is
    /// thrown. `fail` resumes parked waiters directly as well as storing the error for
    /// later `dequeue`/`next` calls, so translating in one place there is what keeps a
    /// parked waiter and a later caller from seeing two different errors.
    static func connectionQueueFailure(role: String, error: Error) -> Error {
        guard let components = frameworkFailureComponents(error) else {
            return error
        }
        return WebTransportNetworkRuntimeError.connectionTransportFailed(
            role: role,
            domain: components.domain,
            code: components.code
        )
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
}

extension InteroperableQUICHelpers {
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

extension InteroperableQUICHelpers {
    fileprivate static func retainPeerCriticalStreamOrThrow(
        _ stream: QUIC.Stream<QUICStream>,
        type: UInt64,
        in inboundStreams: InteroperableQUICInboundStreamCollector
    ) async throws {
        guard await inboundStreams.retainCritical(stream, type: type) else {
            throw HTTP3ConnectionError(
                code: .streamCreationError,
                reason: "peer opened more than one HTTP/3 stream of type \(type)"
            )
        }
    }

    /// Classifies a peer unidirectional stream that carries no WebTransport
    /// prefix, retaining it when it is critical and ignoring it when it is not.
    ///
    /// The peer's control and QPACK streams share the unidirectional direction
    /// with WebTransport streams. ``readPeerControlStream(from:role:timeoutMilliseconds:)``
    /// returns as soon as it reads the control stream, so a QPACK stream that
    /// arrived behind it is still queued when the application starts accepting
    /// WebTransport streams. RFC 9114 section 6.2.1 and RFC 9204 section 4.2 make
    /// those streams critical — they must not be closed — so the accept path
    /// retains them and waits on.
    ///
    /// Every other HTTP/3 stream type is one this runtime does not serve. RFC
    /// 9114 section 6.2 requires an *unknown* one be discarded rather than
    /// reported: a recipient of an unknown stream type "MUST NOT consider [it] to
    /// be a connection error of any kind", and section 6.2.3 reserves the
    /// `0x1f * N + 0x21` range precisely so peers may send such streams. A type
    /// HTTP/3 itself defines — the push stream — is not unknown, so it is
    /// reported instead of being mistaken for one, and bytes that do not begin
    /// with a decodable stream type are reported because no HTTP/3 stream grammar
    /// admits them.
    ///
    /// - Note: internal, not fileprivate, because the session file classifies an unprefixed
    ///   stream with this.
    internal static func classifyPeerUnprefixedUnidirectionalStream(
        _ stream: QUIC.Stream<QUICStream>,
        firstBytes: Data,
        in inboundStreams: InteroperableQUICInboundStreamCollector
    ) async throws -> PeerStreamClassification {
        guard let prefix = try? HTTP3StreamTypeParser.parsePrefix(firstBytes) else {
            return .malformed
        }
        switch prefix.type {
        case HTTP3StreamType.control, HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
            try await retainPeerCriticalStreamOrThrow(stream, type: prefix.type, in: inboundStreams)
            Task {
                await drainPeerCriticalStream(stream)
            }
            return .retained
        case HTTP3StreamType.push:
            InteroperableQUICDebug.log(
                "reporting peer push stream \(stream.streamID): this runtime does not serve server push"
            )
            return .unserved
        default:
            InteroperableQUICDebug.log(
                "ignoring peer unidirectional stream \(stream.streamID) of type \(prefix.type)"
            )
            return .ignored
        }
    }

    // internal, not fileprivate: the client and server files both read the peer's control stream here.
    internal static func readPeerControlStream(
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
                try await retainPeerCriticalStreamOrThrow(stream, type: prefix.type, in: inboundStreams)
                return bytes
            case HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
                InteroperableQUICDebug.log("\(role) ignoring peer QPACK stream type=\(prefix.type)")
                try await retainPeerCriticalStreamOrThrow(stream, type: prefix.type, in: inboundStreams)
                Task {
                    await drainPeerCriticalStream(stream)
                }
                continue
            case HTTP3StreamType.push:
                // HTTP/3 defines the push stream, so it is not an unknown type
                // that RFC 9114 section 6.2 protects; this runtime never
                // negotiates push, and a server push stream arriving before the
                // peer's control stream is reported rather than discarded.
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            default:
                // RFC 9114 section 6.2: an unknown or reserved stream type is
                // discarded rather than reported as a connection error. Only the
                // peer's control stream ends this wait.
                InteroperableQUICDebug.log(
                    "\(role) ignoring peer unidirectional stream type=\(prefix.type) while waiting for control"
                )
                continue
            }
        }
    }
}

extension InteroperableQUICHelpers {
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
}
