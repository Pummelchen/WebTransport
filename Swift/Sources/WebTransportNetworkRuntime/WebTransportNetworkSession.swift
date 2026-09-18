// The WebTransport session and the stream handles it hands out over one QUIC
// connection.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

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
                try manager.receiveAndPopStreamPayload(streamID: self.streamID, payload: payload)
            }
        }
        return payload
    }
}

/// A peer-initiated unidirectional WebTransport stream, accepted from the wire.
///
/// RFC 9000 section 2.1 gives a unidirectional stream to its initiator only, so a
/// stream the peer initiated is receive-only here: this type has no send method,
/// and the session manager refuses a send-side call on the same stream (see
/// `WebTransportSessionManager.sendStreamPayload`). That is the difference from
/// ``WebTransportNetworkBidirectionalStream``, which owns both halves. No abort
/// operation is exposed either: the only signal the receive half could produce is
/// STOP_SENDING, and Network.framework offers no per-stream STOP_SENDING.
public final class WebTransportNetworkUnidirectionalStream: Sendable {
    public let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let state: WebTransportNetworkStreamState
    private let manager: WebTransportNetworkSessionManagerState?

    fileprivate init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        initialPayload: Data = Data(),
        manager: WebTransportNetworkSessionManagerState? = nil
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.state = WebTransportNetworkStreamState(prefix: nil, initialPayload: initialPayload)
        self.manager = manager
    }

    /// Reads the next bytes of the peer's stream.
    ///
    /// The arguments and the buffered-first-chunk behaviour mirror
    /// ``WebTransportNetworkBidirectionalStream/receive(maximumBytes:timeoutMilliseconds:)``;
    /// only the send half is absent.
    public func receive(
        maximumBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
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
                try manager.receiveAndPopStreamPayload(streamID: self.streamID, payload: payload)
            }
        }
        return payload
    }
}

/// Test-support handle for a peer-side unidirectional stream.
///
/// The shipped runtime accepts peer-initiated unidirectional streams
/// (``WebTransportNetworkSession/acceptUnidirectionalStream(maximumInitialBytes:timeoutMilliseconds:)``)
/// but does not open them, so a loopback test that needs a peer to initiate one
/// has no producer. This retains the local QUIC stream for as long as the
/// receiver is reading it — releasing the last handle would let the transport
/// cancel the receive side before the bytes arrive — and writes the WebTransport
/// unidirectional prefix once, before the first payload.
///
/// Internal on purpose: opening a unidirectional stream is not part of the
/// shipped surface, and the finding this supports is about accepting one.
final class UnidirectionalStreamProducer: Sendable {
    let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let state: WebTransportNetworkStreamState

    fileprivate init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        prefix: Data
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.state = WebTransportNetworkStreamState(prefix: prefix, initialPayload: Data())
    }

    /// Sends `data`, writing the WebTransport stream prefix first on the first
    /// call so the peer's `acceptUnidirectionalStream` sees a prefixed stream.
    func send(
        _ data: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        var payload = Data()
        if let prefix = await state.consumeOutboundPrefix() {
            payload.append(prefix)
        }
        payload.append(data)
        let outbound = payload
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.stream.send(outbound, endOfStream: endOfStream)
        }
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
    /// The QUIC connection this session runs on.
    ///
    /// `internal` rather than `private` so the resource behaviour of a session's end is observable: the
    /// framework declares no `cancel()` for a started `NetworkConnection`, so whether closing a session
    /// releases its connection — and whether the peer sees that — can only be settled by looking at the
    /// connection underneath. `WebTransportConnectionReleaseTests` does exactly that (WT-85).
    internal var underlyingConnection: NetworkConnection<QUIC> { connection }
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

    // internal, not fileprivate: the client and server files both build a session here.
    internal init(
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
        // The peer's close ends this CONNECTION, because it serves one session: the capsule that says so has
        // arrived, nothing is in flight towards the peer, and cancelling the inbound task is what closes the
        // socket — measured, the peer's connection fails within 50 ms of it (`WebTransportConnectionReleaseTests`,
        // WT-85). The closure captures the two resources rather than `self`, which is not fully initialized where
        // this task is created, and the reader task itself is already returning at the points that call it.
        let releaseConnection: @Sendable () -> Void = { [inboundTask, lease] in
            inboundTask.cancel()
            lease?.release()
        }
        self.connectCapsuleTask = Task {
            await Self.receiveConnectCapsules(
                from: connectStream,
                manager: managerState,
                streamID: sessionID.rawValue,
                initialBytes: initialConnectCapsuleBytes,
                releaseConnection: releaseConnection
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
        // The prefix is classified before the session manager sees the bytes. A
        // stream for another session must not be registered or buffered for a
        // session this connection never serves: the manager's server role has to
        // buffer a stream whose CONNECT may still be in flight, so it cannot tell
        // that case from a foreign one, but this runtime serves exactly one
        // session and can.
        if let foreignSessionID = InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: firstChunk,
            expectedSessionID: sessionID
        ) {
            stream.streamApplicationErrorCode = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
            InteroperableQUICDebug.log(
                "refusing inbound stream \(stream.streamID): prefix names session \(foreignSessionID), "
                    + "this connection serves \(sessionID)"
            )
            throw WebTransportDraft16Error(
                kind: .sessionGone,
                message: "WebTransport inbound stream names session \(foreignSessionID), not \(sessionID)"
            )
        }
        let accepted = try await manager.withManager { manager in
            try manager.acceptBidirectionalStreamWithActions(
                streamID: stream.streamID,
                firstBytes: firstChunk
            )
        }
        guard let prefix = accepted.prefix, accepted.rejectionFrame == nil else {
            // The manager refused the stream — a buffered-ingress limit or an
            // over-long initial payload — and returned the reset frame the peer
            // must observe. The runtime resets through the framework's stream
            // error code rather than by writing a frame, so name the refusal code
            // and let go of the handle instead of dropping the stream silently.
            stream.streamApplicationErrorCode =
                WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError
            throw WebTransportDraft16Error(
                kind: .bufferedStreamRejected,
                message: "WebTransport inbound stream was refused by the session manager"
            )
        }
        guard prefix.form == .bidirectional, prefix.sessionID.rawValue == sessionID else {
            stream.streamApplicationErrorCode = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
            throw WebTransportDraft16Error(
                kind: .sessionGone,
                message: "WebTransport inbound stream names session \(prefix.sessionID.rawValue), not \(sessionID)"
            )
        }
        return WebTransportNetworkBidirectionalStream(
            stream: stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            initialPayload: prefix.remainingPayload,
            manager: manager
        )
    }

    /// Accepts a peer-initiated unidirectional stream and returns it receive-only.
    ///
    /// The runtime serves exactly one WebTransport session per connection (see
    /// `validateSessionAdmission`), so the demultiplex is by direction plus the
    /// session ID in the stream prefix: a unidirectional stream whose prefix names
    /// this session is delivered here, and one whose prefix names any other
    /// session is refused with `WT_SESSION_GONE` before the session manager can
    /// register or buffer it. There is no multi-session routing on this
    /// connection and none is invented.
    ///
    /// The returned stream has no send half: RFC 9000 section 2.1 gives a
    /// unidirectional stream to the endpoint that initiated it, which here is the
    /// peer. A caller that needs to send must open its own unidirectional stream.
    ///
    /// The peer must have been granted `initialMaxUnidirectionalStreams`: the QUIC
    /// transport enforces that advertisement, and a stream beyond the runtime's
    /// per-direction inbound ceiling is refused with `WT_BUFFERED_STREAM_REJECTED`
    /// (F-swift-line-security-03).
    public func acceptUnidirectionalStream(
        maximumInitialBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> WebTransportNetworkUnidirectionalStream {
        let timeout = overrideTimeoutMilliseconds ?? timeoutMilliseconds
        let started = Date()
        while true {
            let stream = try await inboundStreams.next(
                direction: InteroperableQUICHelpers.unidirectionalStreamDirection,
                timeoutMilliseconds: InteroperableQUICHelpers.remainingTimeout(
                    timeoutMilliseconds: timeout,
                    started: started
                )
            )
            // The budget is the caller's whole wait, so the second await in an
            // iteration gets only what the first one left. Recomputing it here
            // rather than reusing a value captured before `next` is what keeps
            // one iteration — and each critical stream it retains — from
            // spending the deadline twice.
            let firstChunk = try await InteroperableQUICHelpers.readFirstChunk(
                stream,
                timeoutMilliseconds: InteroperableQUICHelpers.remainingTimeout(
                    timeoutMilliseconds: timeout,
                    started: started
                ),
                maxBytes: maximumInitialBytes
            )
            // The peer's HTTP/3 control and QPACK streams share the
            // unidirectional direction with WebTransport streams, and
            // establishment returns as soon as it reads the control stream, so a
            // QPACK stream that arrived behind it is still queued here. Those
            // streams are critical and must not be closed, so they are retained;
            // an unknown HTTP/3 stream type is discarded under RFC 9114 section
            // 6.2. Either outcome leaves the wait for a WebTransport stream
            // running.
            guard WebTransportStreamSignaling.hasStreamPrefix(firstChunk) else {
                switch try await InteroperableQUICHelpers.classifyPeerUnprefixedUnidirectionalStream(
                    stream,
                    firstBytes: firstChunk,
                    in: inboundStreams
                ) {
                case .retained, .ignored:
                    continue
                case .unserved, .malformed:
                    throw WebTransportNetworkRuntimeError.unexpectedFrame
                }
            }
            if let foreignSessionID = InteroperableQUICHelpers.foreignSessionID(
                inPrefixedStream: firstChunk,
                expectedSessionID: sessionID,
                form: .unidirectional
            ) {
                stream.streamApplicationErrorCode = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
                InteroperableQUICDebug.log(
                    "refusing inbound unidirectional stream \(stream.streamID): prefix names session "
                        + "\(foreignSessionID), this connection serves \(sessionID)"
                )
                throw WebTransportDraft16Error(
                    kind: .sessionGone,
                    message: "WebTransport inbound stream names session \(foreignSessionID), not \(sessionID)"
                )
            }
            let accepted = try await manager.withManager { manager in
                try manager.acceptUnidirectionalStreamWithActions(
                    streamID: stream.streamID,
                    firstBytes: firstChunk
                )
            }
            guard let prefix = accepted.prefix, accepted.rejectionFrame == nil else {
                stream.streamApplicationErrorCode =
                    WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError
                throw WebTransportDraft16Error(
                    kind: .bufferedStreamRejected,
                    message: "WebTransport inbound unidirectional stream was refused by the session manager"
                )
            }
            guard prefix.form == .unidirectional, prefix.sessionID.rawValue == sessionID else {
                stream.streamApplicationErrorCode = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
                throw WebTransportDraft16Error(
                    kind: .sessionGone,
                    message: "WebTransport inbound stream names session \(prefix.sessionID.rawValue), not \(sessionID)"
                )
            }
            return WebTransportNetworkUnidirectionalStream(
                stream: stream,
                timeoutMilliseconds: timeout,
                initialPayload: prefix.remainingPayload,
                manager: manager
            )
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

extension WebTransportNetworkSession {

    private static func receiveConnectCapsules(
        from stream: QUIC.Stream<QUICStream>,
        manager: WebTransportNetworkSessionManagerState,
        streamID: UInt64,
        initialBytes: Data,
        releaseConnection: @Sendable () -> Void
    ) async {
        var decoder = InteroperableCONNECTCapsuleDecoder()

        /// Delivers capsules to the session manager in order, returning `true`
        /// when one reset the CONNECT stream and this reader must stop.
        func deliver(_ capsules: [Data]) async throws -> Bool {
            for capsule in capsules {
                let result = try await manager.withManager { manager in
                    try manager.receiveConnectStreamCapsulesWithActions(
                        streamID: streamID,
                        bytes: capsule
                    )
                }
                if result.connectResetFrame != nil {
                    stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
                    try? await stream.send(Data(), endOfStream: true)
                    // The peer closed the session (this is the frame its WT_CLOSE_SESSION capsule produces), so
                    // there is nothing left for this connection to carry.
                    releaseConnection()
                    return true
                }
            }
            return false
        }

        do {
            if try await deliver(try decoder.append(initialBytes)) {
                return
            }
            while !Task.isCancelled {
                let received = try await stream.receive(atMost: 8_192)
                if try await deliver(try decoder.append(received.content)) {
                    return
                }
                if received.metadata.endOfStream {
                    if decoder.hasPendingBytes {
                        // Bytes that never completed a frame or a capsule: the
                        // peer ended the stream mid-unit, which is a truncation
                        // rather than the orderly close a bare FIN is.
                        stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
                        try? await stream.send(Data(), endOfStream: true)
                    } else {
                        _ = try? await manager.withManager { manager in
                            try manager.finishConnectStream(streamID: streamID)
                        }
                        // The peer ended the CONNECT stream, which ends the session (draft-16 section 4.4), so the
                        // connection has no further use either.
                        releaseConnection()
                    }
                    return
                }
            }
        } catch is CancellationError {
            return
        } catch {
            // draft-ietf-webtrans-http3-16 section 5.6.2 names the code for a
            // flow-control violation. The session manager has already closed the
            // session with it by the time this catches, so the CONNECT stream is
            // reset with the same code rather than a generic H3_MESSAGE_ERROR:
            // otherwise the peer cannot tell a malformed capsule from an
            // over-limit flow-control value, and the code the draft requires it
            // close the session with never reaches it.
            if let draft16Error = error as? WebTransportDraft16Error,
                draft16Error.kind == .flowControl
            {
                stream.streamApplicationErrorCode =
                    WebTransportHTTP3DraftConstants.current.wtFlowControlError
            } else {
                stream.streamApplicationErrorCode = HTTP3ApplicationErrorCode.messageError.rawValue
            }
            try? await stream.send(Data(), endOfStream: true)
        }
    }
}

extension WebTransportNetworkSession {
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
        // The datagram has already left the connection-scoped channel and cannot
        // be put back, so the session it names is checked before the manager can
        // retain its payload for a session this connection does not serve. The
        // runtime serves exactly one session per connection (see
        // `validateSessionAdmission`), so a datagram naming a different session is
        // a peer error — not an invalid payload — and must be named as such.
        if let foreignSessionID = try InteroperableQUICHelpers.foreignDatagramSessionID(
            inDatagram: receivedDatagram,
            expectedSessionID: sessionID
        ) {
            InteroperableQUICDebug.log(
                "refusing inbound datagram: prefix names session \(foreignSessionID), "
                    + "this connection serves \(sessionID)"
            )
            throw WebTransportDraft16Error(
                kind: .sessionGone,
                message: "WebTransport datagram names session \(foreignSessionID), not \(sessionID)"
            )
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
}

extension WebTransportNetworkSession {
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
        if await sessionIsClosed() {
            InteroperableQUICDebug.log("session drain ignored: session is already closed")
            return
        }
        let capsule = try await manager.withManager { manager in
            try manager.makeDrainSessionCapsule(sessionID: WebTransportSessionID(rawValue: self.sessionID))
        }
        // The capsule travels in an HTTP/3 DATA frame, not as bare bytes: see
        // `InteroperableCONNECTCapsuleFraming` for the RFC and peer evidence.
        let frame = try InteroperableCONNECTCapsuleFraming.wrap(capsule)
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connectStream.send(frame, endOfStream: false)
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
        if await sessionIsClosed() {
            InteroperableQUICDebug.log("session close ignored: session is already closed")
            return
        }
        let capsule = try await manager.withManager { manager in
            try manager.makeCloseSessionCapsule(
                sessionID: WebTransportSessionID(rawValue: self.sessionID),
                applicationErrorCode: applicationErrorCode,
                message: reason
            )
        }
        // The capsule travels in an HTTP/3 DATA frame: see
        // `InteroperableCONNECTCapsuleFraming`.
        let frame = try InteroperableCONNECTCapsuleFraming.wrap(capsule)
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.connectStream.send(frame, endOfStream: true)
        }
    }

    /// Whether the session manager has already terminated this session.
    ///
    /// The manager treats a second close/drain as a no-op and still returns the
    /// capsule, but writing that capsule a second time would put a duplicate
    /// WT_CLOSE_SESSION on a CONNECT stream that is already finishing. Checking
    /// here keeps the public teardown a true no-op, which is what an application
    /// that closes on an error path and again in a `defer` relies on.
    private func sessionIsClosed() async -> Bool {
        await manager.withManager { manager in
            if case .closed = manager.sessionsByID[WebTransportSessionID(rawValue: self.sessionID)]?.state {
                return true
            }
            return false
        }
    }

    // internal, not fileprivate: the server file drives this wait on an accepted session.
    internal func waitForPeerClosure(timeoutMilliseconds: Int32) async {
        // The manager resumes this wait from its mutation path when the session
        // reaches `.closed`. The timeout is the caller's whole budget, not a poll
        // interval: the old loop took the manager actor and read the state every
        // 5 ms (up to 50 hops per call) to notice something the close path could
        // simply signal.
        await manager.waitForSessionClosure(
            sessionID: sessionID,
            timeoutMilliseconds: timeoutMilliseconds
        )
        if await sessionIsClosed() {
            // The peer ended the session, so this connection is no longer the
            // runtime's to serve even if the application still holds the object.
            lease?.release()
        }
    }
}

extension WebTransportNetworkSession {
    func openUnidirectionalStreamForTesting(
        writingSessionID sessionID: UInt64? = nil,
        firstPayload: Data = Data(),
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> UnidirectionalStreamProducer {
        let timeout = overrideTimeoutMilliseconds ?? timeoutMilliseconds
        let stream = try await InteroperableQUICHelpers.withTimeout(timeout) {
            try await self.connection.openStream(directionality: .unidirectional)
        }
        let targetSessionID = sessionID ?? self.sessionID
        let prefix: Data
        if targetSessionID == self.sessionID {
            prefix = try await manager.withManager { manager in
                try manager.openUnidirectionalStream(
                    streamID: stream.streamID,
                    sessionID: WebTransportSessionID(rawValue: self.sessionID)
                )
            }
        } else {
            prefix = try WebTransportStreamSignaling.serializeUnidirectionalPrefix(
                sessionID: targetSessionID
            )
        }
        let producer = UnidirectionalStreamProducer(
            stream: stream,
            timeoutMilliseconds: timeout,
            prefix: prefix
        )
        if !firstPayload.isEmpty || endOfStream {
            try await producer.send(firstPayload, endOfStream: endOfStream)
        }
        return producer
    }

    /// Test support: opens a locally initiated unidirectional stream and writes
    /// `firstPayload` verbatim, with no WebTransport prefix in front of it.
    ///
    /// HTTP/3 stream types and WebTransport streams share the unidirectional
    /// direction (RFC 9114 section 6.2; draft-ietf-webtrans-http3-16 section 4.4),
    /// so a peer can open a stream this runtime does not serve. The shipped
    /// surface never produces one, which leaves a loopback test no way to make a
    /// peer do it; this helper does, so the runtime's classification of an
    /// unknown or critical HTTP/3 stream type can be exercised end to end.
    func openUnframedUnidirectionalStreamForTesting(
        firstPayload: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> UnidirectionalStreamProducer {
        let timeout = overrideTimeoutMilliseconds ?? timeoutMilliseconds
        let stream = try await InteroperableQUICHelpers.withTimeout(timeout) {
            try await self.connection.openStream(directionality: .unidirectional)
        }
        let producer = UnidirectionalStreamProducer(
            stream: stream,
            timeoutMilliseconds: timeout,
            prefix: Data()
        )
        if !firstPayload.isEmpty || endOfStream {
            try await producer.send(firstPayload, endOfStream: endOfStream)
        }
        return producer
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
        // The base addresses are guarded rather than force-unwrapped. The label always
        // carries its terminator and the context is substituted with one byte when empty, so
        // nil is unreachable today -- but "unreachable" is exactly what `!` asserts, and it
        // is what a future edit can falsify silently. `flatMap` keeps both pointers optional
        // through to the call, and a nil flows into the existing `guard let exported` below,
        // which already reports `exporterUnavailable`.
        let exported = labelBytes.withUnsafeBufferPointer { labelBuffer in
            unsafe labelBuffer.baseAddress.flatMap { labelPointer in
                contextBytes.withUnsafeBufferPointer { contextBuffer in
                    unsafe contextBuffer.baseAddress.flatMap { contextPointer in
                        unsafe sec_protocol_metadata_create_secret_with_context(
                            connection.securityProtocolMetadata,
                            labelBytes.count - 1,
                            labelPointer,
                            context.count,
                            contextPointer,
                            outputByteCount
                        )
                    }
                }
            }
        }
        guard let exported else {
            throw WebTransportNetworkRuntimeError.exporterUnavailable
        }
        return Data(exported as DispatchData)
    }
}
