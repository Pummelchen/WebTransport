import Foundation
import WebTransportQUICCore

private struct WebTransportSessionRejection: Equatable, Sendable {
    var status: UInt16
    var error: WebTransportDraft16Error
}

public struct WebTransportSessionManager: Equatable, Sendable {
    /// Builds an HTTP/3 GOAWAY frame and records that this endpoint sent it.
    ///
    /// Exposed here rather than reaching into ``http3`` directly so the sent
    /// GOAWAY identifier is tracked on the live connection state. Building the
    /// frame from a copy would emit correct bytes but leave this endpoint unable
    /// to reject the requests it just promised not to serve.
    ///
    /// `streamID` is the first client-initiated bidirectional stream the server
    /// will *not* process, per RFC 9114 section 5.2.
    public mutating func makeGoawayFrame(streamID: UInt64) throws -> HTTP3Frame {
        try http3.makeGoawayFrame(streamID: streamID)
    }

    public private(set) var http3: HTTP3ConnectionState
    public private(set) var sessionsByID: [WebTransportSessionID: WebTransportSession]
    public private(set) var sessionIDsByRequestStreamID: [UInt64: WebTransportSessionID]
    public private(set) var streamsByID: [UInt64: WebTransportStreamState]
    public private(set) var streamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public private(set) var bufferedStreamsByID: [UInt64: WebTransportStreamState]
    public private(set) var bufferedStreamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public private(set) var datagramsBySessionID: [WebTransportSessionID: [Data]]
    public private(set) var flowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public private(set) var receiveFlowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public private(set) var blockedFlowCapsulesBySessionID: [WebTransportSessionID: [WebTransportFlowCapsule]]
    /// Largest DATAGRAM this endpoint will accept, matching what the QUIC layer
    /// advertised to the peer. Enforcing a smaller number here rejects peers that
    /// are honouring exactly what we told them they could send.
    public let maxDatagramFrameSize: Int
    /// Largest DATAGRAM this endpoint will attempt to send.
    ///
    /// Defaults to `min(maxDatagramFrameSize, 1200)`, which encodes two rules:
    /// never send more than this endpoint would itself accept, and never exceed
    /// the 1200 bytes a QUIC path is guaranteed to carry (RFC 9000 section 14).
    ///
    /// It is separate from the receive ceiling because the two are not the same
    /// question. A peer may legitimately advertise a large receive limit, but a
    /// QUIC DATAGRAM cannot be fragmented, so anything above the path MTU is
    /// silently undeliverable. Bounding sends turns that silent loss into an
    /// immediate, explicit error.
    public let maxSendableDatagramFrameSize: Int
    public let maxDatagramReceiveBufferBytes: Int
    public let maxStreamReceiveBufferBytes: Int
    public let maxBufferedStreamsPerSession: Int
    public let maxBufferedDatagramsPerSession: Int
    public let maxBufferedSessions: Int
    public let settingsValidation: HTTP3WebTransportSettingsValidation
    /// How many terminated sessions keep their tombstone.
    ///
    /// A terminated session is retained so that late activity on it reports
    /// "session gone" rather than "unknown", which is a materially better error.
    /// The retention has to be bounded, though: the tombstone holds the peer's
    /// own authority and path strings, a CONNECT field section may be up to
    /// 16 KB, and a peer can open and close sessions on one connection
    /// indefinitely. Unbounded retention is remotely triggerable memory growth.
    ///
    /// Beyond this many, the oldest tombstone is dropped and activity on it
    /// degrades to "unknown session", which is a safe answer.
    public let maxRetainedClosedSessions: Int
    /// How many terminated streams keep their tombstone, for the same reason.
    public let maxRetainedClosedStreams: Int

    private var datagramPayloadBytesBySessionID: [WebTransportSessionID: Int]
    private var closedStreamSessionIDsByStreamID: [UInt64: WebTransportSessionID]
    private var requestStreamIDsClosedByReceivedCloseCapsule: Set<UInt64>
    /// Tombstone insertion order, oldest first, so eviction is deterministic.
    private var closedSessionOrder: [WebTransportSessionID]
    private var closedStreamOrder: [UInt64]
    /// How many leading entries of ``closedStreamOrder`` have been evicted.
    private var closedStreamHead: Int
    /// Membership for the tombstones still retained, so a duplicate close is
    /// recognised without scanning ``closedStreamOrder``.
    private var retainedClosedStreamIDs: Set<UInt64>

    /// How many elements ``recordClosedStream(_:)`` moved while evicting.
    ///
    /// A cost probe for the regression test in `WebTransportSessionTests`: a
    /// stream close must not shift the whole retention window.
    private(set) var closedStreamTombstoneMoves = 0

    /// How many stream tombstones are retained, as distinct from the storage they
    /// occupy.
    var retainedClosedStreamCount: Int {
        closedStreamOrder.count - closedStreamHead
    }

    public init(
        http3: HTTP3ConnectionState,
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxDatagramFrameSize: Int = 1_200,
        maxSendableDatagramFrameSize: Int? = nil,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedDatagramsPerSession: Int = 64,
        maxBufferedSessions: Int = 64,
        maxRetainedClosedSessions: Int = 256,
        maxRetainedClosedStreams: Int = 4_096,
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict
    ) {
        self.http3 = http3
        self.sessionsByID = [:]
        self.sessionIDsByRequestStreamID = [:]
        self.streamsByID = [:]
        self.streamIDsBySessionID = [:]
        self.bufferedStreamsByID = [:]
        self.bufferedStreamIDsBySessionID = [:]
        self.datagramsBySessionID = [:]
        self.flowControlStateBySessionID = [:]
        self.receiveFlowControlStateBySessionID = [:]
        self.blockedFlowCapsulesBySessionID = [:]
        self.maxDatagramFrameSize = maxDatagramFrameSize
        self.maxSendableDatagramFrameSize =
            maxSendableDatagramFrameSize
            ?? min(maxDatagramFrameSize, 1_200)
        self.maxDatagramReceiveBufferBytes = maxDatagramReceiveBufferBytes
        self.maxStreamReceiveBufferBytes = maxStreamReceiveBufferBytes
        self.maxBufferedStreamsPerSession = maxBufferedStreamsPerSession
        self.maxBufferedDatagramsPerSession = maxBufferedDatagramsPerSession
        self.maxBufferedSessions = maxBufferedSessions
        self.settingsValidation = settingsValidation
        self.maxRetainedClosedSessions = max(0, maxRetainedClosedSessions)
        self.maxRetainedClosedStreams = max(0, maxRetainedClosedStreams)
        self.datagramPayloadBytesBySessionID = [:]
        self.closedStreamSessionIDsByStreamID = [:]
        self.requestStreamIDsClosedByReceivedCloseCapsule = []
        self.closedSessionOrder = []
        self.closedStreamOrder = []
        self.closedStreamHead = 0
        self.retainedClosedStreamIDs = []
    }

    public mutating func makeClientSessionRequest(
        streamID: UInt64,
        request: WebTransportSessionRequest,
        isZeroRTT: Bool = false
    ) throws -> HTTP3Frame {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients create WebTransport CONNECT requests")
        }
        try validateSettingsReady()
        guard !isZeroRTT else {
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport CONNECT requests are not allowed on 0-RTT"
            )
        }
        try validateRequestAllowedByGoaway(streamID)

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }
        try validateSessionAdmission()

        var requestStream = try http3.openRequestStream(streamID: streamID)
        let frame = try requestStream.makeRequestHeadersFrame(
            request.headers(upgradeToken: settingsValidation.upgradeToken),
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
        http3.storeRequestStream(requestStream)
        let session = WebTransportSession(
            id: sessionID,
            requestStreamID: streamID,
            authority: request.authority,
            path: request.path,
            origin: request.origin,
            availableProtocols: request.availableProtocols,
            selectedProtocol: nil,
            state: .requested
        )
        store(session)
        return frame
    }

    public mutating func receiveServerSessionResponse(
        streamID: UInt64,
        frame: HTTP3Frame
    ) throws -> WebTransportSession {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients receive WebTransport CONNECT responses")
        }
        try validateSettingsReady()
        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard var session = sessionsByID[sessionID] else {
            throw QUICCodecError.malformed("unknown WebTransport session")
        }
        var requestStream = http3.requestStreams[streamID] ?? HTTP3RequestStream(streamID: streamID, role: .client)
        let fields = try QPACK.decodeHeadersFrame(frame)
        let status = try WebTransportSessionHeaders.status(from: fields)
        if (200..<300).contains(status) {
            try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
            let selectedProtocol = try WebTransportSessionHeaders.selectedProtocol(from: fields)
            if let selectedProtocol {
                try WebTransportProtocolNegotiation.validate([selectedProtocol])
                guard session.availableProtocols.contains(selectedProtocol) else {
                    throw WebTransportDraft16Error(
                        kind: .alpn,
                        message: "server selected a WebTransport protocol the client did not offer"
                    )
                }
            }
            session.selectedProtocol = selectedProtocol
            session.state = .accepted
            try requestStream.receive(frame: frame)
        } else {
            session.state = .rejected(status: status)
        }

        http3.storeRequestStream(requestStream)
        store(session)
        if session.state == .accepted {
            try promoteBufferedStreams(for: session.id)
        } else {
            discardBufferedIngress(for: session.id, tombstoneStreams: true)
            // A rejected session is terminal, so it becomes a bounded tombstone
            // rather than being retained for the life of the connection.
            recordClosedSession(session.id)
        }
        return session
    }

    public mutating func receivePeerControlStream(_ bytes: Data) throws -> [HTTP3Frame] {
        // Forward this manager's profile rather than letting the underlying
        // parameter default to draft16Strict. Omitting it made a manager
        // configured for an earlier revision validate the peer's SETTINGS
        // strictly anyway, which rejects the peers that profile exists to
        // accept — browsers in particular, since they do not send
        // SETTINGS_WT_ENABLE_WEBTRANSPORT.
        try http3.receivePeerControlStream(bytes, settingsValidation: settingsValidation)
    }

    public mutating func receiveClientSessionRequest(
        streamID: UInt64,
        frame: HTTP3Frame,
        policy: WebTransportServerSessionPolicy
    ) throws -> WebTransportServerSessionDecision {
        guard http3.role == .server else {
            throw QUICCodecError.malformed("only servers receive WebTransport CONNECT requests")
        }
        try validateSettingsReady()
        try validateRequestAllowedByGoaway(streamID)

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }
        try validateSessionAdmission()
        guard frame.type == HTTP3FrameType.headers else {
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport CONNECT stream must start with HEADERS"
            )
        }

        var requestStream = try http3.acceptRequestStream(streamID: streamID)
        try requestStream.receive(
            frame: frame,
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
        http3.storeRequestStream(requestStream)

        let fields = try QPACK.decodeHeadersFrame(frame)
        let request = try WebTransportSessionHeaders.request(
            from: fields,
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
        let selectedProtocol = try WebTransportSessionHeaders.selectProtocol(
            requestProtocols: request.availableProtocols,
            policy: policy
        )

        let rejection = rejection(for: request, selectedProtocol: selectedProtocol, policy: policy)
        let state: WebTransportSessionState
        let responseFrame: HTTP3Frame
        if let rejection {
            state = .rejected(status: rejection.status)
            responseFrame = try WebTransportSessionHeaders.responseFrame(status: rejection.status)
        } else {
            state = .accepted
            responseFrame = try WebTransportSessionHeaders.responseFrame(
                status: 200,
                selectedProtocol: selectedProtocol
            )
        }

        let session = WebTransportSession(
            id: sessionID,
            requestStreamID: streamID,
            authority: request.authority,
            path: request.path,
            origin: request.origin,
            availableProtocols: request.availableProtocols,
            selectedProtocol: selectedProtocol,
            state: state
        )
        store(session)
        if session.state == .accepted {
            try promoteBufferedStreams(for: session.id)
        } else {
            discardBufferedIngress(for: session.id, tombstoneStreams: true)
            recordClosedSession(session.id)
        }
        return WebTransportServerSessionDecision(
            session: session,
            responseFrame: responseFrame,
            rejectionError: rejection?.error
        )
    }

    public mutating func makeDatagramFrame(
        sessionID: WebTransportSessionID,
        payload: Data
    ) throws -> QUICFrame {
        try validateSettingsReady()
        _ = try writableSession(for: sessionID)

        let datagramPayload = try WebTransportDatagramSignaling.serialize(
            sessionID: sessionID.rawValue,
            payload: payload
        )
        guard datagramPayload.count <= maxSendableDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds the sendable frame size of \(maxSendableDatagramFrameSize)"
            )
        }
        return .datagram(datagramPayload)
    }

    public mutating func receiveDatagramFrame(_ frame: QUICFrame) throws -> WebTransportSessionID {
        try validateSettingsReady()
        guard case .datagram(let payload) = frame else {
            throw QUICCodecError.malformed("expected DATAGRAM frame")
        }
        guard payload.count <= maxDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds maximum frame size of \(maxDatagramFrameSize)"
            )
        }
        let parsed: WebTransportDatagramPrefix
        do {
            parsed = try WebTransportDatagramSignaling.parse(payload)
        } catch {
            throw WebTransportDraft16Error(kind: .h3ID, message: "invalid WebTransport datagram session ID")
        }
        let session = try sessionForIngressOrPending(parsed.sessionID)
        let currentBytes = datagramPayloadBytesBySessionID[parsed.sessionID] ?? 0
        let updatedBytes = currentBytes + parsed.payload.count
        guard updatedBytes <= maxDatagramReceiveBufferBytes else {
            if session == nil || session?.state == .requested {
                return parsed.sessionID
            }
            throw QUICCodecError.valueOutOfRange("WebTransport datagram receive buffer limit exceeded")
        }

        var queue = datagramsBySessionID[parsed.sessionID] ?? []
        if session?.state != .accepted && session?.state != .draining {
            try ensureCanBufferIngress(for: parsed.sessionID)
            guard queue.count < maxBufferedDatagramsPerSession else {
                return parsed.sessionID
            }
        }
        queue.append(parsed.payload)
        datagramsBySessionID[parsed.sessionID] = queue
        datagramPayloadBytesBySessionID[parsed.sessionID] = updatedBytes
        return parsed.sessionID
    }

    public mutating func popDatagramPayload(sessionID: WebTransportSessionID) -> Data? {
        guard var queue = datagramsBySessionID[sessionID] else {
            return nil
        }
        guard let payload = queue.first else {
            return nil
        }
        queue.removeFirst()
        datagramsBySessionID[sessionID] = queue.isEmpty ? [] : queue

        let currentBytes = datagramPayloadBytesBySessionID[sessionID] ?? 0
        datagramPayloadBytesBySessionID[sessionID] = max(0, currentBytes - payload.count)
        return payload
    }

    public mutating func receiveControlFrame(_ frame: HTTP3Frame) throws {
        try http3.receiveControlFrame(frame)
        guard frame.type == HTTP3FrameType.goaway else {
            return
        }
        for (sessionID, var session) in sessionsByID where session.state == .accepted {
            session.state = .draining
            sessionsByID[sessionID] = session
        }
    }

    public mutating func receiveFlowControlCapsule(
        sessionID: WebTransportSessionID,
        bytes: Data
    ) throws -> WebTransportFlowCapsule {
        try receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: bytes).capsule
    }

    public mutating func receiveFlowControlCapsuleWithActions(
        sessionID: WebTransportSessionID,
        bytes: Data
    ) throws -> WebTransportReceivedFlowControlCapsule {
        try validateSettingsReady()
        _ = try sessionForIngress(sessionID)
        let capsuleType = try capsuleTypePrefix(bytes)
        if !webTransportFlowControlNegotiated,
            isHTTP3FlowControlCapsuleType(capsuleType)
        {
            let ignored = try ignoredFlowControlCapsuleEnvelope(bytes)
            return WebTransportReceivedFlowControlCapsule(
                capsule: ignored.capsule,
                terminationActions: nil
            )
        }
        let parsed: WebTransportFlowCapsuleEnvelope
        do {
            parsed = try WebTransportFlowCapsuleCodec.parse(bytes)
        } catch let error as WebTransportDraft16Error where error.kind == .flowControl {
            try closeForFlowControlViolation(sessionID)
            throw error
        }
        var terminationActions: WebTransportSessionTerminationActions?

        switch parsed.capsule {
        case .drainSession:
            try markSessionDraining(sessionID)
        case .closeSession(let applicationErrorCode, let message):
            terminationActions = try markSessionClosed(
                sessionID,
                applicationErrorCode: applicationErrorCode,
                message: message,
                closeCapsuleReceived: true
            )
        default:
            break
        }

        var state = flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.apply(parsed.capsule)
        } catch let error as WebTransportDraft16Error where error.kind == .flowControl {
            try closeForFlowControlViolation(sessionID)
            throw error
        }
        flowControlStateBySessionID[sessionID] = state
        return WebTransportReceivedFlowControlCapsule(
            capsule: parsed.capsule,
            terminationActions: terminationActions
        )
    }

    /// Builds the WT_DRAIN_SESSION capsule for a session.
    ///
    /// Draining a session that has already been closed is a no-op: the capsule is
    /// returned without touching state, because a teardown that runs on an error
    /// path and again in a `defer` must not fail the second time. Only a session
    /// that is gone for another reason (rejected, or never established) throws.
    public mutating func makeDrainSessionCapsule(sessionID: WebTransportSessionID) throws -> Data {
        try validateSettingsReady()
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .closed:
            return try WebTransportFlowCapsuleCodec.serialize(.drainSession)
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        case .requested:
            throw QUICCodecError.malformed("WT_DRAIN_SESSION requires an established session")
        case .accepted, .draining:
            try markSessionDraining(sessionID)
            return try WebTransportFlowCapsuleCodec.serialize(.drainSession)
        }
    }

    public mutating func makeCloseSessionCapsule(
        sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String
    ) throws -> Data {
        try makeCloseSessionCapsuleResult(
            sessionID: sessionID,
            applicationErrorCode: applicationErrorCode,
            message: message
        ).capsuleBytes
    }

    /// Builds the WT_CLOSE_SESSION capsule for a session and terminates it.
    ///
    /// Closing a session that is already closed is a no-op: the capsule is
    /// returned without re-running teardown, because an application that closes on
    /// an error path and again in a `defer` must not get a spuriously failing
    /// teardown. Only a session that is gone for another reason (rejected, or
    /// never established) throws.
    public mutating func makeCloseSessionCapsuleResult(
        sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String
    ) throws -> WebTransportCloseSessionCapsuleResult {
        try validateSettingsReady()
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        let capsuleBytes = try WebTransportFlowCapsuleCodec.serialize(
            .closeSession(
                applicationErrorCode: applicationErrorCode,
                message: message
            ))
        switch session.state {
        case .closed:
            // The streams were terminated by the first close, so there is nothing
            // to reset again; only the CONNECT FIN is re-derived, and a duplicate
            // FIN on an already-finishing stream is not a protocol violation.
            return WebTransportCloseSessionCapsuleResult(
                capsuleBytes: capsuleBytes,
                terminationActions: WebTransportSessionTerminationActions(
                    connectFINFrame: .stream(id: session.requestStreamID, offset: nil, fin: true, data: Data()),
                    connectStopSendingFrame: nil,
                    streamResetFrames: [],
                    streamStopSendingFrames: []
                )
            )
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        case .requested, .accepted, .draining:
            let terminationActions = try markSessionClosed(
                sessionID,
                applicationErrorCode: applicationErrorCode,
                message: message,
                closeCapsuleReceived: false
            )
            return WebTransportCloseSessionCapsuleResult(
                capsuleBytes: capsuleBytes,
                terminationActions: terminationActions
            )
        }
    }

    @discardableResult
    public mutating func finishConnectStream(streamID: UInt64) throws -> WebTransportSessionTerminationActions {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport CONNECT stream")
        }
        return try markSessionClosed(
            sessionID,
            applicationErrorCode: 0,
            message: "",
            closeCapsuleReceived: false
        )
    }

    public mutating func receiveConnectStreamData(streamID: UInt64, data: Data) throws -> QUICFrame? {
        guard !data.isEmpty else {
            return nil
        }
        return try receiveConnectStreamCapsulesWithActions(streamID: streamID, bytes: data).connectResetFrame
    }

    public mutating func receiveConnectStreamCapsulesWithActions(
        streamID: UInt64,
        bytes: Data
    ) throws -> WebTransportConnectStreamCapsuleResult {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport CONNECT stream")
        }

        var remaining = bytes
        var received: [WebTransportReceivedFlowControlCapsule] = []
        var terminationActions: WebTransportSessionTerminationActions?
        while !remaining.isEmpty {
            if requestStreamIDsClosedByReceivedCloseCapsule.contains(streamID) {
                return WebTransportConnectStreamCapsuleResult(
                    receivedCapsules: received,
                    connectResetFrame: connectMessageErrorReset(streamID: streamID),
                    terminationActions: terminationActions
                )
            }

            let capsuleType = try capsuleTypePrefix(remaining)
            do {
                let parsed = try WebTransportFlowCapsuleCodec.parse(remaining)
                let result = try receiveFlowControlCapsuleWithActions(
                    sessionID: sessionID,
                    bytes: Data(remaining.prefix(parsed.bytesConsumed))
                )
                received.append(result)
                terminationActions = result.terminationActions ?? terminationActions
                remaining.removeFirst(parsed.bytesConsumed)
            } catch let error as WebTransportDraft16Error where error.kind == .flowControl {
                // draft-ietf-webtrans-http3-16 section 5.6.2: a flow-control
                // capsule whose value exceeds the draft's maximum is a
                // session-level violation, and the session must be closed with
                // WT_FLOW_CONTROL_ERROR. The parse above runs before
                // `receiveFlowControlCapsuleWithActions` can see the capsule, so
                // this entry point has to route the violation to the same close
                // path the direct one uses; otherwise the error reaches the
                // CONNECT-stream reader, which resets the stream with
                // H3_MESSAGE_ERROR while the session stays `accepted` locally.
                try closeForFlowControlViolation(sessionID)
                throw error
            } catch  where capsuleType == WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule {
                let isAlreadyClosed: Bool
                if case .closed = sessionsByID[sessionID]?.state {
                    isAlreadyClosed = true
                } else {
                    isAlreadyClosed = false
                }
                if !isAlreadyClosed {
                    terminationActions = try? markSessionClosed(
                        sessionID,
                        applicationErrorCode: 0,
                        message: "",
                        closeCapsuleReceived: false
                    )
                }
                return WebTransportConnectStreamCapsuleResult(
                    receivedCapsules: received,
                    connectResetFrame: connectMessageErrorReset(streamID: streamID),
                    terminationActions: terminationActions
                )
            }
        }

        return WebTransportConnectStreamCapsuleResult(
            receivedCapsules: received,
            connectResetFrame: nil,
            terminationActions: terminationActions
        )
    }

    public mutating func popFlowControlCapsule(sessionID: WebTransportSessionID) throws -> Data? {
        guard var queue = blockedFlowCapsulesBySessionID[sessionID], let capsule = queue.first else {
            return nil
        }

        queue.removeFirst()
        blockedFlowCapsulesBySessionID[sessionID] = queue.isEmpty ? [] : queue
        return try WebTransportFlowCapsuleCodec.serialize(capsule)
    }

    public mutating func openBidirectionalStream(
        streamID: UInt64,
        sessionID: WebTransportSessionID
    ) throws -> Data {
        try validateSettingsReady()
        let session = try writableSession(for: sessionID)

        try validateStreamIdentity(
            streamID: streamID,
            direction: .bidirectional,
            initiator: expectedLocalInitiator
        )
        try reserveStream(session.id, form: .bidirectional, receiveSide: false)
        let stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: session.id,
            form: .bidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        register(stream)

        return try WebTransportStreamSignaling.serializePrefix(
            form: .bidirectional,
            sessionID: session.id.rawValue
        )
    }

    public mutating func openUnidirectionalStream(
        streamID: UInt64,
        sessionID: WebTransportSessionID
    ) throws -> Data {
        try validateSettingsReady()
        let session = try writableSession(for: sessionID)

        try validateStreamIdentity(
            streamID: streamID,
            direction: .unidirectional,
            initiator: expectedLocalInitiator
        )
        try reserveStream(session.id, form: .unidirectional, receiveSide: false)
        let stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: session.id,
            form: .unidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        register(stream)

        return try WebTransportStreamSignaling.serializePrefix(
            form: .unidirectional,
            sessionID: session.id.rawValue
        )
    }

    public mutating func acceptBidirectionalStream(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportStreamPrefix {
        let result = try acceptBidirectionalStreamWithActions(streamID: streamID, firstBytes: firstBytes)
        if let prefix = result.prefix {
            return prefix
        }
        throw WebTransportDraft16Error(
            kind: .bufferedStreamRejected,
            message: "buffered WebTransport stream exceeds receive limit"
        )
    }

    public mutating func acceptBidirectionalStreamWithActions(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportIncomingStreamResult {
        try validateSettingsReady()

        try validateStreamIdentity(
            streamID: streamID,
            direction: .bidirectional,
            initiator: expectedRemoteInitiator
        )

        let prefix = try WebTransportStreamSignaling.parsePrefix(firstBytes)
        guard prefix.form == .bidirectional else {
            throw QUICCodecError.malformed("invalid form for bidirectional stream accept")
        }
        let session = try sessionForIngressOrPending(prefix.sessionID)
        if session?.state == .accepted || session?.state == .draining {
            try reserveStream(prefix.sessionID, form: .bidirectional, receiveSide: true)
            try reserveData(for: prefix.sessionID, byteCount: prefix.remainingPayload.count, receiveSide: true)
        }

        var stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: prefix.sessionID,
            form: .bidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        do {
            try receiveInitialPayloadIfPresent(prefix.remainingPayload, into: &stream, buffering: session?.state == .requested || session == nil)
        } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
            return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
        }
        if session?.state == .accepted || session?.state == .draining {
            register(stream)
        } else {
            do {
                try buffer(stream)
            } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
                return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
            }
        }
        return WebTransportIncomingStreamResult(prefix: prefix, rejectionFrame: nil)
    }

    public mutating func acceptUnidirectionalStream(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportStreamPrefix {
        let result = try acceptUnidirectionalStreamWithActions(streamID: streamID, firstBytes: firstBytes)
        if let prefix = result.prefix {
            return prefix
        }
        throw WebTransportDraft16Error(
            kind: .bufferedStreamRejected,
            message: "buffered WebTransport stream exceeds receive limit"
        )
    }

    public mutating func acceptUnidirectionalStreamWithActions(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportIncomingStreamResult {
        try validateSettingsReady()

        try validateStreamIdentity(
            streamID: streamID,
            direction: .unidirectional,
            initiator: expectedRemoteInitiator
        )

        let prefix = try WebTransportStreamSignaling.parsePrefix(firstBytes)
        guard prefix.form == .unidirectional else {
            throw QUICCodecError.malformed("invalid form for unidirectional stream accept")
        }
        let session = try sessionForIngressOrPending(prefix.sessionID)
        if session?.state == .accepted || session?.state == .draining {
            try reserveStream(prefix.sessionID, form: .unidirectional, receiveSide: true)
            try reserveData(for: prefix.sessionID, byteCount: prefix.remainingPayload.count, receiveSide: true)
        }

        var stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: prefix.sessionID,
            form: .unidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        do {
            try receiveInitialPayloadIfPresent(prefix.remainingPayload, into: &stream, buffering: session?.state == .requested || session == nil)
        } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
            return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
        }
        if session?.state == .accepted || session?.state == .draining {
            register(stream)
        } else {
            do {
                try buffer(stream)
            } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
                return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
            }
        }
        return WebTransportIncomingStreamResult(prefix: prefix, rejectionFrame: nil)
    }

    public mutating func receiveStreamPayload(streamID: UInt64, payload: Data) throws {
        let sessionID = try payloadDeliverySessionID(streamID: streamID)
        try reserveData(for: sessionID, byteCount: payload.count, receiveSide: true)
        // Mutating through the subscript reaches the value where it is stored. The
        // old `guard var stream = ...` / `streamsByID[streamID] = stream` round trip
        // left the dictionary holding a second reference to the payload array, so
        // every append copied the whole buffer.
        try streamsByID[streamID]?.receivePayload(payload)
    }

    /// Receives `payload` and returns the payload a read should observe next.
    ///
    /// The read path used to call ``receiveStreamPayload(streamID:payload:)`` and
    /// then ``popStreamPayload(streamID:)``, which appended the arrival only to
    /// pop it again through two dictionary mutations. A read that consumes its own
    /// arrival keeps the same accounting (the QUIC offset advances, flow control
    /// is reserved, the buffer ceiling is enforced) without the round trip, and
    /// still returns the oldest pending payload when one is already buffered.
    public mutating func receiveAndPopStreamPayload(streamID: UInt64, payload: Data) throws -> Data {
        let sessionID = try payloadDeliverySessionID(streamID: streamID)
        try reserveData(for: sessionID, byteCount: payload.count, receiveSide: true)
        guard let delivered = try streamsByID[streamID]?.receivePayloadDeliveringImmediately(payload)
        else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        return delivered
    }

    /// Validates that `streamID` names a live stream and that its session still
    /// accepts ingress, returning the session the payload belongs to.
    private func payloadDeliverySessionID(streamID: UInt64) throws -> WebTransportSessionID {
        guard let stream = streamsByID[streamID] else {
            if let sessionID = closedStreamSessionIDsByStreamID[streamID],
                let state = sessionsByID[sessionID]?.state
            {
                switch state {
                case .closed:
                    throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
                case .rejected:
                    throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
                case .requested, .accepted, .draining:
                    break
                }
            }
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        _ = try sessionForIngress(stream.sessionID)
        return stream.sessionID
    }

    public mutating func sendStreamPayload(
        streamID: UInt64,
        payload: Data,
        fin: Bool = false
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        _ = try writableSession(for: stream.sessionID)
        try reserveData(for: stream.sessionID, byteCount: payload.count, receiveSide: false)
        let frame = try stream.sendPayload(payload, fin: fin)
        streamsByID[streamID] = stream
        return frame
    }

    public mutating func popStreamPayload(streamID: UInt64) -> Data? {
        guard streamsByID[streamID] != nil else {
            return nil
        }
        return streamsByID[streamID]?.popPayload()
    }

    public mutating func resetStream(
        streamID: UInt64,
        applicationErrorCode: UInt64
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        // RFC 9000 section 19.4: RESET_STREAM aborts the sender's send half, so a
        // stream whose send half this endpoint does not own (a peer-initiated
        // unidirectional stream) must not carry one. Emitting it anyway is a
        // STREAM_STATE_ERROR at the peer, so refuse it at the API boundary.
        guard stream.hasSendHalf else {
            throw QUICStateError.streamStateViolation(
                "cannot reset a stream half this endpoint does not own")
        }
        let frame = stream.reset(applicationErrorCode: try mapApplicationErrorCode(applicationErrorCode))
        streamsByID[streamID] = stream
        return frame
    }

    public mutating func stopSendingStream(
        streamID: UInt64,
        applicationErrorCode: UInt64
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        // RFC 9000 section 19.5: STOP_SENDING aborts the receive half, so a stream
        // this endpoint only sends on (a locally initiated unidirectional stream)
        // must not carry one, for the same reason as RESET_STREAM above.
        guard stream.hasReceiveHalf else {
            throw QUICStateError.streamStateViolation(
                "cannot stop a stream half this endpoint does not own")
        }
        let frame = stream.stopSending(applicationErrorCode: try mapApplicationErrorCode(applicationErrorCode))
        streamsByID[streamID] = stream
        return frame
    }

    private mutating func store(_ session: WebTransportSession) {
        sessionsByID[session.id] = session
        sessionIDsByRequestStreamID[session.requestStreamID] = session.id
        datagramsBySessionID[session.id] = datagramsBySessionID[session.id] ?? []
        let negotiated = webTransportFlowControlNegotiated
        flowControlStateBySessionID[session.id] =
            flowControlStateBySessionID[session.id]
            ?? WebTransportFlowControlState(
                settings: http3.remoteSettings ?? .webTransportDraft16Defaults,
                isEnabled: negotiated
            )
        receiveFlowControlStateBySessionID[session.id] =
            receiveFlowControlStateBySessionID[session.id]
            ?? WebTransportFlowControlState(settings: http3.localSettings, isEnabled: negotiated)
        datagramPayloadBytesBySessionID[session.id] = datagramPayloadBytesBySessionID[session.id] ?? 0
        blockedFlowCapsulesBySessionID[session.id] = blockedFlowCapsulesBySessionID[session.id] ?? []
    }

    /// Records a terminated session and evicts the oldest beyond the retention
    /// bound, releasing every per-session map keyed by it.
    private mutating func recordClosedSession(_ sessionID: WebTransportSessionID) {
        if let existing = closedSessionOrder.firstIndex(of: sessionID) {
            closedSessionOrder.remove(at: existing)
        }
        closedSessionOrder.append(sessionID)
        while closedSessionOrder.count > maxRetainedClosedSessions {
            let evicted = closedSessionOrder.removeFirst()
            releaseSessionState(evicted)
        }
    }

    /// Drops every trace of a session. Only ever called for a session already
    /// terminated, so nothing live is discarded.
    private mutating func releaseSessionState(_ sessionID: WebTransportSessionID) {
        if let session = sessionsByID.removeValue(forKey: sessionID) {
            sessionIDsByRequestStreamID.removeValue(forKey: session.requestStreamID)
            requestStreamIDsClosedByReceivedCloseCapsule.remove(session.requestStreamID)
        }
        streamIDsBySessionID.removeValue(forKey: sessionID)
        bufferedStreamIDsBySessionID.removeValue(forKey: sessionID)
        datagramsBySessionID.removeValue(forKey: sessionID)
        datagramPayloadBytesBySessionID.removeValue(forKey: sessionID)
        flowControlStateBySessionID.removeValue(forKey: sessionID)
        receiveFlowControlStateBySessionID.removeValue(forKey: sessionID)
        blockedFlowCapsulesBySessionID.removeValue(forKey: sessionID)
    }

    /// Records a terminated stream and evicts the oldest beyond the bound.
    ///
    /// Membership is a set lookup and eviction advances a head index, so neither
    /// costs anything proportional to the retention window. The consumed prefix is
    /// reclaimed in one move once it is at least half the storage, which makes the
    /// reclaim amortised O(1) per recorded close.
    mutating func recordClosedStream(_ streamID: UInt64) {
        guard retainedClosedStreamIDs.insert(streamID).inserted else {
            return
        }
        closedStreamOrder.append(streamID)
        while retainedClosedStreamCount > maxRetainedClosedStreams {
            let evicted = closedStreamOrder[closedStreamHead]
            closedStreamHead += 1
            retainedClosedStreamIDs.remove(evicted)
            closedStreamSessionIDsByStreamID.removeValue(forKey: evicted)
        }
        compactClosedStreamOrderIfWorthwhile()
    }

    private mutating func compactClosedStreamOrderIfWorthwhile() {
        guard closedStreamHead > 0 else {
            return
        }
        guard closedStreamHead == closedStreamOrder.count || closedStreamHead * 2 >= closedStreamOrder.count else {
            return
        }
        closedStreamTombstoneMoves += retainedClosedStreamCount
        closedStreamOrder.removeFirst(closedStreamHead)
        closedStreamHead = 0
    }

    private mutating func register(_ stream: WebTransportStreamState) {
        streamsByID[stream.streamID] = stream
        streamIDsBySessionID[stream.sessionID, default: Set<UInt64>()].insert(stream.streamID)
    }

    private mutating func buffer(_ stream: WebTransportStreamState) throws {
        try ensureCanBufferIngress(for: stream.sessionID)
        let bufferedStreamIDs = bufferedStreamIDsBySessionID[stream.sessionID] ?? []
        let bufferedPayloadBytes = bufferedStreamIDs.reduce(0) { total, streamID in
            total + (bufferedStreamsByID[streamID]?.bufferedPayloadBytes ?? 0)
        }
        guard bufferedStreamIDs.count < maxBufferedStreamsPerSession,
            bufferedPayloadBytes + stream.bufferedPayloadBytes <= maxStreamReceiveBufferBytes
        else {
            throw WebTransportDraft16Error(
                kind: .bufferedStreamRejected,
                message: "buffered WebTransport stream exceeds receive limit"
            )
        }
        bufferedStreamsByID[stream.streamID] = stream
        bufferedStreamIDsBySessionID[stream.sessionID, default: Set<UInt64>()].insert(stream.streamID)
    }

    private func receiveInitialPayloadIfPresent(
        _ payload: Data,
        into stream: inout WebTransportStreamState,
        buffering: Bool
    ) throws {
        guard !payload.isEmpty else {
            return
        }
        do {
            try stream.receivePayload(payload)
        } catch {
            if buffering {
                throw WebTransportDraft16Error(
                    kind: .bufferedStreamRejected,
                    message: "buffered WebTransport stream exceeds receive limit"
                )
            }
            throw error
        }
    }

    private mutating func promoteBufferedStreams(for sessionID: WebTransportSessionID) throws {
        guard let streamIDs = bufferedStreamIDsBySessionID[sessionID] else {
            return
        }
        for streamID in streamIDs.sorted() {
            guard let stream = bufferedStreamsByID[streamID] else {
                continue
            }
            try reserveStream(sessionID, form: stream.form, receiveSide: true)
            try reserveData(for: sessionID, byteCount: stream.bufferedPayloadBytes, receiveSide: true)
            register(stream)
            bufferedStreamsByID.removeValue(forKey: streamID)
        }
        bufferedStreamIDsBySessionID[sessionID] = []
    }

    private mutating func discardBufferedIngress(
        for sessionID: WebTransportSessionID,
        tombstoneStreams: Bool
    ) {
        let streamIDs = bufferedStreamIDsBySessionID[sessionID] ?? []
        for streamID in streamIDs {
            if tombstoneStreams {
                closedStreamSessionIDsByStreamID[streamID] = sessionID
                recordClosedStream(streamID)
            }
            bufferedStreamsByID.removeValue(forKey: streamID)
        }
        bufferedStreamIDsBySessionID[sessionID] = []
        datagramsBySessionID[sessionID] = []
        datagramPayloadBytesBySessionID[sessionID] = 0
    }

    private func ensureCanBufferIngress(for sessionID: WebTransportSessionID) throws {
        guard hasBufferedIngress(for: sessionID) || bufferedIngressSessionCount < maxBufferedSessions else {
            throw WebTransportDraft16Error(
                kind: .bufferedStreamRejected,
                message: "buffered WebTransport session count exceeds receive limit"
            )
        }
    }

    private func hasBufferedIngress(for sessionID: WebTransportSessionID) -> Bool {
        guard let streamIDs = bufferedStreamIDsBySessionID[sessionID],
            !streamIDs.isEmpty
        else {
            return datagramsBySessionID[sessionID]?.isEmpty == false
        }
        return true
    }

    private var bufferedIngressSessionCount: Int {
        var sessionIDs = Set<WebTransportSessionID>()
        for (sessionID, streamIDs) in bufferedStreamIDsBySessionID where !streamIDs.isEmpty {
            sessionIDs.insert(sessionID)
        }
        for (sessionID, datagrams) in datagramsBySessionID where !datagrams.isEmpty {
            sessionIDs.insert(sessionID)
        }
        return sessionIDs.count
    }

    private mutating func reserveStream(
        _ sessionID: WebTransportSessionID,
        form: WebTransportStreamForm,
        receiveSide: Bool
    ) throws {
        var state =
            receiveSide
            ? receiveFlowControlStateBySessionID[sessionID] ?? .init()
            : flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.registerStream(form)
        } catch {
            if receiveSide {
                try closeForFlowControlViolation(sessionID)
            } else {
                if let capsule = blockedCapsule(for: form, state: state) {
                    enqueueBlockedFlowCapsule(capsule, for: sessionID)
                }
                flowControlStateBySessionID[sessionID] = state
            }
            throw error
        }
        if receiveSide {
            receiveFlowControlStateBySessionID[sessionID] = state
        } else {
            flowControlStateBySessionID[sessionID] = state
        }
    }

    private mutating func reserveData(
        for sessionID: WebTransportSessionID,
        byteCount: Int,
        receiveSide: Bool
    ) throws {
        var state =
            receiveSide
            ? receiveFlowControlStateBySessionID[sessionID] ?? .init()
            : flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.recordData(bytes: byteCount)
        } catch {
            if receiveSide {
                try closeForFlowControlViolation(sessionID)
            } else {
                if let maxData = state.maxData {
                    enqueueBlockedFlowCapsule(.dataBlocked(limit: maxData), for: sessionID)
                }
                flowControlStateBySessionID[sessionID] = state
            }
            throw error
        }
        if receiveSide {
            receiveFlowControlStateBySessionID[sessionID] = state
        } else {
            flowControlStateBySessionID[sessionID] = state
        }
    }

    private mutating func enqueueBlockedFlowCapsule(
        _ capsule: WebTransportFlowCapsule,
        for sessionID: WebTransportSessionID
    ) {
        var queue = blockedFlowCapsulesBySessionID[sessionID] ?? []
        guard !queue.contains(capsule) else {
            blockedFlowCapsulesBySessionID[sessionID] = queue
            return
        }
        queue.append(capsule)
        blockedFlowCapsulesBySessionID[sessionID] = queue
    }

    private mutating func closeForFlowControlViolation(_ sessionID: WebTransportSessionID) throws {
        _ = try markSessionClosed(
            sessionID,
            applicationErrorCode: UInt32(WebTransportHTTP3DraftConstants.current.wtFlowControlError),
            message: "WebTransport flow-control violation",
            closeCapsuleReceived: false
        )
    }

    private func mapApplicationErrorCode(_ applicationErrorCode: UInt64) throws -> UInt64 {
        guard applicationErrorCode <= UInt64(UInt32.max) else {
            throw QUICCodecError.valueOutOfRange("WebTransport application error code exceeds UInt32")
        }
        return WebTransportDraft16ErrorMapper.httpErrorCode(
            forApplicationErrorCode: UInt32(applicationErrorCode)
        )
    }

    private func blockedCapsule(for form: WebTransportStreamForm, state: WebTransportFlowControlState) -> WebTransportFlowCapsule? {
        switch form {
        case .bidirectional:
            guard let limit = state.maxStreamsBidi else { return nil }
            return .streamsBlockedBidi(limit: limit)
        case .unidirectional:
            guard let limit = state.maxStreamsUni else { return nil }
            return .streamsBlockedUni(limit: limit)
        }
    }

    private var expectedLocalInitiator: QUICStreamInitiator {
        http3.role == .client ? .client : .server
    }

    private var expectedRemoteInitiator: QUICStreamInitiator {
        http3.role == .client ? .server : .client
    }

    private func validateStreamIdentity(
        streamID: UInt64,
        direction: QUICStreamDirection,
        initiator: QUICStreamInitiator
    ) throws {
        guard streamsByID[streamID] == nil else {
            throw QUICCodecError.malformed("WebTransport stream already exists")
        }
        guard bufferedStreamsByID[streamID] == nil else {
            throw QUICCodecError.malformed("WebTransport stream is already buffered")
        }
        if let sessionID = closedStreamSessionIDsByStreamID[streamID],
            sessionsByID[sessionID] != nil
        {
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport stream belongs to a terminated session")
        }

        guard QUICStreamID.direction(of: streamID) == direction else {
            throw QUICCodecError.malformed("stream direction mismatch for WebTransport stream")
        }
        guard QUICStreamID.initiator(of: streamID) == initiator else {
            throw QUICCodecError.malformed("stream initiator mismatch for WebTransport stream")
        }
    }

    private mutating func markSessionDraining(_ sessionID: WebTransportSessionID) throws {
        var session = try sessionForIngress(sessionID)
        guard session.state != .requested else {
            throw QUICCodecError.malformed("WT_DRAIN_SESSION requires an established session")
        }
        if session.state == .accepted {
            session.state = .draining
            sessionsByID[sessionID] = session
        }
    }

    private mutating func markSessionClosed(
        _ sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String,
        closeCapsuleReceived: Bool
    ) throws -> WebTransportSessionTerminationActions {
        var session = try sessionForIngress(sessionID)
        session.state = .closed(applicationErrorCode: applicationErrorCode, message: message)
        sessionsByID[sessionID] = session
        if closeCapsuleReceived {
            requestStreamIDsClosedByReceivedCloseCapsule.insert(session.requestStreamID)
        }

        let terminationActions = terminateAssociatedStreams(for: sessionID, requestStreamID: session.requestStreamID)
        datagramsBySessionID[sessionID] = []
        datagramPayloadBytesBySessionID[sessionID] = 0
        recordClosedSession(sessionID)
        return terminationActions
    }

    /// Resets and stops the streams associated with a session that is ending.
    ///
    /// Each frame is produced only for a half this endpoint owns (RFC 9000
    /// section 2.1): a RESET_STREAM for a stream whose send half is ours and a
    /// STOP_SENDING for one whose receive half is ours. A bidirectional stream
    /// owns both; a unidirectional stream owns exactly the direction its
    /// initiator gave it. Emitting the other frame is not merely useless — RFC
    /// 9000 section 19.4 makes RESET_STREAM on a send-only stream a
    /// STREAM_STATE_ERROR and section 19.5 makes STOP_SENDING on a receive-only
    /// stream the same, so the peer would close the connection while this
    /// endpoint is trying to end the session cleanly. A teardown reaches both
    /// shapes because ``openUnidirectionalStream`` registers locally initiated
    /// streams and ``acceptUnidirectionalStreamWithActions`` registers
    /// peer-initiated ones.
    private mutating func terminateAssociatedStreams(
        for sessionID: WebTransportSessionID,
        requestStreamID: UInt64
    ) -> WebTransportSessionTerminationActions {
        let wtSessionGone = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
        var streamResetFrames: [QUICFrame] = []
        var streamStopSendingFrames: [QUICFrame] = []

        let activeStreamIDs = (streamIDsBySessionID[sessionID] ?? []).sorted()
        for streamID in activeStreamIDs {
            guard var stream = streamsByID[streamID] else {
                continue
            }
            if stream.hasSendHalf {
                streamResetFrames.append(stream.reset(applicationErrorCode: wtSessionGone))
            }
            if stream.hasReceiveHalf {
                streamStopSendingFrames.append(stream.stopSending(applicationErrorCode: wtSessionGone))
            }
            closedStreamSessionIDsByStreamID[streamID] = sessionID
            recordClosedStream(streamID)
            streamsByID.removeValue(forKey: streamID)
        }

        let bufferedStreamIDs = (bufferedStreamIDsBySessionID[sessionID] ?? []).sorted()
        for streamID in bufferedStreamIDs {
            guard var stream = bufferedStreamsByID[streamID] else {
                continue
            }
            if stream.hasSendHalf {
                streamResetFrames.append(stream.reset(applicationErrorCode: wtSessionGone))
            }
            if stream.hasReceiveHalf {
                streamStopSendingFrames.append(stream.stopSending(applicationErrorCode: wtSessionGone))
            }
            closedStreamSessionIDsByStreamID[streamID] = sessionID
            recordClosedStream(streamID)
            bufferedStreamsByID.removeValue(forKey: streamID)
        }

        streamIDsBySessionID[sessionID] = []
        bufferedStreamIDsBySessionID[sessionID] = []

        return WebTransportSessionTerminationActions(
            connectFINFrame: .stream(id: requestStreamID, offset: nil, fin: true, data: Data()),
            connectStopSendingFrame: .stopSending(id: requestStreamID, applicationErrorCode: wtSessionGone),
            streamResetFrames: streamResetFrames,
            streamStopSendingFrames: streamStopSendingFrames
        )
    }

    private func rejection(
        for request: WebTransportSessionRequest,
        selectedProtocol: String?,
        policy: WebTransportServerSessionPolicy
    ) -> WebTransportSessionRejection? {
        if let allowedAuthorities = policy.allowedAuthorities, !allowedAuthorities.contains(request.authority) {
            return WebTransportSessionRejection(
                status: 405,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport authority is not allowed")
            )
        }
        if let allowedPaths = policy.allowedPaths, !allowedPaths.contains(request.path) {
            return WebTransportSessionRejection(
                status: 405,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport path is not allowed")
            )
        }
        if let allowedOrigins = policy.allowedOrigins {
            guard let origin = request.origin, allowedOrigins.contains(origin) else {
                return WebTransportSessionRejection(
                    status: 403,
                    error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport origin is not allowed")
                )
            }
        }
        if policy.requireProtocolSelection && selectedProtocol == nil {
            return WebTransportSessionRejection(
                status: 400,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport protocol selection is required")
            )
        }
        return nil
    }
}
