import Foundation
import WebTransportQUICCore

private struct WebTransportSessionRejection: Equatable, Sendable {
    var status: UInt16
    var error: WebTransportDraft16Error
}

/// ``WebTransportSessionManager``'s session admission and lifecycle: the CONNECT handshake in
/// both roles, the WT_DRAIN_SESSION / WT_CLOSE_SESSION teardown, and the bounded tombstone
/// retention for terminated sessions.
///
/// `markSessionDraining` and `markSessionClosed` are `internal` rather than `private` because the
/// flow-control file routes a flow-control violation into the same close path; every other member
/// here is reached only from this file.
extension WebTransportSessionManager {
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
        let sessionID = try validateClientSessionRequest(streamID: streamID, frame: frame)

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
        try storeNewSession(session)
        return WebTransportServerSessionDecision(
            session: session,
            responseFrame: responseFrame,
            rejectionError: rejection?.error
        )
    }

    /// Everything that must be true before a CONNECT request is looked at, and the session
    /// ID the request will get.
    private mutating func validateClientSessionRequest(
        streamID: UInt64,
        frame: HTTP3Frame
    ) throws -> WebTransportSessionID {
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
        return sessionID
    }

    /// Stores the session and applies the consequence of its state: a rejected session's
    /// buffered ingress is discarded and its streams tombstoned.
    private mutating func storeNewSession(_ session: WebTransportSession) throws {
        store(session)
        if session.state == .accepted {
            try promoteBufferedStreams(for: session.id)
        } else {
            discardBufferedIngress(for: session.id, tombstoneStreams: true)
            recordClosedSession(session.id)
        }
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
            closedRequestStreamIDs.remove(session.requestStreamID)
        }
        streamIDsBySessionID.removeValue(forKey: sessionID)
        bufferedStreamIDsBySessionID.removeValue(forKey: sessionID)
        datagramsBySessionID.removeValue(forKey: sessionID)
        datagramPayloadBytesBySessionID.removeValue(forKey: sessionID)
        flowControlStateBySessionID.removeValue(forKey: sessionID)
        receiveFlowControlStateBySessionID.removeValue(forKey: sessionID)
        blockedFlowCapsulesBySessionID.removeValue(forKey: sessionID)
    }

    mutating func markSessionDraining(_ sessionID: WebTransportSessionID) throws {
        var session = try sessionForIngress(sessionID)
        guard session.state != .requested else {
            throw QUICCodecError.malformed("WT_DRAIN_SESSION requires an established session")
        }
        if session.state == .accepted {
            session.state = .draining
            sessionsByID[sessionID] = session
        }
    }

    mutating func markSessionClosed(
        _ sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String,
        closeCapsuleReceived: Bool
    ) throws -> WebTransportSessionTerminationActions {
        var session = try sessionForIngress(sessionID)
        session.state = .closed(applicationErrorCode: applicationErrorCode, message: message)
        sessionsByID[sessionID] = session
        if closeCapsuleReceived {
            closedRequestStreamIDs.insert(session.requestStreamID)
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
