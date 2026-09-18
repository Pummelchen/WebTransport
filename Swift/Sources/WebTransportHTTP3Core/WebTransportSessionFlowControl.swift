import Foundation
import WebTransportQUICCore

/// ``WebTransportSessionManager``'s flow-control handling: the WT_MAX_* / WT_*_BLOCKED capsule
/// exchange, CONNECT-stream capsule reading, and the stream/data reservations that enforce the
/// negotiated limits.
///
/// `reserveStream`, `reserveData` and `mapApplicationErrorCode` are `internal` rather than
/// `private` because the stream file's open/accept/send paths call them; every other member here is
/// reached only from this file.
extension WebTransportSessionManager {
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
            if closedRequestStreamIDs.contains(streamID) {
                return connectStreamResetResult(
                    streamID: streamID,
                    received: received,
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
                return try handleCloseSessionCapsule(
                    streamID: streamID,
                    sessionID: sessionID,
                    received: received,
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

    /// What a reset CONNECT stream yields: everything received so far, plus the frame the
    /// caller must send to reset it.
    private func connectStreamResetResult(
        streamID: UInt64,
        received: [WebTransportReceivedFlowControlCapsule],
        terminationActions: WebTransportSessionTerminationActions?
    ) -> WebTransportConnectStreamCapsuleResult {
        WebTransportConnectStreamCapsuleResult(
            receivedCapsules: received,
            connectResetFrame: connectMessageErrorReset(streamID: streamID),
            terminationActions: terminationActions
        )
    }

    /// A WT_CLOSE_SESSION capsule closes the session -- but only once; a second one is
    /// accepted and changes nothing.
    private mutating func handleCloseSessionCapsule(
        streamID: UInt64,
        sessionID: WebTransportSessionID,
        received: [WebTransportReceivedFlowControlCapsule],
        terminationActions: WebTransportSessionTerminationActions?
    ) throws -> WebTransportConnectStreamCapsuleResult {
        let isAlreadyClosed: Bool
        if case .closed = sessionsByID[sessionID]?.state {
            isAlreadyClosed = true
        } else {
            isAlreadyClosed = false
        }
        var actions = terminationActions
        if !isAlreadyClosed {
            actions = try? markSessionClosed(
                sessionID,
                applicationErrorCode: 0,
                message: "",
                closeCapsuleReceived: false
            )
        }
        return WebTransportConnectStreamCapsuleResult(
            receivedCapsules: received,
            connectResetFrame: connectMessageErrorReset(streamID: streamID),
            terminationActions: actions
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

    mutating func reserveStream(
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

    mutating func reserveData(
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

    func mapApplicationErrorCode(_ applicationErrorCode: UInt64) throws -> UInt64 {
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
}
