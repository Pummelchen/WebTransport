import Foundation
import WebTransportQUICCore

/// ``WebTransportSessionManager``'s stream bookkeeping: opening, accepting and buffering streams,
/// the payload send/receive paths, and the bounded tombstone window for terminated streams.
///
/// `promoteBufferedStreams`, `discardBufferedIngress` and `ensureCanBufferIngress` are `internal`
/// rather than `private` because session admission, session teardown and datagram delivery all
/// reach them; every other member here is reached only from this file.
extension WebTransportSessionManager {
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

    mutating func promoteBufferedStreams(for sessionID: WebTransportSessionID) throws {
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

    mutating func discardBufferedIngress(
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

    func ensureCanBufferIngress(for sessionID: WebTransportSessionID) throws {
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

    /// How many stream tombstones are retained, as distinct from the storage they
    /// occupy.
    var retainedClosedStreamCount: Int {
        closedStreamOrder.count - closedStreamHead
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
}
