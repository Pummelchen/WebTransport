import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportStreamPrefixesRoundTripForBothDirections() throws {
    let bidiPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    let parsedBidi = try WebTransportStreamSignaling.parsePrefix(bidiPrefix)

    #expect(parsedBidi.form == .bidirectional)
    #expect(parsedBidi.sessionID == WebTransportSessionID(rawValue: 0))
    #expect(parsedBidi.bytesConsumed == bidiPrefix.count)
    #expect(parsedBidi.remainingPayload == Data())

    let uniPrefix = try WebTransportStreamSignaling.serializePrefix(form: .unidirectional, sessionID: 0)
    let parsedUni = try WebTransportStreamSignaling.parsePrefix(uniPrefix)

    #expect(parsedUni.form == .unidirectional)
    #expect(parsedUni.sessionID == WebTransportSessionID(rawValue: 0))
    #expect(parsedUni.bytesConsumed == uniPrefix.count)
    #expect(parsedUni.remainingPayload == Data())
}

@Test
func webTransportBidirectionalStreamOpenAcceptRegistersStreamBySession() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: []
        )
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(
        streamID: 0,
        frame: decision.responseFrame
    )

    guard let session = pair.server.session(forRequestStreamID: 0) else {
        throw URLError(.badURL)
    }

    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: session.id)
    let parsed = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix + Data("hello".utf8))

    #expect(parsed.form == .bidirectional)
    #expect(parsed.sessionID == session.id)
    #expect(pair.server.stream(for: 4) != nil)
    #expect(pair.server.streamIDs(for: session.id)?.contains(4) == true)
    #expect(pair.server.popStreamPayload(streamID: 4) == Data("hello".utf8))
}

@Test
func webTransportUnidirectionalStreamOpenAcceptSupportsOwnership() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: []
        )
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(
        streamID: 0,
        frame: decision.responseFrame
    )

    guard let session = pair.server.session(forRequestStreamID: 0) else {
        throw URLError(.badURL)
    }

    let prefix = try pair.client.openUnidirectionalStream(streamID: 6, sessionID: session.id)
    let parsed = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: prefix + Data("uni".utf8))

    #expect(parsed.form == .unidirectional)
    #expect(parsed.sessionID == session.id)
    #expect(pair.server.stream(for: 6) != nil)
    #expect(pair.server.streamIDs(for: session.id)?.contains(6) == true)
    #expect(pair.server.popStreamPayload(streamID: 6) == Data("uni".utf8))
}

@Test
func webTransportStreamReceivePayloadEnforcesBackpressure() throws {
    var client = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .client),
        maxStreamReceiveBufferBytes: 4
    )
    var server = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server),
        maxStreamReceiveBufferBytes: 4
    )

    var clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
    _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())

    client = WebTransportSessionManager(
        http3: clientHTTP3,
        maxStreamReceiveBufferBytes: 4
    )
    server = WebTransportSessionManager(
        http3: serverHTTP3,
        maxStreamReceiveBufferBytes: 4
    )

    let requestFrame = try client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )
    let decision = try server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)

    let session = server.session(forRequestStreamID: 0)!
    let prefix = try client.openBidirectionalStream(streamID: 4, sessionID: session.id)
    _ = try server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)

    try server.receiveStreamPayload(streamID: 4, payload: Data([0x00, 0x00]))
    try server.receiveStreamPayload(streamID: 4, payload: Data([0x00, 0x00]))
    #expect(throws: Error.self) {
        try server.receiveStreamPayload(streamID: 4, payload: Data([0x00, 0x00]))
    }
}

@Test
func webTransportStreamResetAndStopSendingEmitFrames() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: []
        )
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(
        streamID: 0,
        frame: decision.responseFrame
    )

    let session = pair.server.session(forRequestStreamID: 0)!
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: session.id)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)

    let resetFrame = try pair.server.resetStream(streamID: 4, applicationErrorCode: 0x10)
    let stopSendingFrame = try pair.server.stopSendingStream(streamID: 4, applicationErrorCode: 0x11)

    #expect(
        resetFrame
            == .resetStreamAt(
                id: 4,
                applicationErrorCode: WebTransportDraft16ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x10),
                finalSize: 0,
                reliableSize: 0
            ))
    #expect(
        stopSendingFrame
            == .stopSending(
                id: 4,
                applicationErrorCode: WebTransportDraft16ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x11)
            ))
}

/// Session teardown may only signal the stream halves this endpoint owns.
///
/// RFC 9000 section 19.4 makes a RESET_STREAM frame for a send-only stream a
/// STREAM_STATE_ERROR, and section 19.5 makes a STOP_SENDING frame for a
/// receive-only stream the same, so emitting both for every associated stream
/// lets the peer kill the connection on the path whose whole purpose is to end
/// the session cleanly. The associated set holds both peer-initiated
/// unidirectional streams (receive-only here) and locally initiated ones
/// (send-only here), which is exactly the pair a bulk teardown gets wrong.
@Test
func webTransportSessionTeardownSignalsOnlyTheHalvesThisEndpointOwns() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: []
        )
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)

    let session = pair.server.session(forRequestStreamID: 0)!

    // Bidirectional: the server owns both halves, so both frames belong.
    let bidirectionalPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: session.id)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: bidirectionalPrefix)

    // Peer-initiated unidirectional: the server owns the receive half only, so
    // it may STOP_SENDING but must never RESET_STREAM.
    let peerUnidirectionalPrefix = try pair.client.openUnidirectionalStream(streamID: 6, sessionID: session.id)
    _ = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: peerUnidirectionalPrefix)

    // Locally initiated unidirectional: the server owns the send half only, so
    // it may RESET_STREAM but must never STOP_SENDING.
    let localUnidirectionalPrefix = try pair.server.openUnidirectionalStream(streamID: 7, sessionID: session.id)
    _ = try pair.client.acceptUnidirectionalStream(streamID: 7, firstBytes: localUnidirectionalPrefix)

    let close = try pair.server.makeCloseSessionCapsuleResult(
        sessionID: session.id,
        applicationErrorCode: 9,
        message: "bye"
    )

    let resetStreamIDs = close.terminationActions.streamResetFrames.compactMap { frame -> UInt64? in
        guard case .resetStreamAt(let id, _, _, _) = frame else { return nil }
        return id
    }
    let stopSendingStreamIDs = close.terminationActions.streamStopSendingFrames.compactMap { frame -> UInt64? in
        guard case .stopSending(let id, _) = frame else { return nil }
        return id
    }

    #expect(resetStreamIDs == [4, 7])
    #expect(stopSendingStreamIDs == [4, 6])
}

/// The public per-stream reset/stop API must apply the same RFC 9000 section 2.1
/// half-ownership rule as the session teardown path.
///
/// Teardown was fixed to gate its frames on `hasSendHalf` / `hasReceiveHalf`, but
/// a caller could still ask `resetStream` for a peer-initiated unidirectional
/// stream (receive-only here) or `stopSendingStream` for a locally initiated one
/// (send-only here) and receive back a frame that RFC 9000 sections 19.4 and 19.5
/// make a STREAM_STATE_ERROR at the peer.
@Test
func webTransportPublicStreamSignalsApplyTheHalfOwnershipRule() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: []
        )
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)

    let session = pair.server.session(forRequestStreamID: 0)!

    // Bidirectional: the server owns both halves.
    let bidirectionalPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: session.id)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: bidirectionalPrefix)
    // Peer-initiated unidirectional: the server owns the receive half only.
    let peerUnidirectionalPrefix = try pair.client.openUnidirectionalStream(streamID: 6, sessionID: session.id)
    _ = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: peerUnidirectionalPrefix)
    // Locally initiated unidirectional: the server owns the send half only.
    let localUnidirectionalPrefix = try pair.server.openUnidirectionalStream(streamID: 7, sessionID: session.id)
    _ = try pair.client.acceptUnidirectionalStream(streamID: 7, firstBytes: localUnidirectionalPrefix)

    // The halves this endpoint owns still produce frames.
    _ = try pair.server.resetStream(streamID: 4, applicationErrorCode: 0x10)
    _ = try pair.server.stopSendingStream(streamID: 4, applicationErrorCode: 0x11)
    _ = try pair.server.stopSendingStream(streamID: 6, applicationErrorCode: 0x11)
    _ = try pair.server.resetStream(streamID: 7, applicationErrorCode: 0x10)

    // The halves it does not own are refused with the RFC's error, not a frame.
    #expect(
        throws: QUICStateError.streamStateViolation(
            "cannot reset a stream half this endpoint does not own")
    ) {
        _ = try pair.server.resetStream(streamID: 6, applicationErrorCode: 0x10)
    }
    #expect(
        throws: QUICStateError.streamStateViolation(
            "cannot stop a stream half this endpoint does not own")
    ) {
        _ = try pair.server.stopSendingStream(streamID: 7, applicationErrorCode: 0x11)
    }
}

@Test
func webTransportStreamOpenRejectsUnknownSession() throws {
    var pair = try WebTransportStreamTestSupport.makeReadyManagers()

    #expect(throws: Error.self) {
        try pair.client.openBidirectionalStream(
            streamID: 2,
            sessionID: WebTransportSessionID(rawValue: 0)
        )
    }
}

/// F-swift-perf-tests-01: draining a buffered stream must cost O(total bytes).
///
/// The old `popStreamPayload` copied the stream struct out of and back into the
/// manager's dictionary, and `popPayload` used `bufferedPayloads.removeFirst()`,
/// so draining N single-byte payloads moved O(N^2) array elements and forced a
/// copy-on-write copy of the whole array on every operation. A stream is allowed
/// `maxStreamReceiveBufferBytes` (64 KiB) of one-byte payloads, i.e. 65,536
/// entries.
///
/// The bound is a wall-clock one on purpose: the shift and copy-on-write work
/// happens inside the standard library, so there is no operation-counter seam
/// that the old implementation and the new one share. The margin is large — the
/// old implementation takes seconds for this workload and the fixed one
/// milliseconds (see the commit message for both measurements).
@Test
func webTransportStreamDrainCostStaysLinearInBufferedPayloadCount() throws {
    let payloadCount = 16_384
    var (manager, streamID) = try WebTransportStreamTestSupport.makeServerWithAcceptedStream()
    for index in 0..<payloadCount {
        try manager.receiveStreamPayload(
            streamID: streamID,
            payload: Data([UInt8(truncatingIfNeeded: index)])
        )
    }
    #expect(manager.stream(for: streamID)?.bufferedPayloadBytes == payloadCount)

    let start = ContinuousClock.now
    var drainedBytes = 0
    var firstPayload: Data?
    while let payload = manager.popStreamPayload(streamID: streamID) {
        firstPayload = firstPayload ?? payload
        drainedBytes += payload.count
    }
    let elapsed = ContinuousClock.now - start

    #expect(drainedBytes == payloadCount, "every buffered byte is delivered exactly once")
    #expect(firstPayload == Data([0x00]), "the buffer stays FIFO")
    #expect(manager.stream(for: streamID)?.bufferedPayloadBytes == 0)
    #expect(
        elapsed < .seconds(1),
        "draining \(payloadCount) buffered payloads took \(elapsed); the drain must be linear in the buffered bytes"
    )
}

/// F-swift-perf-tests-01: a read that consumes its own arrival must not be buffered
/// and popped again, and FIFO order must survive the shortcut.
@Test
func webTransportStreamImmediateDeliveryPreservesFIFOAndAccounting() throws {
    var (manager, streamID) = try WebTransportStreamTestSupport.makeServerWithAcceptedStream()

    // An earlier payload is pending: the arrival is buffered and the oldest payload
    // is what the read observes.
    try manager.receiveStreamPayload(streamID: streamID, payload: Data("first".utf8))
    let delivered = try manager.receiveAndPopStreamPayload(
        streamID: streamID,
        payload: Data("second".utf8)
    )
    #expect(delivered == Data("first".utf8))

    // "second" is now the oldest pending payload, so the next read returns it even
    // though "third" is the arrival.
    let secondOut = try manager.receiveAndPopStreamPayload(
        streamID: streamID,
        payload: Data("third".utf8)
    )
    #expect(secondOut == Data("second".utf8))
    #expect(manager.stream(for: streamID)?.bufferedPayloadBytes == 5)

    // The buffer is drained and an empty buffer is still reported as such.
    #expect(manager.popStreamPayload(streamID: streamID) == Data("third".utf8))
    #expect(manager.stream(for: streamID)?.bufferedPayloadBytes == 0)
    #expect(manager.stream(for: streamID)?.bufferedPayloads.isEmpty == true)
    #expect(manager.popStreamPayload(streamID: streamID) == nil)

    // With nothing pending, a read is satisfied by its own arrival.
    let own = try manager.receiveAndPopStreamPayload(
        streamID: streamID,
        payload: Data("fourth".utf8)
    )
    #expect(own == Data("fourth".utf8))
    #expect(manager.stream(for: streamID)?.bufferedPayloadBytes == 0)
}

private enum WebTransportStreamTestSupport {
    /// A server-side manager with one accepted bidirectional stream ready for payloads.
    static func makeServerWithAcceptedStream() throws -> (
        manager: WebTransportSessionManager, streamID: UInt64
    ) {
        var pair = try makeReadyManagers()
        let requestFrame = try pair.client.makeClientSessionRequest(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
        let decision = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: requestFrame,
            policy: try WebTransportServerSessionPolicy()
        )
        _ = try pair.client.receiveServerSessionResponse(
            streamID: 0,
            frame: decision.responseFrame
        )
        guard let session = pair.server.session(forRequestStreamID: 0) else {
            throw URLError(.badURL)
        }
        let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: session.id)
        _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
        return (pair.server, 4)
    }

    static func makeReadyManagers() throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(http3: clientHTTP3),
            WebTransportSessionManager(http3: serverHTTP3)
        )
    }
}
