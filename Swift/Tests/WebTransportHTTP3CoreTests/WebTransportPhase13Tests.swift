import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportCloseAndDrainCapsulesDriveSessionStateAndGating() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)

    let drain = try pair.client.makeDrainSessionCapsule(sessionID: sessionID)
    #expect(try WebTransportFlowCapsuleCodec.parse(drain).capsule == .drainSession)
    #expect(pair.client.sessionsByID[sessionID]?.state == .draining)
    _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("x".utf8))
    _ = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)

    let close = try pair.client.makeCloseSessionCapsule(
        sessionID: sessionID,
        applicationErrorCode: 7,
        message: "done"
    )
    #expect(try WebTransportFlowCapsuleCodec.parse(close).capsule == .closeSession(
        applicationErrorCode: 7,
        message: "done"
    ))
    #expect(pair.client.sessionsByID[sessionID]?.state == .closed(applicationErrorCode: 7, message: "done"))
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("x".utf8))
    }
}

@Test
func webTransportCloseSessionResultCarriesFINStopSendingAndStreamCleanupActions() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)

    let result = try pair.client.makeCloseSessionCapsuleResult(
        sessionID: sessionID,
        applicationErrorCode: 7,
        message: "done"
    )

    #expect(try WebTransportFlowCapsuleCodec.parse(result.capsuleBytes).capsule == .closeSession(
        applicationErrorCode: 7,
        message: "done"
    ))
    #expect(result.terminationActions.connectFINFrame == .stream(
        id: sessionID.rawValue,
        offset: nil,
        fin: true,
        data: Data()
    ))
    #expect(result.terminationActions.connectStopSendingFrame == .stopSending(
        id: sessionID.rawValue,
        applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtSessionGoneError
    ))
    #expect(result.terminationActions.streamResetFrames == [
        .resetStream(
            id: 4,
            applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtSessionGoneError,
            finalSize: 0
        )
    ])
    #expect(result.terminationActions.streamStopSendingFrames == [
        .stopSending(
            id: 4,
            applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtSessionGoneError
        )
    ])
    #expect(pair.client.stream(for: 4) == nil)
}

@Test
func webTransportReceivedCloseCleansStreamsAndDatagrams() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix + Data("hello".utf8))
    let datagram = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("d".utf8))
    _ = try pair.server.receiveDatagramFrame(datagram)

    let received = try pair.server.receiveFlowControlCapsuleWithActions(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 9, message: "bye"))
    )

    #expect(received.terminationActions?.connectFINFrame == .stream(
        id: sessionID.rawValue,
        offset: nil,
        fin: true,
        data: Data()
    ))
    #expect(pair.server.stream(for: 4) == nil)
    #expect(pair.server.popDatagramPayload(sessionID: sessionID) == nil)
    #expect(throws: WebTransportDraft15Error.self) {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("x".utf8))
    }
}

@Test
func webTransportReceivedCloseResetsAdditionalConnectStreamDataWithH3MessageError() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)

    _ = try pair.server.receiveFlowControlCapsuleWithActions(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 1, message: "closed"))
    )

    #expect(try pair.server.receiveConnectStreamData(
        streamID: sessionID.rawValue,
        data: Data("late".utf8)
    ) == .resetStream(
        id: sessionID.rawValue,
        applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
        finalSize: 0
    ))
}

@Test
func webTransportCloseSessionRejectsOversizedMessages() throws {
    let oversized = String(repeating: "x", count: WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 1)

    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.serialize(.closeSession(
            applicationErrorCode: 1,
            message: oversized
        ))
    }

    var payload = Data([0, 0, 0, 1])
    payload.append(Data(oversized.utf8))
    var capsule = Data()
    capsule.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule))
    capsule.append(try QUICVarInt.encode(UInt64(payload.count)))
    capsule.append(payload)
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(capsule)
    }
}

@Test
func webTransportConnectStreamFinishClosesSession() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)

    try pair.client.finishConnectStream(streamID: sessionID.rawValue)
    #expect(pair.client.sessionsByID[sessionID]?.state == .closed(applicationErrorCode: 0, message: ""))
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.openUnidirectionalStream(streamID: 2, sessionID: sessionID)
    }
}

@Test
func webTransportBuffersEarlyDatagramsAndStreamsUntilSessionAccept() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )

    let earlyDatagram = try WebTransportDatagramSignaling.serialize(
        sessionID: 0,
        payload: Data("early-d".utf8)
    )
    _ = try pair.client.receiveDatagramFrame(.datagram(earlyDatagram))

    let earlyPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    _ = try pair.client.acceptBidirectionalStream(
        streamID: 1,
        firstBytes: earlyPrefix + Data("early-s".utf8)
    )
    #expect(pair.client.stream(for: 1) == nil)
    #expect(pair.client.bufferedStreamIDs(for: WebTransportSessionID(rawValue: 0))?.contains(1) == true)

    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)

    #expect(pair.client.popDatagramPayload(sessionID: WebTransportSessionID(rawValue: 0)) == Data("early-d".utf8))
    #expect(pair.client.stream(for: 1) != nil)
    #expect(pair.client.popStreamPayload(streamID: 1) == Data("early-s".utf8))
}

@Test
func webTransportEarlyIngressOverflowMapsToBufferedStreamRejected() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers(
        maxDatagramReceiveBufferBytes: 2,
        maxStreamReceiveBufferBytes: 2
    )
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )

    do {
        _ = try pair.client.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("abc".utf8))
        ))
        Issue.record("early oversized datagram should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .bufferedStreamRejected)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError)
    }

    do {
        let prefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
        _ = try pair.client.acceptBidirectionalStream(streamID: 1, firstBytes: prefix + Data("abc".utf8))
        Issue.record("early oversized stream should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .bufferedStreamRejected)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError)
    }
}

@Test
func webTransportMapsUnknownSessionIDsToH3IDError() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    do {
        _ = try pair.client.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("x".utf8))
        ))
        Issue.record("unknown session datagram should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .h3ID)
        #expect(error.code == HTTP3ApplicationErrorCode.idError.rawValue)
    }
}

@Test
func webTransportRejectsZeroRTTConnectAndLateSessionsAfterGoaway() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.makeClientSessionRequest(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt"),
            isZeroRTT: true
        )
    }

    try pair.client.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 0))
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.makeClientSessionRequest(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
    }
}

@Test
func webTransportGoawayDrainsExistingSessionsAndAllowsExistingSessionWork() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)

    try pair.client.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4))
    #expect(pair.client.sessionsByID[sessionID]?.state == .draining)
    _ = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("after-goaway".utf8))
}

private enum WebTransportPhase13Support {
    static func makeReadyManagers(
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxStreamReceiveBufferBytes: Int = 64 * 1024
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(
                http3: clientHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes
            ),
            WebTransportSessionManager(
                http3: serverHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes
            )
        )
    }

    static func establishSession(
        client: inout WebTransportSessionManager,
        server: inout WebTransportSessionManager
    ) throws -> WebTransportSessionID {
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
        return WebTransportSessionID(rawValue: 0)
    }
}
