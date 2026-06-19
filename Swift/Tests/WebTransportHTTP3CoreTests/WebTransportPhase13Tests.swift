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
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("x".utf8))
    }

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
}

@Test
func webTransportReceivedCloseCleansStreamsAndDatagrams() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix + Data("hello".utf8))
    let datagram = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("d".utf8))
    _ = try pair.server.receiveDatagramFrame(datagram)

    _ = try pair.server.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 9, message: "bye"))
    )

    #expect(pair.server.stream(for: 4) == nil)
    #expect(pair.server.popDatagramPayload(sessionID: sessionID) == nil)
    #expect(throws: WebTransportDraft15Error.self) {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("x".utf8))
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
func webTransportGoawayDrainsExistingSessionsAndBlocksNewWork() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let sessionID = try WebTransportPhase13Support.establishSession(client: &pair.client, server: &pair.server)

    try pair.client.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4))
    #expect(pair.client.sessionsByID[sessionID]?.state == .draining)
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    }
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
