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

    #expect(resetFrame == .resetStream(id: 4, applicationErrorCode: 0x10, finalSize: 0))
    #expect(stopSendingFrame == .stopSending(id: 4, applicationErrorCode: 0x11))
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

private enum WebTransportStreamTestSupport {
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
