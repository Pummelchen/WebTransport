import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportDraft15SettingsVectorIsRoundTripCompatible() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let expectedPayload = Data([
        0x08,
        0x01,
        0x33,
        0x01,
        0x6b, 0x61,
        0x00,
        0x6b, 0x64,
        0x00,
        0x6b, 0x65,
        0x00,
        0xac, 0x7c, 0xf0, 0x00,
        0x01
    ])
    let frame = try HTTP3Frame(type: HTTP3FrameType.settings, payload: expectedPayload)
    let settings = try HTTP3Settings.decodePayload(expectedPayload)

    let encoded = try frame.encode()
    let defaultFrame = try HTTP3Settings.webTransportDraft15Defaults.frame().encode()
    #expect(encoded[0] == HTTP3FrameType.settings)
    #expect(encoded == defaultFrame)
    #expect(settings[constants.settingsEnableConnectProtocol] == 1)
    #expect(settings[constants.settingsH3Datagram] == 1)
    #expect(settings[constants.settingsWTEnabled] == 1)
    #expect(settings[constants.settingsWTInitialMaxStreamsUni] == 0)
    #expect(settings[constants.settingsWTInitialMaxStreamsBidi] == 0)
    #expect(settings[constants.settingsWTInitialMaxData] == 0)
}

@Test
func webTransportStreamAndDatagramDraftVectorsRoundTrip() throws {
    let sessionPrefix = try WebTransportStreamSignaling.parsePrefix(
        try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    )
    #expect(sessionPrefix.form == .bidirectional)
    #expect(sessionPrefix.sessionID == WebTransportSessionID(rawValue: 0))

    let uniPrefix = try WebTransportStreamSignaling.parsePrefix(
        try WebTransportStreamSignaling.serializePrefix(form: .unidirectional, sessionID: 0)
    )
    #expect(uniPrefix.form == .unidirectional)
    #expect(uniPrefix.sessionID == WebTransportSessionID(rawValue: 0))

    let serializedDatagram = try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("ping".utf8))
    #expect(serializedDatagram == Data([0x00, 0x70, 0x69, 0x6e, 0x67]))
    let parsedDatagram = try WebTransportDatagramSignaling.parse(serializedDatagram)
    #expect(parsedDatagram.sessionID == WebTransportSessionID(rawValue: 0))
    #expect(parsedDatagram.payload == Data("ping".utf8))
}

@Test
func webTransportStreamStressLongRunningOpenReceiveLoop() throws {
    var pair = WebTransportInteropTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)
    let session = pair.client.session(forRequestStreamID: 0)!

    for index in 0..<512 {
        let streamID = QUICStreamID.make(index: UInt64(index + 1), direction: .bidirectional, initiator: .client)
        let payload = Data(repeating: UInt8(index % 251), count: (index % 16) + 1)

        let prefix = try pair.client.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        _ = try pair.server.acceptBidirectionalStream(streamID: streamID, firstBytes: prefix + payload)

        try pair.server.receiveStreamPayload(streamID: streamID, payload: payload)
        #expect(pair.server.popStreamPayload(streamID: streamID) == payload)
    }
}

@Test
func webTransportDatagramStressLongRunningRoundTripLoop() throws {
    var pair = WebTransportInteropTestSupport.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)
    let session = pair.client.session(forRequestStreamID: 0)!

    for index in 0..<1_024 {
        let payload = Data(repeating: UInt8(index % 251), count: (index % 24) + 1)
        let frame = try pair.client.makeDatagramFrame(sessionID: session.id, payload: payload)
        _ = try pair.server.receiveDatagramFrame(frame)
        #expect(pair.server.popDatagramPayload(sessionID: session.id) == payload)
    }
}

private enum WebTransportInteropTestSupport {
    static func makeReadyManagers() -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try! serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try! clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(http3: clientHTTP3),
            WebTransportSessionManager(http3: serverHTTP3)
        )
    }
}
