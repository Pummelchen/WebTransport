import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportDatagramPrefixesRoundTrip() throws {
    let payload = Data("payload".utf8)
    let serialized = try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: payload)
    let emptyPrefix = try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data())
    let parsed = try WebTransportDatagramSignaling.parse(serialized)

    #expect(parsed.sessionID == WebTransportSessionID(rawValue: 0))
    #expect(parsed.quarterStreamID == 0)
    #expect(parsed.bytesConsumed == emptyPrefix.count)
    #expect(parsed.payload == payload)

    let later = try WebTransportDatagramSignaling.serialize(sessionID: 4, payload: payload)
    let parsedLater = try WebTransportDatagramSignaling.parse(later)
    #expect(later.first == 1)
    #expect(parsedLater.sessionID == WebTransportSessionID(rawValue: 4))
    #expect(parsedLater.quarterStreamID == 1)
}

@Test
func webTransportDatagramSendAndReceiveBySession() throws {
    var pair = try WebTransportDatagramTestSupport.makeReadyManagers()
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

    guard let session = pair.client.session(forRequestStreamID: 0) else {
        throw URLError(.badServerResponse)
    }

    let payload = Data("data".utf8)
    let frame = try pair.client.makeDatagramFrame(sessionID: session.id, payload: payload)
    let datagramSession = try pair.server.receiveDatagramFrame(frame)
    #expect(datagramSession == session.id)
    #expect(pair.server.popDatagramPayload(sessionID: session.id) == payload)
}

@Test
func webTransportDatagramRejectsUnknownSession() throws {
    var pair = try WebTransportDatagramTestSupport.makeReadyManagers()

    let unknownSessionDatagram = try WebTransportDatagramSignaling.serialize(
        sessionID: 0,
        payload: Data("x".utf8)
    )
    #expect(throws: Error.self) {
        try pair.client.receiveDatagramFrame(.datagram(unknownSessionDatagram))
    }
}

@Test
func webTransportDatagramEnforcesConfiguredFrameSize() throws {
    var pair = try WebTransportDatagramTestSupport.makeReadyManagers(maxDatagramFrameSize: 4)
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

    guard let session = pair.client.session(forRequestStreamID: 0) else {
        throw URLError(.badServerResponse)
    }

    // sessionID 0 encodes to one byte, so total frame size of 4 can carry 3 payload bytes.
    let allowed = Data("abc".utf8)
    let datagramFrame = try pair.client.makeDatagramFrame(sessionID: session.id, payload: allowed)
    #expect(datagramFrame == .datagram(try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: allowed)))
    #expect(throws: Error.self) {
        try pair.client.makeDatagramFrame(sessionID: session.id, payload: Data("abcd".utf8))
    }

    _ = try pair.server.receiveDatagramFrame(datagramFrame)
    #expect(pair.server.popDatagramPayload(sessionID: session.id) == allowed)
}

@Test
func webTransportDatagramReceiveBackpressureIsEnforced() throws {
    var pair = try WebTransportDatagramTestSupport.makeReadyManagers(
        maxDatagramFrameSize: 4,
        maxDatagramReceiveBufferBytes: 4
    )

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

    guard let session = pair.server.session(forRequestStreamID: 0) else {
        throw URLError(.badServerResponse)
    }

    let smallPayload = Data([0x01, 0x02])
    let first = try pair.client.makeDatagramFrame(sessionID: session.id, payload: smallPayload)
    let second = try pair.client.makeDatagramFrame(sessionID: session.id, payload: smallPayload)
    _ = try pair.server.receiveDatagramFrame(first)
    _ = try pair.server.receiveDatagramFrame(second)

    #expect(throws: Error.self) {
        let extra = try pair.client.makeDatagramFrame(sessionID: session.id, payload: Data([0x03]))
        _ = try pair.server.receiveDatagramFrame(extra)
    }
}

private enum WebTransportDatagramTestSupport {
    static func makeReadyManagers(
        maxDatagramFrameSize: Int = 1_200,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(
                http3: clientHTTP3,
                maxDatagramFrameSize: maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes
            ),
            WebTransportSessionManager(
                http3: serverHTTP3,
                maxDatagramFrameSize: maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes
            )
        )
    }
}
