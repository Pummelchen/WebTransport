import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportFlowControlCapsulesSerializeAndParseRoundTrip() throws {
    let cases: [WebTransportFlowCapsule] = [
        .maxData(limit: 1),
        .maxStreamsBidi(limit: 2),
        .maxStreamsUni(limit: 3),
        .dataBlocked(limit: 4),
        .streamsBlockedBidi(limit: 5),
        .streamsBlockedUni(limit: 6),
        .unknown(type: 0x190b_4d99, payload: Data([0x0a, 0x0b]))
    ]

    for expected in cases {
        let serialized = try WebTransportFlowCapsuleCodec.serialize(expected)
        let parsed = try WebTransportFlowCapsuleCodec.parse(serialized)
        #expect(parsed.capsule == expected)
    }
}

@Test
func webTransportFlowControlRejectsMalformedCapsulePayload() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let malformedPayloadType = try QUICVarInt.encode(constants.wtMaxDataCapsule)
    let malformedPayloadLength = try QUICVarInt.encode(2)
    let malformedPayload = malformedPayloadType + malformedPayloadLength + Data([0x01])
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(malformedPayload)
    }

    let truncatedPayloadType = try QUICVarInt.encode(constants.wtMaxDataCapsule)
    let truncatedPayloadLength = try QUICVarInt.encode(0)
    let truncatedPayload = truncatedPayloadType + truncatedPayloadLength
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(truncatedPayload)
    }
}

@Test
func webTransportFlowControlStreamLimitsEmitStreamsBlockedCapsules() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(
        maxStreamsBidi: 1,
        maxStreamsUni: 1
    )

    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )
    let openPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: openPrefix)

    #expect(throws: Error.self) {
        try pair.client.openBidirectionalStream(streamID: 8, sessionID: sessionID)
    }

    guard let queued = try pair.client.popFlowControlCapsule(sessionID: sessionID) else {
        throw URLError(.badServerResponse)
    }
    let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
    #expect(parsed.capsule == .streamsBlockedBidi(limit: 1))

    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 2))
    )

    let state = pair.client.flowState(for: sessionID)
    #expect(state?.maxStreamsBidi == 2)
    #expect(state?.openedBidiStreams == 1)

    let reopen = try pair.client.openBidirectionalStream(streamID: 8, sessionID: sessionID)
    #expect(!reopen.isEmpty)
}

@Test
func webTransportFlowControlDataLimitsEmitDataBlockedCapsules() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(maxData: 4)
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data([0x01, 0x02, 0x03]))
    #expect(throws: Error.self) {
        _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data([0x04, 0x05]))
    }
    guard let blocked = try pair.client.popFlowControlCapsule(sessionID: sessionID) else {
        throw URLError(.badServerResponse)
    }
    #expect(
        try WebTransportFlowControlCodecTestHelpers.isDataBlocked(
            parsed: WebTransportFlowCapsuleCodec.parse(blocked),
            limit: 4
        )
    )

    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 6))
    )

    let updatedDatagram = try pair.client.makeDatagramFrame(
        sessionID: sessionID,
        payload: Data([0x04, 0x05])
    )
    #expect(updatedDatagram == .datagram(try WebTransportDatagramSignaling.serialize(
        sessionID: sessionID.rawValue,
        payload: Data([0x04, 0x05])
    )))
}

@Test
func webTransportFlowControlTracksReceivePayloadAgainstSessionDataLimit() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(maxData: 4)
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    let prefix = try pair.client.openUnidirectionalStream(streamID: 6, sessionID: sessionID)
    _ = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: prefix)

    try pair.server.receiveStreamPayload(streamID: 6, payload: Data([0x01, 0x02, 0x03]))
    #expect(throws: Error.self) {
        try pair.server.receiveStreamPayload(streamID: 6, payload: Data([0x03, 0x04]))
    }

    guard let blocked = try pair.server.popFlowControlCapsule(sessionID: sessionID) else {
        throw URLError(.badServerResponse)
    }
    #expect(
        try WebTransportFlowControlCodecTestHelpers.isDataBlocked(
            parsed: WebTransportFlowCapsuleCodec.parse(blocked),
            limit: 4
        )
    )
}

private enum WebTransportFlowControlTestSupport {
    static func makeReadyManagers(
        maxStreamsBidi: UInt64? = nil,
        maxStreamsUni: UInt64? = nil,
        maxData: UInt64? = nil,
        maxDatagramFrameSize: Int = 1_200,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxStreamReceiveBufferBytes: Int = 64 * 1024
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        let constants = WebTransportHTTP3DraftConstants.current
        var clientSettings = HTTP3Settings.webTransportDraft15Defaults
        var serverSettings = HTTP3Settings.webTransportDraft15Defaults

        if let maxStreamsBidi {
            try clientSettings.set(maxStreamsBidi, for: constants.settingsWTInitialMaxStreamsBidi)
            try serverSettings.set(maxStreamsBidi, for: constants.settingsWTInitialMaxStreamsBidi)
        }
        if let maxStreamsUni {
            try clientSettings.set(maxStreamsUni, for: constants.settingsWTInitialMaxStreamsUni)
            try serverSettings.set(maxStreamsUni, for: constants.settingsWTInitialMaxStreamsUni)
        }
        if let maxData {
            try clientSettings.set(maxData, for: constants.settingsWTInitialMaxData)
            try serverSettings.set(maxData, for: constants.settingsWTInitialMaxData)
        }

        var clientHTTP3 = HTTP3ConnectionState(role: .client, localSettings: clientSettings)
        var serverHTTP3 = HTTP3ConnectionState(role: .server, localSettings: serverSettings)

        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())

        return (
            WebTransportSessionManager(
                http3: clientHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramFrameSize: maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes
            ),
            WebTransportSessionManager(
                http3: serverHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramFrameSize: maxDatagramFrameSize,
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

private enum WebTransportFlowControlCodecTestHelpers {
    static func isDataBlocked(
        parsed: WebTransportFlowCapsuleEnvelope,
        limit: UInt64
    ) -> Bool {
        parsed == .init(
            capsule: .dataBlocked(limit: limit),
            bytesConsumed: parsed.bytesConsumed,
            payload: parsed.payload
        )
    }
}
