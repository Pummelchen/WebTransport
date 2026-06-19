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
func webTransportFlowControlStateDistinguishesDisabledZeroAndUnlimitedModes() throws {
    let disabled = WebTransportFlowControlState()
    #expect(disabled.maxDataState == .disabled)
    #expect(disabled.maxStreamsBidiState == .disabled)
    #expect(disabled.maxStreamsUniState == .disabled)
    #expect(disabled.maxData == nil)
    #expect(disabled.maxStreamsBidi == nil)

    let explicitZero = WebTransportFlowControlState(
        maxData: 0,
        maxStreamsBidi: 0,
        maxStreamsUni: 0,
        isEnabled: true
    )
    #expect(explicitZero.maxDataState == .zero)
    #expect(explicitZero.maxStreamsBidiState == .zero)
    #expect(explicitZero.maxStreamsUniState == .zero)
    #expect(explicitZero.maxData == 0)
    #expect(explicitZero.maxStreamsBidi == 0)

    var withSettings = WebTransportFlowControlState(
        maxData: nil,
        maxStreamsBidi: nil,
        maxStreamsUni: nil,
        isEnabled: true
    )
    #expect(withSettings.maxDataState == .unlimited)
    #expect(withSettings.maxStreamsBidiState == .unlimited)
    #expect(withSettings.maxStreamsUniState == .unlimited)
    #expect(withSettings.maxData == nil)
    #expect(withSettings.maxStreamsBidi == nil)

    try withSettings.apply(.maxData(limit: 4))
    try withSettings.apply(.maxStreamsBidi(limit: 2))
    try withSettings.apply(.maxStreamsUni(limit: 1))
    #expect(withSettings.maxData == 4)
    #expect(withSettings.maxStreamsBidi == 2)
    #expect(withSettings.maxStreamsUni == 1)
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
func webTransportMaxStreamsCapsulesRejectValuesAboveDraftLimit() throws {
    let invalidLimit = WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue + 1

    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(try WebTransportFlowCapsuleCodec.serialize(
            .maxStreamsBidi(limit: invalidLimit)
        ))
    }
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(try WebTransportFlowCapsuleCodec.serialize(
            .maxStreamsUni(limit: invalidLimit)
        ))
    }
    _ = try WebTransportFlowCapsuleCodec.parse(try WebTransportFlowCapsuleCodec.serialize(
        .maxStreamsBidi(limit: WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue)
    ))

    var state = WebTransportFlowControlState(maxData: nil, maxStreamsBidi: 0, maxStreamsUni: 0)
    #expect(throws: Error.self) {
        try state.apply(.maxStreamsBidi(limit: invalidLimit))
    }
    #expect(throws: Error.self) {
        try state.apply(.maxStreamsUni(limit: invalidLimit))
    }
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
func webTransportFlowControlRepeatedDataBlockedDoesNotAdvanceUsageOrDuplicateCapsules() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(maxData: 4)
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data([0x01, 0x02, 0x03]))
    #expect(pair.client.flowState(for: sessionID)?.usedData == 3)

    for _ in 0..<3 {
        #expect(throws: Error.self) {
            _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data([0x04, 0x05]))
        }
        #expect(pair.client.flowState(for: sessionID)?.usedData == 3)
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
    #expect(try pair.client.popFlowControlCapsule(sessionID: sessionID) == nil)
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
    #expect(pair.server.sessionsByID[sessionID]?.state == .closed(
        applicationErrorCode: UInt32(WebTransportHTTP3DraftConstants.current.wtFlowControlError),
        message: "WebTransport flow-control violation"
    ))
    #expect(try pair.server.popFlowControlCapsule(sessionID: sessionID) == nil)
}

@Test
func webTransportFlowControlRepeatedStreamsBlockedDoesNotAdvanceOpenCountsOrDuplicateCapsules() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(maxStreamsBidi: 1)
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    _ = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    #expect(pair.client.flowState(for: sessionID)?.openedBidiStreams == 1)

    for streamID in [8, 12, 16] {
        #expect(throws: Error.self) {
            _ = try pair.client.openBidirectionalStream(streamID: UInt64(streamID), sessionID: sessionID)
        }
        #expect(pair.client.flowState(for: sessionID)?.openedBidiStreams == 1)
    }

    guard let blocked = try pair.client.popFlowControlCapsule(sessionID: sessionID) else {
        throw URLError(.badServerResponse)
    }
    #expect(try WebTransportFlowCapsuleCodec.parse(blocked).capsule == .streamsBlockedBidi(limit: 1))
    #expect(try pair.client.popFlowControlCapsule(sessionID: sessionID) == nil)
}

@Test
func webTransportFlowControlRejectsDecreasingMaxUpdates() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(
        maxStreamsBidi: 2,
        maxStreamsUni: 2,
        maxData: 8
    )
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 10))
    )
    #expect(pair.client.flowState(for: sessionID)?.maxData == 10)

    do {
        _ = try pair.client.receiveFlowControlCapsule(
            sessionID: sessionID,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 4))
        )
        Issue.record("decreasing WT_MAX_DATA should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .flowControl)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtFlowControlError)
    }

    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.receiveFlowControlCapsule(
            sessionID: sessionID,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 1))
        )
    }
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.client.receiveFlowControlCapsule(
            sessionID: sessionID,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsUni(limit: 1))
        )
    }
}

@Test
func webTransportFlowControlRejectsMaliciousOrderUpdatesWithoutMutatingState() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(
        maxStreamsBidi: 2,
        maxStreamsUni: 2,
        maxData: 8
    )
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )

    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 10))
    )
    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 4))
    )
    _ = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsUni(limit: 5))
    )
    let before = pair.client.flowState(for: sessionID)

    for capsule in [
        WebTransportFlowCapsule.maxData(limit: 9),
        .maxStreamsBidi(limit: 3),
        .maxStreamsUni(limit: 4)
    ] {
        #expect(throws: WebTransportDraft15Error.self) {
            _ = try pair.client.receiveFlowControlCapsule(
                sessionID: sessionID,
                bytes: try WebTransportFlowCapsuleCodec.serialize(capsule)
            )
        }
        #expect(pair.client.flowState(for: sessionID) == before)
    }
}

@Test
func webTransportFlowControlClosedSessionRejectsPostCloseAccounting() throws {
    var pair = try WebTransportFlowControlTestSupport.makeReadyManagers(maxData: 8)
    let sessionID = try WebTransportFlowControlTestSupport.establishSession(
        client: &pair.client,
        server: &pair.server
    )
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)

    _ = try pair.server.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 1, message: "closed"))
    )

    #expect(throws: WebTransportDraft15Error.self) {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("x".utf8))
    }
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try pair.server.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: sessionID.rawValue, payload: Data("x".utf8))
        ))
    }
    #expect(pair.server.flowState(for: sessionID)?.usedData == 0)
    #expect(pair.server.flowState(for: sessionID)?.openedBidiStreams == 1)
    #expect(try pair.server.popFlowControlCapsule(sessionID: sessionID) == nil)
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
