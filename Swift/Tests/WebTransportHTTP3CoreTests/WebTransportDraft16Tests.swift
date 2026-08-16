import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func draft16RejectsSettingsWTEnabledAboveOneWithH3SettingsError() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var settings = HTTP3Settings.webTransportDraft16Defaults
    try settings.set(2, for: constants.settingsWTEnabled)

    do {
        try settings.validateWebTransportDraft16Requirements(peerRole: .server)
        Issue.record("SETTINGS_WT_ENABLED > 1 should fail")
    } catch let error as HTTP3ConnectionError {
        #expect(error.code == .settingsError)
    }
}

@Test
func draft16FlowControlRequiresNonzeroIntentFromBothEndpointsAndDefaultsMissingLimitsToZero() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var local = HTTP3Settings.webTransportDraft16Defaults
    var remote = HTTP3Settings.webTransportDraft16Defaults
    try local.set(8, for: constants.settingsWTInitialMaxData)

    #expect(!local.webTransportFlowControlEnabled(with: remote))
    try remote.set(4, for: constants.settingsWTInitialMaxStreamsBidi)
    #expect(local.webTransportFlowControlEnabled(with: remote))

    let state = WebTransportFlowControlState(settings: remote, isEnabled: true)
    #expect(state.maxDataState == .zero)
    #expect(state.maxStreamsBidiState == .limited(4))
    #expect(state.maxStreamsUniState == .zero)
}

@Test
func draft16IgnoresFlowControlCapsulesWhenFlowControlWasNotNegotiated() throws {
    var pair = try Draft16TestSupport.makeReadyPair()
    let sessionID = try Draft16TestSupport.establishSession(pair: &pair)
    let constants = WebTransportHTTP3DraftConstants.current
    let oversized = try WebTransportFlowCapsuleCodec.serialize(
        .streamsBlockedBidi(limit: constants.maximumMaxStreamsValue + 1)
    )

    let received = try pair.client.receiveFlowControlCapsule(
        sessionID: sessionID,
        bytes: oversized
    )
    #expect(
        received
            == .unknown(
                type: constants.wtStreamsBlockedBidiCapsule,
                payload: try QUICVarInt.encode(constants.maximumMaxStreamsValue + 1)
            ))
    #expect(pair.client.flowState(for: sessionID)?.isEnabled == false)
    #expect(pair.client.sessionsByID[sessionID]?.state == .accepted)
}

@Test
func draft16EqualFlowControlUpdatesCloseTheSession() throws {
    var pair = try Draft16TestSupport.makeReadyPair(flowControl: true)
    let sessionID = try Draft16TestSupport.establishSession(pair: &pair)

    #expect(throws: WebTransportDraft16Error.self) {
        _ = try pair.client.receiveFlowControlCapsule(
            sessionID: sessionID,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 8))
        )
    }
    #expect(
        pair.client.sessionsByID[sessionID]?.state
            == .closed(
                applicationErrorCode: UInt32(WebTransportHTTP3DraftConstants.current.wtFlowControlError),
                message: "WebTransport flow-control violation"
            ))
}

@Test
func draft16OversizedBlockedAndHTTP2OnlyCapsulesCloseTheSession() throws {
    let constants = WebTransportHTTP3DraftConstants.current

    var blockedPair = try Draft16TestSupport.makeReadyPair(flowControl: true)
    let blockedSession = try Draft16TestSupport.establishSession(pair: &blockedPair)
    #expect(throws: WebTransportDraft16Error.self) {
        _ = try blockedPair.client.receiveFlowControlCapsule(
            sessionID: blockedSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(
                .streamsBlockedBidi(limit: constants.maximumMaxStreamsValue + 1)
            )
        )
    }
    #expect(Draft16TestSupport.isFlowControlClosed(blockedPair.client.sessionsByID[blockedSession]?.state))

    for prohibitedType in [constants.wtMaxStreamDataCapsule, constants.wtStreamDataBlockedCapsule] {
        var pair = try Draft16TestSupport.makeReadyPair(flowControl: true)
        let sessionID = try Draft16TestSupport.establishSession(pair: &pair)
        let bytes = try QUICVarInt.encode(prohibitedType) + QUICVarInt.encode(0)
        #expect(throws: WebTransportDraft16Error.self) {
            _ = try pair.server.receiveFlowControlCapsule(sessionID: sessionID, bytes: bytes)
        }
        #expect(Draft16TestSupport.isFlowControlClosed(pair.server.sessionsByID[sessionID]?.state))
    }
}

@Test
func draft16MalformedCloseMessagesResetConnectStreamWithH3MessageError() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let payloads = [
        Data(repeating: 0, count: 4) + Data(repeating: 0x61, count: constants.wtCloseSessionMaxMessageBytes + 1),
        Data(repeating: 0, count: 4) + Data([0xff]),
    ]

    for payload in payloads {
        var pair = try Draft16TestSupport.makeReadyPair()
        let sessionID = try Draft16TestSupport.establishSession(pair: &pair)
        let capsule =
            try QUICVarInt.encode(constants.wtCloseSessionCapsule)
            + QUICVarInt.encode(UInt64(payload.count))
            + payload
        let result = try pair.server.receiveConnectStreamCapsulesWithActions(
            streamID: sessionID.rawValue,
            bytes: capsule
        )
        #expect(
            result.connectResetFrame
                == .resetStream(
                    id: sessionID.rawValue,
                    applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
                    finalSize: 0
                ))
        #expect(result.terminationActions != nil)
    }
}

@Test
func draft16OptimisticCapsulesAreProcessedOnlyAfterAcceptance() throws {
    var acceptedPair = try Draft16TestSupport.makeReadyPair()
    let request = try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    let requestFrame = try acceptedPair.client.makeClientSessionRequest(streamID: 0, request: request)
    let sessionID = WebTransportSessionID(rawValue: 0)
    let optimisticDrain = try acceptedPair.client.makeOptimisticConnectStreamCapsule(
        sessionID: sessionID,
        capsule: .drainSession
    )
    let decision = try acceptedPair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: WebTransportServerSessionPolicy()
    )
    #expect(decision.session.state == .accepted)
    #expect(acceptedPair.server.sessionsByID[sessionID]?.state == .accepted)

    let processed = try acceptedPair.server.receiveConnectStreamCapsulesWithActions(
        streamID: 0,
        bytes: optimisticDrain
    )
    #expect(processed.receivedCapsules.map(\.capsule) == [.drainSession])
    #expect(acceptedPair.server.sessionsByID[sessionID]?.state == .draining)

    var rejectedPair = try Draft16TestSupport.makeReadyPair()
    let rejectedFrame = try rejectedPair.client.makeClientSessionRequest(streamID: 0, request: request)
    let rejected = try rejectedPair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: rejectedFrame,
        policy: WebTransportServerSessionPolicy(allowedPaths: ["/different"])
    )
    #expect(rejected.session.state == .rejected(status: 405))
    // Deliberately malformed optimistic bytes are discarded by the caller on rejection.
    #expect(rejectedPair.server.sessionsByID[sessionID]?.state == .rejected(status: 405))
}

@Test
func draft16DatagramsDoNotConsumeSessionStreamDataCredit() throws {
    var pair = try Draft16TestSupport.makeReadyPair(flowControl: true)
    let sessionID = try Draft16TestSupport.establishSession(pair: &pair)

    _ = try pair.client.makeDatagramFrame(
        sessionID: sessionID,
        payload: Data(repeating: 1, count: 32)
    )
    #expect(pair.client.flowState(for: sessionID)?.usedData == 0)
}

@Test
func draft16ServerMapsExcessSessionWithoutFlowControlToH3RequestRejected() throws {
    var pair = try Draft16TestSupport.makeReadyPair()
    _ = try Draft16TestSupport.establishSession(pair: &pair)
    let secondRequest = try QPACK.headersFrame(
        fields: WebTransportSessionRequest(
            authority: "example.com",
            path: "/second"
        ).headers())

    do {
        _ = try pair.server.receiveClientSessionRequest(
            streamID: 4,
            frame: secondRequest,
            policy: WebTransportServerSessionPolicy()
        )
        Issue.record("the excessive CONNECT stream should be rejected")
    } catch let error as WebTransportDraft16Error {
        #expect(error.kind == .requestRejected)
        #expect(error.code == HTTP3ApplicationErrorCode.requestRejected.rawValue)
        #expect(
            WebTransportDraft16ErrorMapper.streamFrame(
                for: error.kind,
                signal: .resetStream(streamID: 4, finalSize: 0)
            )
                == .resetStream(
                    id: 4,
                    applicationErrorCode: HTTP3ApplicationErrorCode.requestRejected.rawValue,
                    finalSize: 0
                ))
    }
}

@Test
func draft16ExporterContextUsesFixedSessionIDAndByteLengths() throws {
    let context = try WebTransportExporter.context(
        sessionID: WebTransportSessionID(rawValue: 0x0102_0304_0506_0708),
        applicationLabel: Data("label".utf8),
        applicationContext: Data([0xaa, 0xbb])
    )
    #expect(
        context
            == Data([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c,
                0x02, 0xaa, 0xbb,
            ]))
    #expect(WebTransportExporter.tlsLabel == "EXPORTER-WebTransport")
}

private enum Draft16TestSupport {
    static func makeReadyPair(
        flowControl: Bool = false
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        let constants = WebTransportHTTP3DraftConstants.current
        var clientSettings = HTTP3Settings.webTransportDraft16Defaults
        var serverSettings = HTTP3Settings.webTransportDraft16Defaults
        if flowControl {
            for settingsID in [
                constants.settingsWTInitialMaxStreamsBidi,
                constants.settingsWTInitialMaxStreamsUni,
            ] {
                try clientSettings.set(8, for: settingsID)
                try serverSettings.set(8, for: settingsID)
            }
            try clientSettings.set(8, for: constants.settingsWTInitialMaxData)
            try serverSettings.set(8, for: constants.settingsWTInitialMaxData)
        }

        var clientHTTP3 = HTTP3ConnectionState(role: .client, localSettings: clientSettings)
        var serverHTTP3 = HTTP3ConnectionState(role: .server, localSettings: serverSettings)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(http3: clientHTTP3),
            WebTransportSessionManager(http3: serverHTTP3)
        )
    }

    static func establishSession(
        pair: inout (client: WebTransportSessionManager, server: WebTransportSessionManager)
    ) throws -> WebTransportSessionID {
        let request = try pair.client.makeClientSessionRequest(
            streamID: 0,
            request: WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
        let decision = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: request,
            policy: WebTransportServerSessionPolicy()
        )
        return try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame).id
    }

    static func isFlowControlClosed(_ state: WebTransportSessionState?) -> Bool {
        guard case .closed(let code, _) = state else {
            return false
        }
        return code == UInt32(WebTransportHTTP3DraftConstants.current.wtFlowControlError)
    }
}
