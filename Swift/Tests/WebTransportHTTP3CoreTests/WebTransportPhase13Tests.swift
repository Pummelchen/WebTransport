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
    let maximumSized = String(repeating: "x", count: WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes)
    let oversized = String(repeating: "x", count: WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 1)

    _ = try WebTransportFlowCapsuleCodec.serialize(.closeSession(
        applicationErrorCode: 1,
        message: maximumSized
    ))

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
func webTransportServerBuffersIngressBeforeConnectRequestArrives() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()

    let earlyDatagram = try WebTransportDatagramSignaling.serialize(
        sessionID: 0,
        payload: Data("server-early-d".utf8)
    )
    _ = try pair.server.receiveDatagramFrame(.datagram(earlyDatagram))

    let earlyPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    _ = try pair.server.acceptBidirectionalStream(
        streamID: 4,
        firstBytes: earlyPrefix + Data("server-early-s".utf8)
    )
    #expect(pair.server.stream(for: 4) == nil)
    #expect(pair.server.bufferedStreamIDs(for: WebTransportSessionID(rawValue: 0))?.contains(4) == true)

    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )

    #expect(decision.session.state == .accepted)
    #expect(pair.server.popDatagramPayload(sessionID: WebTransportSessionID(rawValue: 0)) == Data("server-early-d".utf8))
    #expect(pair.server.stream(for: 4) != nil)
    #expect(pair.server.popStreamPayload(streamID: 4) == Data("server-early-s".utf8))
}

@Test
func webTransportServerDiscardsBufferedIngressWhenConnectIsRejected() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    _ = try pair.server.receiveDatagramFrame(.datagram(
        try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("reject-d".utf8))
    ))
    let earlyPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    _ = try pair.server.acceptBidirectionalStream(
        streamID: 4,
        firstBytes: earlyPrefix + Data("reject-s".utf8)
    )

    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/blocked")
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy(allowedPaths: ["/wt"])
    )

    #expect(decision.session.state == .rejected(status: 404))
    #expect(pair.server.popDatagramPayload(sessionID: WebTransportSessionID(rawValue: 0)) == nil)
    #expect(pair.server.stream(for: 4) == nil)
    #expect(throws: WebTransportDraft15Error.self) {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("late".utf8))
    }
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
func webTransportServerBufferedIngressCountExhaustionMapsToBufferedStreamRejected() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers(
        maxBufferedStreamsPerSession: 1,
        maxBufferedDatagramsPerSession: 1
    )

    _ = try pair.server.receiveDatagramFrame(.datagram(
        try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("a".utf8))
    ))
    do {
        _ = try pair.server.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("b".utf8))
        ))
        Issue.record("second early datagram should exceed buffered count")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .bufferedStreamRejected)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError)
    }

    let firstPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: firstPrefix)
    do {
        let secondPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
        _ = try pair.server.acceptBidirectionalStream(streamID: 8, firstBytes: secondPrefix)
        Issue.record("second early stream should exceed buffered count")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .bufferedStreamRejected)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError)
    }
}

@Test
func webTransportServerBufferedSessionExhaustionMapsToBufferedStreamRejected() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers(maxBufferedSessions: 1)

    _ = try pair.server.receiveDatagramFrame(.datagram(
        try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("a".utf8))
    ))
    do {
        _ = try pair.server.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 4, payload: Data("b".utf8))
        ))
        Issue.record("second early session should exceed buffered session count")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .bufferedStreamRejected)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError)
    }
}

@Test
func webTransportDraft15ErrorMapperCoversRequiredOutcomes() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let cases: [(WebTransportDraft15ErrorKind, UInt64)] = [
        (.bufferedStreamRejected, constants.wtBufferedStreamRejectedError),
        (.sessionGone, constants.wtSessionGoneError),
        (.flowControl, constants.wtFlowControlError),
        (.alpn, constants.wtALPNError),
        (.requirementsNotMet, constants.wtRequirementsNotMetError),
        (.h3ID, HTTP3ApplicationErrorCode.idError.rawValue)
    ]

    for (kind, code) in cases {
        #expect(WebTransportDraft15ErrorMapper.code(for: kind) == code)
        #expect(WebTransportDraft15ErrorMapper.connectionCloseFrame(
            for: kind,
            reason: "reason"
        ) == .connectionClose(errorCode: code, frameType: nil, reason: Data("reason".utf8)))
        #expect(WebTransportDraft15ErrorMapper.streamFrame(
            for: kind,
            signal: .resetStream(streamID: 4, finalSize: 9)
        ) == .resetStream(id: 4, applicationErrorCode: code, finalSize: 9))
        #expect(WebTransportDraft15ErrorMapper.streamFrame(
            for: kind,
            signal: .stopSending(streamID: 4)
        ) == .stopSending(id: 4, applicationErrorCode: code))
    }

    let close = try WebTransportDraft15ErrorMapper.closeSessionCapsule(
        for: .requirementsNotMet,
        message: "policy"
    )
    #expect(try WebTransportFlowCapsuleCodec.parse(close).capsule == .closeSession(
        applicationErrorCode: UInt32(constants.wtRequirementsNotMetError),
        message: "policy"
    ))
}

@Test
func webTransportSecurityNegativesAreDeterministicAndPromptFree() throws {
    let constants = WebTransportHTTP3DraftConstants.current

    do {
        try WebTransportALPNPolicy.validateNegotiatedProtocol("hq-interop")
        Issue.record("wrong negotiated ALPN should be rejected")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .alpn)
        #expect(error.code == constants.wtALPNError)
        #expect(WebTransportDraft15ErrorMapper.connectionCloseFrame(
            for: error.kind,
            reason: error.message
        ) == .connectionClose(
            errorCode: constants.wtALPNError,
            frameType: nil,
            reason: Data(error.message.utf8)
        ))
    }
    do {
        try WebTransportALPNPolicy.validateOfferedProtocols(["webtransport"])
        Issue.record("wrong offered ALPN should be rejected")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .alpn)
        #expect(error.code == constants.wtALPNError)
    }
    try WebTransportALPNPolicy.validateOfferedProtocols(["h3"])

    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let badOriginFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            origin: "https://bad.example"
        )
    )
    let originDecision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: badOriginFrame,
        policy: try WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
    )
    #expect(originDecision.session.state == .rejected(status: 403))
    #expect(originDecision.rejectionError?.kind == .requirementsNotMet)
    #expect(originDecision.rejectionError?.code == constants.wtRequirementsNotMetError)
    #expect(pair.server.session(forRequestStreamID: 0)?.state == .rejected(status: 403))

    var wrongSettings = HTTP3Settings.webTransportDraft15Defaults
    try wrongSettings.set(0, for: constants.settingsWTEnabled)
    let wrongSettingsControl = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: wrongSettings.frame().encode()
    )
    var connection = HTTP3ConnectionState(role: .client)
    do {
        _ = try connection.receivePeerControlStream(wrongSettingsControl)
        Issue.record("wrong WebTransport SETTINGS should be rejected")
    } catch let error as QUICCodecError {
        #expect(error == .malformed("WebTransport over HTTP/3 requires SETTINGS_WT_ENABLE_WEBTRANSPORT = 1"))
    }
    #expect(connection.remoteSettings == nil)
    #expect(connection.receivedPeerControlStream == false)
    #expect(connection.closeFrame(
        error: .settingsError,
        reason: "WebTransport settings rejected",
        frameType: HTTP3FrameType.settings
    ) == .connectionClose(
        errorCode: HTTP3ApplicationErrorCode.settingsError.rawValue,
        frameType: HTTP3FrameType.settings,
        reason: Data("WebTransport settings rejected".utf8)
    ))
}

@Test
func webTransportLibrarySmokeMatrixCoversPhase13IScenarios() throws {
    let results = WebTransportLibrarySmokeMatrix.runAll()
    #expect(results.map(\.scenario) == WebTransportLibrarySmokeScenario.allCases)
    #expect(results.allSatisfy { $0.passed })
    #expect(results.map(\.detail).allSatisfy { $0 == "passed" })
}

@Test
func webTransportDraft15ComplianceDefinitionOfDoneIsExplicitAndPassing() {
    let items = WebTransportDraft15ComplianceMatrix.definitionOfDone
    #expect(WebTransportDraft15ComplianceMatrix.allPass)
    #expect(items.map(\.requirementFamily) == [
        "Session establishment and application protocol negotiation",
        "Streams and datagrams, including buffered ingress and rejection behavior",
        "Session close/drain behavior",
        "Flow-control and error codes",
        "H3 control and request stream constraints",
        "Security and identity handling without prompts"
    ])
    #expect(items.allSatisfy { $0.status == .pass })
    #expect(items.allSatisfy { !$0.documentedBehavior.isEmpty })
    #expect(items.allSatisfy { !$0.evidence.isEmpty })
}

@Test
func webTransportRejectsMalformedConnectDataOrderingWithRequirementsNotMet() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    do {
        _ = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: try HTTP3Frame(type: HTTP3FrameType.data, payload: Data("data-first".utf8)),
            policy: try WebTransportServerSessionPolicy()
        )
        Issue.record("CONNECT stream DATA before HEADERS should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .requirementsNotMet)
        #expect(error.code == WebTransportHTTP3DraftConstants.current.wtRequirementsNotMetError)
    }
}

@Test
func webTransportProtocolPolicyRejectionsCarryRequirementsNotMetError() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    let requestFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/blocked")
    )
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy(allowedPaths: ["/wt"])
    )

    #expect(decision.session.state == .rejected(status: 404))
    #expect(decision.rejectionError?.kind == .requirementsNotMet)
    #expect(decision.rejectionError?.code == WebTransportHTTP3DraftConstants.current.wtRequirementsNotMetError)
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
func webTransportMapsInvalidStreamSessionIDsToH3IDError() throws {
    var pair = try WebTransportPhase13Support.makeReadyManagers()
    var firstBytes = Data()
    firstBytes.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtStreamFrame))
    firstBytes.append(try QUICVarInt.encode(2))

    do {
        _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: firstBytes)
        Issue.record("invalid session ID should throw H3_ID_ERROR")
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
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedDatagramsPerSession: Int = 64,
        maxBufferedSessions: Int = 64
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return (
            WebTransportSessionManager(
                http3: clientHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
                maxBufferedSessions: maxBufferedSessions
            ),
            WebTransportSessionManager(
                http3: serverHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
                maxBufferedSessions: maxBufferedSessions
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
