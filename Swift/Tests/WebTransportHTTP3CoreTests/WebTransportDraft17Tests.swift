import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func draft17RejectsSettingsWTEnabledAboveOneWithH3SettingsError() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var settings = HTTP3Settings.webTransportDraft17Defaults
    try settings.set(2, for: constants.settingsWTEnabled)

    do {
        try settings.validateWebTransportDraft17Requirements(peerRole: .server)
        Issue.record("SETTINGS_WT_ENABLED > 1 should fail")
    } catch let error as HTTP3ConnectionError {
        #expect(error.code == .settingsError)
    }
}

@Test
func draft17FlowControlRequiresNonzeroIntentFromBothEndpointsAndDefaultsMissingLimitsToZero() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var local = HTTP3Settings.webTransportDraft17Defaults
    var remote = HTTP3Settings.webTransportDraft17Defaults
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
func draft17IgnoresFlowControlCapsulesWhenFlowControlWasNotNegotiated() throws {
    var pair = try Draft17TestSupport.makeReadyPair()
    let sessionID = try Draft17TestSupport.establishSession(pair: &pair)
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
func draft17EqualFlowControlUpdatesCloseTheSession() throws {
    var pair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let sessionID = try Draft17TestSupport.establishSession(pair: &pair)

    #expect(throws: WebTransportDraft17Error.self) {
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
func draft17OversizedBlockedAndHTTP2OnlyCapsulesCloseTheSession() throws {
    let constants = WebTransportHTTP3DraftConstants.current

    var blockedPair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let blockedSession = try Draft17TestSupport.establishSession(pair: &blockedPair)
    #expect(throws: WebTransportDraft17Error.self) {
        _ = try blockedPair.client.receiveFlowControlCapsule(
            sessionID: blockedSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(
                .streamsBlockedBidi(limit: constants.maximumMaxStreamsValue + 1)
            )
        )
    }
    #expect(Draft17TestSupport.isFlowControlClosed(blockedPair.client.sessionsByID[blockedSession]?.state))

    for prohibitedType in [constants.wtMaxStreamDataCapsule, constants.wtStreamDataBlockedCapsule] {
        var pair = try Draft17TestSupport.makeReadyPair(flowControl: true)
        let sessionID = try Draft17TestSupport.establishSession(pair: &pair)
        let bytes = try QUICVarInt.encode(prohibitedType) + QUICVarInt.encode(0)
        #expect(throws: WebTransportDraft17Error.self) {
            _ = try pair.server.receiveFlowControlCapsule(sessionID: sessionID, bytes: bytes)
        }
        #expect(Draft17TestSupport.isFlowControlClosed(pair.server.sessionsByID[sessionID]?.state))
    }
}

/// draft-ietf-webtrans-http3-17 section 5.6.2: a WT_MAX_STREAMS value above the
/// draft's 2^60 maximum is a session-level flow-control violation, and the
/// session must be closed with WT_FLOW_CONTROL_ERROR — not merely reported to
/// the CONNECT-stream reader.
///
/// The CONNECT-stream entry point used to parse the capsule a second time in
/// `receiveConnectStreamCapsulesWithActions` and let that parse's error escape
/// before `receiveFlowControlCapsuleWithActions` (which owns the close) ran, so
/// the local session stayed `accepted` while the peer was told the wrong code.
@Test
func draft17ConnectStreamFlowControlViolationClosesTheSession() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var pair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let sessionID = try Draft17TestSupport.establishSession(pair: &pair)
    let oversized = try WebTransportFlowCapsuleCodec.serialize(
        .maxStreamsBidi(limit: constants.maximumMaxStreamsValue + 1)
    )

    #expect(throws: WebTransportDraft17Error.self) {
        _ = try pair.server.receiveConnectStreamCapsulesWithActions(
            streamID: sessionID.rawValue,
            bytes: oversized
        )
    }
    #expect(
        Draft17TestSupport.isFlowControlClosed(pair.server.sessionsByID[sessionID]?.state),
        "the CONNECT-stream path must close the session with WT_FLOW_CONTROL_ERROR"
    )
}

@Test
func draft17MalformedCloseMessagesResetConnectStreamWithH3MessageError() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let payloads = [
        Data(repeating: 0, count: 4) + Data(repeating: 0x61, count: constants.wtCloseSessionMaxMessageBytes + 1),
        Data(repeating: 0, count: 4) + Data([0xff]),
    ]

    for payload in payloads {
        var pair = try Draft17TestSupport.makeReadyPair()
        let sessionID = try Draft17TestSupport.establishSession(pair: &pair)
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
func draft17OptimisticCapsulesAreProcessedOnlyAfterAcceptance() throws {
    var acceptedPair = try Draft17TestSupport.makeReadyPair()
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

    var rejectedPair = try Draft17TestSupport.makeReadyPair()
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
func draft17DatagramsDoNotConsumeSessionStreamDataCredit() throws {
    var pair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let sessionID = try Draft17TestSupport.establishSession(pair: &pair)

    _ = try pair.client.makeDatagramFrame(
        sessionID: sessionID,
        payload: Data(repeating: 1, count: 32)
    )
    #expect(pair.client.flowState(for: sessionID)?.usedData == 0)
}

@Test
func draft17ServerMapsExcessSessionWithoutFlowControlToH3RequestRejected() throws {
    var pair = try Draft17TestSupport.makeReadyPair()
    _ = try Draft17TestSupport.establishSession(pair: &pair)
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
    } catch let error as WebTransportDraft17Error {
        #expect(error.kind == .requestRejected)
        #expect(error.code == HTTP3ApplicationErrorCode.requestRejected.rawValue)
        #expect(
            WebTransportDraft17ErrorMapper.streamFrame(
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
func draft17ExporterContextUsesFixedSessionIDAndByteLengths() throws {
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

/// draft-17 section 7.1: the SETTINGS_WT_ENABLED codepoints name the protocol
/// versions in play. A final client sends none, a draft-16 client sends the
/// draft-16 codepoint with value 1, and a server advertises the final codepoint
/// plus the codepoint of every draft it supports. Selection itself is a policy,
/// not a code path — the wire formats did not move between -16 and -17, so one
/// code path serves either peer — and the matrix pins what each profile
/// advertises and which client SETTINGS each accepts instead.
@Test
func draft17VersionNegotiationMatrixFollowsSectionSevenPointOne() throws {
    let constants = WebTransportHTTP3DraftConstants.current

    // Strict server advertisement: the final codepoint only, so a draft-16
    // client finds none of its codepoints and never attempts a session.
    let strictServerSettings = HTTP3WebTransportSettingsValidation.draft17Strict.localSettings(for: .server)
    #expect(strictServerSettings[constants.settingsWTEnabled] == 1)
    #expect(strictServerSettings[constants.settingsWTEnabledDraft16] == nil)

    // Interoperable server advertisement: both codepoints, so a §7.1 server can
    // select the draft-16 version for a draft-16 client.
    let interopServerSettings = HTTP3WebTransportSettingsValidation.interoperable.localSettings(for: .server)
    #expect(interopServerSettings[constants.settingsWTEnabled] == 1)
    #expect(interopServerSettings[constants.settingsWTEnabledDraft16] == 1)

    // Final client (no WT codepoints) and a client that sends the final
    // codepoint are both final-version clients; the server ignores what a
    // client sends, so the strict server accepts both shapes.
    let finalClientSettings = try HTTP3Settings([constants.settingsH3Datagram: 1])
    let finalMarkerClientSettings = try HTTP3Settings([
        constants.settingsH3Datagram: 1,
        constants.settingsWTEnabled: 1,
    ])
    let draft16Client = try draft16ClientSettings()
    for clientSettings in [finalClientSettings, finalMarkerClientSettings, draft16Client] {
        var server = HTTP3ConnectionState(role: .server)
        _ = try server.receivePeerControlStream(controlStreamBytes(clientSettings))
        #expect(server.remoteSettings?.entries == clientSettings.entries)
    }

    // A draft-16 client is identified by the draft-16 codepoint and its value
    // must be 1.
    var invalidVersionServer = HTTP3ConnectionState(role: .server)
    do {
        _ = try invalidVersionServer.receivePeerControlStream(
            controlStreamBytes(
                try HTTP3Settings([
                    constants.settingsH3Datagram: 1,
                    constants.settingsWTEnabledDraft16: 2,
                ])))
        Issue.record("a draft-16 codepoint value other than 1 must be rejected")
    } catch let error as HTTP3ConnectionError {
        #expect(error.code == .settingsError)
    }
}

/// draft-17 section 7.1: a strict client requires the server to advertise the
/// final SETTINGS_WT_ENABLED codepoint; an interoperable client accepts a
/// draft-16-era server that advertises only the draft-16 codepoint.
@Test
func draft17StrictClientRequiresTheFinalServerCodepointAndInteropAcceptsTheDraftOne() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let draft16OnlyServerSettings = try HTTP3Settings([
        constants.settingsEnableConnectProtocol: 1,
        constants.settingsH3Datagram: 1,
        constants.settingsWTEnabledDraft16: 1,
    ])
    let bytes = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try draft16OnlyServerSettings.frame().encode()
    )

    var strictClient = HTTP3ConnectionState(role: .client)
    #expect(throws: Error.self) {
        _ = try strictClient.receivePeerControlStream(bytes)
    }

    var interopClient = HTTP3ConnectionState(role: .client)
    _ = try interopClient.receivePeerControlStream(bytes, settingsValidation: .interoperable)
    #expect(interopClient.remoteSettings?.entries == draft16OnlyServerSettings.entries)
}

/// draft-17 section 3.1: SETTINGS_WT_ENABLED has no meaning when sent by a
/// client, so a final-version client sends none — not even the final codepoint.
@Test
func draft17FinalClientSendsNoSettingsWTEnabled() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let clientSettings = HTTP3WebTransportSettingsValidation.draft17Strict.localSettings(for: .client)
    #expect(clientSettings[constants.settingsEnableConnectProtocol] == 1)
    #expect(clientSettings[constants.settingsH3Datagram] == 1)
    #expect(clientSettings[constants.settingsWTEnabled] == nil)
    #expect(clientSettings[constants.settingsWTEnabledDraft16] == nil)

    // The wire set the client sends is exactly the strict server set minus the
    // final codepoint, and the strict server accepts it as a client's SETTINGS.
    var server = HTTP3ConnectionState(role: .server)
    _ = try server.receivePeerControlStream(
        try HTTP3StreamTypeParser.encodePrefix(
            type: HTTP3StreamType.control,
            payload: try clientSettings.frame().encode()
        ))
    #expect(server.remoteSettings?.entries == clientSettings.entries)
}

/// draft-17 sections 5.6.2 and 5.6.4: a WT_MAX_* capsule must increase the
/// corresponding SETTINGS_WT_INITIAL_MAX_* value when no capsule of that type
/// has been received yet; a grant below that initial value is a flow-control
/// violation and closes the session with WT_FLOW_CONTROL_ERROR.
@Test
func draft17FlowControlGrantBelowSettingsInitialClosesTheSession() throws {
    var streamPair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let streamSession = try Draft17TestSupport.establishSession(pair: &streamPair)
    #expect(throws: WebTransportDraft17Error.self) {
        _ = try streamPair.client.receiveFlowControlCapsule(
            sessionID: streamSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
        )
    }
    #expect(
        Draft17TestSupport.isFlowControlClosed(streamPair.client.sessionsByID[streamSession]?.state),
        "a WT_MAX_STREAMS grant below the peer's SETTINGS initial value must close the session")

    var dataPair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let dataSession = try Draft17TestSupport.establishSession(pair: &dataPair)
    #expect(throws: WebTransportDraft17Error.self) {
        _ = try dataPair.client.receiveFlowControlCapsule(
            sessionID: dataSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 5))
        )
    }
    #expect(
        Draft17TestSupport.isFlowControlClosed(dataPair.client.sessionsByID[dataSession]?.state),
        "a WT_MAX_DATA grant below the peer's SETTINGS initial value must close the session")
}

/// draft-17 sections 5.5 with 5.6.2/5.6.4: the SETTINGS initial value stands in
/// for the "value previously received" while no capsule of that type has arrived,
/// and a capsule that "does not increase" it closes the session — so a grant AT
/// the SETTINGS initial is refused exactly like one below it: the settings
/// themselves already granted that value, and the first capsule must exceed it.
@Test
func draft17FlowControlGrantAtSettingsInitialAlsoClosesTheSession() throws {
    var dataPair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let dataSession = try Draft17TestSupport.establishSession(pair: &dataPair)
    #expect(throws: WebTransportDraft17Error.self) {
        _ = try dataPair.client.receiveFlowControlCapsule(
            sessionID: dataSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 8))
        )
    }
    #expect(
        Draft17TestSupport.isFlowControlClosed(dataPair.client.sessionsByID[dataSession]?.state),
        "a WT_MAX_DATA grant at the peer's SETTINGS initial value does not increase it and must close the session")

    var streamPair = try Draft17TestSupport.makeReadyPair(flowControl: true)
    let streamSession = try Draft17TestSupport.establishSession(pair: &streamPair)
    #expect(throws: WebTransportDraft17Error.self) {
        _ = try streamPair.client.receiveFlowControlCapsule(
            sessionID: streamSession,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 8))
        )
    }
    #expect(
        Draft17TestSupport.isFlowControlClosed(streamPair.client.sessionsByID[streamSession]?.state),
        "a WT_MAX_STREAMS grant at the peer's SETTINGS initial value does not increase it and must close the session")
}

/// draft-17 sections 5.5 with 5.6: which era's flow rule a session runs is decided
/// by what the peer ADVERTISED, and the classifier reads it straight off the parsed
/// SETTINGS — the final codepoint is FINAL whatever its value (the value rules are
/// the settings gate's), the draft-16 codepoint at 1 is DRAFT16, and the earlier
/// drafts' enable settings are LEGACY, which is what every pre-draft-16 peer this
/// tree interoperates with sends (measured against the five deployed VPS peers on
/// 13 November 2026).
@Test
func draft17AdvertisedVersionClassificationFollowsThePeerSettings() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var settings = try HTTP3Settings()
    try settings.set(1, for: constants.settingsWTEnabled)
    #expect(settings.webTransportAdvertisedVersion() == .final)
    try settings.set(7, for: constants.settingsWTEnabled)
    #expect(
        settings.webTransportAdvertisedVersion() == .final,
        "the section 9.2 codepoint's value is the settings gate's rule, not the classifier's")
    var draft = try HTTP3Settings()
    try draft.set(1, for: constants.settingsWTEnabledDraft16)
    #expect(draft.webTransportAdvertisedVersion() == .draft16)
    var legacy = try HTTP3Settings()
    try legacy.set(1, for: HTTP3SettingID.legacyEnableWebTransport)
    try legacy.set(1, for: HTTP3SettingID.legacyWebTransportMaxSessions)
    #expect(
        legacy.webTransportAdvertisedVersion() == .legacy,
        "the advertisement every pre-draft-16 peer sends classifies as legacy")
    #expect(try HTTP3Settings().webTransportAdvertisedVersion() == .legacy)
}

/// A DRAFT16 or LEGACY session runs its era's own rule: no SETTINGS baseline, and a
/// REPEAT of the previously received grant is that era's legal re-grant — only a
/// grant that goes BACKWARDS is the flow-control error. A FINAL session keeps the
/// draft-17 rule, where even a repeat closes the session.
/// A DRAFT16 or LEGACY session runs its era's own rule, which the §7.1 negotiation
/// selected: no SETTINGS baseline, and a REPEAT of the previously received grant is
/// that era's legal re-grant — only a grant that goes BACKWARDS is the flow-control
/// error. A FINAL session keeps the draft-17 rule, where even a repeat closes it.
@Test
func draft17LegacyAdvertisementRunsTheErasOwnFlowRule() throws {
    var legacy = WebTransportFlowControlState(
        maxData: nil,
        maxStreamsBidi: nil,
        maxStreamsUni: nil,
        isEnabled: true,
        refusesRepeats: false
    )
    try legacy.setMaxData(100)
    try legacy.setMaxData(100)
    #expect(legacy.maxData == 100, "a repeat of the received grant is that era's legal re-grant")
    #expect(throws: WebTransportDraft17Error.self) { try legacy.setMaxData(99) }
    try legacy.setMaxStreamsBidi(8)
    try legacy.setMaxStreamsBidi(8)
    #expect(throws: WebTransportDraft17Error.self) { try legacy.setMaxStreamsBidi(4) }

    var strict = WebTransportFlowControlState(
        maxData: nil,
        maxStreamsBidi: nil,
        maxStreamsUni: nil,
        isEnabled: true
    )
    try strict.setMaxData(100)
    #expect(throws: WebTransportDraft17Error.self) {
        try strict.setMaxData(100)
    }
}
/// draft-17 section 4.4: an error code outside the WT_APPLICATION_ERROR range
/// still resets the stream, but it maps to no application error code — a reset
/// with no application error code, and never a session error.
@Test
func draft17ResetOutsideApplicationErrorRangeCarriesNoApplicationErrorCode() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    let inRange = WebTransportDraft17ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x1234)
    #expect(WebTransportDraft17ErrorMapper.receivedApplicationErrorCode(forHTTPErrorCode: inRange) == 0x1234)

    let outsideCodes: [UInt64] = [
        0x21,  // reserved HTTP/3 codepoint form
        0x54,  // an H3-era error code a peer could send on any stream
        HTTP3ApplicationErrorCode.settingsError.rawValue,
        constants.wtApplicationErrorRange.lowerBound - 1,
        constants.wtApplicationErrorRange.upperBound + 1,
    ]
    for code in outsideCodes {
        #expect(
            WebTransportDraft17ErrorMapper.receivedApplicationErrorCode(forHTTPErrorCode: code) == nil,
            "error code outside the WT_APPLICATION_ERROR range maps to no application error")
    }
}

/// draft-17 section 4.6: rejecting a buffered stream does not affect the
/// session it was intended for — the refusal goes to the stream alone, and the
/// session establishes normally afterwards.
@Test
func draft17BufferedStreamRejectionLeavesTheSessionUnaffected() throws {
    var pair = try Draft17TestSupport.makeReadyPair(maxStreamReceiveBufferBytes: 2)
    let request = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )

    let earlyPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    let rejected = try pair.client.acceptBidirectionalStreamWithActions(
        streamID: 1,
        firstBytes: earlyPrefix + Data("abc".utf8)
    )
    #expect(rejected.prefix == nil)
    #expect(
        rejected.rejectionFrame
            == .resetStreamAt(
                id: 1,
                applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError,
                finalSize: 0,
                reliableSize: 0
            ))

    // The session the stream was intended for is untouched and still
    // establishes.
    #expect(pair.client.sessionsByID[WebTransportSessionID(rawValue: 0)]?.state == .requested)
    let decision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: request,
        policy: WebTransportServerSessionPolicy()
    )
    let session = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)
    #expect(session.state == .accepted)
    #expect(pair.client.sessionsByID[session.id]?.state == .accepted)
}

private func draft16ClientSettings() throws -> HTTP3Settings {
    try HTTP3Settings([
        WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1,
        WebTransportHTTP3DraftConstants.current.settingsWTEnabledDraft16: 1,
    ])
}

private func controlStreamBytes(_ settings: HTTP3Settings) throws -> Data {
    try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try settings.frame().encode()
    )
}

private enum Draft17TestSupport {
    static func makeReadyPair(
        flowControl: Bool = false,
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedSessions: Int = 64
    ) throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
        let constants = WebTransportHTTP3DraftConstants.current
        var clientSettings = HTTP3Settings.webTransportDraft17Defaults
        var serverSettings = HTTP3Settings.webTransportDraft17Defaults
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
            WebTransportSessionManager(
                http3: clientHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedSessions: maxBufferedSessions
            ),
            WebTransportSessionManager(
                http3: serverHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedSessions: maxBufferedSessions
            )
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
