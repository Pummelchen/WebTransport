import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func qpackPropertyCorpusRoundTripsAndEnforcesResourceLimits() throws {
    var fields: [HTTPFieldLine] = []
    for index in 0..<80 {
        fields.append(try HTTPFieldLine(name: "x-prop-\(index)", value: String(repeating: "v", count: (index % 17) + 1)))
    }

    for huffman in [false, true] {
        let encoded = try QPACK.encodeFieldSection(fields, huffman: huffman)
        #expect(try QPACK.decodeFieldSection(encoded) == fields)
        #expect(throws: Error.self) {
            _ = try QPACK.decodeFieldSection(
                encoded,
                limits: QPACKDecoderLimits(
                    maxFieldSectionBytes: max(1, encoded.count - 1),
                    maxFieldLineBytes: 1024,
                    maxFieldLineCount: 128
                )
            )
        }
        #expect(throws: Error.self) {
            _ = try QPACK.decodeFieldSection(
                encoded,
                limits: QPACKDecoderLimits(
                    maxFieldSectionBytes: encoded.count,
                    maxFieldLineBytes: 1024,
                    maxFieldLineCount: fields.count - 1
                )
            )
        }
    }

    var table = try QPACKDynamicTable(capacity: 96, maximumCapacity: 128)
    try table.insert(HTTPFieldLine(name: "x-a", value: "1"))
    try table.insert(HTTPFieldLine(name: "x-b", value: "2"))
    try table.insert(HTTPFieldLine(name: "x-c", value: "3"))
    #expect(table.byteSize <= table.capacity)
    #expect(table.entries.count <= 2)
    let before = table
    #expect(throws: Error.self) {
        try table.insert(HTTPFieldLine(name: "x-too-large", value: String(repeating: "x", count: 128)))
    }
    #expect(table == before)
}

@Test
func http3FrameAndCapsulePropertyCorpusRejectsMalformedPeers() throws {
    let frames: [HTTP3Frame] = try [
        HTTP3Frame(type: HTTP3FrameType.data, payload: Data()),
        HTTP3Frame(type: HTTP3FrameType.headers, payload: QPACK.encodeFieldSection([HTTPFieldLine(name: ":status", value: "200")])),
        HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 0),
        HTTP3Settings.webTransportDraft15Defaults.frame(),
        HTTP3Frame(type: 0x21, payload: Data([0x01, 0x02, 0x03]))
    ]
    let encodedFrames = try HTTP3Frame.encodeFrames(frames)
    #expect(try HTTP3Frame.decodeFrames(encodedFrames) == frames)
    for count in 0..<encodedFrames.count {
        let decodedPrefix = try? HTTP3Frame.decodeFrames(Data(encodedFrames.prefix(count)))
        #expect(decodedPrefix != frames)
    }

    let capsules: [WebTransportFlowCapsule] = [
        .drainSession,
        .closeSession(applicationErrorCode: 0x1234, message: "done"),
        .maxData(limit: 9),
        .maxStreamsBidi(limit: 3),
        .maxStreamsUni(limit: 4),
        .dataBlocked(limit: 9),
        .streamsBlockedBidi(limit: 3),
        .streamsBlockedUni(limit: 4),
        .unknown(type: 0x3f, payload: Data([0xde, 0xad]))
    ]
    for capsule in capsules {
        let encoded = try WebTransportFlowCapsuleCodec.serialize(capsule)
        #expect(try WebTransportFlowCapsuleCodec.parse(encoded).capsule == capsule)
        for count in 0..<encoded.count {
            #expect(throws: Error.self) {
                _ = try WebTransportFlowCapsuleCodec.parse(Data(encoded.prefix(count)))
            }
        }
    }

    var drainWithPayload = Data()
    drainWithPayload.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtDrainSessionCapsule))
    drainWithPayload.append(try QUICVarInt.encode(1))
    drainWithPayload.append(Data([0x00]))
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(drainWithPayload)
    }

    var invalidUTF8Close = try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule)
    invalidUTF8Close.append(try QUICVarInt.encode(5))
    invalidUTF8Close.append(Data([0, 0, 0, 1, 0xff]))
    #expect(throws: Error.self) {
        _ = try WebTransportFlowCapsuleCodec.parse(invalidUTF8Close)
    }
}

@Test
func webTransportStreamPrefixPropertyCorpusRejectsMalformedPeers() throws {
    for sessionID in stride(from: UInt64(0), through: UInt64(252), by: 4) {
        for form in [WebTransportStreamForm.bidirectional, .unidirectional] {
            var bytes = try WebTransportStreamSignaling.serializePrefix(form: form, sessionID: sessionID)
            bytes.append(Data("payload-\(sessionID)".utf8))
            let parsed = try WebTransportStreamSignaling.parsePrefix(bytes)
            #expect(parsed.form == form)
            #expect(parsed.sessionID == WebTransportSessionID(rawValue: sessionID))
            #expect(parsed.remainingPayload == Data("payload-\(sessionID)".utf8))
        }
    }

    var truncatedSessionID = Data()
    truncatedSessionID.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtStreamFrame))
    truncatedSessionID.append(try QUICVarInt.encode(1))
    var unknownMarker = Data()
    unknownMarker.append(try QUICVarInt.encode(0x40))
    unknownMarker.append(try QUICVarInt.encode(0))
    let malformed: [Data] = [
        Data(),
        Data([0xff]),
        try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtStreamFrame),
        truncatedSessionID,
        unknownMarker
    ]
    for bytes in malformed {
        #expect(throws: Error.self) {
            _ = try WebTransportStreamSignaling.parsePrefix(bytes)
        }
    }
}

@Test
func resourceLimitsCoverBufferedStreamsDatagramsDynamicTablesAndMalformedPeers() throws {
    var pair = try WebTransportHardeningSupport.makeReadyManagers(
        maxDatagramReceiveBufferBytes: 4,
        maxStreamReceiveBufferBytes: 4,
        maxBufferedStreamsPerSession: 1,
        maxBufferedDatagramsPerSession: 1,
        maxBufferedSessions: 1
    )

    _ = try pair.server.receiveDatagramFrame(QUICFrame.datagram(
        try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("1234".utf8))
    ))
    _ = try pair.server.receiveDatagramFrame(QUICFrame.datagram(
        try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("drop".utf8))
    ))
    #expect(pair.server.datagramQueue(sessionID: WebTransportSessionID(rawValue: 0))?.count == 1)

    let firstPrefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: firstPrefix + Data("1234".utf8))
    let secondResult = try pair.server.acceptBidirectionalStreamWithActions(streamID: 8, firstBytes: firstPrefix)
    #expect(secondResult.prefix == nil)
    #expect(secondResult.rejectionFrame == QUICFrame.resetStreamAt(
        id: 8,
        applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError,
        finalSize: 0,
        reliableSize: 0
    ))

    var orphanClientPair = try WebTransportHardeningSupport.makeReadyManagers()
    #expect(throws: Error.self) {
        _ = try orphanClientPair.client.receiveDatagramFrame(QUICFrame.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("other".utf8))
        ))
    }

    var table = try QPACKDynamicTable(capacity: 64, maximumCapacity: 64)
    for index in 0..<32 {
        try table.insert(HTTPFieldLine(name: "x", value: "\(index)"))
        #expect(table.byteSize <= table.capacity)
        #expect(table.entries.count <= 1)
    }
}

@Test
func adversarialOrderingReplayExhaustionAndCloseResetRacesAreDeterministic() throws {
    let clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    let clientControl = try clientHTTP3.localControlStreamBytes()
    _ = try serverHTTP3.receivePeerControlStream(clientControl)
    #expect(throws: Error.self) {
        _ = try serverHTTP3.receivePeerControlStream(clientControl)
    }
    #expect(throws: Error.self) {
        try serverHTTP3.receiveControlFrame(HTTP3Settings.webTransportDraft15Defaults.frame())
    }

    var pair = try WebTransportHardeningSupport.makeReadyManagers()
    let sessionID = try WebTransportHardeningSupport.establishSession(client: &pair.client, server: &pair.server)
    #expect(throws: Error.self) {
        _ = try pair.client.makeClientSessionRequest(
            streamID: sessionID.rawValue,
            request: WebTransportSessionRequest(authority: "example.com", path: "/replay")
        )
    }

    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
    let close = try pair.client.makeCloseSessionCapsuleResult(sessionID: sessionID, applicationErrorCode: 9, message: "race")
    #expect(close.terminationActions.streamResetFrames == [
        QUICFrame.resetStreamAt(
            id: 4,
            applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtSessionGoneError,
            finalSize: 0,
            reliableSize: 0
        )
    ])
    #expect(throws: Error.self) {
        _ = try pair.client.resetStream(streamID: 4, applicationErrorCode: 10)
    }
    #expect(throws: Error.self) {
        _ = try pair.client.stopSendingStream(streamID: 4, applicationErrorCode: 11)
    }

    let receivedClose = try pair.server.receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: close.capsuleBytes)
    #expect(receivedClose.terminationActions?.streamResetFrames ?? [] == [
        QUICFrame.resetStreamAt(
            id: 4,
            applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtSessionGoneError,
            finalSize: 0,
            reliableSize: 0
        )
    ])
    #expect(try pair.server.receiveConnectStreamData(streamID: sessionID.rawValue, data: Data("late".utf8)) == QUICFrame.resetStream(
        id: sessionID.rawValue,
        applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
        finalSize: 0
    ))
}

private enum WebTransportHardeningSupport {
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
