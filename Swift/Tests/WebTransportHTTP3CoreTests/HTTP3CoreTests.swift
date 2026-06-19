import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func http3FrameHeadersUseSharedQUICVarIntCodec() throws {
    let frame = try HTTP3Frame(type: HTTP3FrameType.headers, payload: Data([0xde, 0xad, 0xbe, 0xef]))
    let encoded = try frame.encode()
    #expect(encoded == Data([0x01, 0x04, 0xde, 0xad, 0xbe, 0xef]))

    var cursor = QUICByteCursor(encoded)
    #expect(try HTTP3Frame.decode(from: &cursor) == frame)
    #expect(cursor.isAtEnd)

    let largeType = UInt64(0x2c7c_f000)
    let largeFrame = try HTTP3Frame(type: largeType, payload: Data(repeating: 0xaa, count: 64))
    var largeCursor = QUICByteCursor(try largeFrame.encode())
    #expect(try QUICVarInt.decode(from: &largeCursor) == largeType)
    #expect(try QUICVarInt.decode(from: &largeCursor) == 64)
}

@Test
func http3FrameSequenceRoundTripsAndVarIntPayloadDecodes() throws {
    let frames = [
        try HTTP3Frame(type: HTTP3FrameType.data, payload: Data("hello".utf8)),
        try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 16),
        try HTTP3Settings([
            HTTP3SettingID.qpackMaxTableCapacity: 0,
            HTTP3SettingID.maxFieldSectionSize: 4_096
        ]).frame()
    ]

    let decoded = try HTTP3Frame.decodeFrames(try HTTP3Frame.encodeFrames(frames))
    #expect(decoded == frames)
    #expect(try decoded[1].singleVarIntPayload() == 16)
}

@Test
func http3SettingsRoundTripAndRejectMalformedSettings() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var settings = try HTTP3Settings()
    try settings.set(1, for: constants.settingsEnableConnectProtocol)
    try settings.set(1, for: constants.settingsH3Datagram)
    try settings.set(1, for: constants.settingsWTEnabled)
    try settings.set(3, for: constants.settingsWTInitialMaxStreamsUni)
    try settings.set(5, for: constants.settingsWTInitialMaxStreamsBidi)
    try settings.set(65_536, for: constants.settingsWTInitialMaxData)

    let frame = try settings.frame()
    #expect(frame.type == HTTP3FrameType.settings)
    #expect(try HTTP3Settings.decodeFrame(frame).entries == settings.entries)

    let duplicatePayload =
        (try QUICVarInt.encode(constants.settingsWTEnabled)) +
        (try QUICVarInt.encode(1)) +
        (try QUICVarInt.encode(constants.settingsWTEnabled)) +
        (try QUICVarInt.encode(1))
    #expect(throws: Error.self) {
        _ = try HTTP3Settings.decodePayload(duplicatePayload)
    }
    #expect(throws: Error.self) {
        _ = try HTTP3Settings([0x02: 0])
    }
    #expect(throws: Error.self) {
        _ = try HTTP3Settings.decodeFrame(try HTTP3Frame(type: HTTP3FrameType.headers))
    }
}

@Test
func http3StreamTypePrefixParsesKnownAndWebTransportStreams() throws {
    let control = try HTTP3StreamTypeParser.parsePrefix(
        HTTP3StreamTypeParser.encodePrefix(type: HTTP3StreamType.control, payload: Data([0x04]))
    )
    #expect(control.type == HTTP3StreamType.control)
    #expect(control.bytesConsumed == 1)
    #expect(control.remainingBytes == Data([0x04]))

    let webTransportBytes = try HTTP3StreamTypeParser.encodePrefix(
        type: WebTransportHTTP3DraftConstants.current.webTransportStream,
        payload: Data("session".utf8)
    )
    let webTransport = try HTTP3StreamTypeParser.parsePrefix(webTransportBytes)
    #expect(webTransport.type == 0x54)
    #expect(webTransport.bytesConsumed == 2)
    #expect(webTransport.remainingBytes == Data("session".utf8))
}

@Test
func reservedCodeHelpersFollowHTTP3Pattern() {
    #expect(HTTP3FrameType.isReserved(0x21))
    #expect(HTTP3FrameType.isReserved(0x40))
    #expect(!HTTP3FrameType.isReserved(HTTP3FrameType.headers))
    #expect(HTTP3StreamType.isReserved(0x21))
    #expect(HTTP3StreamType.isReserved(0x40))
    #expect(!HTTP3StreamType.isReserved(HTTP3StreamType.control))
}

@Test
func webTransportDraft15ConstantsMatchProtocolBible() {
    let constants = WebTransportHTTP3DraftConstants.current
    #expect(constants.name == "draft-ietf-webtrans-http3-15")
    #expect(constants.revision == 15)
    #expect(constants.lastUpdated == "2026-03-02")
    #expect(constants.upgradeToken == "webtransport-h3")
    #expect(constants.settingsEnableConnectProtocol == 0x08)
    #expect(constants.settingsH3Datagram == 0x33)
    #expect(constants.settingsWTEnabled == 0x2c7c_f000)
    #expect(constants.settingsWTInitialMaxStreamsUni == 0x2b64)
    #expect(constants.settingsWTInitialMaxStreamsBidi == 0x2b65)
    #expect(constants.settingsWTInitialMaxData == 0x2b61)
    #expect(constants.wtStreamFrame == 0x41)
    #expect(constants.webTransportStream == 0x54)
    #expect(constants.wtDrainSessionCapsule == 0x78ae)
    #expect(constants.wtCloseSessionCapsule == 0x2843)
    #expect(constants.wtMaxDataCapsule == 0x190b_4d3d)
    #expect(constants.wtMaxStreamsBidiCapsule == 0x190b_4d3f)
    #expect(constants.wtMaxStreamsUniCapsule == 0x190b_4d40)
    #expect(constants.wtDataBlockedCapsule == 0x190b_4d41)
    #expect(constants.wtStreamsBlockedBidiCapsule == 0x190b_4d43)
    #expect(constants.wtStreamsBlockedUniCapsule == 0x190b_4d44)
    #expect(constants.wtBufferedStreamRejectedError == 0x3994_bd84)
    #expect(constants.wtSessionGoneError == 0x170d_7b68)
    #expect(constants.wtFlowControlError == 0x045d_4487)
    #expect(constants.wtALPNError == 0x0817_b3dd)
    #expect(constants.wtRequirementsNotMetError == 0x212c_0d48)
    #expect(constants.wtApplicationErrorRange == 0x52e4_a40f_a8db...0x52e5_ac98_3162)
}
