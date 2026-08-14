import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

/// A WebTransport stream prefix that the peer asserted but built incorrectly
/// must be rejected, not silently reinterpreted as an unprefixed stream.
///
/// `parsePrefix` reports "this is not a prefixed stream" and "this prefix is
/// malformed" as the same thrown error, so callers previously used `try?` and
/// collapsed both into the benign case. `hasStreamPrefix` exists to keep them
/// apart; these tests pin that boundary.

@Test
func streamPrefixDetectionRecognizesBothWebTransportMarkers() throws {
    let bidirectional = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: 0)
    let unidirectional = try WebTransportStreamSignaling.serializeUnidirectionalPrefix(sessionID: 0)

    #expect(WebTransportStreamSignaling.hasStreamPrefix(bidirectional))
    #expect(WebTransportStreamSignaling.hasStreamPrefix(unidirectional))
}

@Test
func streamPrefixDetectionRejectsUnprefixedAndTruncatedPayloads() throws {
    // An HTTP/3 HEADERS frame is how a real extended CONNECT request stream
    // begins; it must not be mistaken for a prefixed WebTransport stream.
    let headersFrame = try HTTP3Frame(type: HTTP3FrameType.headers, payload: Data([0x00, 0x01])).encode()
    #expect(!WebTransportStreamSignaling.hasStreamPrefix(headersFrame))

    #expect(!WebTransportStreamSignaling.hasStreamPrefix(Data()))
    #expect(!WebTransportStreamSignaling.hasStreamPrefix(Data([0x40])))       // truncated 2-byte varint
    #expect(!WebTransportStreamSignaling.hasStreamPrefix(Data([0x00])))       // varint 0, not a marker
}

@Test
func assertedPrefixWithInvalidSessionIDIsRejectedRatherThanDowngraded() throws {
    let constants = WebTransportHTTP3DraftConstants.current

    // A valid bidirectional marker followed by a session ID that is not a legal
    // client-initiated bidirectional request stream ID.
    var malformed = Data()
    malformed.append(try QUICVarInt.encode(constants.wtStreamFrame))
    malformed.append(try QUICVarInt.encode(3))  // server-initiated bidi ID
    malformed.append(Data([0xaa, 0xbb]))

    // The marker is present, so a caller must commit to parsing it...
    #expect(WebTransportStreamSignaling.hasStreamPrefix(malformed))

    // ...and parsing must fail rather than yield a usable prefix.
    #expect(throws: Error.self) {
        _ = try WebTransportStreamSignaling.parsePrefix(malformed)
    }
}

@Test
func wellFormedPrefixStillRoundTrips() throws {
    let payload = Data([0x01, 0x02, 0x03, 0x04])
    var stream = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: 0)
    stream.append(payload)

    #expect(WebTransportStreamSignaling.hasStreamPrefix(stream))
    let parsed = try WebTransportStreamSignaling.parsePrefix(stream)
    #expect(parsed.form == .bidirectional)
    #expect(parsed.remainingPayload == payload)
}

// MARK: - Flow-control monotonicity

/// Draft-16 requires WT_MAX_* limits to strictly increase once established.
///
/// The `.unlimited` state is deliberately not covered here as a rejection case:
/// it means "no limit communicated yet", not "infinity", so the first capsule
/// legitimately establishes the initial limit. An earlier version of this file
/// asserted the opposite and was wrong.
@Test
func finiteFlowControlLimitsRequireStrictIncrease() throws {
    var state = WebTransportFlowControlState(maxData: 100, maxStreamsBidi: 2, maxStreamsUni: 2)

    try state.setMaxData(200)
    #expect(state.maxData == 200)

    #expect(throws: Error.self) { try state.setMaxData(200) }  // equal is not an increase
    #expect(throws: Error.self) { try state.setMaxData(150) }  // decrease
    #expect(state.maxData == 200, "a rejected update must leave the limit untouched")

    try state.setMaxStreamsBidi(5)
    #expect(throws: Error.self) { try state.setMaxStreamsBidi(4) }
    #expect(state.maxStreamsBidi == 5)
}

/// The first limit after an unspecified one is accepted, and monotonicity binds
/// from then on.
@Test
func unspecifiedFlowControlLimitAcceptsItsFirstValueThenLocksMonotonic() throws {
    var state = WebTransportFlowControlState(
        maxData: nil, maxStreamsBidi: nil, maxStreamsUni: nil, isEnabled: true
    )
    #expect(state.maxData == nil, "nil means no limit communicated yet")

    try state.setMaxData(4)
    #expect(state.maxData == 4)

    #expect(throws: Error.self) { try state.setMaxData(3) }
    #expect(state.maxData == 4)
}
