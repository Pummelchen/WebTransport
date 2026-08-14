import Foundation
import Testing
@testable import WebTransportHTTP3Core
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

// MARK: - Settings profile propagation

/// A manager must validate peer SETTINGS with the profile it was configured
/// with, not with the strict default.
///
/// `receivePeerControlStream` previously omitted the argument and inherited the
/// parameter default, so a manager built for an earlier revision still applied
/// draft-16 rules to the peer. That rejects exactly the peers the profile exists
/// to accept: a browser does not send SETTINGS_WT_ENABLE_WEBTRANSPORT, so strict
/// validation refuses it.
@Test
func managerValidatesPeerSettingsWithItsConfiguredProfile() throws {
    // Settings a browser-like peer sends: no draft-16 WT enable setting.
    let browserish = try HTTP3Settings([
        HTTP3SettingID.enableConnectProtocol: 1,
        HTTP3SettingID.h3Datagram: 1,
        HTTP3SettingID.legacyEnableWebTransport: 1
    ])
    let peer = HTTP3ConnectionState(role: .client, localSettings: browserish)
    let peerControl = try peer.localControlStreamBytes()

    // Strict: must reject, since the draft-16 enable setting is absent.
    var strict = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        settingsValidation: .draft16Strict
    )
    #expect(throws: Error.self) {
        _ = try strict.receivePeerControlStream(peerControl)
    }

    // Interoperable: must accept the same bytes, or the profile is inert.
    var interoperable = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportChromiumInteropDefaults),
        settingsValidation: .interoperable
    )
    #expect(throws: Never.self) {
        _ = try interoperable.receivePeerControlStream(peerControl)
    }
}

// MARK: - Datagram ceilings

/// Receive and send datagram ceilings answer different questions and must not
/// be the same number.
///
/// The receive ceiling has to match what the QUIC layer advertised, or a peer
/// honouring exactly what it was told gets rejected. The send ceiling has to
/// stay within what a QUIC path is guaranteed to carry, because a DATAGRAM
/// cannot be fragmented and an oversized one is silently dropped rather than
/// reported.
@Test
func datagramSendCeilingStaysDeliverableWhileReceiveCeilingMatchesAdvertisement() throws {
    // Advertised ceiling large, as the runtime advertises 65535.
    let manager = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxDatagramFrameSize: 65_535
    )
    #expect(manager.maxDatagramFrameSize == 65_535, "must accept what was advertised")
    #expect(
        manager.maxSendableDatagramFrameSize == 1_200,
        "sends stay within the QUIC guaranteed-deliverable size"
    )

    // A ceiling below the guaranteed size must also bound sends: an endpoint
    // must never send more than it would itself accept.
    let tiny = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxDatagramFrameSize: 4
    )
    #expect(tiny.maxSendableDatagramFrameSize == 4)

    // An explicit value still wins.
    let explicit = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxDatagramFrameSize: 65_535,
        maxSendableDatagramFrameSize: 900
    )
    #expect(explicit.maxSendableDatagramFrameSize == 900)
}

// MARK: - Bounded tombstone retention

/// Terminated sessions and streams are retained so that late activity reports
/// "session gone" rather than "unknown". That retention has to be bounded.
///
/// A session tombstone holds the peer's own authority and path strings, a
/// CONNECT field section may be up to 16 KB, and a peer can open and close
/// sessions on a single connection indefinitely. Retaining every one of them for
/// the life of the connection is remotely triggerable memory growth, so the
/// oldest are evicted and late activity on them degrades to "unknown", which is
/// a safe answer.
@Test
func closedStreamTombstonesAreBounded() throws {
    let manager = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxRetainedClosedStreams: 8
    )
    #expect(manager.maxRetainedClosedStreams == 8)

    // Retention is a configured ceiling, not an accident of how many streams a
    // peer happened to open.
    #expect(manager.maxRetainedClosedSessions == 256, "default session tombstone bound")

    // A zero bound is accepted and means "retain nothing", rather than trapping.
    let none = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxRetainedClosedSessions: 0,
        maxRetainedClosedStreams: 0
    )
    #expect(none.maxRetainedClosedSessions == 0)
    #expect(none.maxRetainedClosedStreams == 0)

    // Negative values are clamped rather than producing a negative ceiling that
    // would make the eviction loop misbehave.
    let clamped = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        maxRetainedClosedSessions: -5,
        maxRetainedClosedStreams: -5
    )
    #expect(clamped.maxRetainedClosedSessions == 0)
    #expect(clamped.maxRetainedClosedStreams == 0)
    _ = manager
}

// MARK: - Protocol negotiation must not silently downgrade

/// A malformed subprotocol header is a protocol error, not an absent one.
///
/// Both negotiation headers were parsed with `try?`, so a peer that sent the
/// header and got it wrong was treated as a peer that had said nothing. That
/// leaves the two ends disagreeing about which subprotocol is in force, and for
/// WebTransport the subprotocol decides application semantics — so the peers
/// would go on to speak different protocols over the same session.
///
/// The decoder was already strict; only these call sites were not, which is why
/// the conformance suite's own "decodeList rejects bad input" check passed
/// while the behaviour was still wrong.
@Test
func malformedSelectedProtocolIsRejectedRatherThanTreatedAsNoneSelected() throws {
    // Well-formed still works.
    let good = try QPACK.headersFrame(fields: [
        try HTTPFieldLine(name: ":status", value: "200"),
        try HTTPFieldLine(name: "wt-protocol", value: WebTransportProtocolNegotiation.encodeItem("chat.v1"))
    ])
    let goodFields = try QPACK.decodeHeadersFrame(good)
    #expect(try WebTransportSessionHeaders.selectedProtocol(from: goodFields) == "chat.v1")

    // Absent means none selected, which is legitimate.
    let absent = try QPACK.headersFrame(fields: [try HTTPFieldLine(name: ":status", value: "200")])
    #expect(try WebTransportSessionHeaders.selectedProtocol(from: QPACK.decodeHeadersFrame(absent)) == nil)

    // Present but malformed must throw, not report nil.
    for bad in ["\"unterminated", "not-a-quoted-string", "\"bad\\n\""] {
        let frame = try QPACK.headersFrame(fields: [
            try HTTPFieldLine(name: ":status", value: "200"),
            try HTTPFieldLine(name: "wt-protocol", value: bad)
        ])
        let fields = try QPACK.decodeHeadersFrame(frame)
        #expect(throws: Error.self, "malformed wt-protocol \(bad) must be rejected") {
            _ = try WebTransportSessionHeaders.selectedProtocol(from: fields)
        }
    }
}

@Test
func malformedAvailableProtocolsIsRejectedRatherThanTreatedAsNoneOffered() throws {
    func connectFields(availableProtocols: String?) throws -> [HTTPFieldLine] {
        var fields = try WebTransportHTTP3Headers.connectRequest(
            authority: "example.com",
            path: "/wt",
            origin: nil,
            upgradeToken: WebTransportHTTP3DraftConstants.current.upgradeToken
        )
        if let availableProtocols {
            fields.append(try HTTPFieldLine(
                name: "wt-available-protocols",
                value: availableProtocols
            ))
        }
        return fields
    }

    // Absent is fine and means nothing was offered.
    let none = try WebTransportSessionHeaders.request(from: try connectFields(availableProtocols: nil))
    #expect(none.availableProtocols.isEmpty)

    // Well-formed round-trips.
    let listed = try WebTransportSessionHeaders.request(
        from: try connectFields(availableProtocols: try WebTransportProtocolNegotiation.encodeList(["chat.v1"]))
    )
    #expect(listed.availableProtocols == ["chat.v1"])

    // Malformed must be rejected rather than silently becoming "no protocols".
    for bad in ["\"bad\\n\"", "\"unterminated", "chat.v1"] {
        #expect(throws: Error.self, "malformed wt-available-protocols \(bad) must be rejected") {
            _ = try WebTransportSessionHeaders.request(from: try connectFields(availableProtocols: bad))
        }
    }
}
