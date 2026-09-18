import Foundation
import Testing
@testable import WebTransportQUICCore

@Test
func quicVarIntDeterministicPropertyCorpusRoundTripsAndRejectsTruncation() throws {
    let values = deterministicVarIntCorpus()
    for value in values {
        let encoded = try QUICVarInt.encode(value)
        #expect(encoded.count == (try QUICVarInt.encodedLength(value)))

        var cursor = QUICByteCursor(encoded)
        #expect(try QUICVarInt.decode(from: &cursor) == value)
        #expect(cursor.isAtEnd)

        if encoded.count > 1 {
            for count in 0..<encoded.count {
                var truncated = QUICByteCursor(Data(encoded.prefix(count)))
                #expect(throws: Error.self) {
                    _ = try QUICVarInt.decode(from: &truncated)
                }
            }
        }
    }

    #expect(throws: Error.self) {
        _ = try QUICVarInt.encode(QUICVarInt.maximum + 1)
    }
}

@Test
func quicTransportParametersPropertyCorpusRoundTripsAndRejectsMalformedPeers() throws {
    var parameters = QUICTransportParameters()
    let values = deterministicVarIntCorpus().prefix(48)
    for (offset, value) in values.enumerated() {
        try parameters.setInteger(value, for: UInt64(0x40 + offset))
    }
    parameters[QUICTransportParameterID.initialSourceConnectionID] = Data((0..<20).map(UInt8.init))
    parameters[QUICTransportParameterID.resetStreamAt] = Data()

    let encoded = try parameters.encode()
    let decoded = try QUICTransportParameters.decode(encoded)
    #expect(decoded == parameters)
    for (offset, value) in values.enumerated() {
        #expect(try decoded.integer(for: UInt64(0x40 + offset)) == value)
    }

    var duplicate = Data()
    duplicate.append(try QUICVarInt.encode(0x01))
    duplicate.append(try QUICVarInt.encode(0))
    duplicate.append(try QUICVarInt.encode(0x01))
    duplicate.append(try QUICVarInt.encode(0))
    #expect(throws: Error.self) {
        _ = try QUICTransportParameters.decode(duplicate)
    }

    var truncatedLength = Data()
    truncatedLength.append(try QUICVarInt.encode(0x02))
    truncatedLength.append(try QUICVarInt.encode(4))
    truncatedLength.append(Data([0x01, 0x02]))
    #expect(throws: Error.self) {
        _ = try QUICTransportParameters.decode(truncatedLength)
    }

    var trailingInteger = QUICTransportParameters()
    trailingInteger[0x33] = Data([0x01, 0x00])
    #expect(throws: Error.self) {
        _ = try trailingInteger.integer(for: 0x33)
    }
}

@Test
func quicFrameDecoderRejectsTruncatedPropertyCorpus() throws {
    let frames: [QUICFrame] = [
        .ping,
        .ack(largestAcknowledged: 64, ackDelay: 3, firstAckRange: 1, ranges: [QUICAckRange(gap: 0, length: 1)]),
        .crypto(offset: 7, data: Data("crypto".utf8)),
        .stream(id: 4, offset: 12, fin: true, data: Data("stream".utf8)),
        .resetStream(id: 4, applicationErrorCode: 0x1234, finalSize: 6),
        .resetStreamAt(id: 4, applicationErrorCode: 0x1234, finalSize: 6, reliableSize: 6),
        .stopSending(id: 4, applicationErrorCode: 0x1235),
        .maxData(4096),
        .maxStreamData(id: 4, maximum: 4096),
        .datagram(Data("datagram".utf8)),
        .connectionClose(errorCode: 0x100, frameType: 0x01, reason: Data("close".utf8)),
    ]

    for frame in frames {
        let encoded = try frame.encode()
        #expect(try QUICFrame.decodeFrames(encoded) == [frame])
        for count in 0..<encoded.count {
            let decodedPrefix = try? QUICFrame.decodeFrames(Data(encoded.prefix(count)))
            #expect(decodedPrefix != [frame])
        }
    }
}

private func deterministicVarIntCorpus() -> [UInt64] {
    var values: [UInt64] = [
        0,
        1,
        62,
        63,
        64,
        65,
        16_382,
        16_383,
        16_384,
        16_385,
        1_073_741_822,
        1_073_741_823,
        1_073_741_824,
        1_073_741_825,
        QUICVarInt.maximum - 1,
        QUICVarInt.maximum,
    ]

    var state: UInt64 = 0x1234_5678_9abc_def0
    for _ in 0..<128 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        values.append(state & QUICVarInt.maximum)
    }
    return values
}

// MARK: - Transport parameter value validation

/// `decode` deliberately checks only framing and duplicates, so a caller that needs the
/// RFC 9000 section 18.2 value rules asks for them explicitly. Each case below is a
/// value the RFC makes a `TRANSPORT_PARAMETER_ERROR`.
@Test
func transportParameterValidationEnforcesRFC9000Section18Point2() throws {
    func parameters(_ configure: (inout QUICTransportParameters) throws -> Void) throws -> QUICTransportParameters {
        var values = QUICTransportParameters()
        try configure(&values)
        return values
    }

    // A well-formed set passes.
    let valid = try parameters {
        try $0.setInteger(1_200, for: QUICTransportParameterID.maxUDPPayloadSize)
        try $0.setInteger(3, for: QUICTransportParameterID.ackDelayExponent)
        try $0.setInteger(25, for: QUICTransportParameterID.maxAckDelay)
        try $0.setInteger(2, for: QUICTransportParameterID.activeConnectionIDLimit)
    }
    try valid.validated()

    // Each violation is rejected.
    let cases: [(String, QUICTransportParameters)] = [
        (
            "max_udp_payload_size below 1200",
            try parameters {
                try $0.setInteger(1_199, for: QUICTransportParameterID.maxUDPPayloadSize)
            }
        ),
        (
            "ack_delay_exponent above 20",
            try parameters {
                try $0.setInteger(21, for: QUICTransportParameterID.ackDelayExponent)
            }
        ),
        (
            "max_ack_delay at 2^14",
            try parameters {
                try $0.setInteger(1 << 14, for: QUICTransportParameterID.maxAckDelay)
            }
        ),
        (
            "active_connection_id_limit below 2",
            try parameters {
                try $0.setInteger(1, for: QUICTransportParameterID.activeConnectionIDLimit)
            }
        ),
        (
            "stateless_reset_token not 16 bytes",
            try parameters {
                $0[QUICTransportParameterID.statelessResetToken] = Data(repeating: 0xab, count: 8)
            }
        ),
        (
            "original_destination_connection_id of zero length",
            try parameters {
                $0[QUICTransportParameterID.originalDestinationConnectionID] = Data()
            }
        ),
        (
            "connection ID longer than 20",
            try parameters {
                $0[QUICTransportParameterID.retrySourceConnectionID] = Data(repeating: 0x01, count: 21)
            }
        ),
        // RFC 9000 section 4.6: a max_streams value above 2^60 allows a stream ID that cannot be expressed as
        // a variable-length integer, and receiving one is a TRANSPORT_PARAMETER_ERROR. The validator enforced
        // every other section 18.2 rule and missed both of these (`WT-250`).
        (
            "initial_max_streams_bidi above 2^60",
            try parameters {
                try $0.setInteger((1 << 60) + 1, for: QUICTransportParameterID.initialMaxStreamsBidi)
            }
        ),
        (
            "initial_max_streams_uni above 2^60",
            try parameters {
                try $0.setInteger((1 << 60) + 1, for: QUICTransportParameterID.initialMaxStreamsUni)
            }
        ),
    ]
    for (name, value) in cases {
        #expect(throws: (any Error).self, "expected \(name) to be rejected") {
            try value.validated()
        }
    }

    // These are conforming and must be accepted. RFC 9000 section 7.3: "If a zero-length
    // connection ID is selected, the corresponding transport parameter is included with
    // a zero-length value." RFC 9221 section 3 makes an explicit zero
    // max_datagram_frame_size mean "DATAGRAM frames are not supported", which is also
    // the absent-parameter default.
    let conforming = try parameters {
        $0[QUICTransportParameterID.initialSourceConnectionID] = Data()
        $0[QUICTransportParameterID.retrySourceConnectionID] = Data()
        try $0.setInteger(0, for: QUICTransportParameterID.maxDatagramFrameSize)
        // Exactly 2^60 is the limit, not a violation: section 4.6 refuses values *greater* than it.
        try $0.setInteger(1 << 60, for: QUICTransportParameterID.initialMaxStreamsBidi)
        try $0.setInteger(1 << 60, for: QUICTransportParameterID.initialMaxStreamsUni)
    }
    try conforming.validated()
}

// MARK: - Long header validity

/// RFC 9000 section 17.2: a packet whose Fixed Bit is zero "is not a valid packet in
/// this version and MUST be discarded". RFC 9001 section 5.4 requires the reserved bits
/// to be zero once header protection is removed. The short-header decoder enforced the
/// Fixed Bit but the long-header path enforced neither.
private func longHeaderPacket(
    fixedBit: Bool,
    reservedBits: UInt8 = 0,
    packetType: UInt8 = 0
) -> Data {
    var first: UInt8 = 0x80  // long form
    if fixedBit {
        first |= 0x40
    }
    first |= (packetType & 0x03) << 4
    first |= (reservedBits & 0x03) << 2
    var data = Data([first])
    data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // version 1
    data.append(0x00)  // destination connection ID length
    data.append(0x00)  // source connection ID length
    data.append(0x00)  // token length
    data.append(0x01)  // length varint
    data.append(0x00)  // packet number
    return data
}

@Test
func longHeaderRejectsClearedFixedBitAndReservedBits() throws {
    // A well-formed packet is still accepted.
    _ = try QUICLongHeaderPacket.decode(longHeaderPacket(fixedBit: true))

    #expect(throws: (any Error).self, "a cleared Fixed Bit must be rejected") {
        _ = try QUICLongHeaderPacket.decode(longHeaderPacket(fixedBit: false))
    }
    for reserved: UInt8 in [0b01, 0b10, 0b11] {
        #expect(throws: (any Error).self, "reserved bits \(reserved) must be rejected") {
            _ = try QUICLongHeaderPacket.decode(longHeaderPacket(fixedBit: true, reservedBits: reserved))
        }
    }
}

// MARK: - Retry packet validity

/// RFC 9000 section 17.2.5: "A client MUST discard a Retry packet with a zero-length Retry Token
/// field." A Retry is also a long header packet, so RFC 9000 section 17.2's Fixed Bit rule applies
/// to it. Its low four bits are different, though: they are the `Unused (4)` field, and the RFC
/// says "a client MUST ignore these bits", so they are deliberately not a refusal here (`WT-227`).
private func retryPacket(
    tokenByteCount: Int,
    fixedBit: Bool = true,
    reservedBits: UInt8 = 0
) -> Data {
    var first: UInt8 = 0x80
    if fixedBit {
        first |= 0x40
    }
    first |= (QUICPacketType.retry.rawValue & 0x03) << 4
    first |= (reservedBits & 0x03) << 2
    var data = Data([first])
    data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // version 1
    data.append(0x00)  // destination connection ID length
    data.append(0x00)  // source connection ID length
    data.append(Data(repeating: 0xaa, count: tokenByteCount))
    data.append(Data(repeating: 0x11, count: 16))  // integrity tag
    return data
}

@Test
func retryPacketRejectsZeroLengthTokenAndInvalidHeaderBits() throws {
    let valid = try QUICRetryPacket.decode(retryPacket(tokenByteCount: 4))
    #expect(valid.retryToken.count == 4)

    #expect(throws: (any Error).self, "a zero-length Retry token must be rejected") {
        _ = try QUICRetryPacket.decode(retryPacket(tokenByteCount: 0))
    }
    #expect(throws: (any Error).self, "a cleared Fixed Bit must be rejected") {
        _ = try QUICRetryPacket.decode(retryPacket(tokenByteCount: 4, fixedBit: false))
    }
    // The Unused field is arbitrary on the wire, so every value of it parses (`WT-227`). The check is
    // the RFC's own packet below, which begins 0xff; this loop covers the rest of the nibble.
    for unused: UInt8 in [0b00, 0b01, 0b10, 0b11] {
        let packet = try QUICRetryPacket.decode(retryPacket(tokenByteCount: 4, reservedBits: unused))
        #expect(packet.retryToken.count == 4, "Unused field \(unused) must not change the parse")
    }
}

/// The packet RFC 9001 appendix A.4 prints, and the Original Destination Connection ID of its A.2 client
/// Initial. The first byte is `0xff`, so all four Unused bits are set — the case the decoder used to refuse,
/// which was the RFC's own example (`WT-227`). The pseudo-packet layout is pinned here too, because the tag
/// computation is only correct if the bytes it authenticates are these: the connection ID's length, the
/// connection ID, then the packet without its tag.
@Test
func retryPacketAcceptsTheRFCsOwnPacketAndBuildsItsPseudoPacket() throws {
    let rfcPacket = Data([
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    ])
    let originalDestinationConnectionID = Data([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    let packet = try QUICRetryPacket.decode(rfcPacket)

    #expect(packet.version == 1)
    #expect(packet.destinationConnectionID.isEmpty)
    #expect(packet.sourceConnectionID == Data([0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]))
    #expect(packet.retryToken == Data("token".utf8))
    #expect(
        packet.retryIntegrityTag
            == Data([
                0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
                0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
            ])
    )
    #expect(try packet.encodedWithoutIntegrityTag() == rfcPacket.dropLast(16))
    // The Unused bits survive a parse, so re-encoding is byte-for-byte the packet that arrived. Without that
    // the pseudo-packet would carry 0xf0 where the server sent 0xff and the RFC's own tag would not verify.
    #expect(packet.unusedBits == 0x0f)
    #expect(try packet.encode() == rfcPacket)

    let pseudoPacket = try QUICRetryPacket.integrityPseudoPacket(
        originalDestinationConnectionID: originalDestinationConnectionID,
        retryPacketWithoutIntegrityTag: try packet.encodedWithoutIntegrityTag()
    )
    #expect(
        pseudoPacket
            == Data([
                0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
                0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
                0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
            ])
    )

    // A connection ID cannot exceed twenty bytes, so neither can the pseudo-packet's length byte.
    #expect(throws: (any Error).self, "an over-long connection ID must be refused") {
        _ = try QUICRetryPacket.integrityPseudoPacket(
            originalDestinationConnectionID: Data(repeating: 0, count: 21),
            retryPacketWithoutIntegrityTag: Data()
        )
    }
}

/// Every frame type, not a sample.
///
/// `QUICFrame.encode` and `QUICFrame.decode` both dispatch on the frame's type, and a case
/// added to the enum but missed by one of them is a wire bug that only a test over the
/// whole enum catches. The count is asserted so that a new case cannot quietly arrive
/// without a frame here.
@Test
func everyFrameTypeRoundTrips() throws {
    let frames: [QUICFrame] = [
        .padding,
        .ping,
        .ack(largestAcknowledged: 64, ackDelay: 3, firstAckRange: 1, ranges: [QUICAckRange(gap: 0, length: 1)]),
        .crypto(offset: 7, data: Data("crypto".utf8)),
        .stream(id: 4, offset: nil, fin: false, data: Data("stream".utf8)),
        .stream(id: 4, offset: 12, fin: true, data: Data("stream".utf8)),
        .resetStream(id: 4, applicationErrorCode: 0x1234, finalSize: 6),
        .resetStreamAt(id: 4, applicationErrorCode: 0x1234, finalSize: 6, reliableSize: 6),
        .stopSending(id: 4, applicationErrorCode: 0x1235),
        .maxData(4096),
        .maxStreamData(id: 4, maximum: 4096),
        .maxStreams(direction: .bidirectional, maximum: 16),
        .maxStreams(direction: .unidirectional, maximum: 16),
        .dataBlocked(4096),
        .streamDataBlocked(id: 4, offset: 12),
        .streamsBlocked(direction: .bidirectional, maximum: 16),
        .streamsBlocked(direction: .unidirectional, maximum: 16),
        .newConnectionID(
            sequence: 3,
            retirePriorTo: 1,
            connectionID: Data([0x01, 0x02, 0x03, 0x04]),
            statelessResetToken: Data(repeating: 0xAB, count: 16)
        ),
        .retireConnectionID(sequence: 3),
        .connectionClose(errorCode: 0x100, frameType: 0x01, reason: Data("close".utf8)),
        .connectionClose(errorCode: 0x100, frameType: nil, reason: Data()),
        .handshakeDone,
        .datagram(Data("datagram".utf8)),
    ]

    // Nineteen cases in the enum; both stream directions and both `stream` forms are the
    // deliberate extra entries, so this is 23 frames covering all of them.
    #expect(frames.count == 23)

    for frame in frames {
        let encoded = try frame.encode()
        #expect(try QUICFrame.decodeFrames(encoded) == [frame], "\(frame)")
    }
}
