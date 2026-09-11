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
    }
    try conforming.validated()
}
