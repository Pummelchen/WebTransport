import Foundation
import Testing
@testable import WebTransportQUICCore

@Test
func varIntRoundTripsBoundaryValues() throws {
    let values: [UInt64] = [
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        QUICVarInt.maximum,
    ]

    for value in values {
        var cursor = QUICByteCursor(try QUICVarInt.encode(value))
        #expect(try QUICVarInt.decode(from: &cursor) == value)
        #expect(cursor.isAtEnd)
    }
}

@Test
func frameRoundTripsRepresentativeFrameSet() throws {
    let token = Data(repeating: 0xab, count: 16)
    let frames: [QUICFrame] = [
        .padding,
        .ping,
        .ack(
            largestAcknowledged: 10,
            ackDelay: 3,
            firstAckRange: 2,
            ranges: [QUICAckRange(gap: 1, length: 4)]
        ),
        .crypto(offset: 4, data: Data("crypto".utf8)),
        .stream(id: 0, offset: 0, fin: false, data: Data("bidi".utf8)),
        .stream(id: 2, offset: nil, fin: true, data: Data("uni".utf8)),
        .resetStream(id: 0, applicationErrorCode: 0x54, finalSize: 4),
        .resetStreamAt(id: 0, applicationErrorCode: 0x54, finalSize: 8, reliableSize: 3),
        .stopSending(id: 0, applicationErrorCode: 0x55),
        .maxData(1_000),
        .maxStreamData(id: 0, maximum: 2_000),
        .maxStreams(direction: .bidirectional, maximum: 8),
        .maxStreams(direction: .unidirectional, maximum: 9),
        .dataBlocked(3_000),
        .streamDataBlocked(id: 0, offset: 4_000),
        .streamsBlocked(direction: .bidirectional, maximum: 10),
        .streamsBlocked(direction: .unidirectional, maximum: 11),
        .newConnectionID(sequence: 1, retirePriorTo: 0, connectionID: Data([1, 2, 3, 4]), statelessResetToken: token),
        .retireConnectionID(sequence: 1),
        .connectionClose(errorCode: 0x100, frameType: 0x08, reason: Data("done".utf8)),
        .connectionClose(errorCode: 0x101, frameType: nil, reason: Data("app".utf8)),
        .handshakeDone,
        .datagram(Data("datagram".utf8)),
    ]

    let encoded = try QUICFrame.encodeFrames(frames)
    #expect(try QUICFrame.decodeFrames(encoded) == frames)
}

@Test
func resetStreamAtRejectsReliableSizeBeyondFinalSize() throws {
    #expect(throws: Error.self) {
        _ = try QUICFrame.resetStreamAt(
            id: 0,
            applicationErrorCode: 0x54,
            finalSize: 3,
            reliableSize: 4
        ).encode()
    }
    #expect(throws: Error.self) {
        _ = try QUICFrame.decodeFrames(Data([0x24, 0x00, 0x40, 0x54, 0x03, 0x04]))
    }
}

@Test
func transportParametersRoundTripIntegerValues() throws {
    var parameters = QUICTransportParameters()
    try parameters.setInteger(1_048_576, for: QUICTransportParameterID.initialMaxData)
    try parameters.setInteger(1_200, for: QUICTransportParameterID.maxDatagramFrameSize)
    parameters[QUICTransportParameterID.resetStreamAt] = Data()
    parameters[QUICTransportParameterID.initialSourceConnectionID] = Data([0xca, 0xfe])

    let decoded = try QUICTransportParameters.decode(try parameters.encode())
    #expect(try decoded.integer(for: QUICTransportParameterID.initialMaxData) == 1_048_576)
    #expect(try decoded.integer(for: QUICTransportParameterID.maxDatagramFrameSize) == 1_200)
    #expect(decoded[QUICTransportParameterID.resetStreamAt] == Data())
    #expect(decoded[QUICTransportParameterID.initialSourceConnectionID] == Data([0xca, 0xfe]))
}

@Test
func longHeaderInitialPacketRoundTrips() throws {
    let frames: [QUICFrame] = [
        .crypto(offset: 0, data: Data("hello".utf8)),
        .padding,
    ]
    let packet = QUICLongHeaderPacket(
        packetType: .initial,
        version: 0x0000_0001,
        destinationConnectionID: Data([0x83, 0x94, 0xc8, 0xf0]),
        sourceConnectionID: Data([0xca, 0xfe]),
        token: Data([0x01, 0x02]),
        packetNumber: 10,
        packetNumberLength: 2,
        payload: try QUICFrame.encodeFrames(frames)
    )

    let decoded = try QUICLongHeaderPacket.decode(packet.encode(), largestAcknowledged: 8)
    #expect(decoded.packetType == packet.packetType)
    #expect(decoded.version == packet.version)
    #expect(decoded.destinationConnectionID == packet.destinationConnectionID)
    #expect(decoded.sourceConnectionID == packet.sourceConnectionID)
    #expect(decoded.token == packet.token)
    #expect(decoded.packetNumber == packet.packetNumber)
    #expect(try QUICFrame.decodeFrames(decoded.payload) == frames)
}

@Test
func retryPacketRoundTrips() throws {
    let packet = QUICRetryPacket(
        version: 0x0000_0001,
        destinationConnectionID: Data([0x01, 0x02, 0x03]),
        sourceConnectionID: Data([0x04, 0x05]),
        retryToken: Data("retry-token".utf8),
        retryIntegrityTag: Data(repeating: 0xab, count: 16)
    )

    #expect(try QUICRetryPacket.decode(packet.encode()) == packet)
}

@Test
func shortHeaderPacketRoundTrips() throws {
    let packet = QUICShortHeaderPacket(
        destinationConnectionID: Data([0xde, 0xad, 0xbe, 0xef]),
        keyPhase: true,
        packetNumber: 42,
        packetNumberLength: 1,
        payload: try QUICFrame.encodeFrames([
            .stream(id: 0, offset: 0, fin: false, data: Data("short".utf8)),
            .datagram(Data("packet".utf8)),
        ])
    )

    let decoded = try QUICShortHeaderPacket.decode(
        packet.encode(),
        destinationConnectionIDLength: 4,
        largestAcknowledged: 40
    )
    let decodedFrames = try QUICFrame.decodeFrames(decoded.payload)
    let packetFrames = try QUICFrame.decodeFrames(packet.payload)
    #expect(decoded == packet)
    #expect(decodedFrames == packetFrames)
}

@Test
func packetNumberReconstructionFollowsExpectedWindow() throws {
    #expect(try QUICPacketNumber.decodeTruncated(0x9b32, byteCount: 2, largestAcknowledged: 0xa82e) == 0x9b32)
    #expect(try QUICPacketNumber.decodeTruncated(0x0000, byteCount: 2, largestAcknowledged: 0xffff) == 0x1_0000)
}

// MARK: - Frame encoding validation

/// RFC 9000 section 19.15: a NEW_CONNECTION_ID length "less than 1 [or] greater than
/// 20" is a FRAME_ENCODING_ERROR. A zero-length CID must be rejected rather than
/// accepted as an identity with an empty connection ID.
@Test
func newConnectionIDRejectsZeroLengthConnectionID() throws {
    var bytes = Data([0x18, 0x01, 0x00, 0x00])  // type 0x18, sequence 1, retire_prior_to 0, length 0
    bytes.append(Data(repeating: 0xab, count: 16))  // stateless reset token

    var cursor = QUICByteCursor(bytes)
    #expect(throws: (any Error).self) {
        _ = try QUICFrame.decode(from: &cursor)
    }
}

/// The boundary values that are valid must still be accepted: 1 and 20.
@Test
func newConnectionIDAcceptsBoundaryLengths() throws {
    for length in [1, 20] {
        var bytes = Data([0x18, 0x01, 0x00, UInt8(length)])
        bytes.append(Data(repeating: 0xcd, count: length))
        bytes.append(Data(repeating: 0xab, count: 16))

        var cursor = QUICByteCursor(bytes)
        let frame = try QUICFrame.decode(from: &cursor)
        guard case .newConnectionID(_, _, let connectionID, _) = frame else {
            Issue.record("expected a newConnectionID frame for length \(length)")
            continue
        }
        #expect(connectionID.count == length)
    }
}
