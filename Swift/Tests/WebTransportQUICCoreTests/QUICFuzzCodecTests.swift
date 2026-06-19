import Foundation
import Testing
@testable import WebTransportQUICCore

private struct DeterministicRNG {
    private var state: UInt64

    init(seed: UInt64 = 0x5A4A_6A5B_3C2D_1E0F) {
        state = seed
    }

    mutating func nextUInt64() -> UInt64 {
        state ^= state << 7
        state ^= state >> 9
        state ^= state << 8
        return state
    }

    mutating func nextInt(upperExclusive: Int) -> Int {
        guard upperExclusive > 0 else {
            return 0
        }
        return Int(nextUInt64() % UInt64(upperExclusive))
    }

    mutating func nextUInt64(upperInclusive: UInt64) -> UInt64 {
        guard upperInclusive > 0 else {
            return 0
        }
        return nextUInt64() % (upperInclusive + 1)
    }

    mutating func nextData(length: Int) -> Data {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for _ in 0..<length {
            bytes.append(UInt8(truncatingIfNeeded: nextUInt64()))
        }
        return Data(bytes)
    }
}

private enum FuzzFrameGenerator {
    static func makeRandomFrame(using rng: inout DeterministicRNG, index: Int) throws -> QUICFrame {
        switch rng.nextInt(upperExclusive: 14) {
        case 0:
            return .padding
        case 1:
            return .ping
        case 2:
            return .ack(
                largestAcknowledged: rng.nextUInt64(upperInclusive: 8192),
                ackDelay: rng.nextUInt64(upperInclusive: 256),
                firstAckRange: rng.nextUInt64(upperInclusive: 8),
                ranges: makeRanges(count: rng.nextInt(upperExclusive: 4), rng: &rng)
            )
        case 3:
            return .crypto(
                offset: rng.nextUInt64(upperInclusive: 1024),
                data: rng.nextData(length: rng.nextInt(upperExclusive: 32))
            )
        case 4:
            return .stream(
                id: UInt64(index * 4),
                offset: rng.nextUInt64(upperInclusive: 1_024),
                fin: rng.nextInt(upperExclusive: 2) == 1,
                data: rng.nextData(length: rng.nextInt(upperExclusive: 16))
            )
        case 5:
            return .resetStream(
                id: UInt64(index * 4),
                applicationErrorCode: rng.nextUInt64(upperInclusive: 255),
                finalSize: rng.nextUInt64(upperInclusive: 1_024)
            )
        case 6:
            let finalSize = rng.nextUInt64(upperInclusive: 1_024)
            return try .resetStreamAt(
                id: UInt64(index * 4),
                applicationErrorCode: rng.nextUInt64(upperInclusive: 255),
                finalSize: finalSize,
                reliableSize: rng.nextUInt64(upperInclusive: finalSize)
            )
        case 7:
            return .stopSending(
                id: UInt64(index * 4),
                applicationErrorCode: rng.nextUInt64(upperInclusive: 255)
            )
        case 8:
            return .maxData(rng.nextUInt64(upperInclusive: 4_096))
        case 9:
            return .maxStreamData(
                id: UInt64(index * 4),
                maximum: rng.nextUInt64(upperInclusive: 4_096)
            )
        case 10:
            return .maxStreams(
                direction: rng.nextInt(upperExclusive: 2) == 0 ? .bidirectional : .unidirectional,
                maximum: rng.nextUInt64(upperInclusive: 64)
            )
        case 11:
            return .streamDataBlocked(
                id: UInt64(index * 4),
                offset: rng.nextUInt64(upperInclusive: 2_048)
            )
        case 12:
            return .streamsBlocked(
                direction: rng.nextInt(upperExclusive: 2) == 0 ? .bidirectional : .unidirectional,
                maximum: rng.nextUInt64(upperInclusive: 64)
            )
        default:
            let length = rng.nextInt(upperExclusive: 32)
            return .datagram(rng.nextData(length: length))
        }
    }

    private static func makeRanges(count: Int, rng: inout DeterministicRNG) -> [QUICAckRange] {
        guard count > 0 else {
            return []
        }
        return (0..<count).map { _ in
            QUICAckRange(
                gap: rng.nextUInt64(upperInclusive: 12),
                length: rng.nextUInt64(upperInclusive: 6)
            )
        }
    }

    static func makeSettingsLikeFrames(using rng: inout DeterministicRNG) -> [QUICFrame] {
        return [
            .newConnectionID(
                sequence: rng.nextUInt64(upperInclusive: 12),
                retirePriorTo: 0,
                connectionID: rng.nextData(length: Int(rng.nextUInt64(upperInclusive: 8) + 1)),
                statelessResetToken: rng.nextData(length: 16)
            ),
            .retireConnectionID(
                sequence: rng.nextUInt64(upperInclusive: 8)
            ),
            .connectionClose(
                errorCode: rng.nextUInt64(upperInclusive: 0x20),
                frameType: rng.nextInt(upperExclusive: 2) == 0 ? nil : 0x08,
                reason: rng.nextData(length: Int(rng.nextUInt64(upperInclusive: 8)))
            ),
            .handshakeDone,
            .dataBlocked(rng.nextUInt64(upperInclusive: 2_048)),
            .streamsBlocked(direction: .bidirectional, maximum: rng.nextUInt64(upperInclusive: 8))
        ]
    }
}

@Test
func quicVarIntCodecFuzzRoundTrips() throws {
    let inputs: [UInt64] = [
        0,
        1,
        62,
        6_000,
        0x3fff,
        0x4000,
        0x55_55_55,
        QUICVarInt.maximum
    ]

    for value in inputs {
        let encoded = try QUICVarInt.encode(value)
        var cursor = QUICByteCursor(encoded)
        #expect(try QUICVarInt.decode(from: &cursor) == value)
        #expect(cursor.isAtEnd)
    }

    var rng = DeterministicRNG(seed: 0x1234_5678_9abc_def0)
    for _ in 0..<400 {
        let value = rng.nextUInt64(upperInclusive: 0x3fff_ffff_ffff)
        let encoded = try QUICVarInt.encode(value)
        var cursor = QUICByteCursor(encoded)
        #expect(try QUICVarInt.decode(from: &cursor) == value)
        #expect(cursor.isAtEnd)
    }
}

@Test
func quicFrameCorpusRoundTripsFuzzedDeterministic() throws {
    var rng = DeterministicRNG(seed: 0x0fed_cba9_8765_4321)
    var frames: [QUICFrame] = []

    frames.append(contentsOf: FuzzFrameGenerator.makeSettingsLikeFrames(using: &rng))
    for index in 0..<512 {
        frames.append(try FuzzFrameGenerator.makeRandomFrame(using: &rng, index: index))
    }

    let encoded = try QUICFrame.encodeFrames(frames)
    let decoded = try QUICFrame.decodeFrames(encoded)
    #expect(decoded == frames)
}

@Test
func quicFrameCorpusRejectsTruncatedWireData() throws {
    let malformedVectors: [Data] = [
        Data([0x02, 0x20]),
        Data([0x06, 0x00]),
        Data([0x24, 0x00, 0x00, 0x00]),
        Data([0x31, 0x40]),
        Data([0x08]),
        Data([0x18, 0x01, 0x00, 0x00, 0x21])
    ]

    for payload in malformedVectors {
        #expect(throws: Error.self) {
            try QUICFrame.decodeFrames(payload)
        }
    }
}
