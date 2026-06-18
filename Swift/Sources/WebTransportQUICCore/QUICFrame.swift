import Foundation

public enum QUICStreamDirection: UInt8, Sendable {
    case bidirectional = 0
    case unidirectional = 1
}

public struct QUICAckRange: Equatable, Sendable {
    public var gap: UInt64
    public var length: UInt64

    public init(gap: UInt64, length: UInt64) {
        self.gap = gap
        self.length = length
    }
}

public enum QUICFrame: Equatable, Sendable {
    case padding
    case ping
    case ack(largestAcknowledged: UInt64, ackDelay: UInt64, firstAckRange: UInt64, ranges: [QUICAckRange])
    case crypto(offset: UInt64, data: Data)
    case stream(id: UInt64, offset: UInt64?, fin: Bool, data: Data)
    case resetStream(id: UInt64, applicationErrorCode: UInt64, finalSize: UInt64)
    case stopSending(id: UInt64, applicationErrorCode: UInt64)
    case maxData(UInt64)
    case maxStreamData(id: UInt64, maximum: UInt64)
    case maxStreams(direction: QUICStreamDirection, maximum: UInt64)
    case dataBlocked(UInt64)
    case streamDataBlocked(id: UInt64, offset: UInt64)
    case streamsBlocked(direction: QUICStreamDirection, maximum: UInt64)
    case newConnectionID(sequence: UInt64, retirePriorTo: UInt64, connectionID: Data, statelessResetToken: Data)
    case retireConnectionID(sequence: UInt64)
    case connectionClose(errorCode: UInt64, frameType: UInt64?, reason: Data)
    case handshakeDone
    case datagram(Data)

    public func encode() throws -> Data {
        var output = Data()

        switch self {
        case .padding:
            output.append(0x00)
        case .ping:
            output.append(0x01)
        case .ack(let largestAcknowledged, let ackDelay, let firstAckRange, let ranges):
            output.append(0x02)
            output.append(try QUICVarInt.encode(largestAcknowledged))
            output.append(try QUICVarInt.encode(ackDelay))
            output.append(try QUICVarInt.encode(UInt64(ranges.count)))
            output.append(try QUICVarInt.encode(firstAckRange))
            for range in ranges {
                output.append(try QUICVarInt.encode(range.gap))
                output.append(try QUICVarInt.encode(range.length))
            }
        case .crypto(let offset, let data):
            output.append(0x06)
            output.append(try QUICVarInt.encode(offset))
            output.append(try QUICVarInt.encode(UInt64(data.count)))
            output.append(data)
        case .stream(let id, let offset, let fin, let data):
            var type: UInt8 = 0x08
            if offset != nil {
                type |= 0x04
            }
            type |= 0x02
            if fin {
                type |= 0x01
            }
            output.append(type)
            output.append(try QUICVarInt.encode(id))
            if let offset {
                output.append(try QUICVarInt.encode(offset))
            }
            output.append(try QUICVarInt.encode(UInt64(data.count)))
            output.append(data)
        case .resetStream(let id, let applicationErrorCode, let finalSize):
            output.append(0x04)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(applicationErrorCode))
            output.append(try QUICVarInt.encode(finalSize))
        case .stopSending(let id, let applicationErrorCode):
            output.append(0x05)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(applicationErrorCode))
        case .maxData(let maximum):
            output.append(0x10)
            output.append(try QUICVarInt.encode(maximum))
        case .maxStreamData(let id, let maximum):
            output.append(0x11)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(maximum))
        case .maxStreams(let direction, let maximum):
            output.append(direction == .bidirectional ? 0x12 : 0x13)
            output.append(try QUICVarInt.encode(maximum))
        case .dataBlocked(let maximum):
            output.append(0x14)
            output.append(try QUICVarInt.encode(maximum))
        case .streamDataBlocked(let id, let offset):
            output.append(0x15)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(offset))
        case .streamsBlocked(let direction, let maximum):
            output.append(direction == .bidirectional ? 0x16 : 0x17)
            output.append(try QUICVarInt.encode(maximum))
        case .newConnectionID(let sequence, let retirePriorTo, let connectionID, let statelessResetToken):
            guard connectionID.count <= 20 else {
                throw QUICCodecError.valueOutOfRange("connection ID length exceeds 20")
            }
            guard statelessResetToken.count == 16 else {
                throw QUICCodecError.malformed("stateless reset token must be 16 bytes")
            }
            output.append(0x18)
            output.append(try QUICVarInt.encode(sequence))
            output.append(try QUICVarInt.encode(retirePriorTo))
            output.append(UInt8(connectionID.count))
            output.append(connectionID)
            output.append(statelessResetToken)
        case .retireConnectionID(let sequence):
            output.append(0x19)
            output.append(try QUICVarInt.encode(sequence))
        case .connectionClose(let errorCode, let frameType, let reason):
            if let frameType {
                output.append(0x1c)
                output.append(try QUICVarInt.encode(errorCode))
                output.append(try QUICVarInt.encode(frameType))
            } else {
                output.append(0x1d)
                output.append(try QUICVarInt.encode(errorCode))
            }
            output.append(try QUICVarInt.encode(UInt64(reason.count)))
            output.append(reason)
        case .handshakeDone:
            output.append(0x1e)
        case .datagram(let data):
            output.append(0x31)
            output.append(try QUICVarInt.encode(UInt64(data.count)))
            output.append(data)
        }

        return output
    }

    public static func decode(from cursor: inout QUICByteCursor) throws -> QUICFrame {
        let type = try cursor.readUInt8()

        switch type {
        case 0x00:
            return .padding
        case 0x01:
            return .ping
        case 0x02:
            let largestAcknowledged = try QUICVarInt.decode(from: &cursor)
            let ackDelay = try QUICVarInt.decode(from: &cursor)
            let rangeCount = try QUICVarInt.decode(from: &cursor)
            let firstAckRange = try QUICVarInt.decode(from: &cursor)
            var ranges: [QUICAckRange] = []
            for _ in 0..<rangeCount {
                ranges.append(QUICAckRange(
                    gap: try QUICVarInt.decode(from: &cursor),
                    length: try QUICVarInt.decode(from: &cursor)
                ))
            }
            return .ack(
                largestAcknowledged: largestAcknowledged,
                ackDelay: ackDelay,
                firstAckRange: firstAckRange,
                ranges: ranges
            )
        case 0x04:
            return .resetStream(
                id: try QUICVarInt.decode(from: &cursor),
                applicationErrorCode: try QUICVarInt.decode(from: &cursor),
                finalSize: try QUICVarInt.decode(from: &cursor)
            )
        case 0x05:
            return .stopSending(
                id: try QUICVarInt.decode(from: &cursor),
                applicationErrorCode: try QUICVarInt.decode(from: &cursor)
            )
        case 0x06:
            let offset = try QUICVarInt.decode(from: &cursor)
            let length = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .crypto(offset: offset, data: try cursor.readBytes(count: length))
        case 0x08...0x0f:
            let hasOffset = (type & 0x04) != 0
            let hasLength = (type & 0x02) != 0
            let fin = (type & 0x01) != 0
            let id = try QUICVarInt.decode(from: &cursor)
            let offset = hasOffset ? try QUICVarInt.decode(from: &cursor) : nil
            let data: Data
            if hasLength {
                data = try cursor.readBytes(count: checkedLength(try QUICVarInt.decode(from: &cursor)))
            } else {
                data = try cursor.readBytes(count: cursor.remaining)
            }
            return .stream(id: id, offset: offset, fin: fin, data: data)
        case 0x10:
            return .maxData(try QUICVarInt.decode(from: &cursor))
        case 0x11:
            return .maxStreamData(
                id: try QUICVarInt.decode(from: &cursor),
                maximum: try QUICVarInt.decode(from: &cursor)
            )
        case 0x12:
            return .maxStreams(direction: .bidirectional, maximum: try QUICVarInt.decode(from: &cursor))
        case 0x13:
            return .maxStreams(direction: .unidirectional, maximum: try QUICVarInt.decode(from: &cursor))
        case 0x14:
            return .dataBlocked(try QUICVarInt.decode(from: &cursor))
        case 0x15:
            return .streamDataBlocked(
                id: try QUICVarInt.decode(from: &cursor),
                offset: try QUICVarInt.decode(from: &cursor)
            )
        case 0x16:
            return .streamsBlocked(direction: .bidirectional, maximum: try QUICVarInt.decode(from: &cursor))
        case 0x17:
            return .streamsBlocked(direction: .unidirectional, maximum: try QUICVarInt.decode(from: &cursor))
        case 0x18:
            let sequence = try QUICVarInt.decode(from: &cursor)
            let retirePriorTo = try QUICVarInt.decode(from: &cursor)
            let length = Int(try cursor.readUInt8())
            guard length <= 20 else {
                throw QUICCodecError.valueOutOfRange("connection ID length exceeds 20")
            }
            return .newConnectionID(
                sequence: sequence,
                retirePriorTo: retirePriorTo,
                connectionID: try cursor.readBytes(count: length),
                statelessResetToken: try cursor.readBytes(count: 16)
            )
        case 0x19:
            return .retireConnectionID(sequence: try QUICVarInt.decode(from: &cursor))
        case 0x1c:
            let errorCode = try QUICVarInt.decode(from: &cursor)
            let frameType = try QUICVarInt.decode(from: &cursor)
            let reasonLength = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .connectionClose(
                errorCode: errorCode,
                frameType: frameType,
                reason: try cursor.readBytes(count: reasonLength)
            )
        case 0x1d:
            let errorCode = try QUICVarInt.decode(from: &cursor)
            let reasonLength = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .connectionClose(
                errorCode: errorCode,
                frameType: nil,
                reason: try cursor.readBytes(count: reasonLength)
            )
        case 0x1e:
            return .handshakeDone
        case 0x30:
            return .datagram(try cursor.readBytes(count: cursor.remaining))
        case 0x31:
            let length = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .datagram(try cursor.readBytes(count: length))
        default:
            throw QUICCodecError.malformed("unknown frame type 0x\(String(type, radix: 16))")
        }
    }

    public static func decodeFrames(_ data: Data) throws -> [QUICFrame] {
        var cursor = QUICByteCursor(data)
        var frames: [QUICFrame] = []
        while !cursor.isAtEnd {
            frames.append(try decode(from: &cursor))
        }
        return frames
    }

    public static func encodeFrames(_ frames: [QUICFrame]) throws -> Data {
        var output = Data()
        for frame in frames {
            output.append(try frame.encode())
        }
        return output
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("length exceeds Int.max")
        }
        return Int(value)
    }
}
