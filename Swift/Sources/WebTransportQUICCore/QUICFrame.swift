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
    case resetStreamAt(id: UInt64, applicationErrorCode: UInt64, finalSize: UInt64, reliableSize: UInt64)
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
        case .handshakeDone:
            output.append(0x1e)
        case .stream, .resetStream, .resetStreamAt, .stopSending:
            output.append(try streamFrameBytes())
        case .maxData, .maxStreamData, .maxStreams, .dataBlocked, .streamDataBlocked, .streamsBlocked:
            output.append(try flowControlFrameBytes())
        case .newConnectionID, .retireConnectionID, .connectionClose:
            output.append(try connectionFrameBytes())
        case .ack, .crypto, .datagram:
            output.append(try payloadFrameBytes())
        }
        return output
    }

    /// STREAM, RESET_STREAM, RESET_STREAM_AT and STOP_SENDING.
    ///
    /// The switch above is exhaustive over the frame types and lists every case, so a new
    /// case cannot compile until it is routed to one of these. The `default` in each is
    /// what that routing makes unreachable, and `everyFrameTypeRoundTrips` exercises every
    /// type through it.
    private func streamFrameBytes() throws -> Data {
        var output = Data()
        switch self {
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
        case .resetStreamAt(let id, let applicationErrorCode, let finalSize, let reliableSize):
            guard reliableSize <= finalSize else {
                throw QUICCodecError.valueOutOfRange("RESET_STREAM_AT reliable size exceeds final size")
            }
            output.append(0x24)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(applicationErrorCode))
            output.append(try QUICVarInt.encode(finalSize))
            output.append(try QUICVarInt.encode(reliableSize))
        case .stopSending(let id, let applicationErrorCode):
            output.append(0x05)
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(applicationErrorCode))
        default:
            throw QUICCodecError.malformed("frame is not a stream frame")
        }
        return output
    }

    /// The six flow-control frames. MAX_STREAMS and STREAMS_BLOCKED carry their direction
    /// in the low bit of the type byte.
    private func flowControlFrameBytes() throws -> Data {
        var output = Data()
        switch self {
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
        default:
            throw QUICCodecError.malformed("frame is not a flow-control frame")
        }
        return output
    }

    /// NEW_CONNECTION_ID, RETIRE_CONNECTION_ID and CONNECTION_CLOSE.
    private func connectionFrameBytes() throws -> Data {
        var output = Data()
        switch self {
        case .newConnectionID(let sequence, let retirePriorTo, let connectionID, let statelessResetToken):
            // Symmetric with the decoder: RFC 9000 section 19.15 makes a length
            // outside 1...20 a FRAME_ENCODING_ERROR, and the library must not be able
            // to produce a frame it would refuse to read.
            guard (1...20).contains(connectionID.count) else {
                throw QUICCodecError.valueOutOfRange(
                    "connection ID length must be 1...20, got \(connectionID.count)"
                )
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
        default:
            throw QUICCodecError.malformed("frame is not a connection frame")
        }
        return output
    }

    /// ACK, CRYPTO and DATAGRAM: the frames whose payload is separate from the type byte.
    private func payloadFrameBytes() throws -> Data {
        var output = Data()
        switch self {
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
        case .datagram(let data):
            output.append(0x31)
            output.append(try QUICVarInt.encode(UInt64(data.count)))
            output.append(data)
        default:
            throw QUICCodecError.malformed("frame is not a payload frame")
        }
        return output
    }
}

extension QUICFrame {
    public static func decode(from cursor: inout QUICByteCursor) throws -> QUICFrame {
        let type = try cursor.readUInt8()

        // Each helper recognises its own type bytes and returns `nil` for anything else,
        // so the dispatch is five reads rather than one twenty-three-case switch. The
        // unknown-type error at the end is the same one the single switch threw.
        if let frame = try decodeSimpleOrAckFrame(type: type, from: &cursor) {
            return frame
        }
        if let frame = try decodeStreamFamilyFrame(type: type, from: &cursor) {
            return frame
        }
        if let frame = try decodeFlowControlFrame(type: type, from: &cursor) {
            return frame
        }
        if let frame = try decodeConnectionFrame(type: type, from: &cursor) {
            return frame
        }
        if let frame = try decodePayloadFrame(type: type, from: &cursor) {
            return frame
        }
        throw QUICCodecError.malformed("unknown frame type 0x\(String(type, radix: 16))")
    }

    /// PADDING, PING and ACK.
    private static func decodeSimpleOrAckFrame(
        type: UInt8,
        from cursor: inout QUICByteCursor
    ) throws -> QUICFrame? {
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
                ranges.append(
                    QUICAckRange(
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
        default:
            return nil
        }
    }

    /// RESET_STREAM, STOP_SENDING, RESET_STREAM_AT and the eight STREAM type bytes.
    private static func decodeStreamFamilyFrame(
        type: UInt8,
        from cursor: inout QUICByteCursor
    ) throws -> QUICFrame? {
        switch type {
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
        case 0x24:
            let id = try QUICVarInt.decode(from: &cursor)
            let applicationErrorCode = try QUICVarInt.decode(from: &cursor)
            let finalSize = try QUICVarInt.decode(from: &cursor)
            let reliableSize = try QUICVarInt.decode(from: &cursor)
            guard reliableSize <= finalSize else {
                throw QUICCodecError.valueOutOfRange("RESET_STREAM_AT reliable size exceeds final size")
            }
            return .resetStreamAt(
                id: id,
                applicationErrorCode: applicationErrorCode,
                finalSize: finalSize,
                reliableSize: reliableSize
            )
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
        default:
            return nil
        }
    }

    /// The eight flow-control frames.
    private static func decodeFlowControlFrame(
        type: UInt8,
        from cursor: inout QUICByteCursor
    ) throws -> QUICFrame? {
        switch type {
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
        default:
            return nil
        }
    }

    /// NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, both CONNECTION_CLOSE forms and
    /// HANDSHAKE_DONE.
    private static func decodeConnectionFrame(
        type: UInt8,
        from cursor: inout QUICByteCursor
    ) throws -> QUICFrame? {
        switch type {
        case 0x18:
            let sequence = try QUICVarInt.decode(from: &cursor)
            let retirePriorTo = try QUICVarInt.decode(from: &cursor)
            let length = Int(try cursor.readUInt8())
            // RFC 9000 section 19.15: "Values less than 1 and greater than 20 are
            // invalid and MUST be treated as a connection error of type
            // FRAME_ENCODING_ERROR."
            guard (1...20).contains(length) else {
                throw QUICCodecError.valueOutOfRange(
                    "connection ID length must be 1...20, got \(length)"
                )
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
        default:
            return nil
        }
    }

    /// CRYPTO and both DATAGRAM forms: 0x30 is length-less and consumes the rest.
    private static func decodePayloadFrame(
        type: UInt8,
        from cursor: inout QUICByteCursor
    ) throws -> QUICFrame? {
        switch type {
        case 0x06:
            let offset = try QUICVarInt.decode(from: &cursor)
            let length = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .crypto(offset: offset, data: try cursor.readBytes(count: length))
        case 0x30:
            return .datagram(try cursor.readBytes(count: cursor.remaining))
        case 0x31:
            let length = try checkedLength(try QUICVarInt.decode(from: &cursor))
            return .datagram(try cursor.readBytes(count: length))
        default:
            return nil
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
