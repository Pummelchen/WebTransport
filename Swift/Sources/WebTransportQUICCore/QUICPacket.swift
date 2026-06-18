import Foundation

public enum QUICPacketType: UInt8, Equatable, Sendable {
    case initial = 0x00
    case zeroRTT = 0x01
    case handshake = 0x02
    case retry = 0x03
}

public struct QUICLongHeaderPacket: Equatable, Sendable {
    public var packetType: QUICPacketType
    public var version: UInt32
    public var destinationConnectionID: Data
    public var sourceConnectionID: Data
    public var token: Data
    public var packetNumber: UInt64
    public var packetNumberLength: Int
    public var payload: Data

    public init(
        packetType: QUICPacketType,
        version: UInt32,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        token: Data = Data(),
        packetNumber: UInt64,
        packetNumberLength: Int,
        payload: Data
    ) {
        self.packetType = packetType
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.token = token
        self.packetNumber = packetNumber
        self.packetNumberLength = packetNumberLength
        self.payload = payload
    }

    public func encode() throws -> Data {
        guard packetType != .retry else {
            throw QUICCodecError.malformed("Retry packets use QUICRetryPacket")
        }
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        var output = Data()
        let first = UInt8(0xc0) | (packetType.rawValue << 4) | UInt8(packetNumberLength - 1)
        output.append(first)
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        output.append(buffer.data)
        output.append(UInt8(destinationConnectionID.count))
        output.append(destinationConnectionID)
        output.append(UInt8(sourceConnectionID.count))
        output.append(sourceConnectionID)

        if packetType == .initial {
            output.append(try QUICVarInt.encode(UInt64(token.count)))
            output.append(token)
        }

        let packetNumberBytes = try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength)
        output.append(try QUICVarInt.encode(UInt64(packetNumberBytes.count + payload.count)))
        output.append(packetNumberBytes)
        output.append(payload)
        return output
    }

    public static func decode(_ data: Data, largestAcknowledged: UInt64? = nil) throws -> QUICLongHeaderPacket {
        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        guard let packetType = QUICPacketType(rawValue: (first >> 4) & 0x03) else {
            throw QUICCodecError.malformed("unknown long header packet type")
        }
        guard packetType != .retry else {
            throw QUICCodecError.malformed("Retry packets use QUICRetryPacket")
        }
        let packetNumberLength = Int(first & 0x03) + 1
        let version = try cursor.readUInt32()
        let destinationLength = Int(try cursor.readUInt8())
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destinationConnectionID = try cursor.readBytes(count: destinationLength)
        let sourceLength = Int(try cursor.readUInt8())
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        let sourceConnectionID = try cursor.readBytes(count: sourceLength)

        let token: Data
        if packetType == .initial {
            let tokenLength = try checkedLength(try QUICVarInt.decode(from: &cursor))
            token = try cursor.readBytes(count: tokenLength)
        } else {
            token = Data()
        }

        let length = try QUICVarInt.decode(from: &cursor)
        guard length >= UInt64(packetNumberLength), length <= UInt64(cursor.remaining) else {
            throw QUICCodecError.malformed("invalid long header packet length")
        }
        let packetNumberData = try cursor.readBytes(count: packetNumberLength)
        let truncated = packetNumberData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncated,
            byteCount: packetNumberLength,
            largestAcknowledged: largestAcknowledged
        )
        let payloadLength = Int(length) - packetNumberLength
        let payload = try cursor.readBytes(count: payloadLength)

        return QUICLongHeaderPacket(
            packetType: packetType,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: token,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: payload
        )
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("length exceeds Int.max")
        }
        return Int(value)
    }
}

public struct QUICRetryPacket: Equatable, Sendable {
    public var version: UInt32
    public var destinationConnectionID: Data
    public var sourceConnectionID: Data
    public var retryToken: Data
    public var retryIntegrityTag: Data

    public init(
        version: UInt32,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        retryToken: Data,
        retryIntegrityTag: Data
    ) {
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.retryToken = retryToken
        self.retryIntegrityTag = retryIntegrityTag
    }

    public func encode() throws -> Data {
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        guard retryIntegrityTag.count == 16 else {
            throw QUICCodecError.malformed("Retry integrity tag must be 16 bytes")
        }

        var output = Data()
        output.append(0xf0)
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        output.append(buffer.data)
        output.append(UInt8(destinationConnectionID.count))
        output.append(destinationConnectionID)
        output.append(UInt8(sourceConnectionID.count))
        output.append(sourceConnectionID)
        output.append(retryToken)
        output.append(retryIntegrityTag)
        return output
    }

    public static func decode(_ data: Data) throws -> QUICRetryPacket {
        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        guard ((first >> 4) & 0x03) == QUICPacketType.retry.rawValue else {
            throw QUICCodecError.malformed("not a Retry packet")
        }

        let version = try cursor.readUInt32()
        let destinationLength = Int(try cursor.readUInt8())
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destinationConnectionID = try cursor.readBytes(count: destinationLength)
        let sourceLength = Int(try cursor.readUInt8())
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        let sourceConnectionID = try cursor.readBytes(count: sourceLength)
        guard cursor.remaining >= 16 else {
            throw QUICCodecError.truncated(needed: 16, available: cursor.remaining)
        }
        let token = try cursor.readBytes(count: cursor.remaining - 16)
        let tag = try cursor.readBytes(count: 16)

        return QUICRetryPacket(
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            retryToken: token,
            retryIntegrityTag: tag
        )
    }
}

public struct QUICShortHeaderPacket: Equatable, Sendable {
    public var destinationConnectionID: Data
    public var keyPhase: Bool
    public var packetNumber: UInt64
    public var packetNumberLength: Int
    public var payload: Data

    public init(
        destinationConnectionID: Data,
        keyPhase: Bool = false,
        packetNumber: UInt64,
        packetNumberLength: Int,
        payload: Data
    ) {
        self.destinationConnectionID = destinationConnectionID
        self.keyPhase = keyPhase
        self.packetNumber = packetNumber
        self.packetNumberLength = packetNumberLength
        self.payload = payload
    }

    public func encode() throws -> Data {
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        var output = Data()
        var first = UInt8(0x40) | UInt8(packetNumberLength - 1)
        if keyPhase {
            first |= 0x04
        }
        output.append(first)
        output.append(destinationConnectionID)
        output.append(try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength))
        output.append(payload)
        return output
    }

    public static func decode(
        _ data: Data,
        destinationConnectionIDLength: Int,
        largestAcknowledged: UInt64? = nil
    ) throws -> QUICShortHeaderPacket {
        guard (0...20).contains(destinationConnectionIDLength) else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }

        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        guard (first & 0x80) == 0 else {
            throw QUICCodecError.malformed("not a short header packet")
        }
        guard (first & 0x40) != 0 else {
            throw QUICCodecError.malformed("short header fixed bit is not set")
        }

        let packetNumberLength = Int(first & 0x03) + 1
        let keyPhase = (first & 0x04) != 0
        let destinationConnectionID = try cursor.readBytes(count: destinationConnectionIDLength)
        let packetNumberData = try cursor.readBytes(count: packetNumberLength)
        let truncated = packetNumberData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncated,
            byteCount: packetNumberLength,
            largestAcknowledged: largestAcknowledged
        )

        return QUICShortHeaderPacket(
            destinationConnectionID: destinationConnectionID,
            keyPhase: keyPhase,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: try cursor.readBytes(count: cursor.remaining)
        )
    }
}
