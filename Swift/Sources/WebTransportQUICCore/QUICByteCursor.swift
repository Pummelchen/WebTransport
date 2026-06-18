import Foundation

public enum QUICCodecError: Error, Equatable, CustomStringConvertible, Sendable {
    case truncated(needed: Int, available: Int)
    case malformed(String)
    case valueOutOfRange(String)

    public var description: String {
        switch self {
        case .truncated(let needed, let available):
            "truncated: needed \(needed) bytes, available \(available)"
        case .malformed(let message):
            "malformed: \(message)"
        case .valueOutOfRange(let message):
            "value out of range: \(message)"
        }
    }
}

public struct QUICByteCursor: Sendable {
    public let data: Data
    public private(set) var offset: Int

    public init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    public var remaining: Int {
        data.endIndex - offset
    }

    public var isAtEnd: Bool {
        remaining == 0
    }

    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw QUICCodecError.truncated(needed: 1, available: remaining)
        }

        let value = data[offset]
        offset += 1
        return value
    }

    public mutating func readBytes(count: Int) throws -> Data {
        guard count >= 0 else {
            throw QUICCodecError.valueOutOfRange("negative byte count")
        }
        guard remaining >= count else {
            throw QUICCodecError.truncated(needed: count, available: remaining)
        }

        let end = offset + count
        let bytes = data[offset..<end]
        offset = end
        return Data(bytes)
    }

    public mutating func readUInt16() throws -> UInt16 {
        let bytes = try readBytes(count: 2)
        return bytes.reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
    }

    public mutating func readUInt32() throws -> UInt32 {
        let bytes = try readBytes(count: 4)
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}

public struct QUICByteBuffer: Sendable {
    public private(set) var data: Data

    public init() {
        self.data = Data()
    }

    public init(_ data: Data) {
        self.data = data
    }

    public mutating func appendUInt8(_ value: UInt8) {
        data.append(value)
    }

    public mutating func appendUInt16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    public mutating func appendUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    public mutating func append(_ bytes: Data) {
        data.append(bytes)
    }
}
