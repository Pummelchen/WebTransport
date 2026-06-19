import Foundation
import WebTransportQUICCore

public struct HTTP3Frame: Equatable, Sendable {
    public var type: UInt64
    public var payload: Data

    public init(type: UInt64, payload: Data = Data()) throws {
        guard type <= QUICVarInt.maximum else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 frame type exceeds QUIC varint range")
        }
        guard UInt64(payload.count) <= QUICVarInt.maximum else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 frame payload length exceeds QUIC varint range")
        }

        self.type = type
        self.payload = payload
    }

    public init(type: UInt64, varIntValue: UInt64) throws {
        try self.init(type: type, payload: try QUICVarInt.encode(varIntValue))
    }

    public func encode() throws -> Data {
        var output = Data()
        output.append(try QUICVarInt.encode(type))
        output.append(try QUICVarInt.encode(UInt64(payload.count)))
        output.append(payload)
        return output
    }

    public static func decode(from cursor: inout QUICByteCursor) throws -> HTTP3Frame {
        let type = try QUICVarInt.decode(from: &cursor)
        let length = try checkedLength(try QUICVarInt.decode(from: &cursor))
        return try HTTP3Frame(type: type, payload: try cursor.readBytes(count: length))
    }

    public static func decodeFrames(_ data: Data) throws -> [HTTP3Frame] {
        var cursor = QUICByteCursor(data)
        var frames: [HTTP3Frame] = []
        while !cursor.isAtEnd {
            frames.append(try decode(from: &cursor))
        }
        return frames
    }

    public static func encodeFrames(_ frames: [HTTP3Frame]) throws -> Data {
        var output = Data()
        for frame in frames {
            output.append(try frame.encode())
        }
        return output
    }

    public func singleVarIntPayload() throws -> UInt64 {
        var cursor = QUICByteCursor(payload)
        let value = try QUICVarInt.decode(from: &cursor)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("HTTP/3 frame payload has trailing bytes")
        }
        return value
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 frame length exceeds Int.max")
        }
        return Int(value)
    }
}
