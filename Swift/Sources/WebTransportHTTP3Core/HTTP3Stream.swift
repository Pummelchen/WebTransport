import Foundation
import WebTransportQUICCore

public struct HTTP3StreamTypePrefix: Equatable, Sendable {
    public var type: UInt64
    public var bytesConsumed: Int
    public var remainingBytes: Data

    public init(type: UInt64, bytesConsumed: Int, remainingBytes: Data) {
        self.type = type
        self.bytesConsumed = bytesConsumed
        self.remainingBytes = remainingBytes
    }
}

public enum HTTP3StreamTypeParser {
    public static func parsePrefix(_ bytes: Data) throws -> HTTP3StreamTypePrefix {
        let totalLength = bytes.count
        var cursor = QUICByteCursor(bytes)
        let type = try QUICVarInt.decode(from: &cursor)
        let consumed = totalLength - cursor.remaining
        return HTTP3StreamTypePrefix(
            type: type,
            bytesConsumed: consumed,
            remainingBytes: try cursor.readBytes(count: cursor.remaining)
        )
    }

    public static func encodePrefix(type: UInt64, payload: Data = Data()) throws -> Data {
        guard type <= QUICVarInt.maximum else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 stream type exceeds QUIC varint range")
        }
        var output = try QUICVarInt.encode(type)
        output.append(payload)
        return output
    }
}
