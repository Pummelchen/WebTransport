import Foundation
import WebTransportQUICCore

public enum TLSHandshakeType: UInt8, Equatable, Sendable {
    case clientHello = 1
    case serverHello = 2
    case encryptedExtensions = 8
    case certificate = 11
    case certificateVerify = 15
    case finished = 20
}

public struct TLSHandshakeMessage: Equatable, Sendable {
    public var type: TLSHandshakeType
    public var body: Data

    public init(type: TLSHandshakeType, body: Data) {
        self.type = type
        self.body = body
    }

    public func encode() throws -> Data {
        guard body.count <= 0x00ff_ffff else {
            throw QUICCodecError.valueOutOfRange("TLS handshake body exceeds uint24 length")
        }

        var output = Data()
        output.append(type.rawValue)
        output.append(UInt8((body.count >> 16) & 0xff))
        output.append(UInt8((body.count >> 8) & 0xff))
        output.append(UInt8(body.count & 0xff))
        output.append(body)
        return output
    }

    public static func decode(from cursor: inout QUICByteCursor) throws -> TLSHandshakeMessage {
        guard let type = TLSHandshakeType(rawValue: try cursor.readUInt8()) else {
            throw QUICCodecError.malformed("unknown TLS handshake type")
        }
        let length =
            (Int(try cursor.readUInt8()) << 16) |
            (Int(try cursor.readUInt8()) << 8) |
            Int(try cursor.readUInt8())
        return TLSHandshakeMessage(type: type, body: try cursor.readBytes(count: length))
    }

    public static func decodeAll(_ data: Data) throws -> [TLSHandshakeMessage] {
        var cursor = QUICByteCursor(data)
        var messages: [TLSHandshakeMessage] = []
        while !cursor.isAtEnd {
            messages.append(try decode(from: &cursor))
        }
        return messages
    }
}
