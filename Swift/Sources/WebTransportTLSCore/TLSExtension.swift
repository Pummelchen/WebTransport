import Foundation
import WebTransportQUICCore

public enum TLSExtensionType: UInt16, Equatable, Sendable {
    case applicationLayerProtocolNegotiation = 0x0010
    case quicTransportParameters = 0x0039
}

public struct TLSExtension: Equatable, Sendable {
    public var type: UInt16
    public var data: Data

    public init(type: UInt16, data: Data) {
        self.type = type
        self.data = data
    }

    public init(type: TLSExtensionType, data: Data) {
        self.init(type: type.rawValue, data: data)
    }

    public func encode() throws -> Data {
        guard data.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("TLS extension data exceeds uint16 length")
        }

        var buffer = QUICByteBuffer()
        buffer.appendUInt16(type)
        buffer.appendUInt16(UInt16(data.count))
        buffer.append(data)
        return buffer.data
    }

    public static func decode(from cursor: inout QUICByteCursor) throws -> TLSExtension {
        let type = try cursor.readUInt16()
        let length = Int(try cursor.readUInt16())
        return TLSExtension(type: type, data: try cursor.readBytes(count: length))
    }

    public static func encodeList(_ extensions: [TLSExtension]) throws -> Data {
        var body = Data()
        for item in extensions {
            body.append(try item.encode())
        }
        guard body.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("TLS extension list exceeds uint16 length")
        }

        var buffer = QUICByteBuffer()
        buffer.appendUInt16(UInt16(body.count))
        buffer.append(body)
        return buffer.data
    }

    public static func decodeList(_ data: Data) throws -> [TLSExtension] {
        var cursor = QUICByteCursor(data)
        let length = Int(try cursor.readUInt16())
        let extensionBytes = try cursor.readBytes(count: length)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("TLS extension list has trailing bytes")
        }

        var extensionCursor = QUICByteCursor(extensionBytes)
        var extensions: [TLSExtension] = []
        while !extensionCursor.isAtEnd {
            extensions.append(try decode(from: &extensionCursor))
        }
        return extensions
    }
}

public enum TLSALPNExtension {
    public static func make(protocols: [String]) throws -> TLSExtension {
        guard !protocols.isEmpty else {
            throw QUICCodecError.malformed("ALPN protocol list must not be empty")
        }

        var protocolList = Data()
        for item in protocols {
            let bytes = Data(item.utf8)
            guard !bytes.isEmpty else {
                throw QUICCodecError.malformed("ALPN protocol ID must not be empty")
            }
            guard bytes.count <= UInt8.max else {
                throw QUICCodecError.valueOutOfRange("ALPN protocol ID exceeds uint8 length")
            }
            protocolList.append(UInt8(bytes.count))
            protocolList.append(bytes)
        }

        guard protocolList.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("ALPN protocol list exceeds uint16 length")
        }

        var data = Data()
        data.append(UInt8((protocolList.count >> 8) & 0xff))
        data.append(UInt8(protocolList.count & 0xff))
        data.append(protocolList)
        return TLSExtension(type: .applicationLayerProtocolNegotiation, data: data)
    }

    public static func protocols(from extensionData: Data) throws -> [String] {
        var cursor = QUICByteCursor(extensionData)
        let length = Int(try cursor.readUInt16())
        let protocolList = try cursor.readBytes(count: length)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("ALPN extension has trailing bytes")
        }

        var listCursor = QUICByteCursor(protocolList)
        var result: [String] = []
        while !listCursor.isAtEnd {
            let itemLength = Int(try listCursor.readUInt8())
            guard itemLength > 0 else {
                throw QUICCodecError.malformed("ALPN protocol ID is empty")
            }
            let item = try listCursor.readBytes(count: itemLength)
            guard let value = String(data: item, encoding: .utf8) else {
                throw QUICCodecError.malformed("ALPN protocol ID is not UTF-8")
            }
            result.append(value)
        }
        return result
    }
}

public enum TLSQUICTransportParametersExtension {
    public static func make(_ parameters: QUICTransportParameters) throws -> TLSExtension {
        try TLSExtension(
            type: .quicTransportParameters,
            data: parameters.encode()
        )
    }

    public static func parameters(from extensionData: Data) throws -> QUICTransportParameters {
        try QUICTransportParameters.decode(extensionData)
    }
}
