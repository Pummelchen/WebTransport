import Foundation
import WebTransportQUICCore

public enum TLSExtensionType: UInt16, Equatable, Sendable {
    case signatureAlgorithms = 0x000d
    case applicationLayerProtocolNegotiation = 0x0010
    case supportedVersions = 0x002b
    case keyShare = 0x0033
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

public enum TLSProtocolVersion {
    public static let tls12: UInt16 = 0x0303
    public static let tls13: UInt16 = 0x0304
}

public enum TLSCipherSuite {
    public static let aes128GCM_SHA256: UInt16 = 0x1301
}

public enum TLSSignatureScheme {
    public static let ecdsaSecp256r1SHA256: UInt16 = 0x0403
    public static let rsaPSSRSAESHA256: UInt16 = 0x0804
    public static let ed25519: UInt16 = 0x0807
}

public enum TLSNamedGroup {
    public static let secp256r1: UInt16 = 0x0017
    public static let x25519: UInt16 = 0x001d
}

public enum TLSSupportedVersionsExtension {
    public static func client(_ versions: [UInt16] = [TLSProtocolVersion.tls13]) throws -> TLSExtension {
        guard !versions.isEmpty else {
            throw QUICCodecError.malformed("supported_versions list must not be empty")
        }
        let byteCount = versions.count * MemoryLayout<UInt16>.size
        guard byteCount <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("supported_versions list too large")
        }

        var data = Data()
        data.append(UInt8(byteCount))
        for version in versions {
            var buffer = QUICByteBuffer()
            buffer.appendUInt16(version)
            data.append(buffer.data)
        }
        return TLSExtension(type: .supportedVersions, data: data)
    }

    public static func server(_ version: UInt16 = TLSProtocolVersion.tls13) -> TLSExtension {
        var buffer = QUICByteBuffer()
        buffer.appendUInt16(version)
        return TLSExtension(type: .supportedVersions, data: buffer.data)
    }

    public static func clientVersions(from extensionData: Data) throws -> [UInt16] {
        var cursor = QUICByteCursor(extensionData)
        let length = Int(try cursor.readUInt8())
        let data = try cursor.readBytes(count: length)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("supported_versions extension has trailing bytes")
        }
        guard length > 0 else {
            throw QUICCodecError.malformed("supported_versions list must not be empty")
        }
        guard length.isMultiple(of: 2) else {
            throw QUICCodecError.malformed("supported_versions length is not even")
        }

        var versionsCursor = QUICByteCursor(data)
        var versions: [UInt16] = []
        while !versionsCursor.isAtEnd {
            versions.append(try versionsCursor.readUInt16())
        }
        return versions
    }

    public static func serverVersion(from extensionData: Data) throws -> UInt16 {
        var cursor = QUICByteCursor(extensionData)
        let version = try cursor.readUInt16()
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("server supported_versions extension has trailing bytes")
        }
        return version
    }
}

public enum TLSSignatureAlgorithmsExtension {
    public static func make(_ schemes: [UInt16]) throws -> TLSExtension {
        guard !schemes.isEmpty else {
            throw QUICCodecError.malformed("signature_algorithms list must not be empty")
        }
        let byteCount = schemes.count * MemoryLayout<UInt16>.size
        guard byteCount <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("signature_algorithms list too large")
        }

        var body = QUICByteBuffer()
        body.appendUInt16(UInt16(byteCount))
        for item in schemes {
            body.appendUInt16(item)
        }
        return TLSExtension(type: .signatureAlgorithms, data: body.data)
    }

    public static func schemes(from extensionData: Data) throws -> [UInt16] {
        var cursor = QUICByteCursor(extensionData)
        let length = Int(try cursor.readUInt16())
        let body = try cursor.readBytes(count: length)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("signature_algorithms extension has trailing bytes")
        }
        guard length > 0 else {
            throw QUICCodecError.malformed("signature_algorithms list must not be empty")
        }
        guard length.isMultiple(of: 2) else {
            throw QUICCodecError.malformed("signature_algorithms length is not even")
        }

        var bodyCursor = QUICByteCursor(body)
        var schemes: [UInt16] = []
        while !bodyCursor.isAtEnd {
            schemes.append(try bodyCursor.readUInt16())
        }
        return schemes
    }
}

public struct TLSKeyShareEntry: Equatable, Sendable {
    public var group: UInt16
    public var keyExchange: Data

    public init(group: UInt16, keyExchange: Data) {
        self.group = group
        self.keyExchange = keyExchange
    }

    func encode() throws -> Data {
        guard keyExchange.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("key_share key exchange too large")
        }

        var buffer = QUICByteBuffer()
        buffer.appendUInt16(group)
        buffer.appendUInt16(UInt16(keyExchange.count))
        buffer.append(keyExchange)
        return buffer.data
    }

    static func decode(from cursor: inout QUICByteCursor) throws -> TLSKeyShareEntry {
        let group = try cursor.readUInt16()
        let length = Int(try cursor.readUInt16())
        guard length > 0 else {
            throw QUICCodecError.malformed("key_share key exchange must not be empty")
        }
        return TLSKeyShareEntry(group: group, keyExchange: try cursor.readBytes(count: length))
    }
}

public enum TLSKeyShareExtension {
    public static func client(_ entries: [TLSKeyShareEntry]) throws -> TLSExtension {
        guard !entries.isEmpty else {
            throw QUICCodecError.malformed("key_share list must not be empty")
        }

        var shares = Data()
        for entry in entries {
            shares.append(try entry.encode())
        }
        guard shares.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("key_share list too large")
        }

        var data = QUICByteBuffer()
        data.appendUInt16(UInt16(shares.count))
        data.append(shares)
        return TLSExtension(type: .keyShare, data: data.data)
    }

    public static func server(_ entry: TLSKeyShareEntry) throws -> TLSExtension {
        try TLSExtension(type: .keyShare, data: entry.encode())
    }

    public static func clientShares(from extensionData: Data) throws -> [TLSKeyShareEntry] {
        var cursor = QUICByteCursor(extensionData)
        let length = Int(try cursor.readUInt16())
        let body = try cursor.readBytes(count: length)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("client key_share extension has trailing bytes")
        }

        var bodyCursor = QUICByteCursor(body)
        var entries: [TLSKeyShareEntry] = []
        while !bodyCursor.isAtEnd {
            entries.append(try TLSKeyShareEntry.decode(from: &bodyCursor))
        }
        return entries
    }

    public static func serverShare(from extensionData: Data) throws -> TLSKeyShareEntry {
        var cursor = QUICByteCursor(extensionData)
        let entry = try TLSKeyShareEntry.decode(from: &cursor)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("server key_share extension has trailing bytes")
        }
        return entry
    }
}
