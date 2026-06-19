import Foundation
import WebTransportQUICCore

public struct TLSCertificateEntry: Equatable, Sendable {
    public var certificateData: Data
    public var extensions: [TLSExtension]

    public init(certificateData: Data, extensions: [TLSExtension] = []) throws {
        guard !certificateData.isEmpty else {
            throw QUICCodecError.malformed("certificate entry data must not be empty")
        }
        guard certificateData.count <= 0x00ff_ffff else {
            throw QUICCodecError.valueOutOfRange("certificate entry data exceeds uint24 length")
        }
        self.certificateData = certificateData
        self.extensions = extensions
    }

    func encode() throws -> Data {
        var output = Data()
        try output.appendUInt24(certificateData.count)
        output.append(certificateData)
        output.append(try TLSExtension.encodeList(extensions))
        return output
    }

    static func decode(from cursor: inout QUICByteCursor) throws -> TLSCertificateEntry {
        let certificateData = try cursor.readBytes(count: try cursor.readUInt24())
        let extensionsLength = Int(try cursor.readUInt16())
        let extensionsBody = try cursor.readBytes(count: extensionsLength)
        var extensionsVector = QUICByteBuffer()
        extensionsVector.appendUInt16(UInt16(extensionsLength))
        extensionsVector.append(extensionsBody)
        let extensions = try TLSExtension.decodeList(extensionsVector.data)
        return try TLSCertificateEntry(certificateData: certificateData, extensions: extensions)
    }
}

public struct TLSCertificate: Equatable, Sendable {
    public var requestContext: Data
    public var entries: [TLSCertificateEntry]

    public init(requestContext: Data = Data(), entries: [TLSCertificateEntry]) throws {
        guard requestContext.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("certificate request context exceeds uint8 length")
        }
        guard !entries.isEmpty else {
            throw QUICCodecError.malformed("certificate message must include at least one certificate entry")
        }
        self.requestContext = requestContext
        self.entries = entries
    }

    public func body() throws -> Data {
        var list = Data()
        for entry in entries {
            list.append(try entry.encode())
        }
        guard list.count <= 0x00ff_ffff else {
            throw QUICCodecError.valueOutOfRange("certificate list exceeds uint24 length")
        }

        var output = Data()
        output.append(UInt8(requestContext.count))
        output.append(requestContext)
        try output.appendUInt24(list.count)
        output.append(list)
        return output
    }

    public func handshakeMessage() throws -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .certificate, body: try body())
    }

    public static func decode(_ body: Data) throws -> TLSCertificate {
        var cursor = QUICByteCursor(body)
        let context = try cursor.readBytes(count: Int(try cursor.readUInt8()))
        let list = try cursor.readBytes(count: try cursor.readUInt24())
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("certificate message has trailing bytes")
        }

        var listCursor = QUICByteCursor(list)
        var entries: [TLSCertificateEntry] = []
        while !listCursor.isAtEnd {
            entries.append(try TLSCertificateEntry.decode(from: &listCursor))
        }
        return try TLSCertificate(requestContext: context, entries: entries)
    }
}

public struct TLSCertificateVerify: Equatable, Sendable {
    public var algorithm: UInt16
    public var signature: Data

    public init(algorithm: UInt16, signature: Data) throws {
        guard !signature.isEmpty else {
            throw QUICCodecError.malformed("CertificateVerify signature must not be empty")
        }
        guard signature.count <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("CertificateVerify signature exceeds uint16 length")
        }
        self.algorithm = algorithm
        self.signature = signature
    }

    public func body() -> Data {
        var output = QUICByteBuffer()
        output.appendUInt16(algorithm)
        output.appendUInt16(UInt16(signature.count))
        output.append(signature)
        return output.data
    }

    public func handshakeMessage() -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .certificateVerify, body: body())
    }

    public static func decode(_ body: Data) throws -> TLSCertificateVerify {
        var cursor = QUICByteCursor(body)
        let algorithm = try cursor.readUInt16()
        let signature = try cursor.readBytes(count: Int(try cursor.readUInt16()))
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("CertificateVerify has trailing bytes")
        }
        return try TLSCertificateVerify(algorithm: algorithm, signature: signature)
    }
}

private extension QUICByteCursor {
    mutating func readUInt24() throws -> Int {
        let first = Int(try readUInt8())
        let second = Int(try readUInt8())
        let third = Int(try readUInt8())
        return (first << 16) | (second << 8) | third
    }
}

private extension Data {
    mutating func appendUInt24(_ value: Int) throws {
        guard value >= 0, value <= 0x00ff_ffff else {
            throw QUICCodecError.valueOutOfRange("uint24 value out of range")
        }
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }
}
