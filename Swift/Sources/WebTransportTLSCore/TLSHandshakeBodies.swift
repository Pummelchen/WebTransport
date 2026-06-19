import Foundation
import WebTransportQUICCore

public struct TLSClientHello: Equatable, Sendable {
    public var random: Data
    public var legacySessionID: Data
    public var cipherSuites: [UInt16]
    public var extensions: [TLSExtension]

    public init(
        random: Data,
        legacySessionID: Data = Data(),
        cipherSuites: [UInt16] = [TLSCipherSuite.aes128GCM_SHA256],
        extensions: [TLSExtension]
    ) throws {
        guard random.count == 32 else {
            throw QUICCodecError.malformed("ClientHello random must be 32 bytes")
        }
        guard legacySessionID.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("legacy_session_id too large")
        }
        guard !cipherSuites.isEmpty else {
            throw QUICCodecError.malformed("ClientHello must contain at least one cipher suite")
        }
        guard cipherSuites.count * MemoryLayout<UInt16>.size <= UInt16.max else {
            throw QUICCodecError.valueOutOfRange("ClientHello cipher suite list too large")
        }
        self.random = random
        self.legacySessionID = legacySessionID
        self.cipherSuites = cipherSuites
        self.extensions = extensions
    }

    public func body() throws -> Data {
        var output = QUICByteBuffer()
        output.appendUInt16(TLSProtocolVersion.tls12)
        output.append(random)
        output.appendUInt8(UInt8(legacySessionID.count))
        output.append(legacySessionID)
        output.appendUInt16(UInt16(cipherSuites.count * MemoryLayout<UInt16>.size))
        for cipherSuite in cipherSuites {
            output.appendUInt16(cipherSuite)
        }
        output.appendUInt8(1)
        output.appendUInt8(0)
        output.append(try TLSExtension.encodeList(extensions))
        return output.data
    }

    public func handshakeMessage() throws -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .clientHello, body: try body())
    }

    public static func decode(_ body: Data) throws -> TLSClientHello {
        var cursor = QUICByteCursor(body)
        let legacyVersion = try cursor.readUInt16()
        guard legacyVersion == TLSProtocolVersion.tls12 else {
            throw QUICCodecError.malformed("ClientHello legacy_version is not TLS 1.2")
        }
        let random = try cursor.readBytes(count: 32)
        let sessionID = try cursor.readBytes(count: Int(try cursor.readUInt8()))
        let cipherSuiteLength = Int(try cursor.readUInt16())
        guard cipherSuiteLength > 0, cipherSuiteLength.isMultiple(of: 2) else {
            throw QUICCodecError.malformed("ClientHello cipher suite list length is invalid")
        }
        let cipherSuiteData = try cursor.readBytes(count: cipherSuiteLength)
        var cipherSuiteCursor = QUICByteCursor(cipherSuiteData)
        var cipherSuites: [UInt16] = []
        while !cipherSuiteCursor.isAtEnd {
            cipherSuites.append(try cipherSuiteCursor.readUInt16())
        }
        let compressionLength = Int(try cursor.readUInt8())
        let compressionMethods = try cursor.readBytes(count: compressionLength)
        guard compressionMethods == Data([0]) else {
            throw QUICCodecError.malformed("ClientHello compression methods must be null-only")
        }
        let extensions = try TLSExtension.decodeList(try cursor.readBytes(count: cursor.remaining))
        return try TLSClientHello(
            random: random,
            legacySessionID: sessionID,
            cipherSuites: cipherSuites,
            extensions: extensions
        )
    }
}

public struct TLSServerHello: Equatable, Sendable {
    public var random: Data
    public var legacySessionIDEcho: Data
    public var cipherSuite: UInt16
    public var extensions: [TLSExtension]

    public init(
        random: Data,
        legacySessionIDEcho: Data = Data(),
        cipherSuite: UInt16 = TLSCipherSuite.aes128GCM_SHA256,
        extensions: [TLSExtension]
    ) throws {
        guard random.count == 32 else {
            throw QUICCodecError.malformed("ServerHello random must be 32 bytes")
        }
        guard legacySessionIDEcho.count <= UInt8.max else {
            throw QUICCodecError.valueOutOfRange("legacy_session_id_echo too large")
        }
        self.random = random
        self.legacySessionIDEcho = legacySessionIDEcho
        self.cipherSuite = cipherSuite
        self.extensions = extensions
    }

    public func body() throws -> Data {
        var output = QUICByteBuffer()
        output.appendUInt16(TLSProtocolVersion.tls12)
        output.append(random)
        output.appendUInt8(UInt8(legacySessionIDEcho.count))
        output.append(legacySessionIDEcho)
        output.appendUInt16(cipherSuite)
        output.appendUInt8(0)
        output.append(try TLSExtension.encodeList(extensions))
        return output.data
    }

    public func handshakeMessage() throws -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .serverHello, body: try body())
    }

    public static func decode(_ body: Data) throws -> TLSServerHello {
        var cursor = QUICByteCursor(body)
        let legacyVersion = try cursor.readUInt16()
        guard legacyVersion == TLSProtocolVersion.tls12 else {
            throw QUICCodecError.malformed("ServerHello legacy_version is not TLS 1.2")
        }
        let random = try cursor.readBytes(count: 32)
        let sessionID = try cursor.readBytes(count: Int(try cursor.readUInt8()))
        let cipherSuite = try cursor.readUInt16()
        let compressionMethod = try cursor.readUInt8()
        guard compressionMethod == 0 else {
            throw QUICCodecError.malformed("ServerHello compression method must be null")
        }
        let extensions = try TLSExtension.decodeList(try cursor.readBytes(count: cursor.remaining))
        return try TLSServerHello(
            random: random,
            legacySessionIDEcho: sessionID,
            cipherSuite: cipherSuite,
            extensions: extensions
        )
    }
}

public struct TLSEncryptedExtensions: Equatable, Sendable {
    public var extensions: [TLSExtension]

    public init(extensions: [TLSExtension]) {
        self.extensions = extensions
    }

    public func body() throws -> Data {
        try TLSExtension.encodeList(extensions)
    }

    public func handshakeMessage() throws -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .encryptedExtensions, body: try body())
    }

    public static func decode(_ body: Data) throws -> TLSEncryptedExtensions {
        try TLSEncryptedExtensions(extensions: TLSExtension.decodeList(body))
    }
}

public struct TLSFinished: Equatable, Sendable {
    public var verifyData: Data

    public init(verifyData: Data) {
        self.verifyData = verifyData
    }

    public func handshakeMessage() -> TLSHandshakeMessage {
        TLSHandshakeMessage(type: .finished, body: verifyData)
    }

    public static func decode(_ body: Data) -> TLSFinished {
        TLSFinished(verifyData: body)
    }
}
