import Foundation
import WebTransportCryptoApple
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple

public enum WebTransportNetworkRuntimeError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidEndpoint(String)
    case invalidProbePayload
    case invalidTransport(String)
    case unexpectedPacket
    case unexpectedFrame

    public var description: String {
        switch self {
        case .invalidEndpoint(let value):
            return "invalid endpoint: \(value)"
        case .invalidProbePayload:
            return "invalid WebTransport network probe payload"
        case .invalidTransport(let value):
            return "invalid WebTransport network probe transport: \(value)"
        case .unexpectedPacket:
            return "unexpected packet in WebTransport network probe"
        case .unexpectedFrame:
            return "unexpected frame in WebTransport network probe packet"
        }
    }
}

public enum WebTransportNetworkProbeTransport: String, CaseIterable, Sendable {
    case packet
    case frame

    public static func parse(_ value: String) throws -> WebTransportNetworkProbeTransport {
        guard let transport = WebTransportNetworkProbeTransport(rawValue: value) else {
            throw WebTransportNetworkRuntimeError.invalidTransport(value)
        }
        return transport
    }
}

public struct WebTransportNetworkEndpoint: Equatable, Sendable {
    public var host: String
    public var port: UInt16

    public init(host: String = "127.0.0.1", port: UInt16) {
        self.host = host
        self.port = port
    }

    public static func parse(_ value: String) throws -> WebTransportNetworkEndpoint {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].isEmpty,
              let port = UInt16(parts[1]) else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
        }
        return WebTransportNetworkEndpoint(host: String(parts[0]), port: port)
    }

    var udpEndpoint: QUICUDPEndpoint {
        QUICUDPEndpoint(host: host, port: port)
    }
}

public struct WebTransportNetworkProbeResult: Equatable, Sendable {
    public var localEndpoint: WebTransportNetworkEndpoint
    public var remoteEndpoint: WebTransportNetworkEndpoint
    public var message: String
    public var transport: WebTransportNetworkProbeTransport

    public init(
        localEndpoint: WebTransportNetworkEndpoint,
        remoteEndpoint: WebTransportNetworkEndpoint,
        message: String,
        transport: WebTransportNetworkProbeTransport = .frame
    ) {
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.message = message
        self.transport = transport
    }
}

public final class WebTransportQUICPacketProbeServer: @unchecked Sendable {
    private let port: QUICUDPPort

    public var localEndpoint: WebTransportNetworkEndpoint {
        WebTransportNetworkEndpoint(
            host: port.localEndpoint.host,
            port: port.localEndpoint.port
        )
    }

    public init(bindPort: UInt16) throws {
        self.port = try QUICUDPPort(bindPort: bindPort)
    }

    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) throws -> WebTransportNetworkProbeResult {
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let decoded = try WebTransportQUICPacketProbeCodec.decodeClientInitial(bytes)
        let response = try WebTransportQUICPacketProbeCodec.encodeServerInitial(
            request: decoded,
            message: decoded.message
        )
        try port.send(response, to: remote)
        return WebTransportNetworkProbeResult(
            localEndpoint: localEndpoint,
            remoteEndpoint: WebTransportNetworkEndpoint(host: remote.host, port: remote.port),
            message: decoded.message,
            transport: .packet
        )
    }
}

public struct WebTransportQUICPacketProbeClient: Sendable {
    public var localPort: UInt16

    public init(localPort: UInt16 = 0) {
        self.localPort = localPort
    }

    @discardableResult
    public func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        timeoutMilliseconds: Int32 = 1_000
    ) throws -> WebTransportNetworkProbeResult {
        let port = try QUICUDPPort(bindPort: localPort)
        let packet = try WebTransportQUICPacketProbeCodec.encodeClientInitial(message: message)
        try port.send(packet, to: endpoint.udpEndpoint)
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let remoteEndpoint = WebTransportNetworkEndpoint(host: remote.host, port: remote.port)
        guard remoteEndpoint == endpoint else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let responseMessage = try WebTransportQUICPacketProbeCodec.decodeServerInitial(bytes)
        guard responseMessage == message else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return WebTransportNetworkProbeResult(
            localEndpoint: WebTransportNetworkEndpoint(
                host: port.localEndpoint.host,
                port: port.localEndpoint.port
            ),
            remoteEndpoint: remoteEndpoint,
            message: responseMessage,
            transport: .packet
        )
    }
}

public final class WebTransportNetworkProbeServer: @unchecked Sendable {
    private let port: QUICUDPPort

    public var localEndpoint: WebTransportNetworkEndpoint {
        WebTransportNetworkEndpoint(
            host: port.localEndpoint.host,
            port: port.localEndpoint.port
        )
    }

    public init(bindPort: UInt16) throws {
        self.port = try QUICUDPPort(bindPort: bindPort)
    }

    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) throws -> WebTransportNetworkProbeResult {
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let message = try WebTransportNetworkProbeCodec.decodeProbePacket(bytes)
        let response = try WebTransportNetworkProbeCodec.encodeAckPacket(message: message)
        try port.send(response, to: remote)
        return WebTransportNetworkProbeResult(
            localEndpoint: localEndpoint,
            remoteEndpoint: WebTransportNetworkEndpoint(host: remote.host, port: remote.port),
            message: message,
            transport: .frame
        )
    }
}

public struct WebTransportNetworkProbeClient: Sendable {
    public var localPort: UInt16

    public init(localPort: UInt16 = 0) {
        self.localPort = localPort
    }

    @discardableResult
    public func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        timeoutMilliseconds: Int32 = 1_000
    ) throws -> WebTransportNetworkProbeResult {
        let port = try QUICUDPPort(bindPort: localPort)
        let packet = try WebTransportNetworkProbeCodec.encodeProbePacket(message: message)
        try port.send(packet, to: endpoint.udpEndpoint)
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let remoteEndpoint = WebTransportNetworkEndpoint(host: remote.host, port: remote.port)
        guard remoteEndpoint == endpoint else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let responseMessage = try WebTransportNetworkProbeCodec.decodeAckPacket(bytes)
        guard responseMessage == message else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return WebTransportNetworkProbeResult(
            localEndpoint: WebTransportNetworkEndpoint(
                host: port.localEndpoint.host,
                port: port.localEndpoint.port
            ),
            remoteEndpoint: remoteEndpoint,
            message: responseMessage,
            transport: .frame
        )
    }
}

public struct WebTransportQUICPacketProbeRequest: Equatable, Sendable {
    public var message: String
    public var packetNumber: UInt64
    public var destinationConnectionID: Data
    public var sourceConnectionID: Data
    public var handshakeMessages: [TLSHandshakeMessage]

    public init(
        message: String,
        packetNumber: UInt64,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        handshakeMessages: [TLSHandshakeMessage] = []
    ) {
        self.message = message
        self.packetNumber = packetNumber
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.handshakeMessages = handshakeMessages
    }
}

public enum WebTransportQUICPacketProbeCodec {
    public static let quicVersion: UInt32 = 0x0000_0001
    public static let minimumInitialDatagramBytes = 1_200

    private static let clientDestinationConnectionID = Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65])
    private static let clientSourceConnectionID = Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e])
    private static let probePrefix = Data("WT-QUIC-CLIENT-FLIGHT\0".utf8)
    private static let ackPrefix = Data("WT-QUIC-SERVER-FLIGHT\0".utf8)
    private static let readyBody = Data("WT-QUIC-HANDSHAKE-READY".utf8)
    private static let clientCryptoFramePayloadBytes = 7
    private static let serverCryptoFramePayloadBytes = 9

    public static func encodeClientInitial(
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        let flight = TLSHandshakeFlight(messages: [
            TLSHandshakeMessage(type: .clientHello, body: probePrefix + Data(message.utf8))
        ])
        return try encodeProtectedInitial(
            destinationConnectionID: clientDestinationConnectionID,
            sourceConnectionID: clientSourceConnectionID,
            packetNumber: packetNumber,
            keyPhase: .client,
            initialSecretConnectionID: clientDestinationConnectionID,
            frames: try flight.cryptoFrames(maxFramePayloadBytes: clientCryptoFramePayloadBytes) + [.ping],
            minimumDatagramBytes: minimumInitialDatagramBytes
        )
    }

    public static func encodeServerInitial(
        request: WebTransportQUICPacketProbeRequest,
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        let flight = TLSHandshakeFlight(messages: [
            TLSHandshakeMessage(type: .serverHello, body: ackPrefix + Data(message.utf8)),
            TLSHandshakeMessage(type: .encryptedExtensions, body: readyBody)
        ])
        return try encodeProtectedInitial(
            destinationConnectionID: request.sourceConnectionID,
            sourceConnectionID: request.destinationConnectionID,
            packetNumber: packetNumber,
            keyPhase: .server,
            initialSecretConnectionID: request.destinationConnectionID,
            frames: [.ack(largestAcknowledged: request.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: [])]
                + (try flight.cryptoFrames(maxFramePayloadBytes: serverCryptoFramePayloadBytes)),
            minimumDatagramBytes: 0
        )
    }

    public static func decodeClientInitial(_ data: Data) throws -> WebTransportQUICPacketProbeRequest {
        guard data.count >= minimumInitialDatagramBytes else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let packet = try decodeProtectedInitial(data, keyPhase: .client)
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let decoded = try decodeHandshakeFlight(
            from: frames,
            expectedPrefix: probePrefix,
            expectedTypes: [.clientHello],
            requiresPing: true,
            requiresAck: false
        )
        return WebTransportQUICPacketProbeRequest(
            message: decoded.message,
            packetNumber: packet.packetNumber,
            destinationConnectionID: packet.destinationConnectionID,
            sourceConnectionID: packet.sourceConnectionID,
            handshakeMessages: decoded.messages
        )
    }

    public static func decodeServerInitial(_ data: Data) throws -> String {
        let packet = try decodeProtectedInitial(
            data,
            keyPhase: .server,
            initialSecretConnectionID: clientDestinationConnectionID
        )
        guard packet.destinationConnectionID == clientSourceConnectionID,
              packet.sourceConnectionID == clientDestinationConnectionID else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let frames = try QUICFrame.decodeFrames(packet.payload)
        return try decodeHandshakeFlight(
            from: frames,
            expectedPrefix: ackPrefix,
            expectedTypes: [.serverHello, .encryptedExtensions],
            requiresPing: false,
            requiresAck: true
        ).message
    }

    private static func encodeProtectedInitial(
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        packetNumber: UInt64,
        keyPhase: QUICInitialPacketProtection.KeyPhase,
        initialSecretConnectionID: Data,
        frames: [QUICFrame],
        minimumDatagramBytes: Int
    ) throws -> Data {
        var payload = try QUICFrame.encodeFrames(frames)
        var encoded = try QUICInitialPacketProtection.seal(
            packetType: .initial,
            version: quicVersion,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: Data(),
            packetNumber: packetNumber,
            packetNumberLength: 2,
            plaintextPayload: payload,
            keyPhase: keyPhase,
            initialSecretConnectionID: initialSecretConnectionID
        )
        while encoded.count < minimumDatagramBytes {
            payload.append(0x00)
            encoded = try QUICInitialPacketProtection.seal(
                packetType: .initial,
                version: quicVersion,
                destinationConnectionID: destinationConnectionID,
                sourceConnectionID: sourceConnectionID,
                token: Data(),
                packetNumber: packetNumber,
                packetNumberLength: 2,
                plaintextPayload: payload,
                keyPhase: keyPhase,
                initialSecretConnectionID: initialSecretConnectionID
            )
        }
        return encoded
    }

    private static func decodeProtectedInitial(
        _ data: Data,
        keyPhase: QUICInitialPacketProtection.KeyPhase,
        initialSecretConnectionID explicitInitialSecretConnectionID: Data? = nil
    ) throws -> QUICLongHeaderPacket {
        let parsed = try QUICInitialPacketProtection.parseProtectedLongHeader(data)
        let packet = try QUICInitialPacketProtection.open(
            data,
            keyPhase: keyPhase,
            initialSecretConnectionID: explicitInitialSecretConnectionID ?? parsed.destinationConnectionID,
            parsedHeader: parsed
        )
        guard packet.packetType == .initial,
              packet.version == quicVersion,
              packet.token.isEmpty else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        return packet
    }

    private static func decodeHandshakeFlight(
        from frames: [QUICFrame],
        expectedPrefix: Data,
        expectedTypes: [TLSHandshakeType],
        requiresPing: Bool,
        requiresAck: Bool
    ) throws -> (message: String, messages: [TLSHandshakeMessage]) {
        var hasPing = false
        var hasAck = false
        var cryptoFrames: [QUICFrame] = []

        for frame in frames {
            switch frame {
            case .padding:
                continue
            case .ping:
                hasPing = true
            case .ack:
                hasAck = true
            case .crypto:
                cryptoFrames.append(frame)
            default:
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            }
        }

        guard (!requiresPing || hasPing),
              (!requiresAck || hasAck) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }

        var decoder = TLSHandshakeFlightDecoder()
        let messages = try decoder.receive(frames: cryptoFrames)
        guard messages.map(\.type) == expectedTypes,
              let first = messages.first,
              first.body.starts(with: expectedPrefix) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        if expectedTypes.contains(.encryptedExtensions) {
            guard messages.last?.body == readyBody else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
        }
        let messageBytes = first.body.dropFirst(expectedPrefix.count)
        guard let message = String(data: Data(messageBytes), encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return (message, messages)
    }
}

enum QUICInitialPacketProtection {
    enum KeyPhase {
        case client
        case server
    }

    struct ParsedLongHeader: Equatable, Sendable {
        var firstByte: UInt8
        var packetType: QUICPacketType
        var version: UInt32
        var destinationConnectionID: Data
        var sourceConnectionID: Data
        var token: Data
        var length: UInt64
        var packetNumberOffset: Int
        var payloadEndOffset: Int
    }

    static func seal(
        packetType: QUICPacketType,
        version: UInt32,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        token: Data,
        packetNumber: UInt64,
        packetNumberLength: Int,
        plaintextPayload: Data,
        keyPhase: KeyPhase,
        initialSecretConnectionID: Data
    ) throws -> Data {
        guard packetType == .initial else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        guard destinationConnectionID.count <= 20, sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        let keys = try packetProtectionKeys(for: keyPhase, initialSecretConnectionID: initialSecretConnectionID)
        let packetNumberBytes = try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength)
        let protectedLength = UInt64(packetNumberBytes.count + plaintextPayload.count + 16)

        var header = Data()
        header.append(UInt8(0xc0) | (packetType.rawValue << 4) | UInt8(packetNumberLength - 1))
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        header.append(buffer.data)
        header.append(UInt8(destinationConnectionID.count))
        header.append(destinationConnectionID)
        header.append(UInt8(sourceConnectionID.count))
        header.append(sourceConnectionID)
        header.append(try QUICVarInt.encode(UInt64(token.count)))
        header.append(token)
        header.append(try QUICVarInt.encode(protectedLength))
        let packetNumberOffset = header.count
        header.append(packetNumberBytes)

        let ciphertextAndTag = try QUICPacketProtection.seal(
            plaintext: plaintextPayload,
            packetNumber: packetNumber,
            associatedData: header,
            keys: keys
        )
        return try applyHeaderProtection(
            headerAndCiphertext: header + ciphertextAndTag,
            packetNumberOffset: packetNumberOffset,
            packetNumberLength: packetNumberLength,
            headerProtectionKey: keys.headerProtectionKey
        )
    }

    static func open(
        _ data: Data,
        keyPhase: KeyPhase,
        initialSecretConnectionID: Data,
        parsedHeader: ParsedLongHeader? = nil
    ) throws -> QUICLongHeaderPacket {
        let parsed = try parsedHeader ?? parseProtectedLongHeader(data)
        guard parsed.packetType == .initial else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }

        let keys = try packetProtectionKeys(for: keyPhase, initialSecretConnectionID: initialSecretConnectionID)
        var unprotected = data
        try removeHeaderProtection(
            packet: &unprotected,
            packetNumberOffset: parsed.packetNumberOffset,
            headerProtectionKey: keys.headerProtectionKey
        )
        let packetNumberLength = Int(unprotected[0] & 0x03) + 1
        guard parsed.length >= UInt64(packetNumberLength + 16) else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        guard parsed.packetNumberOffset + packetNumberLength <= parsed.payloadEndOffset,
              parsed.payloadEndOffset <= unprotected.count else {
            throw QUICCodecError.truncated(
                needed: parsed.payloadEndOffset,
                available: unprotected.count
            )
        }

        let packetNumberBytes = unprotected[parsed.packetNumberOffset..<(parsed.packetNumberOffset + packetNumberLength)]
        let truncatedPacketNumber = packetNumberBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncatedPacketNumber,
            byteCount: packetNumberLength,
            largestAcknowledged: nil
        )
        let ciphertextOffset = parsed.packetNumberOffset + packetNumberLength
        let associatedData = Data(unprotected[..<ciphertextOffset])
        let ciphertextAndTag = Data(unprotected[ciphertextOffset..<parsed.payloadEndOffset])
        let plaintextPayload = try QUICPacketProtection.open(
            ciphertextAndTag: ciphertextAndTag,
            packetNumber: packetNumber,
            associatedData: associatedData,
            keys: keys
        )

        return QUICLongHeaderPacket(
            packetType: parsed.packetType,
            version: parsed.version,
            destinationConnectionID: parsed.destinationConnectionID,
            sourceConnectionID: parsed.sourceConnectionID,
            token: parsed.token,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: plaintextPayload
        )
    }

    static func parseProtectedLongHeader(_ data: Data) throws -> ParsedLongHeader {
        guard data.count >= 7 else {
            throw QUICCodecError.truncated(needed: 7, available: data.count)
        }
        var offset = 0
        let first = data[offset]
        offset += 1
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        guard let packetType = QUICPacketType(rawValue: (first >> 4) & 0x03),
              packetType == .initial else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let version = try readUInt32(data, offset: &offset)
        let destinationLength = Int(try readUInt8(data, offset: &offset))
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destinationConnectionID = try readBytes(data, offset: &offset, count: destinationLength)
        let sourceLength = Int(try readUInt8(data, offset: &offset))
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        let sourceConnectionID = try readBytes(data, offset: &offset, count: sourceLength)
        let tokenLength = try checkedLength(try readVarInt(data, offset: &offset))
        let token = try readBytes(data, offset: &offset, count: tokenLength)
        let length = try readVarInt(data, offset: &offset)
        let packetNumberOffset = offset
        guard length <= UInt64(data.count - packetNumberOffset) else {
            throw QUICCodecError.malformed("invalid protected packet length")
        }
        let payloadEndOffset = packetNumberOffset + Int(length)
        guard packetNumberOffset + 4 + 16 <= data.count else {
            throw QUICCodecError.truncated(needed: packetNumberOffset + 20, available: data.count)
        }
        return ParsedLongHeader(
            firstByte: first,
            packetType: packetType,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: token,
            length: length,
            packetNumberOffset: packetNumberOffset,
            payloadEndOffset: payloadEndOffset
        )
    }

    private static func packetProtectionKeys(
        for keyPhase: KeyPhase,
        initialSecretConnectionID: Data
    ) throws -> QUICPacketProtectionKeys {
        let secrets = try QUICInitialKeyDerivation.deriveVersion1Secrets(
            destinationConnectionID: initialSecretConnectionID
        )
        switch keyPhase {
        case .client:
            return QUICPacketProtectionKeys(
                key: secrets.clientKey,
                iv: secrets.clientIV,
                headerProtectionKey: secrets.clientHeaderProtectionKey
            )
        case .server:
            return QUICPacketProtectionKeys(
                key: secrets.serverKey,
                iv: secrets.serverIV,
                headerProtectionKey: secrets.serverHeaderProtectionKey
            )
        }
    }

    private static func applyHeaderProtection(
        headerAndCiphertext: Data,
        packetNumberOffset: Int,
        packetNumberLength: Int,
        headerProtectionKey: Data
    ) throws -> Data {
        guard packetNumberOffset + 4 + 16 <= headerAndCiphertext.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + 20,
                available: headerAndCiphertext.count
            )
        }
        var output = headerAndCiphertext
        let sampleStart = packetNumberOffset + 4
        let sample = Data(output[sampleStart..<(sampleStart + 16)])
        let mask = try QUICPacketProtection.headerProtectionMask(
            sample: sample,
            headerProtectionKey: headerProtectionKey
        )
        output[0] ^= mask[0] & 0x0f
        for index in 0..<packetNumberLength {
            output[packetNumberOffset + index] ^= mask[index + 1]
        }
        return output
    }

    private static func removeHeaderProtection(
        packet: inout Data,
        packetNumberOffset: Int,
        headerProtectionKey: Data
    ) throws {
        guard packetNumberOffset + 4 + 16 <= packet.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + 20,
                available: packet.count
            )
        }
        let sampleStart = packetNumberOffset + 4
        let sample = Data(packet[sampleStart..<(sampleStart + 16)])
        let mask = try QUICPacketProtection.headerProtectionMask(
            sample: sample,
            headerProtectionKey: headerProtectionKey
        )
        packet[0] ^= mask[0] & 0x0f
        let packetNumberLength = Int(packet[0] & 0x03) + 1
        guard packetNumberOffset + packetNumberLength <= packet.count else {
            throw QUICCodecError.truncated(
                needed: packetNumberOffset + packetNumberLength,
                available: packet.count
            )
        }
        for index in 0..<packetNumberLength {
            packet[packetNumberOffset + index] ^= mask[index + 1]
        }
    }

    private static func readUInt8(_ data: Data, offset: inout Int) throws -> UInt8 {
        guard offset < data.count else {
            throw QUICCodecError.truncated(needed: offset + 1, available: data.count)
        }
        defer { offset += 1 }
        return data[offset]
    }

    private static func readUInt32(_ data: Data, offset: inout Int) throws -> UInt32 {
        let bytes = try readBytes(data, offset: &offset, count: 4)
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private static func readBytes(_ data: Data, offset: inout Int, count: Int) throws -> Data {
        guard count >= 0 else {
            throw QUICCodecError.valueOutOfRange("negative byte count")
        }
        guard offset + count <= data.count else {
            throw QUICCodecError.truncated(needed: offset + count, available: data.count)
        }
        let end = offset + count
        defer { offset = end }
        return Data(data[offset..<end])
    }

    private static func readVarInt(_ data: Data, offset: inout Int) throws -> UInt64 {
        let first = try readUInt8(data, offset: &offset)
        let length = 1 << Int(first >> 6)
        var value = UInt64(first & 0x3f)
        guard length > 1 else {
            return value
        }
        for _ in 1..<length {
            value = (value << 8) | UInt64(try readUInt8(data, offset: &offset))
        }
        return value
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("length exceeds Int.max")
        }
        return Int(value)
    }
}

public enum WebTransportNetworkProbeCodec {
    private static let probePrefix = Data("WT-NET-PROBE\0".utf8)
    private static let ackPrefix = Data("WT-NET-ACK\0".utf8)

    public static func encodeProbePacket(message: String) throws -> Data {
        try QUICFrame.encodeFrames([.datagram(probePrefix + Data(message.utf8))])
    }

    public static func encodeAckPacket(message: String) throws -> Data {
        try QUICFrame.encodeFrames([.datagram(ackPrefix + Data(message.utf8))])
    }

    public static func decodeProbePacket(_ packet: Data) throws -> String {
        try decode(packet, expectedPrefix: probePrefix)
    }

    public static func decodeAckPacket(_ packet: Data) throws -> String {
        try decode(packet, expectedPrefix: ackPrefix)
    }

    private static func decode(_ packet: Data, expectedPrefix: Data) throws -> String {
        let frames = try QUICFrame.decodeFrames(packet)
        guard frames.count == 1, case .datagram(let payload) = frames[0] else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        guard payload.starts(with: expectedPrefix) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        let messageBytes = payload.dropFirst(expectedPrefix.count)
        guard let message = String(data: Data(messageBytes), encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return message
    }
}
