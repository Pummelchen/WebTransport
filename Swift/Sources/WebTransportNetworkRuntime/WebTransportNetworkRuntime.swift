import Foundation
import WebTransportQUICCore
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

    public init(
        message: String,
        packetNumber: UInt64,
        destinationConnectionID: Data,
        sourceConnectionID: Data
    ) {
        self.message = message
        self.packetNumber = packetNumber
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
    }
}

public enum WebTransportQUICPacketProbeCodec {
    public static let quicVersion: UInt32 = 0x0000_0001
    public static let minimumInitialDatagramBytes = 1_200

    private static let clientDestinationConnectionID = Data([0x77, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65])
    private static let clientSourceConnectionID = Data([0x77, 0x74, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e])
    private static let probePrefix = Data("WT-QUIC-PROBE\0".utf8)
    private static let ackPrefix = Data("WT-QUIC-ACK\0".utf8)

    public static func encodeClientInitial(
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        try encodeInitial(
            destinationConnectionID: clientDestinationConnectionID,
            sourceConnectionID: clientSourceConnectionID,
            packetNumber: packetNumber,
            frames: [
                .crypto(offset: 0, data: probePrefix + Data(message.utf8)),
                .ping
            ],
            minimumDatagramBytes: minimumInitialDatagramBytes
        )
    }

    public static func encodeServerInitial(
        request: WebTransportQUICPacketProbeRequest,
        message: String,
        packetNumber: UInt64 = 0
    ) throws -> Data {
        try encodeInitial(
            destinationConnectionID: request.sourceConnectionID,
            sourceConnectionID: request.destinationConnectionID,
            packetNumber: packetNumber,
            frames: [
                .ack(largestAcknowledged: request.packetNumber, ackDelay: 0, firstAckRange: 0, ranges: []),
                .crypto(offset: 0, data: ackPrefix + Data(message.utf8))
            ],
            minimumDatagramBytes: 0
        )
    }

    public static func decodeClientInitial(_ data: Data) throws -> WebTransportQUICPacketProbeRequest {
        guard data.count >= minimumInitialDatagramBytes else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let packet = try decodeInitial(data)
        let frames = try QUICFrame.decodeFrames(packet.payload)
        let message = try decodeMessage(from: frames, expectedPrefix: probePrefix, requiresPing: true, requiresAck: false)
        return WebTransportQUICPacketProbeRequest(
            message: message,
            packetNumber: packet.packetNumber,
            destinationConnectionID: packet.destinationConnectionID,
            sourceConnectionID: packet.sourceConnectionID
        )
    }

    public static func decodeServerInitial(_ data: Data) throws -> String {
        let packet = try decodeInitial(data)
        guard packet.destinationConnectionID == clientSourceConnectionID,
              packet.sourceConnectionID == clientDestinationConnectionID else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let frames = try QUICFrame.decodeFrames(packet.payload)
        return try decodeMessage(from: frames, expectedPrefix: ackPrefix, requiresPing: false, requiresAck: true)
    }

    private static func encodeInitial(
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        packetNumber: UInt64,
        frames: [QUICFrame],
        minimumDatagramBytes: Int
    ) throws -> Data {
        var payload = try QUICFrame.encodeFrames(frames)
        var packet = QUICLongHeaderPacket(
            packetType: .initial,
            version: quicVersion,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            packetNumber: packetNumber,
            packetNumberLength: 2,
            payload: payload
        )
        var encoded = try packet.encode()
        while encoded.count < minimumDatagramBytes {
            payload.append(0x00)
            packet.payload = payload
            encoded = try packet.encode()
        }
        return encoded
    }

    private static func decodeInitial(_ data: Data) throws -> QUICLongHeaderPacket {
        let packet = try QUICLongHeaderPacket.decode(data)
        guard packet.packetType == .initial,
              packet.version == quicVersion,
              packet.token.isEmpty else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        return packet
    }

    private static func decodeMessage(
        from frames: [QUICFrame],
        expectedPrefix: Data,
        requiresPing: Bool,
        requiresAck: Bool
    ) throws -> String {
        var hasPing = false
        var hasAck = false
        var message: String?

        for frame in frames {
            switch frame {
            case .padding:
                continue
            case .ping:
                hasPing = true
            case .ack:
                hasAck = true
            case .crypto(let offset, let data):
                guard message == nil, offset == 0, data.starts(with: expectedPrefix) else {
                    throw WebTransportNetworkRuntimeError.invalidProbePayload
                }
                let messageBytes = data.dropFirst(expectedPrefix.count)
                guard let decoded = String(data: Data(messageBytes), encoding: .utf8) else {
                    throw WebTransportNetworkRuntimeError.invalidProbePayload
                }
                message = decoded
            default:
                throw WebTransportNetworkRuntimeError.unexpectedFrame
            }
        }

        guard let message,
              (!requiresPing || hasPing),
              (!requiresAck || hasAck) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return message
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
