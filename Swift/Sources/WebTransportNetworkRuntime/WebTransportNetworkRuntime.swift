import Foundation
import WebTransportQUICCore
import WebTransportUDPApple

public enum WebTransportNetworkRuntimeError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidEndpoint(String)
    case invalidProbePayload
    case unexpectedFrame

    public var description: String {
        switch self {
        case .invalidEndpoint(let value):
            return "invalid endpoint: \(value)"
        case .invalidProbePayload:
            return "invalid WebTransport network probe payload"
        case .unexpectedFrame:
            return "unexpected frame in WebTransport network probe packet"
        }
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

    public init(
        localEndpoint: WebTransportNetworkEndpoint,
        remoteEndpoint: WebTransportNetworkEndpoint,
        message: String
    ) {
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.message = message
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
            message: message
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
        let responseMessage = try WebTransportNetworkProbeCodec.decodeAckPacket(bytes)
        guard responseMessage == message else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        return WebTransportNetworkProbeResult(
            localEndpoint: WebTransportNetworkEndpoint(
                host: port.localEndpoint.host,
                port: port.localEndpoint.port
            ),
            remoteEndpoint: WebTransportNetworkEndpoint(host: remote.host, port: remote.port),
            message: responseMessage
        )
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
