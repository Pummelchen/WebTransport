import Foundation
import WebTransportUDPApple

public enum WebTransportNetworkRuntimeError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidEndpoint(String)
    case invalidPayload
    case invalidTransport(String)
    case exporterUnavailable
    case unexpectedPacket
    case unexpectedFrame
    case timeout(Int32)
    /// The peer's HTTP/3 control stream never arrived.
    ///
    /// Distinguished from a plain timeout because the cause is known and the
    /// remedy is different: the transport can drop an inbound QUIC stream on a
    /// saturated host, and when the lost stream is the control stream both ends
    /// wait for each other until the deadline. Nothing is recoverable on this
    /// connection — the stream is not resent — so a caller seeing this should
    /// establish a new one rather than wait longer.
    case peerControlStreamNotDelivered(role: String, timeoutMilliseconds: Int32)
    /// The peer ended a stream before sending the bytes that stream has to begin with.
    ///
    /// Measured against the real framework: `receive(atMost:)` waits for at least one
    /// byte, and a stream the peer opens without writing to it is not even delivered to
    /// the inbound-stream handler until its first byte arrives — so an empty read is
    /// never "nothing yet" (WebTransport issue #24). It means the peer ended the stream
    /// with nothing on it. Without this case the codec's own report,
    /// `QUICCodecError.truncated(needed: 1, available: 0)`, is what a caller sees, which
    /// reads like an internal truncation rather than a peer that closed a stream it had
    /// not written to.
    case peerClosedStreamWithoutData(streamID: UInt64)

    public var description: String {
        switch self {
        case .invalidEndpoint(let value):
            return "invalid endpoint: \(value)"
        case .invalidPayload:
            return "invalid WebTransport network payload"
        case .invalidTransport(let value):
            return "invalid WebTransport network transport: \(value)"
        case .exporterUnavailable:
            return "WebTransport TLS exporter is unavailable"
        case .unexpectedPacket:
            return "unexpected packet in WebTransport network runtime"
        case .unexpectedFrame:
            return "unexpected frame in WebTransport network packet"
        case .timeout(let value):
            return "network runtime operation timed out after \(value)ms"
        case .peerControlStreamNotDelivered(let role, let timeoutMilliseconds):
            return "\(role) never received the peer's HTTP/3 control stream within \(timeoutMilliseconds)ms; "
                + "the connection cannot proceed and should be retried"
        case .peerClosedStreamWithoutData(let streamID):
            return "the peer ended stream \(streamID) before sending any bytes; "
                + "the stream cannot be used and the peer is not following the protocol"
        }
    }
}

public enum WebTransportNetworkTransport: String, CaseIterable, Sendable {
    case packet
    case frame

    public static func parse(_ value: String) throws -> WebTransportNetworkTransport {
        guard let transport = WebTransportNetworkTransport(rawValue: value) else {
            throw WebTransportNetworkRuntimeError.invalidTransport(value)
        }
        return transport
    }
}

public enum WebTransportNetworkExchangeMode: String, CaseIterable, Sendable {
    case auto
    case stream
    case datagram

    public static func parse(_ value: String) throws -> WebTransportNetworkExchangeMode {
        guard let mode = WebTransportNetworkExchangeMode(rawValue: value) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("unknown exchange mode: \(value)")
        }
        return mode
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
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"),
                value.index(after: close) < value.endIndex,
                value[value.index(after: close)] == ":"
            else {
                throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
            }
            let host = String(value[value.index(after: value.startIndex)..<close])
            let portStart = value.index(close, offsetBy: 2)
            guard !host.isEmpty,
                portStart < value.endIndex,
                let port = UInt16(value[portStart...])
            else {
                throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
            }
            return WebTransportNetworkEndpoint(host: host, port: port)
        }

        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2,
            !parts[0].isEmpty,
            let port = UInt16(parts[1])
        else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
        }
        return WebTransportNetworkEndpoint(host: String(parts[0]), port: port)
    }

    public var commandLineValue: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    var udpEndpoint: QUICUDPEndpoint {
        QUICUDPEndpoint(host: host, port: port)
    }
}

public struct WebTransportNetworkSessionResult: Equatable, Sendable {
    public var localEndpoint: WebTransportNetworkEndpoint
    public var remoteEndpoint: WebTransportNetworkEndpoint
    public var message: String
    public var transport: WebTransportNetworkTransport
    public var sessionEstablished: Bool

    public init(
        localEndpoint: WebTransportNetworkEndpoint,
        remoteEndpoint: WebTransportNetworkEndpoint,
        message: String,
        transport: WebTransportNetworkTransport = .frame,
        sessionEstablished: Bool = false
    ) {
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.message = message
        self.transport = transport
        self.sessionEstablished = sessionEstablished
    }
}
