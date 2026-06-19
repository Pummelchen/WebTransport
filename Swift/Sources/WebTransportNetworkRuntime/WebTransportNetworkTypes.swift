import Foundation
import WebTransportUDPApple

public enum WebTransportNetworkRuntimeError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidEndpoint(String)
    case invalidPayload
    case invalidTransport(String)
    case unexpectedPacket
    case unexpectedFrame
    case timeout(Int32)

    public var description: String {
        switch self {
        case .invalidEndpoint(let value):
            return "invalid endpoint: \(value)"
        case .invalidPayload:
            return "invalid WebTransport network payload"
        case .invalidTransport(let value):
            return "invalid WebTransport network transport: \(value)"
        case .unexpectedPacket:
            return "unexpected packet in WebTransport network runtime"
        case .unexpectedFrame:
            return "unexpected frame in WebTransport network packet"
        case .timeout(let value):
            return "network runtime operation timed out after \(value)ms"
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
                  value[value.index(after: close)] == ":" else {
                throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
            }
            let host = String(value[value.index(after: value.startIndex)..<close])
            let portStart = value.index(close, offsetBy: 2)
            guard !host.isEmpty,
                  portStart < value.endIndex,
                  let port = UInt16(value[portStart...]) else {
                throw WebTransportNetworkRuntimeError.invalidEndpoint(value)
            }
            return WebTransportNetworkEndpoint(host: host, port: port)
        }

        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].isEmpty,
              let port = UInt16(parts[1]) else {
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
