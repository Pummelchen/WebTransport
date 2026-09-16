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
    /// The transport failed to establish the connection.
    ///
    /// `NetworkConnection.State.failed` carries whatever the framework reports, and on a
    /// loaded host that is a transient POSIX condition — `ENETDOWN`, `ENOTCONN` — rather
    /// than anything about the endpoint. Rethrowing it verbatim put a bare
    /// `POSIXErrorCode` in front of a caller, which cannot tell "the local stack was
    /// momentarily unavailable, try again" from "that address is wrong"; it is also what
    /// reached `listenerServesMoreSequentialSessionsThanTheDefaultCeiling` under
    /// Thread Sanitizer as `POSIXErrorCode(rawValue: 50)` and `(rawValue: 57)` (WT-185).
    ///
    /// Naming it is what lets a caller apply the documented remedy — establish a new
    /// connection — and what lets a test retry a condition that is not the property it
    /// asserts. A POSIX condition is reported as `NSPOSIXErrorDomain` with the errno in
    /// `code`; anything else keeps the framework's own domain and code. That
    /// normalisation is deliberate: `NWError.posix` bridges to `NSError` under
    /// `"Network.NWError"`, so a predicate reading the bridged domain would never match a
    /// real failure.
    case connectionEstablishmentFailed(role: String, domain: String, code: Int)
    /// The transport failed on a connection the runtime had already taken on.
    ///
    /// Distinct from ``connectionEstablishmentFailed(role:domain:code:)`` because the two
    /// queues that raise it are used after establishment as well as during it:
    /// `InteroperableQUICConnectionQueue` serves every session a listener accepts, and
    /// `InteroperableQUICInboundStreamCollector` only fails once the connection is carrying
    /// streams. Calling a failure at either point an *establishment* failure would be false,
    /// and it would make ``isTransientEstablishmentFailure`` retry a session that may
    /// already have exchanged data. This case claims only what is true of both sites — the
    /// transport failed while the runtime was using the connection — and keeps the
    /// framework's domain and code for diagnosis.
    ///
    /// It is deliberately outside ``isTransientEstablishmentFailure``: a caller retries
    /// that class of condition by opening a fresh connection, and a session that has
    /// already carried data is not one to silently re-drive.
    case connectionTransportFailed(role: String, domain: String, code: Int)

    /// The transport conditions that mean the local stack could not carry a connection
    /// at that instant, as opposed to the peer refusing or resetting one.
    ///
    /// `ENETDOWN` and `ENOTCONN` are the two a saturated macOS CI runner produced, and
    /// they are named as a class rather than as a single errno precisely because the two
    /// occurrences were two different codes: a fix that special-cased `ENETDOWN` would
    /// have missed `ENOTCONN` (WT-185).
    ///
    /// Three of the five — `ENETUNREACH`, `EHOSTUNREACH` and `EADDRNOTAVAIL` — can also
    /// describe a route, host or address that is simply wrong and will not come back. They
    /// are kept because the same errno is equally what a stack reports while a route or an
    /// interface is still settling, and this set is not a licence to loop: see the bound
    /// `isTransientEstablishmentFailure` documents.
    private static let transientEstablishmentPOSIXCodes: Set<Int> = [
        Int(POSIXErrorCode.ENETDOWN.rawValue),
        Int(POSIXErrorCode.ENOTCONN.rawValue),
        Int(POSIXErrorCode.ENETUNREACH.rawValue),
        Int(POSIXErrorCode.EHOSTUNREACH.rawValue),
        Int(POSIXErrorCode.EADDRNOTAVAIL.rawValue),
    ]

    /// Whether this is a transport condition a fresh connection can clear.
    ///
    /// True only for a named establishment failure whose framework error was one of the
    /// transient POSIX codes above. A caller may retry on it; a wrong address, a refused
    /// port, or a handshake the peer rejected is not this case and is never retried here.
    ///
    /// **A caller that retries must bound the attempts.** This answers "could a fresh
    /// connection clear it", not "will it" — some of the codes above also describe a route
    /// or an address that will never come back — so retrying on this property in a loop is
    /// a way to turn a fast, accurate failure into a slow one.
    public var isTransientEstablishmentFailure: Bool {
        guard case .connectionEstablishmentFailed(_, let domain, let code) = self,
            domain == NSPOSIXErrorDomain
        else {
            return false
        }
        return Self.transientEstablishmentPOSIXCodes.contains(code)
    }

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
        case .connectionEstablishmentFailed(let role, let domain, let code):
            return "the transport failed to establish the \(role) connection "
                + "(\(domain) \(code)); the connection was never established, so opening "
                + "a new one is the remedy"
        case .connectionTransportFailed(let role, let domain, let code):
            return "the transport failed on the \(role) connection after the runtime had "
                + "taken it on (\(domain) \(code)); the connection is no longer usable"
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
