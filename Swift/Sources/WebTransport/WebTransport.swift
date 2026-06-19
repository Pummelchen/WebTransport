import Foundation
import WebTransportHTTP3Core
import WebTransportNetworkRuntime
import WebTransportQUICCore

/// Client-side options for Swift concurrency WebTransport session establishment.
public struct WebTransportClientConfiguration: Equatable, Sendable {
    /// The expected `:authority` value on the extended CONNECT request.
    public var authority: String
    /// The expected `:path` value on the extended CONNECT request.
    public var path: String
    /// Optional origin header value for server-side origin policy checks.
    public var origin: String?
    /// Client-offered WebTransport subprotocol tokens.
    public var availableProtocols: [String]
    /// Transport path used by the Network.framework runtime.
    public var transport: WebTransportNetworkTransport
    /// Certificate trust policy. Defaults to platform system trust.
    public var trustPolicy: WebTransportQUICPeerTrustPolicy
    /// HTTP/3 WebTransport settings validation profile.
    public var settingsValidation: HTTP3WebTransportSettingsValidation
    /// End-to-end connect timeout in milliseconds.
    public var timeoutMilliseconds: Int32

    public init(
        authority: String,
        path: String,
        origin: String? = nil,
        availableProtocols: [String] = [],
        transport: WebTransportNetworkTransport = .packet,
        trustPolicy: WebTransportQUICPeerTrustPolicy = .systemTrust,
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        timeoutMilliseconds: Int32 = 15_000
    ) {
        self.authority = authority
        self.path = path
        self.origin = origin
        self.availableProtocols = availableProtocols
        self.transport = transport
        self.trustPolicy = trustPolicy
        self.settingsValidation = settingsValidation
        self.timeoutMilliseconds = timeoutMilliseconds
    }
}

/// Server-side options for Swift concurrency WebTransport session establishment.
public struct WebTransportServerConfiguration: Equatable, Sendable {
    /// Allowed CONNECT authority.
    public var authority: String
    /// Allowed CONNECT path.
    public var path: String
    /// Optional required origin value.
    public var origin: String?
    /// Server-supported WebTransport subprotocol tokens.
    public var supportedProtocols: [String]
    /// HTTP/3 WebTransport settings validation profile.
    public var settingsValidation: HTTP3WebTransportSettingsValidation
    /// Listener/session timeout in milliseconds.
    public var timeoutMilliseconds: Int32

    public init(
        authority: String = "localhost",
        path: String = "/wt",
        origin: String? = nil,
        supportedProtocols: [String] = [],
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft15Strict,
        timeoutMilliseconds: Int32 = 15_000
    ) {
        self.authority = authority
        self.path = path
        self.origin = origin
        self.supportedProtocols = supportedProtocols
        self.settingsValidation = settingsValidation
        self.timeoutMilliseconds = timeoutMilliseconds
    }
}

/// Sanitized production log event emitted by the high-level WebTransport API.
///
/// Events intentionally avoid TLS secrets, certificate material, QUIC connection
/// IDs, raw session IDs, packet bytes, datagram payloads, and close reason text.
public enum WebTransportLogEvent: Equatable, Sendable, CustomStringConvertible {
    case clientControlExchanged
    case serverControlAccepted
    case sessionEstablished(role: String)
    case datagramSent(byteCount: Int)
    case datagramReceived(byteCount: Int)
    case sessionClosed(applicationErrorCode: UInt32, reasonByteCount: Int)

    public var description: String {
        switch self {
        case .clientControlExchanged:
            return "webtransport.client_control_exchanged"
        case .serverControlAccepted:
            return "webtransport.server_control_accepted"
        case .sessionEstablished(let role):
            return "webtransport.session_established role=\(role)"
        case .datagramSent(let byteCount):
            return "webtransport.datagram_sent bytes=\(byteCount)"
        case .datagramReceived(let byteCount):
            return "webtransport.datagram_received bytes=\(byteCount)"
        case .sessionClosed(let applicationErrorCode, let reasonByteCount):
            return "webtransport.session_closed code=\(applicationErrorCode) reason_bytes=\(reasonByteCount)"
        }
    }
}

/// Opt-in sink for sanitized production log events.
public struct WebTransportLogger: Sendable {
    public typealias Sink = @Sendable (WebTransportLogEvent) -> Void

    /// Logger that drops all events.
    public static let disabled = WebTransportLogger()

    private let sink: Sink?

    public init(_ sink: Sink? = nil) {
        self.sink = sink
    }

    public func record(_ event: WebTransportLogEvent) {
        sink?(event)
    }
}

/// Public error text helper for production surfaces.
///
/// Use this for user-visible/logged error text when the original error might
/// carry peer input, close messages, packet bytes, or transport identifiers.
public enum WebTransportErrorSurface {
    public static func publicDescription(for error: Error) -> String {
        if let draftError = error as? WebTransportDraft15Error {
            switch draftError.kind {
            case .sessionGone:
                return "WebTransport session is gone"
            case .bufferedStreamRejected:
                return "WebTransport buffered stream was rejected"
            case .flowControl:
                return "WebTransport flow-control violation"
            case .requirementsNotMet:
                return "WebTransport peer requirements were not met"
            case .alpn:
                return "WebTransport ALPN negotiation failed"
            case .h3ID:
                return "WebTransport session identifier was invalid"
            }
        }
        if error is QUICCodecError {
            return "WebTransport protocol codec rejected malformed input"
        }
        return "WebTransport operation failed"
    }
}

/// Network endpoint for the production WebTransport runtime.
public struct WebTransportEndpoint: Equatable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public static func parse(_ value: String) throws -> WebTransportEndpoint {
        let endpoint = try WebTransportNetworkEndpoint.parse(value)
        return WebTransportEndpoint(host: endpoint.host, port: endpoint.port)
    }

    public var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    var networkEndpoint: WebTransportNetworkEndpoint {
        WebTransportNetworkEndpoint(host: host, port: port)
    }

    init(_ endpoint: WebTransportNetworkEndpoint) {
        self.host = endpoint.host
        self.port = endpoint.port
    }
}

/// Result returned by the production network WebTransport facade.
public struct WebTransportConnectionResult: Equatable, Sendable {
    public var localEndpoint: WebTransportEndpoint
    public var remoteEndpoint: WebTransportEndpoint
    public var message: String
    public var transport: WebTransportNetworkTransport
    public var sessionEstablished: Bool

    init(_ result: WebTransportNetworkSessionResult) {
        self.localEndpoint = WebTransportEndpoint(result.localEndpoint)
        self.remoteEndpoint = WebTransportEndpoint(result.remoteEndpoint)
        self.message = result.message
        self.transport = result.transport
        self.sessionEstablished = result.sessionEstablished
    }
}

/// Client API backed by the Network.framework QUIC/TLS/HTTP/3 WebTransport runtime.
public actor WebTransportClient {
    public let configuration: WebTransportClientConfiguration
    private let logger: WebTransportLogger

    public init(configuration: WebTransportClientConfiguration, logger: WebTransportLogger = .disabled) {
        self.configuration = configuration
        self.logger = logger
    }

    /// Establishes a real WebTransport session to a network endpoint and performs
    /// a reliable-stream echo exchange used by the current runtime smoke path.
    public func connect(
        to endpoint: WebTransportEndpoint,
        message: String
    ) async throws -> WebTransportConnectionResult {
        guard configuration.transport == .packet else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "WebTransport facade currently supports packet transport only"
            )
        }
        let result = try await WebTransportQUICClient(
            trustPolicy: configuration.trustPolicy
        ).run(
            to: endpoint.networkEndpoint,
            message: message,
            authority: configuration.authority,
            path: configuration.path,
            origin: configuration.origin,
            protocols: configuration.availableProtocols,
            settingsValidation: configuration.settingsValidation,
            timeoutMilliseconds: configuration.timeoutMilliseconds
        )
        logger.record(.sessionEstablished(role: "client"))
        return WebTransportConnectionResult(result)
    }
}

/// Server factory backed by the Network.framework QUIC/TLS/HTTP/3 WebTransport runtime.
public actor WebTransportServer {
    public let configuration: WebTransportServerConfiguration
    private let logger: WebTransportLogger

    public init(configuration: WebTransportServerConfiguration, logger: WebTransportLogger = .disabled) {
        self.configuration = configuration
        self.logger = logger
    }

    /// Starts a network listener. The returned server owns the underlying
    /// listener and can serve accepted WebTransport sessions.
    public func listen(
        on endpoint: WebTransportEndpoint,
        maxConcurrentConnections: Int = 16
    ) async throws -> WebTransportListeningServer {
        let server = try WebTransportQUICServer(
            endpoint: endpoint.networkEndpoint,
            maxConcurrentConnections: maxConcurrentConnections,
            authority: configuration.authority,
            path: configuration.path,
            allowedOrigin: configuration.origin,
            protocols: configuration.supportedProtocols,
            settingsValidation: configuration.settingsValidation
        )
        let local = try await server.waitForListening(timeoutMilliseconds: configuration.timeoutMilliseconds)
        logger.record(.serverControlAccepted)
        return WebTransportListeningServer(
            runtime: server,
            localEndpoint: WebTransportEndpoint(local),
            logger: logger,
            timeoutMilliseconds: configuration.timeoutMilliseconds
        )
    }
}

/// Active network WebTransport listener returned by `WebTransportServer.listen`.
public final class WebTransportListeningServer: @unchecked Sendable {
    public let localEndpoint: WebTransportEndpoint
    public let certificateSHA256: Data

    private let runtime: WebTransportQUICServer
    private let logger: WebTransportLogger
    private let timeoutMilliseconds: Int32

    init(
        runtime: WebTransportQUICServer,
        localEndpoint: WebTransportEndpoint,
        logger: WebTransportLogger,
        timeoutMilliseconds: Int32
    ) {
        self.runtime = runtime
        self.localEndpoint = localEndpoint
        self.certificateSHA256 = runtime.certificateSHA256
        self.logger = logger
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    @discardableResult
    public func serveOne() async throws -> WebTransportConnectionResult {
        let result = try await runtime.serveOne(timeoutMilliseconds: timeoutMilliseconds)
        logger.record(.sessionEstablished(role: "server"))
        return WebTransportConnectionResult(result)
    }
}
