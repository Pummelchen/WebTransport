import Foundation
import WebTransportQUICCore

public enum WebTransportSessionState: Equatable, Sendable {
    case requested
    case accepted
    case rejected(status: UInt16)
}

public struct WebTransportSessionID: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public static func fromRequestStreamID(_ streamID: UInt64) throws -> WebTransportSessionID {
        guard QUICStreamID.direction(of: streamID) == .bidirectional,
              QUICStreamID.initiator(of: streamID) == .client else {
            throw QUICCodecError.malformed("WebTransport session ID must be a client-initiated bidirectional request stream ID")
        }
        return WebTransportSessionID(rawValue: streamID)
    }
}

public struct WebTransportSession: Equatable, Sendable {
    public var id: WebTransportSessionID
    public var requestStreamID: UInt64
    public var authority: String
    public var path: String
    public var origin: String?
    public var availableProtocols: [String]
    public var selectedProtocol: String?
    public var state: WebTransportSessionState

    public init(
        id: WebTransportSessionID,
        requestStreamID: UInt64,
        authority: String,
        path: String,
        origin: String?,
        availableProtocols: [String],
        selectedProtocol: String?,
        state: WebTransportSessionState
    ) {
        self.id = id
        self.requestStreamID = requestStreamID
        self.authority = authority
        self.path = path
        self.origin = origin
        self.availableProtocols = availableProtocols
        self.selectedProtocol = selectedProtocol
        self.state = state
    }
}

public struct WebTransportSessionRequest: Equatable, Sendable {
    public var authority: String
    public var path: String
    public var origin: String?
    public var availableProtocols: [String]

    public init(
        authority: String,
        path: String,
        origin: String? = nil,
        availableProtocols: [String] = []
    ) throws {
        guard !authority.isEmpty else {
            throw QUICCodecError.malformed("WebTransport session authority must not be empty")
        }
        guard path.hasPrefix("/") else {
            throw QUICCodecError.malformed("WebTransport session path must be absolute")
        }
        try WebTransportProtocolNegotiation.validate(availableProtocols)
        self.authority = authority
        self.path = path
        self.origin = origin
        self.availableProtocols = availableProtocols
    }

    public func headers() throws -> [HTTPFieldLine] {
        var fields = try WebTransportHTTP3Headers.connectRequest(
            authority: authority,
            path: path,
            origin: origin
        )
        if !availableProtocols.isEmpty {
            fields.append(try HTTPFieldLine(
                name: WebTransportHeaderName.availableProtocols,
                value: WebTransportProtocolNegotiation.encodeList(availableProtocols)
            ))
        }
        return fields
    }
}

public struct WebTransportServerSessionPolicy: Equatable, Sendable {
    public var allowedAuthorities: Set<String>?
    public var allowedPaths: Set<String>?
    public var allowedOrigins: Set<String>?
    public var supportedProtocols: [String]
    public var requireProtocolSelection: Bool

    public init(
        allowedAuthorities: Set<String>? = nil,
        allowedPaths: Set<String>? = nil,
        allowedOrigins: Set<String>? = nil,
        supportedProtocols: [String] = [],
        requireProtocolSelection: Bool = false
    ) throws {
        try WebTransportProtocolNegotiation.validate(supportedProtocols)
        self.allowedAuthorities = allowedAuthorities
        self.allowedPaths = allowedPaths
        self.allowedOrigins = allowedOrigins
        self.supportedProtocols = supportedProtocols
        self.requireProtocolSelection = requireProtocolSelection
    }
}

public struct WebTransportServerSessionDecision: Equatable, Sendable {
    public var session: WebTransportSession
    public var responseFrame: HTTP3Frame

    public init(session: WebTransportSession, responseFrame: HTTP3Frame) {
        self.session = session
        self.responseFrame = responseFrame
    }
}

public struct WebTransportSessionManager: Equatable, Sendable {
    public private(set) var http3: HTTP3ConnectionState
    public private(set) var sessionsByID: [WebTransportSessionID: WebTransportSession]
    public private(set) var sessionIDsByRequestStreamID: [UInt64: WebTransportSessionID]

    public init(http3: HTTP3ConnectionState) {
        self.http3 = http3
        self.sessionsByID = [:]
        self.sessionIDsByRequestStreamID = [:]
    }

    public mutating func makeClientSessionRequest(
        streamID: UInt64,
        request: WebTransportSessionRequest
    ) throws -> HTTP3Frame {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients create WebTransport CONNECT requests")
        }
        try validateSettingsReady()

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }

        var requestStream = try http3.openRequestStream(streamID: streamID)
        let frame = try requestStream.makeRequestHeadersFrame(request.headers())
        http3.storeRequestStream(requestStream)
        let session = WebTransportSession(
            id: sessionID,
            requestStreamID: streamID,
            authority: request.authority,
            path: request.path,
            origin: request.origin,
            availableProtocols: request.availableProtocols,
            selectedProtocol: nil,
            state: .requested
        )
        store(session)
        return frame
    }

    public mutating func receiveServerSessionResponse(
        streamID: UInt64,
        frame: HTTP3Frame
    ) throws -> WebTransportSession {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients receive WebTransport CONNECT responses")
        }
        try validateSettingsReady()
        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard var session = sessionsByID[sessionID] else {
            throw QUICCodecError.malformed("unknown WebTransport session")
        }
        var requestStream = http3.requestStreams[streamID] ?? HTTP3RequestStream(streamID: streamID, role: .client)
        let fields = try QPACK.decodeHeadersFrame(frame)
        let status = try WebTransportSessionHeaders.status(from: fields)
        if (200..<300).contains(status) {
            try WebTransportHTTP3Headers.validateSuccessfulResponse(fields)
            let selectedProtocol = try WebTransportSessionHeaders.selectedProtocol(from: fields)
            if let selectedProtocol {
                try WebTransportProtocolNegotiation.validate([selectedProtocol])
                guard session.availableProtocols.contains(selectedProtocol) else {
                    throw QUICCodecError.malformed("server selected a WebTransport protocol the client did not offer")
                }
            }
            session.selectedProtocol = selectedProtocol
            session.state = .accepted
            try requestStream.receive(frame: frame)
        } else {
            session.state = .rejected(status: status)
        }

        http3.storeRequestStream(requestStream)
        store(session)
        return session
    }

    public mutating func receiveClientSessionRequest(
        streamID: UInt64,
        frame: HTTP3Frame,
        policy: WebTransportServerSessionPolicy
    ) throws -> WebTransportServerSessionDecision {
        guard http3.role == .server else {
            throw QUICCodecError.malformed("only servers receive WebTransport CONNECT requests")
        }
        try validateSettingsReady()

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }

        var requestStream = try http3.acceptRequestStream(streamID: streamID)
        try requestStream.receive(frame: frame)
        http3.storeRequestStream(requestStream)

        let fields = try QPACK.decodeHeadersFrame(frame)
        let request = try WebTransportSessionHeaders.request(from: fields)
        let selectedProtocol = try WebTransportSessionHeaders.selectProtocol(
            requestProtocols: request.availableProtocols,
            policy: policy
        )

        let rejectionStatus = rejectionStatus(for: request, selectedProtocol: selectedProtocol, policy: policy)
        let state: WebTransportSessionState
        let responseFrame: HTTP3Frame
        if let rejectionStatus {
            state = .rejected(status: rejectionStatus)
            responseFrame = try WebTransportSessionHeaders.responseFrame(status: rejectionStatus)
        } else {
            state = .accepted
            responseFrame = try WebTransportSessionHeaders.responseFrame(
                status: 200,
                selectedProtocol: selectedProtocol
            )
        }

        let session = WebTransportSession(
            id: sessionID,
            requestStreamID: streamID,
            authority: request.authority,
            path: request.path,
            origin: request.origin,
            availableProtocols: request.availableProtocols,
            selectedProtocol: selectedProtocol,
            state: state
        )
        store(session)
        return WebTransportServerSessionDecision(session: session, responseFrame: responseFrame)
    }

    public func session(forRequestStreamID streamID: UInt64) -> WebTransportSession? {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            return nil
        }
        return sessionsByID[sessionID]
    }

    private mutating func store(_ session: WebTransportSession) {
        sessionsByID[session.id] = session
        sessionIDsByRequestStreamID[session.requestStreamID] = session.id
    }

    private func validateSettingsReady() throws {
        try http3.localSettings.validateWebTransportDraft15Requirements()
        guard let remoteSettings = http3.remoteSettings else {
            throw QUICCodecError.malformed("peer HTTP/3 SETTINGS are required before WebTransport session establishment")
        }
        try remoteSettings.validateWebTransportDraft15Requirements()
    }

    private func rejectionStatus(
        for request: WebTransportSessionRequest,
        selectedProtocol: String?,
        policy: WebTransportServerSessionPolicy
    ) -> UInt16? {
        if let allowedAuthorities = policy.allowedAuthorities, !allowedAuthorities.contains(request.authority) {
            return 404
        }
        if let allowedPaths = policy.allowedPaths, !allowedPaths.contains(request.path) {
            return 404
        }
        if let allowedOrigins = policy.allowedOrigins {
            guard let origin = request.origin, allowedOrigins.contains(origin) else {
                return 403
            }
        }
        if policy.requireProtocolSelection && selectedProtocol == nil {
            return 400
        }
        return nil
    }
}

public enum WebTransportHeaderName {
    public static let availableProtocols = "wt-available-protocols"
    public static let selectedProtocol = "wt-protocol"
}

public enum WebTransportProtocolNegotiation {
    public static func validate(_ protocols: [String]) throws {
        var seen = Set<String>()
        for name in protocols {
            guard !name.isEmpty else {
                throw QUICCodecError.malformed("WebTransport protocol token must not be empty")
            }
            guard name.utf8.allSatisfy({ byte in
                byte >= 0x21 && byte <= 0x7e && byte != 0x22 && byte != 0x2c && byte != 0x5c
            }) else {
                throw QUICCodecError.malformed("WebTransport protocol token contains invalid bytes")
            }
            guard seen.insert(name).inserted else {
                throw QUICCodecError.malformed("duplicate WebTransport protocol token")
            }
        }
    }

    public static func encodeList(_ protocols: [String]) throws -> String {
        try validate(protocols)
        return protocols.map { "\"\($0)\"" }.joined(separator: ", ")
    }

    public static func decodeList(_ value: String) throws -> [String] {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            return []
        }

        let parts = trimmed.split(separator: ",", omittingEmptySubsequences: false)
        var protocols: [String] = []
        for part in parts {
            let token = part.trimmingCharacters(in: .whitespaces)
            guard token.count >= 2, token.first == "\"", token.last == "\"" else {
                throw QUICCodecError.malformed("WebTransport protocol list must contain quoted strings")
            }
            let inner = String(token.dropFirst().dropLast())
            protocols.append(inner)
        }
        try validate(protocols)
        return protocols
    }

    public static func select(requested: [String], supported: [String]) -> String? {
        guard !requested.isEmpty, !supported.isEmpty else {
            return nil
        }
        let supportedSet = Set(supported)
        return requested.first { supportedSet.contains($0) }
    }
}

enum WebTransportSessionHeaders {
    static func request(from fields: [HTTPFieldLine]) throws -> WebTransportSessionRequest {
        try WebTransportHTTP3Headers.validateConnectRequest(fields)
        return try WebTransportSessionRequest(
            authority: try requiredField(":authority", from: fields),
            path: try requiredField(":path", from: fields),
            origin: optionalField("origin", from: fields),
            availableProtocols: try availableProtocols(from: fields)
        )
    }

    static func status(from fields: [HTTPFieldLine]) throws -> UInt16 {
        guard let statusValue = try optionalUniqueField(":status", from: fields),
              let status = UInt16(statusValue),
              (100...599).contains(status) else {
            throw QUICCodecError.malformed("WebTransport response requires a valid :status")
        }
        return status
    }

    static func selectedProtocol(from fields: [HTTPFieldLine]) throws -> String? {
        guard let value = try optionalUniqueField(WebTransportHeaderName.selectedProtocol, from: fields) else {
            return nil
        }
        try WebTransportProtocolNegotiation.validate([value])
        return value
    }

    static func selectProtocol(
        requestProtocols: [String],
        policy: WebTransportServerSessionPolicy
    ) throws -> String? {
        try WebTransportProtocolNegotiation.validate(requestProtocols)
        try WebTransportProtocolNegotiation.validate(policy.supportedProtocols)
        return WebTransportProtocolNegotiation.select(
            requested: requestProtocols,
            supported: policy.supportedProtocols
        )
    }

    static func responseFrame(status: UInt16, selectedProtocol: String? = nil) throws -> HTTP3Frame {
        guard (100...599).contains(status) else {
            throw QUICCodecError.valueOutOfRange("HTTP status must be 100...599")
        }
        var fields = [
            try HTTPFieldLine(name: ":status", value: String(status))
        ]
        if let selectedProtocol {
            try WebTransportProtocolNegotiation.validate([selectedProtocol])
            fields.append(try HTTPFieldLine(name: WebTransportHeaderName.selectedProtocol, value: selectedProtocol))
        }
        return try QPACK.headersFrame(fields: fields)
    }

    private static func availableProtocols(from fields: [HTTPFieldLine]) throws -> [String] {
        guard let value = try optionalUniqueField(WebTransportHeaderName.availableProtocols, from: fields) else {
            return []
        }
        return try WebTransportProtocolNegotiation.decodeList(value)
    }

    private static func requiredField(_ name: String, from fields: [HTTPFieldLine]) throws -> String {
        guard let value = try optionalUniqueField(name, from: fields), !value.isEmpty else {
            throw QUICCodecError.malformed("required WebTransport field \(name) is missing")
        }
        return value
    }

    private static func optionalField(_ name: String, from fields: [HTTPFieldLine]) -> String? {
        fields.first { $0.name == name }?.value
    }

    private static func optionalUniqueField(_ name: String, from fields: [HTTPFieldLine]) throws -> String? {
        let matches = fields.filter { $0.name == name }
        guard matches.count <= 1 else {
            throw QUICCodecError.malformed("duplicate WebTransport field \(name)")
        }
        return matches.first?.value
    }
}
