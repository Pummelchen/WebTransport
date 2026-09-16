import Foundation
import WebTransportQUICCore

public enum WebTransportSessionState: Equatable, Sendable {
    case requested
    case accepted
    case draining
    case closed(applicationErrorCode: UInt32, message: String)
    case rejected(status: UInt16)
}

public struct WebTransportSessionID: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public static func fromRequestStreamID(_ streamID: UInt64) throws -> WebTransportSessionID {
        guard QUICStreamID.direction(of: streamID) == .bidirectional,
            QUICStreamID.initiator(of: streamID) == .client
        else {
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

    public func headers(
        upgradeToken: String = WebTransportHTTP3DraftConstants.current.upgradeToken
    ) throws -> [HTTPFieldLine] {
        var fields = try WebTransportHTTP3Headers.connectRequest(
            authority: authority,
            path: path,
            origin: origin,
            upgradeToken: upgradeToken
        )
        if !availableProtocols.isEmpty {
            fields.append(
                try HTTPFieldLine(
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
    public var rejectionError: WebTransportDraft16Error?

    public init(
        session: WebTransportSession,
        responseFrame: HTTP3Frame,
        rejectionError: WebTransportDraft16Error? = nil
    ) {
        self.session = session
        self.responseFrame = responseFrame
        self.rejectionError = rejectionError
    }
}

public struct WebTransportSessionTerminationActions: Equatable, Sendable {
    public var connectFINFrame: QUICFrame
    public var connectStopSendingFrame: QUICFrame?
    public var streamResetFrames: [QUICFrame]
    public var streamStopSendingFrames: [QUICFrame]

    public init(
        connectFINFrame: QUICFrame,
        connectStopSendingFrame: QUICFrame?,
        streamResetFrames: [QUICFrame],
        streamStopSendingFrames: [QUICFrame]
    ) {
        self.connectFINFrame = connectFINFrame
        self.connectStopSendingFrame = connectStopSendingFrame
        self.streamResetFrames = streamResetFrames
        self.streamStopSendingFrames = streamStopSendingFrames
    }
}

public struct WebTransportCloseSessionCapsuleResult: Equatable, Sendable {
    public var capsuleBytes: Data
    public var terminationActions: WebTransportSessionTerminationActions

    public init(capsuleBytes: Data, terminationActions: WebTransportSessionTerminationActions) {
        self.capsuleBytes = capsuleBytes
        self.terminationActions = terminationActions
    }
}

public struct WebTransportReceivedFlowControlCapsule: Equatable, Sendable {
    public var capsule: WebTransportFlowCapsule
    public var terminationActions: WebTransportSessionTerminationActions?

    public init(
        capsule: WebTransportFlowCapsule,
        terminationActions: WebTransportSessionTerminationActions?
    ) {
        self.capsule = capsule
        self.terminationActions = terminationActions
    }
}

public struct WebTransportConnectStreamCapsuleResult: Equatable, Sendable {
    public var receivedCapsules: [WebTransportReceivedFlowControlCapsule]
    public var connectResetFrame: QUICFrame?
    public var terminationActions: WebTransportSessionTerminationActions?

    public init(
        receivedCapsules: [WebTransportReceivedFlowControlCapsule],
        connectResetFrame: QUICFrame?,
        terminationActions: WebTransportSessionTerminationActions?
    ) {
        self.receivedCapsules = receivedCapsules
        self.connectResetFrame = connectResetFrame
        self.terminationActions = terminationActions
    }
}

public struct WebTransportIncomingStreamResult: Equatable, Sendable {
    public var prefix: WebTransportStreamPrefix?
    public var rejectionFrame: QUICFrame?

    public init(prefix: WebTransportStreamPrefix?, rejectionFrame: QUICFrame?) {
        self.prefix = prefix
        self.rejectionFrame = rejectionFrame
    }
}
