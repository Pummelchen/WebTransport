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

private struct WebTransportSessionRejection: Equatable, Sendable {
    var status: UInt16
    var error: WebTransportDraft16Error
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

public struct WebTransportSessionManager: Equatable, Sendable {
    /// Builds an HTTP/3 GOAWAY frame and records that this endpoint sent it.
    ///
    /// Exposed here rather than reaching into ``http3`` directly so the sent
    /// GOAWAY identifier is tracked on the live connection state. Building the
    /// frame from a copy would emit correct bytes but leave this endpoint unable
    /// to reject the requests it just promised not to serve.
    ///
    /// `streamID` is the first client-initiated bidirectional stream the server
    /// will *not* process, per RFC 9114 section 5.2.
    public mutating func makeGoawayFrame(streamID: UInt64) throws -> HTTP3Frame {
        try http3.makeGoawayFrame(streamID: streamID)
    }

    public private(set) var http3: HTTP3ConnectionState
    public private(set) var sessionsByID: [WebTransportSessionID: WebTransportSession]
    public private(set) var sessionIDsByRequestStreamID: [UInt64: WebTransportSessionID]
    public private(set) var streamsByID: [UInt64: WebTransportStreamState]
    public private(set) var streamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public private(set) var bufferedStreamsByID: [UInt64: WebTransportStreamState]
    public private(set) var bufferedStreamIDsBySessionID: [WebTransportSessionID: Set<UInt64>]
    public private(set) var datagramsBySessionID: [WebTransportSessionID: [Data]]
    public private(set) var flowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public private(set) var receiveFlowControlStateBySessionID: [WebTransportSessionID: WebTransportFlowControlState]
    public private(set) var blockedFlowCapsulesBySessionID: [WebTransportSessionID: [WebTransportFlowCapsule]]
    /// Largest DATAGRAM this endpoint will accept, matching what the QUIC layer
    /// advertised to the peer. Enforcing a smaller number here rejects peers that
    /// are honouring exactly what we told them they could send.
    public let maxDatagramFrameSize: Int
    /// Largest DATAGRAM this endpoint will attempt to send.
    ///
    /// Defaults to `min(maxDatagramFrameSize, 1200)`, which encodes two rules:
    /// never send more than this endpoint would itself accept, and never exceed
    /// the 1200 bytes a QUIC path is guaranteed to carry (RFC 9000 section 14).
    ///
    /// It is separate from the receive ceiling because the two are not the same
    /// question. A peer may legitimately advertise a large receive limit, but a
    /// QUIC DATAGRAM cannot be fragmented, so anything above the path MTU is
    /// silently undeliverable. Bounding sends turns that silent loss into an
    /// immediate, explicit error.
    public let maxSendableDatagramFrameSize: Int
    public let maxDatagramReceiveBufferBytes: Int
    public let maxStreamReceiveBufferBytes: Int
    public let maxBufferedStreamsPerSession: Int
    public let maxBufferedDatagramsPerSession: Int
    public let maxBufferedSessions: Int
    public let settingsValidation: HTTP3WebTransportSettingsValidation
    /// How many terminated sessions keep their tombstone.
    ///
    /// A terminated session is retained so that late activity on it reports
    /// "session gone" rather than "unknown", which is a materially better error.
    /// The retention has to be bounded, though: the tombstone holds the peer's
    /// own authority and path strings, a CONNECT field section may be up to
    /// 16 KB, and a peer can open and close sessions on one connection
    /// indefinitely. Unbounded retention is remotely triggerable memory growth.
    ///
    /// Beyond this many, the oldest tombstone is dropped and activity on it
    /// degrades to "unknown session", which is a safe answer.
    public let maxRetainedClosedSessions: Int
    /// How many terminated streams keep their tombstone, for the same reason.
    public let maxRetainedClosedStreams: Int

    private var datagramPayloadBytesBySessionID: [WebTransportSessionID: Int]
    private var closedStreamSessionIDsByStreamID: [UInt64: WebTransportSessionID]
    private var requestStreamIDsClosedByReceivedCloseCapsule: Set<UInt64>
    /// Tombstone insertion order, oldest first, so eviction is deterministic.
    private var closedSessionOrder: [WebTransportSessionID]
    private var closedStreamOrder: [UInt64]

    public init(
        http3: HTTP3ConnectionState,
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxDatagramFrameSize: Int = 1_200,
        maxSendableDatagramFrameSize: Int? = nil,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedDatagramsPerSession: Int = 64,
        maxBufferedSessions: Int = 64,
        maxRetainedClosedSessions: Int = 256,
        maxRetainedClosedStreams: Int = 4_096,
        settingsValidation: HTTP3WebTransportSettingsValidation = .draft16Strict
    ) {
        self.http3 = http3
        self.sessionsByID = [:]
        self.sessionIDsByRequestStreamID = [:]
        self.streamsByID = [:]
        self.streamIDsBySessionID = [:]
        self.bufferedStreamsByID = [:]
        self.bufferedStreamIDsBySessionID = [:]
        self.datagramsBySessionID = [:]
        self.flowControlStateBySessionID = [:]
        self.receiveFlowControlStateBySessionID = [:]
        self.blockedFlowCapsulesBySessionID = [:]
        self.maxDatagramFrameSize = maxDatagramFrameSize
        self.maxSendableDatagramFrameSize = maxSendableDatagramFrameSize
            ?? min(maxDatagramFrameSize, 1_200)
        self.maxDatagramReceiveBufferBytes = maxDatagramReceiveBufferBytes
        self.maxStreamReceiveBufferBytes = maxStreamReceiveBufferBytes
        self.maxBufferedStreamsPerSession = maxBufferedStreamsPerSession
        self.maxBufferedDatagramsPerSession = maxBufferedDatagramsPerSession
        self.maxBufferedSessions = maxBufferedSessions
        self.settingsValidation = settingsValidation
        self.maxRetainedClosedSessions = max(0, maxRetainedClosedSessions)
        self.maxRetainedClosedStreams = max(0, maxRetainedClosedStreams)
        self.datagramPayloadBytesBySessionID = [:]
        self.closedStreamSessionIDsByStreamID = [:]
        self.requestStreamIDsClosedByReceivedCloseCapsule = []
        self.closedSessionOrder = []
        self.closedStreamOrder = []
    }

    public mutating func makeClientSessionRequest(
        streamID: UInt64,
        request: WebTransportSessionRequest,
        isZeroRTT: Bool = false
    ) throws -> HTTP3Frame {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients create WebTransport CONNECT requests")
        }
        try validateSettingsReady()
        guard !isZeroRTT else {
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport CONNECT requests are not allowed on 0-RTT"
            )
        }
        try validateRequestAllowedByGoaway(streamID)

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }
        try validateSessionAdmission()

        var requestStream = try http3.openRequestStream(streamID: streamID)
        let frame = try requestStream.makeRequestHeadersFrame(
            request.headers(upgradeToken: settingsValidation.upgradeToken),
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
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
                    throw WebTransportDraft16Error(
                        kind: .alpn,
                        message: "server selected a WebTransport protocol the client did not offer"
                    )
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
        if session.state == .accepted {
            try promoteBufferedStreams(for: session.id)
        } else {
            discardBufferedIngress(for: session.id, tombstoneStreams: true)
            // A rejected session is terminal, so it becomes a bounded tombstone
            // rather than being retained for the life of the connection.
            recordClosedSession(session.id)
        }
        return session
    }

    public mutating func receivePeerControlStream(_ bytes: Data) throws -> [HTTP3Frame] {
        // Forward this manager's profile rather than letting the underlying
        // parameter default to draft16Strict. Omitting it made a manager
        // configured for an earlier revision validate the peer's SETTINGS
        // strictly anyway, which rejects the peers that profile exists to
        // accept — browsers in particular, since they do not send
        // SETTINGS_WT_ENABLE_WEBTRANSPORT.
        try http3.receivePeerControlStream(bytes, settingsValidation: settingsValidation)
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
        try validateRequestAllowedByGoaway(streamID)

        let sessionID = try WebTransportSessionID.fromRequestStreamID(streamID)
        guard sessionsByID[sessionID] == nil else {
            throw QUICCodecError.malformed("WebTransport session already exists")
        }
        try validateSessionAdmission()
        guard frame.type == HTTP3FrameType.headers else {
            throw WebTransportDraft16Error(
                kind: .requirementsNotMet,
                message: "WebTransport CONNECT stream must start with HEADERS"
            )
        }

        var requestStream = try http3.acceptRequestStream(streamID: streamID)
        try requestStream.receive(
            frame: frame,
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
        http3.storeRequestStream(requestStream)

        let fields = try QPACK.decodeHeadersFrame(frame)
        let request = try WebTransportSessionHeaders.request(
            from: fields,
            acceptedProtocolTokens: settingsValidation.acceptedUpgradeTokens
        )
        let selectedProtocol = try WebTransportSessionHeaders.selectProtocol(
            requestProtocols: request.availableProtocols,
            policy: policy
        )

        let rejection = rejection(for: request, selectedProtocol: selectedProtocol, policy: policy)
        let state: WebTransportSessionState
        let responseFrame: HTTP3Frame
        if let rejection {
            state = .rejected(status: rejection.status)
            responseFrame = try WebTransportSessionHeaders.responseFrame(status: rejection.status)
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
        if session.state == .accepted {
            try promoteBufferedStreams(for: session.id)
        } else {
            discardBufferedIngress(for: session.id, tombstoneStreams: true)
            recordClosedSession(session.id)
        }
        return WebTransportServerSessionDecision(
            session: session,
            responseFrame: responseFrame,
            rejectionError: rejection?.error
        )
    }

    public mutating func makeDatagramFrame(
        sessionID: WebTransportSessionID,
        payload: Data
    ) throws -> QUICFrame {
        try validateSettingsReady()
        _ = try writableSession(for: sessionID)

        let datagramPayload = try WebTransportDatagramSignaling.serialize(
            sessionID: sessionID.rawValue,
            payload: payload
        )
        guard datagramPayload.count <= maxSendableDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds the sendable frame size of \(maxSendableDatagramFrameSize)"
            )
        }
        return .datagram(datagramPayload)
    }

    public mutating func receiveDatagramFrame(_ frame: QUICFrame) throws -> WebTransportSessionID {
        try validateSettingsReady()
        guard case .datagram(let payload) = frame else {
            throw QUICCodecError.malformed("expected DATAGRAM frame")
        }
        guard payload.count <= maxDatagramFrameSize else {
            throw QUICCodecError.valueOutOfRange(
                "WebTransport datagram payload exceeds maximum frame size of \(maxDatagramFrameSize)"
            )
        }
        let parsed: WebTransportDatagramPrefix
        do {
            parsed = try WebTransportDatagramSignaling.parse(payload)
        } catch {
            throw WebTransportDraft16Error(kind: .h3ID, message: "invalid WebTransport datagram session ID")
        }
        let session = try sessionForIngressOrPending(parsed.sessionID)
        let currentBytes = datagramPayloadBytesBySessionID[parsed.sessionID] ?? 0
        let updatedBytes = currentBytes + parsed.payload.count
        guard updatedBytes <= maxDatagramReceiveBufferBytes else {
            if session == nil || session?.state == .requested {
                return parsed.sessionID
            }
            throw QUICCodecError.valueOutOfRange("WebTransport datagram receive buffer limit exceeded")
        }

        var queue = datagramsBySessionID[parsed.sessionID] ?? []
        if session?.state != .accepted && session?.state != .draining {
            try ensureCanBufferIngress(for: parsed.sessionID)
            guard queue.count < maxBufferedDatagramsPerSession else {
                return parsed.sessionID
            }
        }
        queue.append(parsed.payload)
        datagramsBySessionID[parsed.sessionID] = queue
        datagramPayloadBytesBySessionID[parsed.sessionID] = updatedBytes
        return parsed.sessionID
    }

    public mutating func popDatagramPayload(sessionID: WebTransportSessionID) -> Data? {
        guard var queue = datagramsBySessionID[sessionID] else {
            return nil
        }
        guard let payload = queue.first else {
            return nil
        }
        queue.removeFirst()
        datagramsBySessionID[sessionID] = queue.isEmpty ? [] : queue

        let currentBytes = datagramPayloadBytesBySessionID[sessionID] ?? 0
        datagramPayloadBytesBySessionID[sessionID] = max(0, currentBytes - payload.count)
        return payload
    }

    public func datagramQueue(sessionID: WebTransportSessionID) -> [Data]? {
        datagramsBySessionID[sessionID]
    }

    public func bufferedStreamIDs(for sessionID: WebTransportSessionID) -> Set<UInt64>? {
        bufferedStreamIDsBySessionID[sessionID]
    }

    public func flowState(for sessionID: WebTransportSessionID) -> WebTransportFlowControlState? {
        flowControlStateBySessionID[sessionID]
    }

    public func receiveFlowState(for sessionID: WebTransportSessionID) -> WebTransportFlowControlState? {
        receiveFlowControlStateBySessionID[sessionID]
    }

    public mutating func receiveControlFrame(_ frame: HTTP3Frame) throws {
        try http3.receiveControlFrame(frame)
        guard frame.type == HTTP3FrameType.goaway else {
            return
        }
        for (sessionID, var session) in sessionsByID where session.state == .accepted {
            session.state = .draining
            sessionsByID[sessionID] = session
        }
    }

    public mutating func receiveFlowControlCapsule(
        sessionID: WebTransportSessionID,
        bytes: Data
    ) throws -> WebTransportFlowCapsule {
        try receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: bytes).capsule
    }

    public mutating func receiveFlowControlCapsuleWithActions(
        sessionID: WebTransportSessionID,
        bytes: Data
    ) throws -> WebTransportReceivedFlowControlCapsule {
        try validateSettingsReady()
        _ = try sessionForIngress(sessionID)
        let capsuleType = try capsuleTypePrefix(bytes)
        if !webTransportFlowControlNegotiated,
           isHTTP3FlowControlCapsuleType(capsuleType) {
            let ignored = try ignoredFlowControlCapsuleEnvelope(bytes)
            return WebTransportReceivedFlowControlCapsule(
                capsule: ignored.capsule,
                terminationActions: nil
            )
        }
        let parsed: WebTransportFlowCapsuleEnvelope
        do {
            parsed = try WebTransportFlowCapsuleCodec.parse(bytes)
        } catch let error as WebTransportDraft16Error where error.kind == .flowControl {
            try closeForFlowControlViolation(sessionID)
            throw error
        }
        var terminationActions: WebTransportSessionTerminationActions?

        switch parsed.capsule {
        case .drainSession:
            try markSessionDraining(sessionID)
        case .closeSession(let applicationErrorCode, let message):
            terminationActions = try markSessionClosed(
                sessionID,
                applicationErrorCode: applicationErrorCode,
                message: message,
                closeCapsuleReceived: true
            )
        default:
            break
        }

        var state = flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.apply(parsed.capsule)
        } catch let error as WebTransportDraft16Error where error.kind == .flowControl {
            try closeForFlowControlViolation(sessionID)
            throw error
        }
        flowControlStateBySessionID[sessionID] = state
        return WebTransportReceivedFlowControlCapsule(
            capsule: parsed.capsule,
            terminationActions: terminationActions
        )
    }

    public mutating func makeDrainSessionCapsule(sessionID: WebTransportSessionID) throws -> Data {
        try validateSettingsReady()
        _ = try writableSession(for: sessionID)
        try markSessionDraining(sessionID)
        return try WebTransportFlowCapsuleCodec.serialize(.drainSession)
    }

    public func makeOptimisticConnectStreamCapsule(
        sessionID: WebTransportSessionID,
        capsule: WebTransportFlowCapsule
    ) throws -> Data {
        guard http3.role == .client else {
            throw QUICCodecError.malformed("only clients send optimistic WebTransport capsules")
        }
        guard sessionsByID[sessionID]?.state == .requested else {
            throw QUICCodecError.malformed("optimistic WebTransport capsules require a pending CONNECT request")
        }
        return try WebTransportFlowCapsuleCodec.serialize(capsule)
    }

    public mutating func makeCloseSessionCapsule(
        sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String
    ) throws -> Data {
        try makeCloseSessionCapsuleResult(
            sessionID: sessionID,
            applicationErrorCode: applicationErrorCode,
            message: message
        ).capsuleBytes
    }

    public mutating func makeCloseSessionCapsuleResult(
        sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String
    ) throws -> WebTransportCloseSessionCapsuleResult {
        try validateSettingsReady()
        _ = try sessionForIngress(sessionID)
        let capsuleBytes = try WebTransportFlowCapsuleCodec.serialize(.closeSession(
            applicationErrorCode: applicationErrorCode,
            message: message
        ))
        let terminationActions = try markSessionClosed(
            sessionID,
            applicationErrorCode: applicationErrorCode,
            message: message,
            closeCapsuleReceived: false
        )
        return WebTransportCloseSessionCapsuleResult(
            capsuleBytes: capsuleBytes,
            terminationActions: terminationActions
        )
    }

    @discardableResult
    public mutating func finishConnectStream(streamID: UInt64) throws -> WebTransportSessionTerminationActions {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport CONNECT stream")
        }
        return try markSessionClosed(
            sessionID,
            applicationErrorCode: 0,
            message: "",
            closeCapsuleReceived: false
        )
    }

    public mutating func receiveConnectStreamData(streamID: UInt64, data: Data) throws -> QUICFrame? {
        guard !data.isEmpty else {
            return nil
        }
        return try receiveConnectStreamCapsulesWithActions(streamID: streamID, bytes: data).connectResetFrame
    }

    public mutating func receiveConnectStreamCapsulesWithActions(
        streamID: UInt64,
        bytes: Data
    ) throws -> WebTransportConnectStreamCapsuleResult {
        guard let sessionID = sessionIDsByRequestStreamID[streamID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport CONNECT stream")
        }

        var remaining = bytes
        var received: [WebTransportReceivedFlowControlCapsule] = []
        var terminationActions: WebTransportSessionTerminationActions?
        while !remaining.isEmpty {
            if requestStreamIDsClosedByReceivedCloseCapsule.contains(streamID) {
                return WebTransportConnectStreamCapsuleResult(
                    receivedCapsules: received,
                    connectResetFrame: connectMessageErrorReset(streamID: streamID),
                    terminationActions: terminationActions
                )
            }

            let capsuleType = try capsuleTypePrefix(remaining)
            do {
                let parsed = try WebTransportFlowCapsuleCodec.parse(remaining)
                let result = try receiveFlowControlCapsuleWithActions(
                    sessionID: sessionID,
                    bytes: Data(remaining.prefix(parsed.bytesConsumed))
                )
                received.append(result)
                terminationActions = result.terminationActions ?? terminationActions
                remaining.removeFirst(parsed.bytesConsumed)
            } catch where capsuleType == WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule {
                let isAlreadyClosed: Bool
                if case .closed = sessionsByID[sessionID]?.state {
                    isAlreadyClosed = true
                } else {
                    isAlreadyClosed = false
                }
                if !isAlreadyClosed {
                    terminationActions = try? markSessionClosed(
                        sessionID,
                        applicationErrorCode: 0,
                        message: "",
                        closeCapsuleReceived: false
                    )
                }
                return WebTransportConnectStreamCapsuleResult(
                    receivedCapsules: received,
                    connectResetFrame: connectMessageErrorReset(streamID: streamID),
                    terminationActions: terminationActions
                )
            }
        }

        return WebTransportConnectStreamCapsuleResult(
            receivedCapsules: received,
            connectResetFrame: nil,
            terminationActions: terminationActions
        )
    }

    public mutating func popFlowControlCapsule(sessionID: WebTransportSessionID) throws -> Data? {
        guard var queue = blockedFlowCapsulesBySessionID[sessionID], let capsule = queue.first else {
            return nil
        }

        queue.removeFirst()
        blockedFlowCapsulesBySessionID[sessionID] = queue.isEmpty ? [] : queue
        return try WebTransportFlowCapsuleCodec.serialize(capsule)
    }

    public mutating func openBidirectionalStream(
        streamID: UInt64,
        sessionID: WebTransportSessionID
    ) throws -> Data {
        try validateSettingsReady()
        let session = try writableSession(for: sessionID)

        try validateStreamIdentity(
            streamID: streamID,
            direction: .bidirectional,
            initiator: expectedLocalInitiator
        )
        try reserveStream(session.id, form: .bidirectional, receiveSide: false)
        let stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: session.id,
            form: .bidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        register(stream)

        return try WebTransportStreamSignaling.serializePrefix(
            form: .bidirectional,
            sessionID: session.id.rawValue
        )
    }

    public mutating func openUnidirectionalStream(
        streamID: UInt64,
        sessionID: WebTransportSessionID
    ) throws -> Data {
        try validateSettingsReady()
        let session = try writableSession(for: sessionID)

        try validateStreamIdentity(
            streamID: streamID,
            direction: .unidirectional,
            initiator: expectedLocalInitiator
        )
        try reserveStream(session.id, form: .unidirectional, receiveSide: false)
        let stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: session.id,
            form: .unidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        register(stream)

        return try WebTransportStreamSignaling.serializePrefix(
            form: .unidirectional,
            sessionID: session.id.rawValue
        )
    }

    public mutating func acceptBidirectionalStream(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportStreamPrefix {
        let result = try acceptBidirectionalStreamWithActions(streamID: streamID, firstBytes: firstBytes)
        if let prefix = result.prefix {
            return prefix
        }
        throw WebTransportDraft16Error(
            kind: .bufferedStreamRejected,
            message: "buffered WebTransport stream exceeds receive limit"
        )
    }

    public mutating func acceptBidirectionalStreamWithActions(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportIncomingStreamResult {
        try validateSettingsReady()

        try validateStreamIdentity(
            streamID: streamID,
            direction: .bidirectional,
            initiator: expectedRemoteInitiator
        )

        let prefix = try WebTransportStreamSignaling.parsePrefix(firstBytes)
        guard prefix.form == .bidirectional else {
            throw QUICCodecError.malformed("invalid form for bidirectional stream accept")
        }
        let session = try sessionForIngressOrPending(prefix.sessionID)
        if session?.state == .accepted || session?.state == .draining {
            try reserveStream(prefix.sessionID, form: .bidirectional, receiveSide: true)
            try reserveData(for: prefix.sessionID, byteCount: prefix.remainingPayload.count, receiveSide: true)
        }

        var stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: prefix.sessionID,
            form: .bidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        do {
            try receiveInitialPayloadIfPresent(prefix.remainingPayload, into: &stream, buffering: session?.state == .requested || session == nil)
        } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
            return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
        }
        if session?.state == .accepted || session?.state == .draining {
            register(stream)
        } else {
            do {
                try buffer(stream)
            } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
                return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
            }
        }
        return WebTransportIncomingStreamResult(prefix: prefix, rejectionFrame: nil)
    }

    public mutating func acceptUnidirectionalStream(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportStreamPrefix {
        let result = try acceptUnidirectionalStreamWithActions(streamID: streamID, firstBytes: firstBytes)
        if let prefix = result.prefix {
            return prefix
        }
        throw WebTransportDraft16Error(
            kind: .bufferedStreamRejected,
            message: "buffered WebTransport stream exceeds receive limit"
        )
    }

    public mutating func acceptUnidirectionalStreamWithActions(
        streamID: UInt64,
        firstBytes: Data
    ) throws -> WebTransportIncomingStreamResult {
        try validateSettingsReady()

        try validateStreamIdentity(
            streamID: streamID,
            direction: .unidirectional,
            initiator: expectedRemoteInitiator
        )

        let prefix = try WebTransportStreamSignaling.parsePrefix(firstBytes)
        guard prefix.form == .unidirectional else {
            throw QUICCodecError.malformed("invalid form for unidirectional stream accept")
        }
        let session = try sessionForIngressOrPending(prefix.sessionID)
        if session?.state == .accepted || session?.state == .draining {
            try reserveStream(prefix.sessionID, form: .unidirectional, receiveSide: true)
            try reserveData(for: prefix.sessionID, byteCount: prefix.remainingPayload.count, receiveSide: true)
        }

        var stream = try WebTransportStreamState(
            streamID: streamID,
            sessionID: prefix.sessionID,
            form: .unidirectional,
            localRole: http3.role,
            maxSendOffset: UInt64.max,
            maxReceiveOffset: UInt64.max,
            maxBufferedBytes: maxStreamReceiveBufferBytes
        )
        do {
            try receiveInitialPayloadIfPresent(prefix.remainingPayload, into: &stream, buffering: session?.state == .requested || session == nil)
        } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
            return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
        }
        if session?.state == .accepted || session?.state == .draining {
            register(stream)
        } else {
            do {
                try buffer(stream)
            } catch let error as WebTransportDraft16Error where error.kind == .bufferedStreamRejected {
                return WebTransportIncomingStreamResult(prefix: nil, rejectionFrame: bufferedStreamRejectedFrame(streamID: streamID))
            }
        }
        return WebTransportIncomingStreamResult(prefix: prefix, rejectionFrame: nil)
    }

    public mutating func receiveStreamPayload(streamID: UInt64, payload: Data) throws {
        guard var stream = streamsByID[streamID] else {
            if let sessionID = closedStreamSessionIDsByStreamID[streamID],
               let state = sessionsByID[sessionID]?.state {
                switch state {
                case .closed:
                    throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
                case .rejected:
                    throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
                case .requested, .accepted, .draining:
                    break
                }
            }
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        _ = try sessionForIngress(stream.sessionID)
        try reserveData(for: stream.sessionID, byteCount: payload.count, receiveSide: true)
        try stream.receivePayload(payload)
        streamsByID[streamID] = stream
    }

    public mutating func sendStreamPayload(
        streamID: UInt64,
        payload: Data,
        fin: Bool = false
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        _ = try writableSession(for: stream.sessionID)
        try reserveData(for: stream.sessionID, byteCount: payload.count, receiveSide: false)
        let frame = try stream.sendPayload(payload, fin: fin)
        streamsByID[streamID] = stream
        return frame
    }

    public mutating func popStreamPayload(streamID: UInt64) -> Data? {
        guard var stream = streamsByID[streamID] else {
            return nil
        }
        let payload = stream.popPayload()
        streamsByID[streamID] = stream
        return payload
    }

    public mutating func resetStream(
        streamID: UInt64,
        applicationErrorCode: UInt64
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        let frame = stream.reset(applicationErrorCode: try mapApplicationErrorCode(applicationErrorCode))
        streamsByID[streamID] = stream
        return frame
    }

    public mutating func stopSendingStream(
        streamID: UInt64,
        applicationErrorCode: UInt64
    ) throws -> QUICFrame {
        guard var stream = streamsByID[streamID] else {
            throw QUICCodecError.malformed("unknown WebTransport stream")
        }
        let frame = stream.stopSending(applicationErrorCode: try mapApplicationErrorCode(applicationErrorCode))
        streamsByID[streamID] = stream
        return frame
    }

    public func stream(for streamID: UInt64) -> WebTransportStreamState? {
        streamsByID[streamID]
    }

    public func streamIDs(for sessionID: WebTransportSessionID) -> Set<UInt64>? {
        streamIDsBySessionID[sessionID]
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
        datagramsBySessionID[session.id] = datagramsBySessionID[session.id] ?? []
        let negotiated = webTransportFlowControlNegotiated
        flowControlStateBySessionID[session.id] = flowControlStateBySessionID[session.id]
            ?? WebTransportFlowControlState(
                settings: http3.remoteSettings ?? .webTransportDraft16Defaults,
                isEnabled: negotiated
            )
        receiveFlowControlStateBySessionID[session.id] = receiveFlowControlStateBySessionID[session.id]
            ?? WebTransportFlowControlState(settings: http3.localSettings, isEnabled: negotiated)
        datagramPayloadBytesBySessionID[session.id] = datagramPayloadBytesBySessionID[session.id] ?? 0
        blockedFlowCapsulesBySessionID[session.id] = blockedFlowCapsulesBySessionID[session.id] ?? []
    }

    /// Records a terminated session and evicts the oldest beyond the retention
    /// bound, releasing every per-session map keyed by it.
    private mutating func recordClosedSession(_ sessionID: WebTransportSessionID) {
        if let existing = closedSessionOrder.firstIndex(of: sessionID) {
            closedSessionOrder.remove(at: existing)
        }
        closedSessionOrder.append(sessionID)
        while closedSessionOrder.count > maxRetainedClosedSessions {
            let evicted = closedSessionOrder.removeFirst()
            releaseSessionState(evicted)
        }
    }

    /// Drops every trace of a session. Only ever called for a session already
    /// terminated, so nothing live is discarded.
    private mutating func releaseSessionState(_ sessionID: WebTransportSessionID) {
        if let session = sessionsByID.removeValue(forKey: sessionID) {
            sessionIDsByRequestStreamID.removeValue(forKey: session.requestStreamID)
            requestStreamIDsClosedByReceivedCloseCapsule.remove(session.requestStreamID)
        }
        streamIDsBySessionID.removeValue(forKey: sessionID)
        bufferedStreamIDsBySessionID.removeValue(forKey: sessionID)
        datagramsBySessionID.removeValue(forKey: sessionID)
        datagramPayloadBytesBySessionID.removeValue(forKey: sessionID)
        flowControlStateBySessionID.removeValue(forKey: sessionID)
        receiveFlowControlStateBySessionID.removeValue(forKey: sessionID)
        blockedFlowCapsulesBySessionID.removeValue(forKey: sessionID)
    }

    /// Records a terminated stream and evicts the oldest beyond the bound.
    private mutating func recordClosedStream(_ streamID: UInt64) {
        if let existing = closedStreamOrder.firstIndex(of: streamID) {
            closedStreamOrder.remove(at: existing)
        }
        closedStreamOrder.append(streamID)
        while closedStreamOrder.count > maxRetainedClosedStreams {
            let evicted = closedStreamOrder.removeFirst()
            closedStreamSessionIDsByStreamID.removeValue(forKey: evicted)
        }
    }

    private mutating func register(_ stream: WebTransportStreamState) {
        streamsByID[stream.streamID] = stream
        streamIDsBySessionID[stream.sessionID, default: Set<UInt64>()].insert(stream.streamID)
    }

    private mutating func buffer(_ stream: WebTransportStreamState) throws {
        try ensureCanBufferIngress(for: stream.sessionID)
        let bufferedStreamIDs = bufferedStreamIDsBySessionID[stream.sessionID] ?? []
        let bufferedPayloadBytes = bufferedStreamIDs.reduce(0) { total, streamID in
            total + (bufferedStreamsByID[streamID]?.bufferedPayloadBytes ?? 0)
        }
        guard bufferedStreamIDs.count < maxBufferedStreamsPerSession,
              bufferedPayloadBytes + stream.bufferedPayloadBytes <= maxStreamReceiveBufferBytes else {
            throw WebTransportDraft16Error(
                kind: .bufferedStreamRejected,
                message: "buffered WebTransport stream exceeds receive limit"
            )
        }
        bufferedStreamsByID[stream.streamID] = stream
        bufferedStreamIDsBySessionID[stream.sessionID, default: Set<UInt64>()].insert(stream.streamID)
    }

    private func receiveInitialPayloadIfPresent(
        _ payload: Data,
        into stream: inout WebTransportStreamState,
        buffering: Bool
    ) throws {
        guard !payload.isEmpty else {
            return
        }
        do {
            try stream.receivePayload(payload)
        } catch {
            if buffering {
                throw WebTransportDraft16Error(
                    kind: .bufferedStreamRejected,
                    message: "buffered WebTransport stream exceeds receive limit"
                )
            }
            throw error
        }
    }

    private mutating func promoteBufferedStreams(for sessionID: WebTransportSessionID) throws {
        guard let streamIDs = bufferedStreamIDsBySessionID[sessionID] else {
            return
        }
        for streamID in streamIDs.sorted() {
            guard let stream = bufferedStreamsByID[streamID] else {
                continue
            }
            try reserveStream(sessionID, form: stream.form, receiveSide: true)
            try reserveData(for: sessionID, byteCount: stream.bufferedPayloadBytes, receiveSide: true)
            register(stream)
            bufferedStreamsByID.removeValue(forKey: streamID)
        }
        bufferedStreamIDsBySessionID[sessionID] = []
    }

    private mutating func discardBufferedIngress(
        for sessionID: WebTransportSessionID,
        tombstoneStreams: Bool
    ) {
        let streamIDs = bufferedStreamIDsBySessionID[sessionID] ?? []
        for streamID in streamIDs {
            if tombstoneStreams {
                closedStreamSessionIDsByStreamID[streamID] = sessionID
                recordClosedStream(streamID)
            }
            bufferedStreamsByID.removeValue(forKey: streamID)
        }
        bufferedStreamIDsBySessionID[sessionID] = []
        datagramsBySessionID[sessionID] = []
        datagramPayloadBytesBySessionID[sessionID] = 0
    }

    private func ensureCanBufferIngress(for sessionID: WebTransportSessionID) throws {
        guard hasBufferedIngress(for: sessionID) || bufferedIngressSessionCount < maxBufferedSessions else {
            throw WebTransportDraft16Error(
                kind: .bufferedStreamRejected,
                message: "buffered WebTransport session count exceeds receive limit"
            )
        }
    }

    private func hasBufferedIngress(for sessionID: WebTransportSessionID) -> Bool {
        guard let streamIDs = bufferedStreamIDsBySessionID[sessionID],
              !streamIDs.isEmpty else {
            return datagramsBySessionID[sessionID]?.isEmpty == false
        }
        return true
    }

    private var bufferedIngressSessionCount: Int {
        var sessionIDs = Set<WebTransportSessionID>()
        for (sessionID, streamIDs) in bufferedStreamIDsBySessionID where !streamIDs.isEmpty {
            sessionIDs.insert(sessionID)
        }
        for (sessionID, datagrams) in datagramsBySessionID where !datagrams.isEmpty {
            sessionIDs.insert(sessionID)
        }
        return sessionIDs.count
    }

    private mutating func reserveStream(
        _ sessionID: WebTransportSessionID,
        form: WebTransportStreamForm,
        receiveSide: Bool
    ) throws {
        var state = receiveSide
            ? receiveFlowControlStateBySessionID[sessionID] ?? .init()
            : flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.registerStream(form)
        } catch {
            if receiveSide {
                try closeForFlowControlViolation(sessionID)
            } else {
                if let capsule = blockedCapsule(for: form, state: state) {
                    enqueueBlockedFlowCapsule(capsule, for: sessionID)
                }
                flowControlStateBySessionID[sessionID] = state
            }
            throw error
        }
        if receiveSide {
            receiveFlowControlStateBySessionID[sessionID] = state
        } else {
            flowControlStateBySessionID[sessionID] = state
        }
    }

    private mutating func reserveData(
        for sessionID: WebTransportSessionID,
        byteCount: Int,
        receiveSide: Bool
    ) throws {
        var state = receiveSide
            ? receiveFlowControlStateBySessionID[sessionID] ?? .init()
            : flowControlStateBySessionID[sessionID] ?? .init()
        do {
            try state.recordData(bytes: byteCount)
        } catch {
            if receiveSide {
                try closeForFlowControlViolation(sessionID)
            } else {
                if let maxData = state.maxData {
                    enqueueBlockedFlowCapsule(.dataBlocked(limit: maxData), for: sessionID)
                }
                flowControlStateBySessionID[sessionID] = state
            }
            throw error
        }
        if receiveSide {
            receiveFlowControlStateBySessionID[sessionID] = state
        } else {
            flowControlStateBySessionID[sessionID] = state
        }
    }

    private mutating func enqueueBlockedFlowCapsule(
        _ capsule: WebTransportFlowCapsule,
        for sessionID: WebTransportSessionID
    ) {
        var queue = blockedFlowCapsulesBySessionID[sessionID] ?? []
        guard !queue.contains(capsule) else {
            blockedFlowCapsulesBySessionID[sessionID] = queue
            return
        }
        queue.append(capsule)
        blockedFlowCapsulesBySessionID[sessionID] = queue
    }

    private mutating func closeForFlowControlViolation(_ sessionID: WebTransportSessionID) throws {
        _ = try markSessionClosed(
            sessionID,
            applicationErrorCode: UInt32(WebTransportHTTP3DraftConstants.current.wtFlowControlError),
            message: "WebTransport flow-control violation",
            closeCapsuleReceived: false
        )
    }

    private func mapApplicationErrorCode(_ applicationErrorCode: UInt64) throws -> UInt64 {
        guard applicationErrorCode <= UInt64(UInt32.max) else {
            throw QUICCodecError.valueOutOfRange("WebTransport application error code exceeds UInt32")
        }
        return WebTransportDraft16ErrorMapper.httpErrorCode(
            forApplicationErrorCode: UInt32(applicationErrorCode)
        )
    }

    private func blockedCapsule(for form: WebTransportStreamForm, state: WebTransportFlowControlState) -> WebTransportFlowCapsule? {
        switch form {
        case .bidirectional:
            guard let limit = state.maxStreamsBidi else { return nil }
            return .streamsBlockedBidi(limit: limit)
        case .unidirectional:
            guard let limit = state.maxStreamsUni else { return nil }
            return .streamsBlockedUni(limit: limit)
        }
    }

    private var expectedLocalInitiator: QUICStreamInitiator {
        http3.role == .client ? .client : .server
    }

    private var expectedRemoteInitiator: QUICStreamInitiator {
        http3.role == .client ? .server : .client
    }

    private func validateStreamIdentity(
        streamID: UInt64,
        direction: QUICStreamDirection,
        initiator: QUICStreamInitiator
    ) throws {
        guard streamsByID[streamID] == nil else {
            throw QUICCodecError.malformed("WebTransport stream already exists")
        }
        guard bufferedStreamsByID[streamID] == nil else {
            throw QUICCodecError.malformed("WebTransport stream is already buffered")
        }
        if let sessionID = closedStreamSessionIDsByStreamID[streamID],
           sessionsByID[sessionID] != nil {
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport stream belongs to a terminated session")
        }

        guard QUICStreamID.direction(of: streamID) == direction else {
            throw QUICCodecError.malformed("stream direction mismatch for WebTransport stream")
        }
        guard QUICStreamID.initiator(of: streamID) == initiator else {
            throw QUICCodecError.malformed("stream initiator mismatch for WebTransport stream")
        }
    }

    private func writableSession(for sessionID: WebTransportSessionID) throws -> WebTransportSession {
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        case .requested:
            throw QUICCodecError.malformed("WebTransport session is not accepted")
        }
    }

    private mutating func markSessionDraining(_ sessionID: WebTransportSessionID) throws {
        var session = try sessionForIngress(sessionID)
        guard session.state != .requested else {
            throw QUICCodecError.malformed("WT_DRAIN_SESSION requires an established session")
        }
        if session.state == .accepted {
            session.state = .draining
            sessionsByID[sessionID] = session
        }
    }

    private mutating func markSessionClosed(
        _ sessionID: WebTransportSessionID,
        applicationErrorCode: UInt32,
        message: String,
        closeCapsuleReceived: Bool
    ) throws -> WebTransportSessionTerminationActions {
        var session = try sessionForIngress(sessionID)
        session.state = .closed(applicationErrorCode: applicationErrorCode, message: message)
        sessionsByID[sessionID] = session
        if closeCapsuleReceived {
            requestStreamIDsClosedByReceivedCloseCapsule.insert(session.requestStreamID)
        }

        let terminationActions = terminateAssociatedStreams(for: sessionID, requestStreamID: session.requestStreamID)
        datagramsBySessionID[sessionID] = []
        datagramPayloadBytesBySessionID[sessionID] = 0
        recordClosedSession(sessionID)
        return terminationActions
    }

    private mutating func terminateAssociatedStreams(
        for sessionID: WebTransportSessionID,
        requestStreamID: UInt64
    ) -> WebTransportSessionTerminationActions {
        let wtSessionGone = WebTransportHTTP3DraftConstants.current.wtSessionGoneError
        var streamResetFrames: [QUICFrame] = []
        var streamStopSendingFrames: [QUICFrame] = []

        let activeStreamIDs = (streamIDsBySessionID[sessionID] ?? []).sorted()
        for streamID in activeStreamIDs {
            guard var stream = streamsByID[streamID] else {
                continue
            }
            streamResetFrames.append(stream.reset(applicationErrorCode: wtSessionGone))
            streamStopSendingFrames.append(stream.stopSending(applicationErrorCode: wtSessionGone))
            closedStreamSessionIDsByStreamID[streamID] = sessionID
            recordClosedStream(streamID)
            streamsByID.removeValue(forKey: streamID)
        }

        let bufferedStreamIDs = (bufferedStreamIDsBySessionID[sessionID] ?? []).sorted()
        for streamID in bufferedStreamIDs {
            guard var stream = bufferedStreamsByID[streamID] else {
                continue
            }
            streamResetFrames.append(stream.reset(applicationErrorCode: wtSessionGone))
            streamStopSendingFrames.append(stream.stopSending(applicationErrorCode: wtSessionGone))
            closedStreamSessionIDsByStreamID[streamID] = sessionID
            recordClosedStream(streamID)
            bufferedStreamsByID.removeValue(forKey: streamID)
        }

        streamIDsBySessionID[sessionID] = []
        bufferedStreamIDsBySessionID[sessionID] = []

        return WebTransportSessionTerminationActions(
            connectFINFrame: .stream(id: requestStreamID, offset: nil, fin: true, data: Data()),
            connectStopSendingFrame: .stopSending(id: requestStreamID, applicationErrorCode: wtSessionGone),
            streamResetFrames: streamResetFrames,
            streamStopSendingFrames: streamStopSendingFrames
        )
    }

    private func sessionForIngress(_ sessionID: WebTransportSessionID) throws -> WebTransportSession {
        guard let session = sessionsByID[sessionID] else {
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .requested, .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        }
    }

    private func sessionForIngressOrPending(_ sessionID: WebTransportSessionID) throws -> WebTransportSession? {
        guard let session = sessionsByID[sessionID] else {
            if http3.role == .server {
                return nil
            }
            throw WebTransportDraft16Error(kind: .h3ID, message: "unknown WebTransport session")
        }
        switch session.state {
        case .requested, .accepted, .draining:
            return session
        case .closed:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session is closed")
        case .rejected:
            throw WebTransportDraft16Error(kind: .sessionGone, message: "WebTransport session was rejected")
        }
    }

    private func validateSettingsReady() throws {
        switch settingsValidation {
        case .draft16Strict:
            try http3.localSettings.validateWebTransportDraft16Requirements()
        case .interoperable, .chromiumInterop:
            try http3.localSettings.validateWebTransportChromiumInteropRequirements()
        case .pywebtransportStreamInterop:
            try http3.localSettings.validateWebTransportPyWebTransportStreamInteropRequirements()
        }
        guard let remoteSettings = http3.remoteSettings else {
            throw QUICCodecError.malformed("peer HTTP/3 SETTINGS are required before WebTransport session establishment")
        }
        let peerRole: HTTP3ConnectionRole = http3.role == .client ? .server : .client
        switch settingsValidation {
        case .draft16Strict:
            try remoteSettings.validateWebTransportDraft16Requirements(peerRole: peerRole)
        case .interoperable, .chromiumInterop:
            try remoteSettings.validateWebTransportChromiumInteropRequirements(peerRole: peerRole)
        case .pywebtransportStreamInterop:
            try remoteSettings.validateWebTransportPyWebTransportStreamInteropRequirements(peerRole: peerRole)
        }
    }

    private func validateSessionAdmission() throws {
        guard !webTransportFlowControlNegotiated else {
            return
        }
        let activeCount = sessionsByID.values.filter { session in
            switch session.state {
            case .requested, .accepted, .draining:
                return true
            case .closed, .rejected:
                return false
            }
        }.count
        guard activeCount == 0 else {
            throw WebTransportDraft16Error(
                kind: http3.role == .server ? .requestRejected : .requirementsNotMet,
                message: "multiple simultaneous WebTransport sessions require WebTransport flow control"
            )
        }
    }

    private var webTransportFlowControlNegotiated: Bool {
        guard let remoteSettings = http3.remoteSettings else {
            return false
        }
        return http3.localSettings.webTransportFlowControlEnabled(with: remoteSettings)
    }

    private func validateRequestAllowedByGoaway(_ streamID: UInt64) throws {
        guard let goawayID = http3.receivedGoawayID else {
            return
        }
        guard streamID < goawayID else {
            throw WebTransportDraft16Error(
                kind: .sessionGone,
                message: "new WebTransport session is blocked by GOAWAY"
            )
        }
    }

    private func rejection(
        for request: WebTransportSessionRequest,
        selectedProtocol: String?,
        policy: WebTransportServerSessionPolicy
    ) -> WebTransportSessionRejection? {
        if let allowedAuthorities = policy.allowedAuthorities, !allowedAuthorities.contains(request.authority) {
            return WebTransportSessionRejection(
                status: 405,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport authority is not allowed")
            )
        }
        if let allowedPaths = policy.allowedPaths, !allowedPaths.contains(request.path) {
            return WebTransportSessionRejection(
                status: 405,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport path is not allowed")
            )
        }
        if let allowedOrigins = policy.allowedOrigins {
            guard let origin = request.origin, allowedOrigins.contains(origin) else {
                return WebTransportSessionRejection(
                    status: 403,
                    error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport origin is not allowed")
                )
            }
        }
        if policy.requireProtocolSelection && selectedProtocol == nil {
            return WebTransportSessionRejection(
                status: 400,
                error: WebTransportDraft16Error(kind: .requirementsNotMet, message: "WebTransport protocol selection is required")
            )
        }
        return nil
    }
}

private func capsuleTypePrefix(_ bytes: Data) throws -> UInt64 {
    var cursor = QUICByteCursor(bytes)
    return try QUICVarInt.decode(from: &cursor)
}

private func isHTTP3FlowControlCapsuleType(_ type: UInt64) -> Bool {
    let constants = WebTransportHTTP3DraftConstants.current
    return type == constants.wtMaxDataCapsule
        || type == constants.wtMaxStreamsBidiCapsule
        || type == constants.wtMaxStreamsUniCapsule
        || type == constants.wtDataBlockedCapsule
        || type == constants.wtStreamsBlockedBidiCapsule
        || type == constants.wtStreamsBlockedUniCapsule
}

private func ignoredFlowControlCapsuleEnvelope(_ bytes: Data) throws -> WebTransportFlowCapsuleEnvelope {
    var cursor = QUICByteCursor(bytes)
    let type = try QUICVarInt.decode(from: &cursor)
    let payloadLength = try QUICVarInt.decode(from: &cursor)
    guard payloadLength <= UInt64(Int.max) else {
        throw QUICCodecError.valueOutOfRange("flow control capsule payload length exceeds Int.max")
    }
    let payload = try cursor.readBytes(count: Int(payloadLength))
    return WebTransportFlowCapsuleEnvelope(
        capsule: .unknown(type: type, payload: payload),
        bytesConsumed: bytes.count - cursor.remaining,
        payload: payload
    )
}

private func connectMessageErrorReset(streamID: UInt64) -> QUICFrame {
    .resetStream(
        id: streamID,
        applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
        finalSize: 0
    )
}

private func bufferedStreamRejectedFrame(streamID: UInt64) -> QUICFrame {
    .resetStreamAt(
        id: streamID,
        applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError,
        finalSize: 0,
        reliableSize: 0
    )
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
        return protocols.map { encodeItem($0) }.joined(separator: ", ")
    }

    public static func decodeList(_ value: String) throws -> [String] {
        var parser = StructuredFieldStringParser(value)
        let protocols = try parser.parseStringList()
        try validate(protocols)
        return protocols
    }

    public static func encodeItem(_ value: String) -> String {
        let escaped = value.flatMap { character -> [Character] in
            switch character {
            case "\"", "\\":
                return ["\\", character]
            default:
                return [character]
            }
        }
        return "\"\(String(escaped))\""
    }

    public static func decodeItem(_ value: String) throws -> String {
        var parser = StructuredFieldStringParser(value)
        let item = try parser.parseStringItem()
        try validate([item])
        return item
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
    static func request(
        from fields: [HTTPFieldLine],
        acceptedProtocolTokens: Set<String> = [WebTransportHTTP3DraftConstants.current.upgradeToken]
    ) throws -> WebTransportSessionRequest {
        try WebTransportHTTP3Headers.validateConnectRequest(
            fields,
            acceptedProtocolTokens: acceptedProtocolTokens
        )
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
        return try? WebTransportProtocolNegotiation.decodeItem(value)
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
            fields.append(try HTTPFieldLine(
                name: WebTransportHeaderName.selectedProtocol,
                value: WebTransportProtocolNegotiation.encodeItem(selectedProtocol)
            ))
        }
        return try QPACK.headersFrame(fields: fields)
    }

    private static func availableProtocols(from fields: [HTTPFieldLine]) throws -> [String] {
        guard let value = try optionalUniqueField(WebTransportHeaderName.availableProtocols, from: fields) else {
            return []
        }
        return (try? WebTransportProtocolNegotiation.decodeList(value)) ?? []
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

private struct StructuredFieldStringParser {
    private let scalars: [UnicodeScalar]
    private var index: Int

    init(_ value: String) {
        self.scalars = Array(value.unicodeScalars)
        self.index = 0
    }

    mutating func parseStringList() throws -> [String] {
        skipSpaces()
        guard !isAtEnd else { return [] }

        var items: [String] = []
        while true {
            items.append(try parseStringItem())
            skipSpaces()
            guard !isAtEnd else { return items }
            guard consume(",") else {
                throw QUICCodecError.malformed("Structured Field list expected comma")
            }
            skipSpaces()
            guard !isAtEnd else {
                throw QUICCodecError.malformed("Structured Field list has trailing comma")
            }
        }
    }

    mutating func parseStringItem() throws -> String {
        skipSpaces()
        let item = try parseBareString()
        skipParameters()
        skipSpaces()
        guard isAtEnd || current == "," else {
            throw QUICCodecError.malformed("Structured Field item has trailing bytes")
        }
        return item
    }

    private mutating func parseBareString() throws -> String {
        guard consume("\"") else {
            throw QUICCodecError.malformed("Structured Field item must be a string")
        }
        var output = String.UnicodeScalarView()
        while !isAtEnd {
            let scalar = scalars[index]
            index += 1
            if scalar == "\"" {
                return String(output)
            }
            if scalar == "\\" {
                guard !isAtEnd else {
                    throw QUICCodecError.malformed("Structured Field string has dangling escape")
                }
                let escaped = scalars[index]
                index += 1
                guard escaped == "\"" || escaped == "\\" else {
                    throw QUICCodecError.malformed("Structured Field string has invalid escape")
                }
                output.append(escaped)
                continue
            }
            guard scalar.value >= 0x20 && scalar.value <= 0x7e else {
                throw QUICCodecError.malformed("Structured Field string contains invalid character")
            }
            output.append(scalar)
        }
        throw QUICCodecError.malformed("Structured Field string is unterminated")
    }

    private mutating func skipParameters() {
        while true {
            skipSpaces()
            guard consume(";") else { return }
            while !isAtEnd, current != ",", current != ";" {
                index += 1
            }
        }
    }

    private mutating func skipSpaces() {
        while !isAtEnd, current == " " {
            index += 1
        }
    }

    private mutating func consume(_ scalar: UnicodeScalar) -> Bool {
        guard !isAtEnd, current == scalar else { return false }
        index += 1
        return true
    }

    private var current: UnicodeScalar {
        scalars[index]
    }

    private var isAtEnd: Bool {
        index >= scalars.count
    }
}
