import Foundation
import WebTransportQUICCore

public enum TLSQUICConnectionPhase: Equatable, Sendable {
    case idle
    case handshakeInProgress
    case handshakeKeysReady
    case applicationKeysReady
    case closed
}

public enum TLSQUICConnectionStateError: Error, Equatable, CustomStringConvertible, Sendable {
    case connectionClosed
    case handshakeKeysNotReady
    case applicationKeysNotReady
    case unknownStream(UInt64)
    case expectedStreamFrame

    public var description: String {
        switch self {
        case .connectionClosed:
            "TLS/QUIC connection is closed"
        case .handshakeKeysNotReady:
            "TLS handshake traffic secrets are not available"
        case .applicationKeysNotReady:
            "TLS application traffic secrets are not available"
        case .unknownStream(let streamID):
            "unknown QUIC stream: \(streamID)"
        case .expectedStreamFrame:
            "expected STREAM frame"
        }
    }
}

/// Deterministic TLS-for-QUIC primitive state used by tests, spikes, and the
/// native connection scaffolding.
///
/// This type derives and advances key-schedule material after the caller has
/// supplied the relevant handshake inputs. It is not the authoritative
/// production handshake gate for peer authentication. A production connection
/// must only treat application traffic as authenticated after certificate trust,
/// CertificateVerify, Finished, ALPN `h3`, and QUIC transport parameters have
/// all been validated by the layer that owns the complete handshake policy.
public struct TLSQUICConnectionState: Equatable, Sendable {
    public let role: QUICEndpointRole
    public private(set) var phase: TLSQUICConnectionPhase
    public private(set) var handshakeDecoder: TLSHandshakeFlightDecoder
    public private(set) var handshakeSecret: Data?
    public private(set) var handshakeTrafficSecrets: TLS13HandshakeTrafficSecrets?
    public private(set) var masterSecret: Data?
    public private(set) var applicationTrafficSecrets: TLS13ApplicationTrafficSecrets?
    public private(set) var keyUpdateGeneration: UInt64
    public private(set) var closeState: QUICConnectionCloseState
    public private(set) var streams: [UInt64: QUICStreamState]

    public init(
        role: QUICEndpointRole,
        idleTimeoutMicros: UInt64 = 30_000_000,
        nowMicros: UInt64 = 0
    ) {
        self.role = role
        self.phase = .idle
        self.handshakeDecoder = TLSHandshakeFlightDecoder()
        self.handshakeSecret = nil
        self.handshakeTrafficSecrets = nil
        self.masterSecret = nil
        self.applicationTrafficSecrets = nil
        self.keyUpdateGeneration = 0
        self.closeState = QUICConnectionCloseState(idleTimeoutMicros: idleTimeoutMicros, nowMicros: nowMicros)
        self.streams = [:]
    }

    public var transcript: TLS13Transcript {
        handshakeDecoder.transcript
    }

    public mutating func sendHandshakeFlight(
        messages: [TLSHandshakeMessage],
        startingOffset: UInt64 = 0,
        maxFramePayloadBytes: Int
    ) throws -> [QUICFrame] {
        try ensureOpen()
        let flight = TLSHandshakeFlight(messages: messages)
        let frames = try flight.cryptoFrames(
            startingOffset: startingOffset,
            maxFramePayloadBytes: maxFramePayloadBytes
        )
        for message in messages {
            try handshakeDecoder.appendTranscript(message)
        }
        if phase == .idle {
            phase = .handshakeInProgress
        }
        return frames
    }

    @discardableResult
    public mutating func receiveHandshakeFrames(_ frames: [QUICFrame]) throws -> [TLSHandshakeMessage] {
        try ensureOpen()
        let messages = try handshakeDecoder.receive(frames: frames)
        if !messages.isEmpty, phase == .idle {
            phase = .handshakeInProgress
        }
        return messages
    }

    @discardableResult
    public mutating func deriveHandshakeTrafficSecrets(sharedSecret: Data) throws -> TLS13HandshakeTrafficSecrets {
        try ensureOpen()
        let secret = try TLS13KeyAgreement.handshakeSecret(sharedSecret: sharedSecret)
        let trafficSecrets = try TLS13KeyAgreement.handshakeTrafficSecrets(
            handshakeSecret: secret,
            transcriptHash: transcript.hash
        )
        handshakeSecret = secret
        handshakeTrafficSecrets = trafficSecrets
        phase = .handshakeKeysReady
        return trafficSecrets
    }

    @discardableResult
    public mutating func deriveApplicationTrafficSecrets() throws -> TLS13ApplicationTrafficSecrets {
        try ensureOpen()
        guard let handshakeSecret else {
            throw TLSQUICConnectionStateError.handshakeKeysNotReady
        }

        let secret = try TLS13KeyAgreement.masterSecret(handshakeSecret: handshakeSecret)
        let trafficSecrets = try TLS13KeyAgreement.applicationTrafficSecrets(
            masterSecret: secret,
            transcriptHash: transcript.hash
        )
        masterSecret = secret
        applicationTrafficSecrets = trafficSecrets
        keyUpdateGeneration = 0
        phase = .applicationKeysReady
        return trafficSecrets
    }

    @discardableResult
    public mutating func updateApplicationTrafficSecrets() throws -> TLS13ApplicationTrafficSecrets {
        try ensureOpen()
        guard let applicationTrafficSecrets else {
            _ = closeTransport(
                error: .keyUpdateError,
                frameType: nil,
                reason: "key update before application traffic secrets"
            )
            throw TLSQUICConnectionStateError.applicationKeysNotReady
        }

        do {
            let updated = TLS13ApplicationTrafficSecrets(
                clientApplicationTrafficSecret: try TLS13KeyAgreement.nextApplicationTrafficSecret(
                    applicationTrafficSecrets.clientApplicationTrafficSecret
                ),
                serverApplicationTrafficSecret: try TLS13KeyAgreement.nextApplicationTrafficSecret(
                    applicationTrafficSecrets.serverApplicationTrafficSecret
                )
            )
            guard keyUpdateGeneration < UInt64.max else {
                _ = closeTransport(error: .keyUpdateError, frameType: nil, reason: "key update generation exhausted")
                throw QUICCodecError.valueOutOfRange("key update generation exhausted")
            }
            self.applicationTrafficSecrets = updated
            keyUpdateGeneration += 1
            return updated
        } catch {
            _ = closeTransport(error: .keyUpdateError, frameType: nil, reason: "key update failed")
            throw error
        }
    }

    public mutating func openStream(
        id: UInt64,
        maxSendOffset: UInt64,
        maxReceiveOffset: UInt64
    ) throws {
        try ensureOpen()
        streams[id] = QUICStreamState(
            id: id,
            localRole: role,
            maxSendOffset: maxSendOffset,
            maxReceiveOffset: maxReceiveOffset
        )
    }

    @discardableResult
    public mutating func receiveStreamFrame(_ frame: QUICFrame) throws -> Data {
        try ensureOpen()
        guard case .stream(let streamID, _, _, _) = frame else {
            throw TLSQUICConnectionStateError.expectedStreamFrame
        }
        guard var stream = streams[streamID] else {
            throw TLSQUICConnectionStateError.unknownStream(streamID)
        }
        try closeIfFrameExceedsFinalSize(frame, stream: stream)

        do {
            let data = try stream.receive(frame)
            streams[streamID] = stream
            return data
        } catch let stateError as QUICStateError {
            closeDueToStreamError(stateError)
            throw stateError
        }
    }

    public mutating func resetStream(streamID: UInt64, applicationErrorCode: UInt64) throws -> QUICFrame {
        try ensureOpen()
        guard var stream = streams[streamID] else {
            throw TLSQUICConnectionStateError.unknownStream(streamID)
        }
        let frame = stream.reset(applicationErrorCode: applicationErrorCode)
        streams[streamID] = stream
        return frame
    }

    @discardableResult
    public mutating func closeApplication(errorCode: UInt64, reason: String) -> QUICFrame {
        if let closeFrame = closeState.closeFrame {
            return closeFrame
        }
        phase = .closed
        return closeState.closeApplication(errorCode: errorCode, reason: reason)
    }

    @discardableResult
    public mutating func closeTransport(
        error: QUICTransportErrorCode,
        frameType: UInt64?,
        reason: String
    ) -> QUICFrame {
        if let closeFrame = closeState.closeFrame {
            return closeFrame
        }
        phase = .closed
        return closeState.closeTransport(error: error, frameType: frameType, reason: reason)
    }

    private func ensureOpen() throws {
        guard !closeState.isClosed else {
            throw TLSQUICConnectionStateError.connectionClosed
        }
    }

    private mutating func closeDueToStreamError(_ error: QUICStateError) {
        switch error {
        case .flowControlViolation:
            _ = closeTransport(error: .flowControlError, frameType: nil, reason: error.description)
        case .streamStateViolation(let message) where message.contains("final size"):
            _ = closeTransport(error: .finalSizeError, frameType: nil, reason: error.description)
        case .streamStateViolation:
            _ = closeTransport(error: .streamStateError, frameType: nil, reason: error.description)
        default:
            _ = closeTransport(error: .protocolViolation, frameType: nil, reason: error.description)
        }
    }

    private mutating func closeIfFrameExceedsFinalSize(_ frame: QUICFrame, stream: QUICStreamState) throws {
        guard
            let finalReceiveSize = stream.finalReceiveSize,
            case .stream(_, let offset, _, let data) = frame
        else {
            return
        }

        let frameOffset = offset ?? 0
        let (attempted, overflow) = frameOffset.addingReportingOverflow(UInt64(data.count))
        let error: QUICStateError?
        if overflow {
            error = .streamStateViolation("STREAM data exceeds final size")
        } else if attempted > finalReceiveSize {
            error = .streamStateViolation("STREAM data exceeds final size")
        } else {
            error = nil
        }

        if let error {
            closeDueToStreamError(error)
            throw error
        }
    }
}
