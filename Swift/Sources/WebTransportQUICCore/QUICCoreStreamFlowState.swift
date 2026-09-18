import Foundation

public enum QUICStreamInitiator: UInt8, Equatable, Sendable {
    case client = 0
    case server = 1
}

public enum QUICStreamID {
    public static func direction(of streamID: UInt64) -> QUICStreamDirection {
        (streamID & 0x02) == 0 ? .bidirectional : .unidirectional
    }

    public static func initiator(of streamID: UInt64) -> QUICStreamInitiator {
        (streamID & 0x01) == 0 ? .client : .server
    }

    public static func make(index: UInt64, direction: QUICStreamDirection, initiator: QUICStreamInitiator) -> UInt64 {
        (index << 2) | (UInt64(direction.rawValue) << 1) | UInt64(initiator.rawValue)
    }
}

public struct QUICFlowController: Equatable, Sendable {
    public private(set) var maximumData: UInt64
    public private(set) var sentData: UInt64
    public private(set) var receivedData: UInt64

    public init(maximumData: UInt64, sentData: UInt64 = 0, receivedData: UInt64 = 0) {
        self.maximumData = maximumData
        self.sentData = sentData
        self.receivedData = receivedData
    }

    public var availableSendBytes: UInt64 {
        maximumData > sentData ? maximumData - sentData : 0
    }

    public mutating func reserveSendBytes(_ count: UInt64) throws {
        let (attempted, overflow) = sentData.addingReportingOverflow(count)
        guard !overflow else {
            throw QUICStateError.flowControlViolation(limit: maximumData, attempted: UInt64.max)
        }
        guard attempted <= maximumData else {
            throw QUICStateError.flowControlViolation(limit: maximumData, attempted: attempted)
        }
        sentData = attempted
    }

    public mutating func receiveBytes(_ count: UInt64) throws {
        let (attempted, overflow) = receivedData.addingReportingOverflow(count)
        guard !overflow else {
            throw QUICStateError.flowControlViolation(limit: maximumData, attempted: UInt64.max)
        }
        guard attempted <= maximumData else {
            throw QUICStateError.flowControlViolation(limit: maximumData, attempted: attempted)
        }
        receivedData = attempted
    }

    public mutating func increaseMaximumData(to newMaximum: UInt64) {
        maximumData = max(maximumData, newMaximum)
    }

    public func maxDataFrame() -> QUICFrame {
        .maxData(maximumData)
    }
}

public struct QUICStreamState: Equatable, Sendable {
    public let id: UInt64
    public let localRole: QUICEndpointRole
    public let direction: QUICStreamDirection
    public let initiator: QUICStreamInitiator
    public private(set) var maxSendOffset: UInt64
    public private(set) var maxReceiveOffset: UInt64
    public private(set) var sendOffset: UInt64
    public private(set) var receiveOffset: UInt64
    public private(set) var finalReceiveSize: UInt64?
    public private(set) var sendClosed: Bool
    public private(set) var receiveClosed: Bool
    public private(set) var resetSent: Bool
    public private(set) var stopSendingSent: Bool

    public init(
        id: UInt64,
        localRole: QUICEndpointRole,
        maxSendOffset: UInt64,
        maxReceiveOffset: UInt64
    ) {
        self.id = id
        self.localRole = localRole
        self.direction = QUICStreamID.direction(of: id)
        self.initiator = QUICStreamID.initiator(of: id)
        self.maxSendOffset = maxSendOffset
        self.maxReceiveOffset = maxReceiveOffset
        self.sendOffset = 0
        self.receiveOffset = 0
        self.finalReceiveSize = nil
        self.sendClosed = false
        self.receiveClosed = false
        self.resetSent = false
        self.stopSendingSent = false
    }

    public mutating func send(data: Data, fin: Bool = false, maxFrameBytes: Int? = nil) throws -> QUICFrame {
        try ensureCanSend()
        if let maxFrameBytes, data.count > maxFrameBytes {
            throw QUICStateError.streamStateViolation("STREAM frame data exceeds maxFrameBytes")
        }
        let (attempted, sendOverflow) = sendOffset.addingReportingOverflow(UInt64(data.count))
        guard !sendOverflow else {
            throw QUICStateError.flowControlViolation(limit: maxSendOffset, attempted: UInt64.max)
        }
        guard attempted <= maxSendOffset else {
            throw QUICStateError.flowControlViolation(limit: maxSendOffset, attempted: attempted)
        }

        let frame = QUICFrame.stream(id: id, offset: sendOffset, fin: fin, data: data)
        sendOffset = attempted
        if fin {
            sendClosed = true
        }
        return frame
    }

    @discardableResult
    public mutating func receive(_ frame: QUICFrame) throws -> Data {
        switch frame {
        case .resetStream(let streamID, _, let finalSize):
            guard streamID == id else {
                throw QUICStateError.streamStateViolation("expected STREAM frame for stream \(id)")
            }
            try receiveResetStream(finalSize: finalSize)
            return Data()
        case .stream(let streamID, let offset, let fin, let data):
            guard streamID == id else {
                throw QUICStateError.streamStateViolation("expected STREAM frame for stream \(id)")
            }
            return try receiveStream(offset: offset, fin: fin, data: data)
        default:
            throw QUICStateError.streamStateViolation("expected STREAM frame for stream \(id)")
        }
    }

    /// One STREAM frame's payload, in the order RFC 9000 section 4.5 requires.
    ///
    /// Both final-size rules are checked before the receive-closed gate. The FIN that
    /// records the final size closes the receive half in the same step, so a check placed
    /// after that gate can never observe a non-nil `finalReceiveSize`.
    private mutating func receiveStream(offset: UInt64?, fin: Bool, data: Data) throws -> Data {
        let frameOffset = offset ?? 0
        let (attempted, receiveOverflow) = frameOffset.addingReportingOverflow(UInt64(data.count))

        if let finalReceiveSize {
            guard !receiveOverflow, attempted <= finalReceiveSize else {
                throw QUICStateError.finalSizeViolation("STREAM data exceeds final size")
            }
            if fin, attempted != finalReceiveSize {
                throw QUICStateError.finalSizeViolation("inconsistent final stream size")
            }
        }

        try ensureCanReceive()
        guard !receiveOverflow else {
            throw QUICStateError.flowControlViolation(limit: maxReceiveOffset, attempted: UInt64.max)
        }
        guard frameOffset == receiveOffset else {
            throw QUICStateError.streamStateViolation("out-of-order STREAM data is not accepted")
        }
        guard attempted <= maxReceiveOffset else {
            throw QUICStateError.flowControlViolation(limit: maxReceiveOffset, attempted: attempted)
        }

        receiveOffset = attempted
        if fin {
            finalReceiveSize = attempted
            receiveClosed = true
        }
        return data
    }

    /// Records the Final Size carried by an inbound RESET_STREAM frame and closes
    /// the receive half (RFC 9000 sections 4.5 and 19.4).
    ///
    /// A RESET_STREAM is produced by the peer's send side, so for this endpoint it
    /// is the receive half's final size, and it is the only way that size becomes
    /// known when the peer resets without ever sending FIN. Once recorded the size
    /// cannot change, and it cannot be below the bytes already received.
    private mutating func receiveResetStream(finalSize: UInt64) throws {
        guard hasReceiveHalf else {
            throw QUICStateError.streamStateViolation(
                "cannot receive on locally initiated unidirectional stream")
        }
        guard finalSize >= receiveOffset else {
            throw QUICStateError.finalSizeViolation(
                "RESET_STREAM final size is below the bytes already received")
        }
        if let finalReceiveSize, finalReceiveSize != finalSize {
            throw QUICStateError.finalSizeViolation("inconsistent final stream size")
        }
        finalReceiveSize = finalSize
        receiveClosed = true
    }

    public mutating func applyMaxStreamData(_ maximum: UInt64) {
        maxSendOffset = max(maxSendOffset, maximum)
    }

    public mutating func increaseReceiveLimit(to maximum: UInt64) {
        maxReceiveOffset = max(maxReceiveOffset, maximum)
    }

    public func maxStreamDataFrame() -> QUICFrame {
        .maxStreamData(id: id, maximum: maxReceiveOffset)
    }

    public mutating func reset(applicationErrorCode: UInt64) -> QUICFrame {
        resetSent = true
        sendClosed = true
        return .resetStream(id: id, applicationErrorCode: applicationErrorCode, finalSize: sendOffset)
    }

    public mutating func stopSending(applicationErrorCode: UInt64) -> QUICFrame {
        stopSendingSent = true
        receiveClosed = true
        return .stopSending(id: id, applicationErrorCode: applicationErrorCode)
    }

    /// Whether this endpoint owns the stream's send half.
    ///
    /// RFC 9000 section 2.1: a bidirectional stream is owned in both
    /// directions by both endpoints, while a unidirectional stream is owned in
    /// its single direction by the endpoint that initiated it. Callers use this
    /// to decide whether a send-side signal (STREAM data, RESET_STREAM) may be
    /// produced at all, which is a different question from whether the send
    /// side is still open.
    public var hasSendHalf: Bool {
        direction == .bidirectional || localRole == endpointRole(for: initiator)
    }

    /// Whether this endpoint owns the stream's receive half.
    ///
    /// The mirror of ``hasSendHalf``: a unidirectional stream whose peer is the
    /// initiator can only be received from, so a receive-side signal
    /// (STOP_SENDING) must not be produced for the other form.
    public var hasReceiveHalf: Bool {
        direction == .bidirectional || localRole != endpointRole(for: initiator)
    }

    private func ensureCanSend() throws {
        guard !sendClosed && !resetSent else {
            throw QUICStateError.streamStateViolation("send side is closed")
        }
        guard hasSendHalf else {
            throw QUICStateError.streamStateViolation("cannot send on peer-initiated unidirectional stream")
        }
    }

    private func ensureCanReceive() throws {
        guard !receiveClosed && !stopSendingSent else {
            throw QUICStateError.streamStateViolation("receive side is closed")
        }
        guard hasReceiveHalf else {
            throw QUICStateError.streamStateViolation("cannot receive on locally initiated unidirectional stream")
        }
    }
}

public struct QUICDatagramQueue: Equatable, Sendable {
    public var maximumPayloadSize: Int
    public private(set) var receivedDatagrams: [Data]

    public init(maximumPayloadSize: Int) {
        self.maximumPayloadSize = maximumPayloadSize
        self.receivedDatagrams = []
    }

    public func makeDatagramFrame(_ data: Data) throws -> QUICFrame {
        guard data.count <= maximumPayloadSize else {
            throw QUICStateError.datagramTooLarge(limit: maximumPayloadSize, attempted: data.count)
        }
        return .datagram(data)
    }

    public mutating func receive(_ frame: QUICFrame) throws {
        guard case .datagram(let data) = frame else {
            throw QUICStateError.streamStateViolation("expected DATAGRAM frame")
        }
        guard data.count <= maximumPayloadSize else {
            throw QUICStateError.datagramTooLarge(limit: maximumPayloadSize, attempted: data.count)
        }
        receivedDatagrams.append(data)
    }

    public mutating func popReceived() -> Data? {
        receivedDatagrams.isEmpty ? nil : receivedDatagrams.removeFirst()
    }
}
