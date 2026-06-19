import Foundation

public enum QUICStateError: Error, Equatable, CustomStringConvertible, Sendable {
    case invalidConnectionIDLength(Int)
    case invalidStatelessResetTokenLength(Int)
    case invalidRetirePriorTo(sequence: UInt64, retirePriorTo: UInt64)
    case connectionIDLimitExceeded(Int)
    case unknownConnectionIDSequence(UInt64)
    case inconsistentConnectionID(UInt64)
    case invalidAckFrame
    case flowControlViolation(limit: UInt64, attempted: UInt64)
    case streamStateViolation(String)
    case datagramTooLarge(limit: Int, attempted: Int)
    case connectionClosed
    case idleTimeout

    public var description: String {
        switch self {
        case .invalidConnectionIDLength(let length):
            "invalid connection ID length: \(length)"
        case .invalidStatelessResetTokenLength(let length):
            "invalid stateless reset token length: \(length)"
        case .invalidRetirePriorTo(let sequence, let retirePriorTo):
            "retire_prior_to \(retirePriorTo) exceeds sequence \(sequence)"
        case .connectionIDLimitExceeded(let limit):
            "active connection ID limit exceeded: \(limit)"
        case .unknownConnectionIDSequence(let sequence):
            "unknown connection ID sequence: \(sequence)"
        case .inconsistentConnectionID(let sequence):
            "inconsistent connection ID for sequence: \(sequence)"
        case .invalidAckFrame:
            "invalid ACK frame"
        case .flowControlViolation(let limit, let attempted):
            "flow control violation: attempted \(attempted), limit \(limit)"
        case .streamStateViolation(let message):
            "stream state violation: \(message)"
        case .datagramTooLarge(let limit, let attempted):
            "datagram too large: attempted \(attempted), limit \(limit)"
        case .connectionClosed:
            "connection closed"
        case .idleTimeout:
            "idle timeout"
        }
    }
}

public enum QUICEndpointRole: UInt8, Equatable, Sendable {
    case client = 0
    case server = 1
}

public struct QUICVersionPolicy: Equatable, Sendable {
    public static let quicV1: UInt32 = 0x0000_0001

    public var supportedVersions: [UInt32]

    public init(supportedVersions: [UInt32] = [QUICVersionPolicy.quicV1]) {
        self.supportedVersions = supportedVersions
    }

    public func select(offeredVersion: UInt32) -> UInt32? {
        supportedVersions.contains(offeredVersion) ? offeredVersion : nil
    }

    public func shouldSendVersionNegotiation(for offeredVersion: UInt32) -> Bool {
        select(offeredVersion: offeredVersion) == nil
    }
}

public struct QUICConnectionID: Equatable, Sendable {
    public var sequence: UInt64
    public var connectionID: Data
    public var statelessResetToken: Data?

    public init(sequence: UInt64, connectionID: Data, statelessResetToken: Data? = nil) throws {
        guard connectionID.count <= 20 else {
            throw QUICStateError.invalidConnectionIDLength(connectionID.count)
        }
        if let statelessResetToken {
            guard statelessResetToken.count == 16 else {
                throw QUICStateError.invalidStatelessResetTokenLength(statelessResetToken.count)
            }
        }

        self.sequence = sequence
        self.connectionID = connectionID
        self.statelessResetToken = statelessResetToken
    }
}

public struct QUICConnectionIDStore: Equatable, Sendable {
    public let activeConnectionIDLimit: Int
    public private(set) var activeDestinationSequence: UInt64
    public private(set) var active: [UInt64: QUICConnectionID]
    public private(set) var retiredSequences: Set<UInt64>

    public init(
        initialConnectionID: Data,
        activeConnectionIDLimit: Int = 8
    ) throws {
        guard activeConnectionIDLimit >= 2 else {
            throw QUICStateError.connectionIDLimitExceeded(activeConnectionIDLimit)
        }

        self.activeConnectionIDLimit = activeConnectionIDLimit
        self.activeDestinationSequence = 0
        self.active = [
            0: try QUICConnectionID(sequence: 0, connectionID: initialConnectionID)
        ]
        self.retiredSequences = []
    }

    public var activeConnectionIDs: [QUICConnectionID] {
        active.values.sorted { $0.sequence < $1.sequence }
    }

    public mutating func applyNewConnectionID(
        sequence: UInt64,
        retirePriorTo: UInt64,
        connectionID: Data,
        statelessResetToken: Data
    ) throws -> [QUICFrame] {
        guard retirePriorTo <= sequence else {
            throw QUICStateError.invalidRetirePriorTo(sequence: sequence, retirePriorTo: retirePriorTo)
        }

        var retireFrames: [QUICFrame] = []
        if let existing = active[sequence] {
            let incoming = try QUICConnectionID(
                sequence: sequence,
                connectionID: connectionID,
                statelessResetToken: statelessResetToken
            )
            guard existing == incoming else {
                throw QUICStateError.inconsistentConnectionID(sequence)
            }
        } else if !retiredSequences.contains(sequence) {
            active[sequence] = try QUICConnectionID(
                sequence: sequence,
                connectionID: connectionID,
                statelessResetToken: statelessResetToken
            )
        }

        for activeSequence in active.keys.sorted() where activeSequence < retirePriorTo {
            try retire(activeSequence, appendingTo: &retireFrames)
        }

        while active.count > activeConnectionIDLimit {
            guard let oldest = active.keys.sorted().first(where: { $0 != activeDestinationSequence }) else {
                throw QUICStateError.connectionIDLimitExceeded(activeConnectionIDLimit)
            }
            try retire(oldest, appendingTo: &retireFrames)
        }

        return retireFrames
    }

    public mutating func retire(sequence: UInt64) throws -> QUICFrame {
        if retiredSequences.contains(sequence) {
            return .retireConnectionID(sequence: sequence)
        }
        var frames: [QUICFrame] = []
        try retire(sequence, appendingTo: &frames)
        guard let frame = frames.first else {
            throw QUICStateError.unknownConnectionIDSequence(sequence)
        }
        return frame
    }

    public mutating func useDestinationConnectionID(sequence: UInt64) throws -> QUICConnectionID {
        guard let connectionID = active[sequence] else {
            throw QUICStateError.unknownConnectionIDSequence(sequence)
        }
        activeDestinationSequence = sequence
        return connectionID
    }

    private mutating func retire(_ sequence: UInt64, appendingTo frames: inout [QUICFrame]) throws {
        guard active.removeValue(forKey: sequence) != nil else {
            if retiredSequences.contains(sequence) {
                return
            }
            throw QUICStateError.unknownConnectionIDSequence(sequence)
        }
        retiredSequences.insert(sequence)
        if activeDestinationSequence == sequence {
            activeDestinationSequence = active.keys.sorted().first ?? sequence
        }
        frames.append(.retireConnectionID(sequence: sequence))
    }
}

public enum QUICPacketNumberSpace: UInt8, CaseIterable, Equatable, Sendable {
    case initial
    case handshake
    case applicationData
}

public struct QUICAckTracker: Equatable, Sendable {
    public let packetNumberSpace: QUICPacketNumberSpace
    public var ackDelayExponent: UInt8
    public private(set) var receivedPacketNumbers: Set<UInt64>
    public private(set) var largestReceived: UInt64?
    public private(set) var largestAckElicitingReceiveTimeMicros: UInt64?

    public init(packetNumberSpace: QUICPacketNumberSpace, ackDelayExponent: UInt8 = 3) {
        self.packetNumberSpace = packetNumberSpace
        self.ackDelayExponent = ackDelayExponent
        self.receivedPacketNumbers = []
        self.largestReceived = nil
        self.largestAckElicitingReceiveTimeMicros = nil
    }

    @discardableResult
    public mutating func recordReceived(
        packetNumber: UInt64,
        nowMicros: UInt64,
        ackEliciting: Bool = true
    ) -> Bool {
        let inserted = receivedPacketNumbers.insert(packetNumber).inserted
        if inserted && shouldUpdateLargestReceived(packetNumber) {
            largestReceived = packetNumber
            if ackEliciting {
                largestAckElicitingReceiveTimeMicros = nowMicros
            }
        }
        return inserted
    }

    private func shouldUpdateLargestReceived(_ packetNumber: UInt64) -> Bool {
        guard let largestReceived else {
            return true
        }
        return packetNumber > largestReceived
    }

    public func makeAckFrame(nowMicros: UInt64) -> QUICFrame? {
        guard let largestReceived else {
            return nil
        }

        let ranges = contiguousRangesDescending(Array(receivedPacketNumbers).sorted(by: >))
        guard let first = ranges.first else {
            return nil
        }

        let firstAckRange = first.high - first.low
        var extraRanges: [QUICAckRange] = []
        var previousLow = first.low
        for range in ranges.dropFirst() {
            let gap = previousLow - range.high - 2
            extraRanges.append(QUICAckRange(gap: gap, length: range.high - range.low))
            previousLow = range.low
        }

        let delayMicros = largestAckElicitingReceiveTimeMicros.map { nowMicros >= $0 ? nowMicros - $0 : 0 } ?? 0
        let divisor = ackDelayExponent >= 63 ? UInt64.max : UInt64(1) << UInt64(ackDelayExponent)
        return .ack(
            largestAcknowledged: largestReceived,
            ackDelay: delayMicros / divisor,
            firstAckRange: firstAckRange,
            ranges: extraRanges
        )
    }

    public static func acknowledgedPacketNumbers(from frame: QUICFrame) throws -> Set<UInt64> {
        guard case .ack(let largest, _, let firstRange, let ranges) = frame else {
            throw QUICStateError.invalidAckFrame
        }
        guard largest >= firstRange else {
            throw QUICStateError.invalidAckFrame
        }

        var numbers: Set<UInt64> = []
        var rangeHigh = largest
        var rangeLow = largest - firstRange
        insertClosedRange(low: rangeLow, high: rangeHigh, into: &numbers)

        for range in ranges {
            guard range.gap <= UInt64.max - 2 else {
                throw QUICStateError.invalidAckFrame
            }
            let encodedGap = range.gap + 2
            guard rangeLow >= encodedGap else {
                throw QUICStateError.invalidAckFrame
            }
            rangeHigh = rangeLow - encodedGap
            guard rangeHigh >= range.length else {
                throw QUICStateError.invalidAckFrame
            }
            rangeLow = rangeHigh - range.length
            insertClosedRange(low: rangeLow, high: rangeHigh, into: &numbers)
        }

        return numbers
    }
}

public struct QUICSentPacket: Equatable, Sendable {
    public var packetNumberSpace: QUICPacketNumberSpace
    public var packetNumber: UInt64
    public var sentTimeMicros: UInt64
    public var bytes: UInt64
    public var frames: [QUICFrame]
    public var ackEliciting: Bool

    public init(
        packetNumberSpace: QUICPacketNumberSpace,
        packetNumber: UInt64,
        sentTimeMicros: UInt64,
        bytes: UInt64,
        frames: [QUICFrame],
        ackEliciting: Bool = true
    ) {
        self.packetNumberSpace = packetNumberSpace
        self.packetNumber = packetNumber
        self.sentTimeMicros = sentTimeMicros
        self.bytes = bytes
        self.frames = frames
        self.ackEliciting = ackEliciting
    }
}

public struct QUICAckProcessingResult: Equatable, Sendable {
    public var acknowledged: [QUICSentPacket]
    public var lost: [QUICSentPacket]
    public var retransmittableFrames: [QUICFrame]

    public init(acknowledged: [QUICSentPacket], lost: [QUICSentPacket], retransmittableFrames: [QUICFrame]) {
        self.acknowledged = acknowledged
        self.lost = lost
        self.retransmittableFrames = retransmittableFrames
    }
}

public struct QUICLossRecovery: Equatable, Sendable {
    public var packetThreshold: UInt64
    public private(set) var sentPackets: [QUICPacketNumberSpace: [UInt64: QUICSentPacket]]

    public init(packetThreshold: UInt64 = 3) {
        self.packetThreshold = packetThreshold
        self.sentPackets = [:]
    }

    public mutating func recordSent(_ packet: QUICSentPacket) {
        sentPackets[packet.packetNumberSpace, default: [:]][packet.packetNumber] = packet
    }

    public mutating func processAck(
        _ ackFrame: QUICFrame,
        in packetNumberSpace: QUICPacketNumberSpace
    ) throws -> QUICAckProcessingResult {
        let acknowledgedNumbers = try QUICAckTracker.acknowledgedPacketNumbers(from: ackFrame)
        guard !acknowledgedNumbers.isEmpty else {
            throw QUICStateError.invalidAckFrame
        }
        let largestAcknowledged = acknowledgedNumbers.max() ?? 0

        var acknowledged: [QUICSentPacket] = []
        var lost: [QUICSentPacket] = []
        var packets = sentPackets[packetNumberSpace, default: [:]]

        for packetNumber in acknowledgedNumbers.sorted() {
            if let packet = packets.removeValue(forKey: packetNumber) {
                acknowledged.append(packet)
            }
        }

        for packetNumber in packets.keys.sorted() where isPacketThresholdLost(
            packetNumber: packetNumber,
            largestAcknowledged: largestAcknowledged
        ) {
            if let packet = packets.removeValue(forKey: packetNumber) {
                lost.append(packet)
            }
        }

        sentPackets[packetNumberSpace] = packets
        let retransmittableFrames = lost.flatMap { $0.frames.filter(\.isRetransmittable) }
        return QUICAckProcessingResult(
            acknowledged: acknowledged,
            lost: lost,
            retransmittableFrames: retransmittableFrames
        )
    }

    private func isPacketThresholdLost(packetNumber: UInt64, largestAcknowledged: UInt64) -> Bool {
        guard packetNumber <= largestAcknowledged else {
            return false
        }
        return largestAcknowledged - packetNumber >= packetThreshold
    }
}

public struct QUICCongestionController: Equatable, Sendable {
    public let maxDatagramSize: UInt64
    public let minimumWindow: UInt64
    public private(set) var congestionWindow: UInt64
    public private(set) var bytesInFlight: UInt64

    public init(maxDatagramSize: UInt64 = 1_200) {
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = maxDatagramSize * 2
        self.congestionWindow = max(maxDatagramSize * 10, 14_720)
        self.bytesInFlight = 0
    }

    public func canSend(bytes: UInt64) -> Bool {
        let (attempted, overflow) = bytesInFlight.addingReportingOverflow(bytes)
        return !overflow && attempted <= congestionWindow
    }

    public mutating func onPacketSent(bytes: UInt64, ackEliciting: Bool = true) {
        guard ackEliciting else {
            return
        }
        let (newBytesInFlight, overflow) = bytesInFlight.addingReportingOverflow(bytes)
        bytesInFlight = overflow ? UInt64.max : newBytesInFlight
    }

    public mutating func onPacketAcknowledged(bytes: UInt64) {
        bytesInFlight = bytes > bytesInFlight ? 0 : bytesInFlight - bytes
        let (newWindow, overflow) = congestionWindow.addingReportingOverflow(min(bytes, maxDatagramSize))
        congestionWindow = overflow ? UInt64.max : newWindow
    }

    public mutating func onPacketsLost(bytes: UInt64) {
        bytesInFlight = bytes > bytesInFlight ? 0 : bytesInFlight - bytes
        congestionWindow = max(congestionWindow / 2, minimumWindow)
    }
}

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
        try ensureCanReceive()
        guard case .stream(let streamID, let offset, let fin, let data) = frame, streamID == id else {
            throw QUICStateError.streamStateViolation("expected STREAM frame for stream \(id)")
        }
        let frameOffset = offset ?? 0
        guard frameOffset == receiveOffset else {
            throw QUICStateError.streamStateViolation("out-of-order STREAM data is not accepted by this deterministic core")
        }
        let (attempted, receiveOverflow) = frameOffset.addingReportingOverflow(UInt64(data.count))
        guard !receiveOverflow else {
            throw QUICStateError.flowControlViolation(limit: maxReceiveOffset, attempted: UInt64.max)
        }
        guard attempted <= maxReceiveOffset else {
            throw QUICStateError.flowControlViolation(limit: maxReceiveOffset, attempted: attempted)
        }
        if let finalReceiveSize, attempted > finalReceiveSize {
            throw QUICStateError.streamStateViolation("STREAM data exceeds final size")
        }

        receiveOffset = attempted
        if fin {
            if let finalReceiveSize, finalReceiveSize != attempted {
                throw QUICStateError.streamStateViolation("inconsistent final stream size")
            }
            finalReceiveSize = attempted
            receiveClosed = true
        }
        return data
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

    private func ensureCanSend() throws {
        guard !sendClosed && !resetSent else {
            throw QUICStateError.streamStateViolation("send side is closed")
        }
        if direction == .unidirectional && localRole != endpointRole(for: initiator) {
            throw QUICStateError.streamStateViolation("cannot send on peer-initiated unidirectional stream")
        }
    }

    private func ensureCanReceive() throws {
        guard !receiveClosed && !stopSendingSent else {
            throw QUICStateError.streamStateViolation("receive side is closed")
        }
        if direction == .unidirectional && localRole == endpointRole(for: initiator) {
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

public enum QUICTransportErrorCode: UInt64, Equatable, Sendable {
    case noError = 0x00
    case internalError = 0x01
    case connectionRefused = 0x02
    case flowControlError = 0x03
    case streamLimitError = 0x04
    case streamStateError = 0x05
    case finalSizeError = 0x06
    case frameEncodingError = 0x07
    case transportParameterError = 0x08
    case connectionIDLimitError = 0x09
    case protocolViolation = 0x0a
    case invalidToken = 0x0b
    case applicationError = 0x0c
    case cryptoBufferExceeded = 0x0d
    case keyUpdateError = 0x0e
    case aeadLimitReached = 0x0f
    case noViablePath = 0x10
}

public struct QUICConnectionCloseState: Equatable, Sendable {
    public var idleTimeoutMicros: UInt64
    public private(set) var lastActivityMicros: UInt64
    public private(set) var closeFrame: QUICFrame?

    public init(idleTimeoutMicros: UInt64, nowMicros: UInt64 = 0) {
        self.idleTimeoutMicros = idleTimeoutMicros
        self.lastActivityMicros = nowMicros
        self.closeFrame = nil
    }

    public var isClosed: Bool {
        closeFrame != nil
    }

    public mutating func recordActivity(nowMicros: UInt64) throws {
        guard closeFrame == nil else {
            throw QUICStateError.connectionClosed
        }
        lastActivityMicros = nowMicros
    }

    public mutating func checkIdleTimeout(nowMicros: UInt64) throws -> Bool {
        guard closeFrame == nil else {
            throw QUICStateError.connectionClosed
        }
        guard nowMicros >= lastActivityMicros else {
            return false
        }
        if nowMicros - lastActivityMicros >= idleTimeoutMicros {
            closeFrame = .connectionClose(
                errorCode: QUICTransportErrorCode.noError.rawValue,
                frameType: nil,
                reason: Data("idle timeout".utf8)
            )
            return true
        }
        return false
    }

    public mutating func closeTransport(
        error: QUICTransportErrorCode,
        frameType: UInt64?,
        reason: String
    ) -> QUICFrame {
        let frame = QUICFrame.connectionClose(
            errorCode: error.rawValue,
            frameType: frameType,
            reason: Data(reason.utf8)
        )
        closeFrame = frame
        return frame
    }

    public mutating func closeApplication(errorCode: UInt64, reason: String) -> QUICFrame {
        let frame = QUICFrame.connectionClose(
            errorCode: errorCode,
            frameType: nil,
            reason: Data(reason.utf8)
        )
        closeFrame = frame
        return frame
    }
}

extension QUICFrame {
    public var isRetransmittable: Bool {
        switch self {
        case .padding, .ack, .connectionClose:
            false
        default:
            true
        }
    }
}

private func endpointRole(for initiator: QUICStreamInitiator) -> QUICEndpointRole {
    switch initiator {
    case .client:
        .client
    case .server:
        .server
    }
}

private func contiguousRangesDescending(_ numbers: [UInt64]) -> [(high: UInt64, low: UInt64)] {
    guard var high = numbers.first else {
        return []
    }

    var low = high
    var ranges: [(high: UInt64, low: UInt64)] = []
    for number in numbers.dropFirst() {
        if low > 0 && number == low - 1 {
            low = number
        } else {
            ranges.append((high: high, low: low))
            high = number
            low = number
        }
    }
    ranges.append((high: high, low: low))
    return ranges
}

private func insertClosedRange(low: UInt64, high: UInt64, into numbers: inout Set<UInt64>) {
    var packetNumber = low
    while packetNumber <= high {
        numbers.insert(packetNumber)
        if packetNumber == UInt64.max {
            break
        }
        packetNumber += 1
    }
}
