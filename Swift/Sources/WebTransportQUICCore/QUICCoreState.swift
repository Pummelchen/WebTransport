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
    /// A final-size rule was broken (RFC 9000 section 4.5).
    ///
    /// Kept separate from ``streamStateViolation(_:)`` so the FINAL_SIZE_ERROR
    /// versus STREAM_STATE_ERROR choice is made on the error case rather than on
    /// the wording of a message.
    case finalSizeViolation(String)
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
        case .finalSizeViolation(let message):
            "final size violation: \(message)"
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

    /// The largest `retire_prior_to` value seen.
    ///
    /// RFC 9000 section 19.15 makes every sequence below a received Retire Prior To
    /// permanently retired, and gives a later, smaller value no effect. Without
    /// remembering the high-water mark, a subsequent frame naming a sequence below it
    /// would be treated as new and re-activated, making a retired connection ID
    /// usable again.
    public private(set) var largestRetirePriorTo: UInt64 = 0

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
        if retirePriorTo > largestRetirePriorTo {
            largestRetirePriorTo = retirePriorTo
        }

        var retireFrames: [QUICFrame] = []
        // A sequence below the watermark never becomes usable, even if the peer names
        // it later with a smaller Retire Prior To. Recording it as retired is enough to
        // keep it out of `active`; a RETIRE_CONNECTION_ID frame is only owed if this
        // endpoint actually held that connection ID, and the peer already told us to
        // stop using it. `retire` refuses an unknown sequence, so mark it directly.
        if sequence < largestRetirePriorTo {
            active.removeValue(forKey: sequence)
            retiredSequences.insert(sequence)
            // RFC 9000 section 19.15: an endpoint receiving a sequence below a Retire
            // Prior To it has already seen "MUST send a corresponding
            // RETIRE_CONNECTION_ID frame ... unless it has already done so". The frame is
            // owed even though this endpoint may never have held the connection ID.
            retireFrames.append(.retireConnectionID(sequence: sequence))
            return retireFrames
        }
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
    public static let maximumExpandedAckedPacketNumbers = 16_384

    /// How many packet numbers below the largest received one stay individually
    /// tracked.
    ///
    /// Something has to bound this. A connection receives packets for as long as
    /// it lives, and retaining every number seen would grow without limit and make
    /// acknowledgement generation walk the entire history on each call, so the
    /// cost of acknowledging would rise with the age of the connection rather than
    /// with what is being acknowledged. RFC 9000 section 13.2.4 anticipates exactly
    /// this and permits an endpoint to limit what it tracks.
    ///
    /// The window doubles as the replay boundary: a packet number below it is
    /// refused rather than forgotten, so dropping old numbers cannot let an old
    /// packet be accepted a second time.
    public static let maximumTrackedReceivedPacketNumbers = 8_192

    public let packetNumberSpace: QUICPacketNumberSpace
    public var ackDelayExponent: UInt8
    public private(set) var receivedPacketNumbers: Set<UInt64>
    public private(set) var largestReceived: UInt64?
    public private(set) var largestAckElicitingReceiveTimeMicros: UInt64?

    /// Packet numbers below this are no longer tracked and are refused on sight.
    public private(set) var discardedBelow: UInt64

    /// The tracked numbers as descending, non-overlapping, non-adjacent ranges.
    ///
    /// Maintained as numbers arrive so that ``makeAckFrame(nowMicros:)`` can emit
    /// an acknowledgement without copying and sorting the whole tracked set: an
    /// endpoint builds an ACK per ACK-eliciting packet, and ordering 16,384
    /// numbers per call made acknowledgement cost grow with the window rather
    /// than with what is being acknowledged. Insertion extends the nearest range
    /// in place, which is O(1) for the in-order arrival that dominates, and only
    /// the amortised window trim rebuilds the list.
    private var receivedRangesDescending: [ClosedRange<UInt64>]

    public init(packetNumberSpace: QUICPacketNumberSpace, ackDelayExponent: UInt8 = 3) {
        self.packetNumberSpace = packetNumberSpace
        self.ackDelayExponent = ackDelayExponent
        self.discardedBelow = 0
        self.receivedPacketNumbers = []
        self.largestReceived = nil
        self.largestAckElicitingReceiveTimeMicros = nil
        self.receivedRangesDescending = []
    }

    @discardableResult
    public mutating func recordReceived(
        packetNumber: UInt64,
        nowMicros: UInt64,
        ackEliciting: Bool = true
    ) -> Bool {
        // Below the window this tracker still remembers, so it cannot be
        // distinguished from one already seen. Refusing rather than accepting is
        // the safe direction: it keeps an old packet from being processed twice.
        guard packetNumber >= discardedBelow else {
            return false
        }

        let inserted = receivedPacketNumbers.insert(packetNumber).inserted
        if inserted {
            insertReceivedRange(packetNumber)
            if shouldUpdateLargestReceived(packetNumber) {
                largestReceived = packetNumber
                if ackEliciting {
                    largestAckElicitingReceiveTimeMicros = nowMicros
                }
            }
        }
        if inserted {
            discardOutsideTrackingWindow()
        }
        return inserted
    }

    /// Adds one packet number to ``receivedRangesDescending``.
    ///
    /// The list stays sorted high to low with no two ranges adjacent, so
    /// ``makeAckFrame(nowMicros:)`` can translate it directly into ACK ranges.
    private mutating func insertReceivedRange(_ packetNumber: UInt64) {
        guard !receivedRangesDescending.isEmpty else {
            receivedRangesDescending.append(packetNumber...packetNumber)
            return
        }
        // In-order arrival is the common case and costs O(1): extend the newest
        // range, or open a new one above it.
        if let highest = receivedRangesDescending.first, packetNumber > highest.upperBound {
            if highest.upperBound != UInt64.max, packetNumber == highest.upperBound + 1 {
                receivedRangesDescending[0] = highest.lowerBound...packetNumber
            } else {
                receivedRangesDescending.insert(packetNumber...packetNumber, at: 0)
            }
            return
        }
        if let lowest = receivedRangesDescending.last, packetNumber < lowest.lowerBound {
            if packetNumber + 1 == lowest.lowerBound {
                receivedRangesDescending[receivedRangesDescending.count - 1] = packetNumber...lowest.upperBound
            } else {
                receivedRangesDescending.append(packetNumber...packetNumber)
            }
            return
        }

        // A gap in the middle: find the first range whose lower bound is at or
        // below the number. Ranges descend, so that range is the one below the
        // insertion point and the one before it is the range above.
        var low = 0
        var high = receivedRangesDescending.count
        while low < high {
            let mid = low + (high - low) / 2
            if receivedRangesDescending[mid].lowerBound > packetNumber {
                low = mid + 1
            } else {
                high = mid
            }
        }
        guard low < receivedRangesDescending.count else {
            // The end cases above make this unreachable, but a number the set has
            // accepted must never be dropped from the range list.
            receivedRangesDescending.append(packetNumber...packetNumber)
            return
        }
        if receivedRangesDescending[low].contains(packetNumber) {
            return
        }

        let aboveIndex = low - 1
        let touchesAbove =
            low > 0 && receivedRangesDescending[aboveIndex].lowerBound > 0
            && packetNumber == receivedRangesDescending[aboveIndex].lowerBound - 1
        let belowUpperBound = receivedRangesDescending[low].upperBound
        let touchesBelow = belowUpperBound != UInt64.max && packetNumber == belowUpperBound + 1

        if touchesAbove && touchesBelow {
            // The range below supplies the lower bound, the one above the upper.
            receivedRangesDescending[aboveIndex] =
                receivedRangesDescending[low].lowerBound...receivedRangesDescending[aboveIndex].upperBound
            receivedRangesDescending.remove(at: low)
        } else if touchesAbove {
            receivedRangesDescending[aboveIndex] =
                packetNumber...receivedRangesDescending[aboveIndex].upperBound
        } else if touchesBelow {
            receivedRangesDescending[low] = receivedRangesDescending[low].lowerBound...packetNumber
        } else {
            receivedRangesDescending.insert(packetNumber...packetNumber, at: low)
        }
    }

    /// Drops packet numbers that have fallen out of the tracking window and
    /// raises the floor below which numbers are refused.
    ///
    /// Pruning waits until the set is well past the window rather than trimming
    /// on every packet. Trimming as soon as it is one over means rebuilding the
    /// whole set per packet, which is the same cost profile this window exists to
    /// remove. Letting it overshoot and then trimming in one pass makes the cost
    /// amortize to a constant per packet, at the price of holding at most twice
    /// the window.
    private mutating func discardOutsideTrackingWindow() {
        guard receivedPacketNumbers.count > Self.maximumTrackedReceivedPacketNumbers * 2,
            let largestReceived
        else {
            return
        }
        let window = UInt64(Self.maximumTrackedReceivedPacketNumbers)
        guard largestReceived >= window else {
            return
        }
        let floor = largestReceived - window + 1
        guard floor > discardedBelow else {
            return
        }
        discardedBelow = floor
        receivedPacketNumbers = receivedPacketNumbers.filter { $0 >= floor }
        // This runs once per window's worth of packets, so rebuilding the range
        // list by sorting here amortises to nothing per packet.
        receivedRangesDescending = contiguousClosedRangesDescending(
            receivedPacketNumbers.sorted(by: >)
        )
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

        // The ranges are already ordered high to low and non-adjacent, so this is
        // a walk over the gaps rather than a copy and sort of the whole window.
        let ranges = receivedRangesDescending
        guard let first = ranges.first else {
            return nil
        }

        let firstAckRange = first.upperBound - first.lowerBound
        var extraRanges: [QUICAckRange] = []
        var previousLow = first.lowerBound
        for range in ranges.dropFirst() {
            let gap = previousLow - range.upperBound - 2
            extraRanges.append(QUICAckRange(gap: gap, length: range.upperBound - range.lowerBound))
            previousLow = range.lowerBound
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
        let ranges = try acknowledgedPacketNumberRanges(from: frame)
        let total = try ranges.reduce(UInt64(0)) { partial, range in
            let count = range.high - range.low + 1
            let (sum, overflow) = partial.addingReportingOverflow(count)
            guard !overflow else {
                throw QUICStateError.invalidAckFrame
            }
            return sum
        }
        guard total <= UInt64(maximumExpandedAckedPacketNumbers) else {
            throw QUICStateError.invalidAckFrame
        }

        var numbers: Set<UInt64> = []
        for range in ranges {
            insertClosedRange(low: range.low, high: range.high, into: &numbers)
        }
        return numbers
    }

    public static func acknowledgedPacketNumberRanges(from frame: QUICFrame) throws -> [(low: UInt64, high: UInt64)] {
        guard case .ack(let largest, _, let firstRange, let ranges) = frame else {
            throw QUICStateError.invalidAckFrame
        }
        guard largest >= firstRange else {
            throw QUICStateError.invalidAckFrame
        }

        var rangeHigh = largest
        var rangeLow = largest - firstRange
        var decodedRanges: [(low: UInt64, high: UInt64)] = [(low: rangeLow, high: rangeHigh)]

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
            decodedRanges.append((low: rangeLow, high: rangeHigh))
        }

        return decodedRanges
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

    /// How many packet numbers the last ``processAck(_:in:)`` passed through a sort.
    ///
    /// A cost probe, not protocol state. The regression test in
    /// `QUICCoreStateTests` pins the classification to one ordering of the
    /// outstanding set, because the cost of acknowledging must not double just
    /// because two passes need the same numbers in order.
    private(set) var acknowledgementOrderingSteps = 0

    /// How many ACK ranges the last ``processAck(_:in:)`` compared a packet against.
    ///
    /// The peer chooses how many ranges its ACK frame carries, so a per-packet
    /// scan over all of them is a peer-controlled cost. The test pins the
    /// classification to O(packets + ranges).
    private(set) var acknowledgementRangeProbes = 0

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
        acknowledgementOrderingSteps = 0
        acknowledgementRangeProbes = 0
        let acknowledgedRanges = try QUICAckTracker.acknowledgedPacketNumberRanges(from: ackFrame)
        guard !acknowledgedRanges.isEmpty else {
            throw QUICStateError.invalidAckFrame
        }
        let largestAcknowledged = acknowledgedRanges[0].high

        var acknowledged: [QUICSentPacket] = []
        var lost: [QUICSentPacket] = []
        var packets = sentPackets[packetNumberSpace, default: [:]]

        // Both passes need the outstanding numbers in ascending order, and the old
        // code sorted the key set once per pass. The peer's ranges are decoded high
        // to low, so one cursor over them classifies every packet in ascending
        // order without re-testing ranges that cannot contain it: the cursor only
        // ever moves towards the higher ranges as the packet numbers grow.
        let orderedPacketNumbers = packets.keys.sorted()
        acknowledgementOrderingSteps += orderedPacketNumbers.count

        var rangeCursor = acknowledgedRanges.count - 1
        for packetNumber in orderedPacketNumbers {
            while rangeCursor >= 0, packetNumber > acknowledgedRanges[rangeCursor].high {
                acknowledgementRangeProbes += 1
                rangeCursor -= 1
            }
            guard rangeCursor >= 0 else {
                break
            }
            acknowledgementRangeProbes += 1
            guard packetNumber >= acknowledgedRanges[rangeCursor].low else {
                continue
            }
            if let packet = packets.removeValue(forKey: packetNumber) {
                acknowledged.append(packet)
            }
        }

        for packetNumber in orderedPacketNumbers
        where isPacketThresholdLost(
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

extension QUICFrame {
    /// Whether losing this frame obliges the sender to send its content again.
    ///
    /// `DATAGRAM` is deliberately excluded. RFC 9221 section 5.2 states that DATAGRAM
    /// frames "are not retransmitted upon loss detection", because resending one turns
    /// an unreliable datagram into a delayed duplicate. A caller that resends
    /// everything in ``QUICAckProcessingResult/retransmittableFrames`` would otherwise
    /// deliver the same datagram twice.
    ///
    /// `PING` and `PADDING` are excluded because they carry no content to repair.
    /// RFC 9000 section 13.3 notes that a lost PING needs no replacement: if another
    /// ack-eliciting packet is outstanding the peer still acknowledges it, and if not,
    /// the sender's own PTO produces a new one.
    public var isRetransmittable: Bool {
        switch self {
        case .padding, .ping, .ack, .connectionClose, .datagram:
            false
        default:
            true
        }
    }
}

// internal because QUICStreamState, which calls it from `hasSendHalf` / `hasReceiveHalf`,
// lives in QUICCoreStreamFlowState.swift
func endpointRole(for initiator: QUICStreamInitiator) -> QUICEndpointRole {
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

/// The same grouping as ``contiguousRangesDescending(_:)``, in the closed-range
/// form ``QUICAckTracker`` maintains between trims.
private func contiguousClosedRangesDescending(_ numbers: [UInt64]) -> [ClosedRange<UInt64>] {
    contiguousRangesDescending(numbers).map { $0.low...$0.high }
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
