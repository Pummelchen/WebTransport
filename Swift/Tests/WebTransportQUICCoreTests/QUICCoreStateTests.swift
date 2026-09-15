import Foundation
import Testing
@testable import WebTransportQUICCore

@Test
func versionPolicySelectsOnlySupportedQUICVersions() {
    let policy = QUICVersionPolicy()

    #expect(policy.select(offeredVersion: QUICVersionPolicy.quicV1) == QUICVersionPolicy.quicV1)
    #expect(policy.select(offeredVersion: 0xface_b00c) == nil)
    #expect(policy.shouldSendVersionNegotiation(for: 0xface_b00c))
}

@Test
func connectionIDStoreRetiresOlderConnectionIDs() throws {
    let token = Data(repeating: 0xab, count: 16)
    var store = try QUICConnectionIDStore(initialConnectionID: Data([0x00]), activeConnectionIDLimit: 3)

    #expect(
        try store.applyNewConnectionID(
            sequence: 1,
            retirePriorTo: 0,
            connectionID: Data([0x01]),
            statelessResetToken: token
        ).isEmpty)
    _ = try store.useDestinationConnectionID(sequence: 1)

    let retireFrames = try store.applyNewConnectionID(
        sequence: 2,
        retirePriorTo: 1,
        connectionID: Data([0x02]),
        statelessResetToken: token
    )

    #expect(retireFrames == [.retireConnectionID(sequence: 0)])
    #expect(store.retiredSequences.contains(0))
    #expect(store.activeConnectionIDs.map(\.sequence) == [1, 2])
    #expect(try store.retire(sequence: 0) == .retireConnectionID(sequence: 0))
    #expect(throws: Error.self) {
        _ = try store.applyNewConnectionID(
            sequence: 3,
            retirePriorTo: 4,
            connectionID: Data([0x03]),
            statelessResetToken: token
        )
    }
}

/// F-swift-perf-tests-03: building an ACK must not re-order the tracked window.
///
/// `makeAckFrame` did `Array(receivedPacketNumbers).sorted(by: >)` on every call,
/// and an endpoint builds an ACK per ACK-eliciting packet. The tracking window
/// caps the set at 16,384 numbers but the per-call copy and sort remained, so the
/// doc-comment's claim that the window removed that cost was not covered by any
/// test — the existing window test only asserted set size, `largestReceived` and
/// `discardedBelow`.
///
/// The bound is a wall-clock one because the sort happens inside the standard
/// library; the margin is large (the old implementation takes seconds on this
/// workload, the maintained ranges take microseconds).
@Test
func acknowledgementFramesDoNotReorderTheTrackedWindowPerCall() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)
    let window = QUICAckTracker.maximumTrackedReceivedPacketNumbers * 2
    for number in 0..<UInt64(window) {
        tracker.recordReceived(packetNumber: number, nowMicros: 0)
    }
    #expect(tracker.receivedPacketNumbers.count == window)

    let start = ContinuousClock.now
    for _ in 0..<1_000 {
        _ = tracker.makeAckFrame(nowMicros: 1_000_000)
    }
    let elapsed = ContinuousClock.now - start
    #expect(
        elapsed < .seconds(1),
        "1,000 ACK frames over a \(window)-number window took \(elapsed); an ACK must not re-sort the window"
    )
}

/// The maintained ranges must survive out-of-order arrival, duplicates and the
/// window trim: whatever `makeAckFrame` emits must decode back to exactly the
/// tracked set.
@Test
func acknowledgementFrameRangesMatchTheTrackedSetAfterOutOfOrderArrivalAndTrim() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)

    // Even numbers first, then the odd neighbours that bridge every gap.
    for number in stride(from: 0, to: 600, by: 2) {
        let inserted = tracker.recordReceived(packetNumber: UInt64(number), nowMicros: 0)
        #expect(inserted)
    }
    for number in stride(from: 1, to: 600, by: 2) {
        let inserted = tracker.recordReceived(packetNumber: UInt64(number), nowMicros: 0)
        #expect(inserted)
    }
    // Duplicates are refused and must not disturb the ranges.
    let duplicateLow = tracker.recordReceived(packetNumber: 0, nowMicros: 0)
    let duplicateHigh = tracker.recordReceived(packetNumber: 599, nowMicros: 0)
    #expect(!duplicateLow)
    #expect(!duplicateHigh)
    let frame = try #require(tracker.makeAckFrame(nowMicros: 0))
    #expect(try QUICAckTracker.acknowledgedPacketNumbers(from: frame) == tracker.receivedPacketNumbers)

    // Push past the window so the trim rewrites the range list, then round-trip again.
    for number in 600..<UInt64(QUICAckTracker.maximumTrackedReceivedPacketNumbers * 2 + 100) {
        tracker.recordReceived(packetNumber: number, nowMicros: 0)
    }
    #expect(tracker.discardedBelow > 0)
    let trimmed = try #require(tracker.makeAckFrame(nowMicros: 0))
    #expect(try QUICAckTracker.acknowledgedPacketNumbers(from: trimmed) == tracker.receivedPacketNumbers)
}

/// The incremental range list has four insertion positions (extend either end,
/// bridge one gap, open a new range) and a trim rebuild; a deterministic
/// pseudo-random arrival order exercises all of them against a decode round-trip.
@Test
func acknowledgementFrameRangesSurviveArbitraryInsertionOrder() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)
    var generator: UInt64 = 0x9e37_79b9_7f4a_7c15
    var seen: Set<UInt64> = []
    for step in 0..<4_000 {
        generator = generator &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        let number = generator % 2_048
        let inserted = tracker.recordReceived(packetNumber: number, nowMicros: 0)
        #expect(inserted == !seen.contains(number))
        seen.insert(number)
        if step % 97 == 0 {
            let frame = try #require(tracker.makeAckFrame(nowMicros: 0))
            #expect(
                try QUICAckTracker.acknowledgedPacketNumbers(from: frame) == tracker.receivedPacketNumbers
            )
        }
    }
    let frame = try #require(tracker.makeAckFrame(nowMicros: 0))
    #expect(try QUICAckTracker.acknowledgedPacketNumbers(from: frame) == tracker.receivedPacketNumbers)
}

@Test
func ackTrackerBuildsAckRangesAndDecodesThem() throws {
    var zeroTracker = QUICAckTracker(packetNumberSpace: .initial)
    let zeroInserted = zeroTracker.recordReceived(packetNumber: 0, nowMicros: 100)
    #expect(zeroInserted)
    #expect(
        zeroTracker.makeAckFrame(nowMicros: 108)
            == .ack(
                largestAcknowledged: 0,
                ackDelay: 1,
                firstAckRange: 0,
                ranges: []
            ))
    var highExponentTracker = QUICAckTracker(packetNumberSpace: .initial, ackDelayExponent: 63)
    _ = highExponentTracker.recordReceived(packetNumber: 1, nowMicros: 100)
    #expect(
        highExponentTracker.makeAckFrame(nowMicros: 200)
            == .ack(
                largestAcknowledged: 1,
                ackDelay: 0,
                firstAckRange: 0,
                ranges: []
            ))

    var tracker = QUICAckTracker(packetNumberSpace: .applicationData, ackDelayExponent: 3)
    for packetNumber in [2, 6, 7, 9, 10] as [UInt64] {
        let inserted = tracker.recordReceived(packetNumber: packetNumber, nowMicros: 1_000 + packetNumber)
        #expect(inserted)
    }
    let duplicateInserted = tracker.recordReceived(packetNumber: 7, nowMicros: 2_000)
    #expect(!duplicateInserted)

    let frame = try #require(tracker.makeAckFrame(nowMicros: 1_090))
    #expect(
        frame
            == .ack(
                largestAcknowledged: 10,
                ackDelay: 10,
                firstAckRange: 1,
                ranges: [
                    QUICAckRange(gap: 0, length: 1),
                    QUICAckRange(gap: 2, length: 0),
                ]
            ))
    #expect(try QUICAckTracker.acknowledgedPacketNumbers(from: frame) == Set([2, 6, 7, 9, 10]))
}

@Test
func ackTrackerRejectsPathologicallyLargeExpandedAckRanges() throws {
    let frame = QUICFrame.ack(
        largestAcknowledged: 100_000,
        ackDelay: 0,
        firstAckRange: 100_000,
        ranges: []
    )

    #expect(throws: Error.self) {
        _ = try QUICAckTracker.acknowledgedPacketNumbers(from: frame)
    }
    let ranges = try QUICAckTracker.acknowledgedPacketNumberRanges(from: frame)
    #expect(ranges.count == 1)
    #expect(ranges.first?.low == 0)
    #expect(ranges.first?.high == 100_000)
}

@Test
func lossRecoveryReturnsRetransmittableFrames() throws {
    var recovery = QUICLossRecovery(packetThreshold: 3)
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 1,
            sentTimeMicros: 100,
            bytes: 100,
            frames: [.stream(id: 0, offset: 0, fin: false, data: Data("lost".utf8))]
        ))
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 2,
            sentTimeMicros: 110,
            bytes: 20,
            frames: [.ack(largestAcknowledged: 1, ackDelay: 0, firstAckRange: 0, ranges: [])],
            ackEliciting: false
        ))
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 4,
            sentTimeMicros: 130,
            bytes: 120,
            frames: [.datagram(Data("acked".utf8))]
        ))

    let result = try recovery.processAck(
        .ack(largestAcknowledged: 4, ackDelay: 0, firstAckRange: 0, ranges: []),
        in: .applicationData
    )

    #expect(result.acknowledged.map(\.packetNumber) == [4])
    #expect(result.lost.map(\.packetNumber) == [1])
    #expect(
        result.retransmittableFrames == [
            .stream(id: 0, offset: 0, fin: false, data: Data("lost".utf8))
        ])
    #expect(recovery.sentPackets[.applicationData]?.keys.sorted() == [2])
}

/// F-swift-perf-tests-02: classifying an ACK must not sort the outstanding packet
/// set twice nor scan every peer-supplied ACK range for every outstanding packet.
///
/// `processAck` built `packets.keys.sorted()` once per pass, and the first pass
/// used `acknowledgedRanges.contains(where:)`, which re-tested every range for
/// every packet — O(packets x ranges), with the range count bounded only by the
/// 16,384 expanded packet numbers a peer may put in one ACK frame. The probes
/// below are the same operations counted, so the bound is on work rather than on
/// wall-clock time.
@Test
func lossRecoveryClassifiesAckRangesWithoutScanningEveryRangePerPacket() throws {
    let packetCount = 8_193
    let rangeCount = 1_024
    var recovery = QUICLossRecovery(packetThreshold: 3)
    for number in 0..<UInt64(packetCount) {
        recovery.recordSent(
            QUICSentPacket(
                packetNumberSpace: .applicationData,
                packetNumber: number,
                sentTimeMicros: 0,
                bytes: 1,
                frames: [.ping]
            ))
    }

    // Single-packet ranges two apart: the peer acknowledges every even packet in
    // the top 2,048 numbers. Every odd packet below them must be tested against
    // the whole range list by a per-range scan. One range comes from
    // `firstAckRange`, the rest from the gaps.
    let largest = UInt64(packetCount - 1)
    let result = try recovery.processAck(
        .ack(
            largestAcknowledged: largest,
            ackDelay: 0,
            firstAckRange: 0,
            ranges: Array(repeating: QUICAckRange(gap: 0, length: 0), count: rangeCount - 1)
        ),
        in: .applicationData
    )

    #expect(result.acknowledged.count == rangeCount)
    #expect(result.acknowledged.allSatisfy { $0.packetNumber % 2 == largest % 2 })
    #expect(recovery.sentPackets[.applicationData]?.keys.sorted() == [largest - 1])

    // One ordering pass over the outstanding set, not one sort per loop.
    #expect(
        recovery.acknowledgementOrderingSteps <= packetCount + 1,
        "the outstanding set was ordered \(recovery.acknowledgementOrderingSteps) times for \(packetCount) packets"
    )
    // One range comparison per packet at worst, plus the ranges stepped over once.
    #expect(
        recovery.acknowledgementRangeProbes <= 4 * (packetCount + rangeCount),
        "classifying \(packetCount) packets against \(rangeCount) ranges took \(recovery.acknowledgementRangeProbes) range comparisons"
    )
}

@Test
func lossRecoveryProcessesLargeAckRangesWithoutExpandingEveryPacketNumber() throws {
    var recovery = QUICLossRecovery(packetThreshold: 3)
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 1,
            sentTimeMicros: 100,
            bytes: 1,
            frames: [.ping]
        ))
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 100_000,
            sentTimeMicros: 200,
            bytes: 1,
            frames: [.ping]
        ))

    let result = try recovery.processAck(
        .ack(largestAcknowledged: 100_000, ackDelay: 0, firstAckRange: 100_000, ranges: []),
        in: .applicationData
    )

    #expect(result.acknowledged.map(\.packetNumber) == [1, 100_000])
    #expect(recovery.sentPackets[.applicationData]?.isEmpty == true)
}

@Test
func congestionControllerTracksBytesInFlightAndWindow() {
    var controller = QUICCongestionController(maxDatagramSize: 1_200)
    let initialWindow = controller.congestionWindow

    #expect(controller.canSend(bytes: 1_200))
    controller.onPacketSent(bytes: 1_200)
    #expect(controller.bytesInFlight == 1_200)
    controller.onPacketAcknowledged(bytes: 1_200)
    #expect(controller.bytesInFlight == 0)
    #expect(controller.congestionWindow == initialWindow + 1_200)

    controller.onPacketSent(bytes: 4_800)
    controller.onPacketsLost(bytes: 4_800)
    #expect(controller.bytesInFlight == 0)
    #expect(controller.congestionWindow >= controller.minimumWindow)
}

@Test
func streamStateHandlesBidirectionalAndUnidirectionalFlowControl() throws {
    var clientBidi = QUICStreamState(
        id: QUICStreamID.make(index: 0, direction: .bidirectional, initiator: .client),
        localRole: .client,
        maxSendOffset: 8,
        maxReceiveOffset: 8
    )
    let first = try clientBidi.send(data: Data("ping".utf8))
    #expect(first == .stream(id: 0, offset: 0, fin: false, data: Data("ping".utf8)))
    clientBidi.applyMaxStreamData(16)
    let second = try clientBidi.send(data: Data("pong".utf8), fin: true)
    #expect(second == .stream(id: 0, offset: 4, fin: true, data: Data("pong".utf8)))
    #expect(clientBidi.sendClosed)

    var serverUni = QUICStreamState(
        id: QUICStreamID.make(index: 0, direction: .unidirectional, initiator: .server),
        localRole: .client,
        maxSendOffset: 0,
        maxReceiveOffset: 5
    )
    #expect(
        try serverUni.receive(
            .stream(
                id: 3,
                offset: 0,
                fin: true,
                data: Data("hello".utf8)
            )) == Data("hello".utf8))
    #expect(serverUni.receiveClosed)
    #expect(throws: Error.self) {
        _ = try serverUni.send(data: Data("x".utf8))
    }
}

@Test
func connectionAndStreamFlowControlRejectExcessBytes() throws {
    var connectionFlow = QUICFlowController(maximumData: 10)
    try connectionFlow.reserveSendBytes(6)
    #expect(connectionFlow.availableSendBytes == 4)
    #expect(throws: Error.self) {
        try connectionFlow.reserveSendBytes(5)
    }
    connectionFlow.increaseMaximumData(to: 20)
    try connectionFlow.reserveSendBytes(5)
    #expect(connectionFlow.sentData == 11)
    #expect(connectionFlow.maxDataFrame() == .maxData(20))

    var stream = QUICStreamState(
        id: 0,
        localRole: .client,
        maxSendOffset: 3,
        maxReceiveOffset: 3
    )
    #expect(throws: Error.self) {
        _ = try stream.send(data: Data("toolong".utf8))
    }
    stream.increaseReceiveLimit(to: 9)
    #expect(stream.maxStreamDataFrame() == .maxStreamData(id: 0, maximum: 9))
}

@Test
func datagramQueueEnforcesMaximumPayloadSize() throws {
    var datagrams = QUICDatagramQueue(maximumPayloadSize: 4)
    let frame = try datagrams.makeDatagramFrame(Data("ping".utf8))
    #expect(frame == .datagram(Data("ping".utf8)))
    try datagrams.receive(frame)
    #expect(datagrams.popReceived() == Data("ping".utf8))

    #expect(throws: Error.self) {
        _ = try datagrams.makeDatagramFrame(Data("oversized".utf8))
    }
    #expect(throws: Error.self) {
        try datagrams.receive(.datagram(Data("oversized".utf8)))
    }
}

@Test
func closeStateMapsTransportApplicationAndIdleClose() throws {
    var close = QUICConnectionCloseState(idleTimeoutMicros: 100, nowMicros: 1_000)
    try close.recordActivity(nowMicros: 1_050)
    #expect(try close.checkIdleTimeout(nowMicros: 1_120) == false)
    #expect(try close.checkIdleTimeout(nowMicros: 1_150))
    #expect(
        close.closeFrame
            == .connectionClose(
                errorCode: QUICTransportErrorCode.noError.rawValue,
                frameType: nil,
                reason: Data("idle timeout".utf8)
            ))

    var transportClose = QUICConnectionCloseState(idleTimeoutMicros: 100)
    #expect(
        transportClose.closeTransport(
            error: .flowControlError,
            frameType: 0x08,
            reason: "flow"
        )
            == .connectionClose(
                errorCode: QUICTransportErrorCode.flowControlError.rawValue,
                frameType: 0x08,
                reason: Data("flow".utf8)
            ))

    var applicationClose = QUICConnectionCloseState(idleTimeoutMicros: 100)
    #expect(
        applicationClose.closeApplication(errorCode: 0x54, reason: "app")
            == .connectionClose(
                errorCode: 0x54,
                frameType: nil,
                reason: Data("app".utf8)
            ))
}

// MARK: - Acknowledgement tracking window

/// A connection receives packets for as long as it lives, so what the tracker
/// remembers has to be bounded. Retaining every number seen grew without limit
/// and made each `makeAckFrame` sort the whole history, so acknowledging got
/// slower the longer a connection stayed up.
@Test
func ackTrackerBoundsWhatItRemembers() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)
    let window = QUICAckTracker.maximumTrackedReceivedPacketNumbers

    for packetNumber in 0..<UInt64(window * 3) {
        tracker.recordReceived(packetNumber: packetNumber, nowMicros: packetNumber)
    }

    #expect(tracker.receivedPacketNumbers.count <= window * 2)
    #expect(tracker.largestReceived == UInt64(window * 3 - 1))
    #expect(tracker.discardedBelow > 0)
}

/// Dropping an old packet number must not make it acceptable again. The window
/// floor is a replay boundary, not just an eviction policy.
@Test
func ackTrackerRefusesPacketNumbersItHasForgotten() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)
    let window = QUICAckTracker.maximumTrackedReceivedPacketNumbers

    // Past the point where the tracker trims, so the oldest numbers are gone.
    for packetNumber in 0..<UInt64(window * 3) {
        tracker.recordReceived(packetNumber: packetNumber, nowMicros: packetNumber)
    }
    #expect(tracker.discardedBelow > 0)

    // Packet 0 was seen and has since been forgotten. Re-offering it must not
    // read as new, or an old packet would be processed a second time.
    #expect(tracker.recordReceived(packetNumber: 0, nowMicros: 1) == false)
    // A number inside the window still behaves normally.
    let insideWindow = tracker.discardedBelow
    #expect(tracker.recordReceived(packetNumber: insideWindow, nowMicros: 1) == false)
}

/// Ordinary duplicate detection inside the window is unchanged.
@Test
func ackTrackerStillRejectsDuplicatesInsideTheWindow() throws {
    var tracker = QUICAckTracker(packetNumberSpace: .applicationData)
    #expect(tracker.recordReceived(packetNumber: 7, nowMicros: 1) == true)
    #expect(tracker.recordReceived(packetNumber: 7, nowMicros: 2) == false)
    #expect(tracker.largestReceived == 7)
}

// MARK: - Retransmission classification

/// RFC 9221 section 5.2: DATAGRAM frames "are not retransmitted upon loss detection".
/// RFC 9000 section 13.3: a lost PING or PADDING frame requires no repair.
///
/// A caller resends everything in `retransmittableFrames`, so classifying either of
/// these as retransmittable would re-send an unreliable datagram and deliver it twice.
@Test
func lossRecoveryDoesNotRetransmitUnreliableOrEmptyFrames() throws {
    var recovery = QUICLossRecovery(packetThreshold: 3)
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 1,
            sentTimeMicros: 100,
            bytes: 10,
            frames: [.datagram(Data("unreliable".utf8)), .ping, .padding]
        ))
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 5,
            sentTimeMicros: 100,
            bytes: 10,
            frames: [.ping]
        ))

    // Acknowledge 5 so that 1 is declared lost by the packet threshold.
    let result = try recovery.processAck(
        .ack(largestAcknowledged: 5, ackDelay: 0, firstAckRange: 0, ranges: []),
        in: .applicationData
    )

    #expect(result.lost.map(\.packetNumber) == [1])
    #expect(
        result.retransmittableFrames.isEmpty,
        "lost packet carried only DATAGRAM/PING/PADDING, none of which are retransmitted; got \(result.retransmittableFrames)"
    )
}

/// A lost packet carrying real stream data is still retransmitted.
@Test
func lossRecoveryStillRetransmitsStreamData() throws {
    var recovery = QUICLossRecovery(packetThreshold: 3)
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 1,
            sentTimeMicros: 100,
            bytes: 20,
            frames: [.stream(id: 0, offset: 0, fin: false, data: Data("keep".utf8))]
        ))
    recovery.recordSent(
        QUICSentPacket(
            packetNumberSpace: .applicationData,
            packetNumber: 5,
            sentTimeMicros: 100,
            bytes: 20,
            frames: [.ping]
        ))

    let result = try recovery.processAck(
        .ack(largestAcknowledged: 5, ackDelay: 0, firstAckRange: 0, ranges: []),
        in: .applicationData
    )
    #expect(result.retransmittableFrames == [.stream(id: 0, offset: 0, fin: false, data: Data("keep".utf8))])
}

// MARK: - Connection ID retirement watermark

/// RFC 9000 section 19.15: every sequence below a received Retire Prior To is retired
/// permanently, and a later, smaller Retire Prior To has no effect. Without remembering
/// the high-water mark a sequence below it could be re-activated and used again.
@Test
func connectionIDStoreKeepsRetiredSequencesBelowTheWatermark() throws {
    var store = try QUICConnectionIDStore(initialConnectionID: Data([0x00]), activeConnectionIDLimit: 8)

    let first = try store.applyNewConnectionID(
        sequence: 10,
        retirePriorTo: 5,
        connectionID: Data([0x0a]),
        statelessResetToken: Data(repeating: 1, count: 16)
    )
    #expect(first.count == 1)
    #expect(store.largestRetirePriorTo == 5)
    #expect(store.active.keys.sorted() == [10])

    // A later frame naming a sequence below the watermark, with a lower Retire Prior To,
    // must not make it usable.
    let second = try store.applyNewConnectionID(
        sequence: 3,
        retirePriorTo: 0,
        connectionID: Data([0x03]),
        statelessResetToken: Data(repeating: 2, count: 16)
    )
    // RFC 9000 section 19.15 requires a RETIRE_CONNECTION_ID for the newly received
    // sequence, even though this endpoint never held that connection ID.
    #expect(second == [.retireConnectionID(sequence: 3)])
    #expect(store.active.keys.sorted() == [10])
    #expect(store.retiredSequences.contains(3))
    // The destination cannot be switched to a sequence below the watermark.
    #expect(throws: (any Error).self) {
        try store.useDestinationConnectionID(sequence: 3)
    }

    // A sequence at or above the watermark is still accepted normally.
    _ = try store.applyNewConnectionID(
        sequence: 11,
        retirePriorTo: 5,
        connectionID: Data([0x0b]),
        statelessResetToken: Data(repeating: 3, count: 16)
    )
    #expect(store.active.keys.sorted() == [10, 11])
}

/// RFC 9000 section 4.5: once a final size is known it cannot change, so a
/// STREAM frame that would exceed it and a FIN that would redefine it are both
/// FINAL_SIZE_ERROR. Both checks live in `QUICStreamState.receive`, and both
/// used to sit after the receive-closed gate that the very FIN which records
/// the final size closes, so neither branch could ever run.
@Test
func streamStateEnforcesARecordedFinalSize() throws {
    var stream = QUICStreamState(
        id: 0,
        localRole: .client,
        maxSendOffset: 0,
        maxReceiveOffset: 64
    )
    #expect(
        try stream.receive(.stream(id: 0, offset: 0, fin: true, data: Data("hello".utf8)))
            == Data("hello".utf8))
    #expect(stream.finalReceiveSize == 5)
    #expect(stream.receiveClosed)

    // A STREAM frame past the recorded final size is FINAL_SIZE_ERROR even
    // though the receive half is already closed.
    #expect(throws: QUICStateError.finalSizeViolation("STREAM data exceeds final size")) {
        _ = try stream.receive(.stream(id: 0, offset: 5, fin: false, data: Data("x".utf8)))
    }
    // A FIN whose size disagrees with the recorded final size is FINAL_SIZE_ERROR.
    #expect(throws: QUICStateError.finalSizeViolation("inconsistent final stream size")) {
        _ = try stream.receive(.stream(id: 0, offset: 0, fin: true, data: Data("hi".utf8)))
    }
}

/// RFC 9000 sections 4.5 and 19.4: a RESET_STREAM frame carries the sender's
/// Final Size, which is the receive half's final size. The state machine used to
/// ignore RESET_STREAM entirely, so a reset stream had no recorded final size
/// and the section 4.5 checks never had a value to compare against.
@Test
func streamStateRecordsFinalSizeFromResetStream() throws {
    var stream = QUICStreamState(
        id: 0,
        localRole: .client,
        maxSendOffset: 0,
        maxReceiveOffset: 64
    )
    _ = try stream.receive(.stream(id: 0, offset: 0, fin: false, data: Data("hello".utf8)))
    #expect(stream.finalReceiveSize == nil)

    _ = try stream.receive(.resetStream(id: 0, applicationErrorCode: 0x10, finalSize: 5))
    #expect(stream.finalReceiveSize == 5)
    #expect(stream.receiveClosed)

    // The reset's final size now bounds later STREAM frames.
    #expect(throws: QUICStateError.finalSizeViolation("STREAM data exceeds final size")) {
        _ = try stream.receive(.stream(id: 0, offset: 5, fin: false, data: Data("x".utf8)))
    }
    // A second RESET_STREAM that changes the final size is FINAL_SIZE_ERROR.
    #expect(throws: QUICStateError.finalSizeViolation("inconsistent final stream size")) {
        _ = try stream.receive(.resetStream(id: 0, applicationErrorCode: 0x10, finalSize: 9))
    }

    // A RESET_STREAM below the bytes already received is FINAL_SIZE_ERROR.
    var short = QUICStreamState(
        id: 0,
        localRole: .client,
        maxSendOffset: 0,
        maxReceiveOffset: 64
    )
    _ = try short.receive(.stream(id: 0, offset: 0, fin: false, data: Data("hello".utf8)))
    #expect(
        throws: QUICStateError.finalSizeViolation(
            "RESET_STREAM final size is below the bytes already received")
    ) {
        _ = try short.receive(.resetStream(id: 0, applicationErrorCode: 0x10, finalSize: 3))
    }
    // The rejected reset left no final size behind.
    #expect(short.finalReceiveSize == nil)
}
