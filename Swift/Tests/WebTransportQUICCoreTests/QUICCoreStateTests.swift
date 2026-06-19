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

    #expect(try store.applyNewConnectionID(
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

@Test
func ackTrackerBuildsAckRangesAndDecodesThem() throws {
    var zeroTracker = QUICAckTracker(packetNumberSpace: .initial)
    let zeroInserted = zeroTracker.recordReceived(packetNumber: 0, nowMicros: 100)
    #expect(zeroInserted)
    #expect(zeroTracker.makeAckFrame(nowMicros: 108) == .ack(
        largestAcknowledged: 0,
        ackDelay: 1,
        firstAckRange: 0,
        ranges: []
    ))
    var highExponentTracker = QUICAckTracker(packetNumberSpace: .initial, ackDelayExponent: 63)
    _ = highExponentTracker.recordReceived(packetNumber: 1, nowMicros: 100)
    #expect(highExponentTracker.makeAckFrame(nowMicros: 200) == .ack(
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
    #expect(frame == .ack(
        largestAcknowledged: 10,
        ackDelay: 10,
        firstAckRange: 1,
        ranges: [
            QUICAckRange(gap: 0, length: 1),
            QUICAckRange(gap: 2, length: 0)
        ]
    ))
    #expect(try QUICAckTracker.acknowledgedPacketNumbers(from: frame) == Set([2, 6, 7, 9, 10]))
}

@Test
func lossRecoveryReturnsRetransmittableFrames() throws {
    var recovery = QUICLossRecovery(packetThreshold: 3)
    recovery.recordSent(QUICSentPacket(
        packetNumberSpace: .applicationData,
        packetNumber: 1,
        sentTimeMicros: 100,
        bytes: 100,
        frames: [.stream(id: 0, offset: 0, fin: false, data: Data("lost".utf8))]
    ))
    recovery.recordSent(QUICSentPacket(
        packetNumberSpace: .applicationData,
        packetNumber: 2,
        sentTimeMicros: 110,
        bytes: 20,
        frames: [.ack(largestAcknowledged: 1, ackDelay: 0, firstAckRange: 0, ranges: [])],
        ackEliciting: false
    ))
    recovery.recordSent(QUICSentPacket(
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
    #expect(result.retransmittableFrames == [
        .stream(id: 0, offset: 0, fin: false, data: Data("lost".utf8))
    ])
    #expect(recovery.sentPackets[.applicationData]?.keys.sorted() == [2])
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
    #expect(try serverUni.receive(.stream(
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
    #expect(close.closeFrame == .connectionClose(
        errorCode: QUICTransportErrorCode.noError.rawValue,
        frameType: nil,
        reason: Data("idle timeout".utf8)
    ))

    var transportClose = QUICConnectionCloseState(idleTimeoutMicros: 100)
    #expect(transportClose.closeTransport(
        error: .flowControlError,
        frameType: 0x08,
        reason: "flow"
    ) == .connectionClose(
        errorCode: QUICTransportErrorCode.flowControlError.rawValue,
        frameType: 0x08,
        reason: Data("flow".utf8)
    ))

    var applicationClose = QUICConnectionCloseState(idleTimeoutMicros: 100)
    #expect(applicationClose.closeApplication(errorCode: 0x54, reason: "app") == .connectionClose(
        errorCode: 0x54,
        frameType: nil,
        reason: Data("app".utf8)
    ))
}
