import Foundation
import Testing
@testable import WebTransportNetworkRuntime

/// Delivery guarantees for the queue that hands inbound QUIC streams to whoever
/// is waiting for one.
///
/// Both cases below are regressions. A connection that loses a single inbound
/// stream does not fail loudly: the peer's HTTP/3 control stream is the first
/// thing to arrive, and losing it leaves both ends waiting on each other until
/// the operation times out. That surfaced as an intermittent hang rather than an
/// error, which is why it survived the rest of the suite.
@Suite("Inbound stream queue")
struct WebTransportInboundStreamQueueTests {
    private static let direction = 1

    @Test
    func streamEnqueuedWhileACallerIsWaitingIsDeliveredToIt() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()

        let receiver = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }
        // Let `next` reach the point where it parks before anything is enqueued,
        // so this exercises the waiter path rather than the already-queued path.
        try await Task.sleep(for: .milliseconds(50))
        await queue.enqueue(7, direction: Self.direction, streamID: 7)

        let received = try await receiver.value
        #expect(received == 7)
    }

    @Test
    func streamQueuedBeforeAnyCallerArrivesIsReturnedImmediately() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.enqueue(3, direction: Self.direction, streamID: 3)

        let received = try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        #expect(received == 3)
    }

    /// A timed-out wait must not leave a claim behind.
    ///
    /// The earlier implementation raced the wait against a timer and abandoned
    /// the loser, which left the abandoned waiter parked. The next stream to
    /// arrive was handed to that dead caller and dropped, so a caller polling
    /// with a timeout — which `acceptBidirectionalStream` does — could lose a
    /// stream the peer had genuinely opened.
    @Test
    func aStreamArrivingAfterATimeoutIsStillDeliveredToTheNextCaller() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()

        await #expect(throws: (any Error).self) {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 50)
        }

        await queue.enqueue(11, direction: Self.direction, streamID: 11)
        let received = try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        #expect(received == 11)
    }

    /// A timeout must fail only its own waiter, not whichever is at the front.
    @Test
    func oneWaiterTimingOutLeavesAnotherAbleToReceive() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()

        let expiring = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 100)
        }
        try await Task.sleep(for: .milliseconds(30))
        let surviving = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }

        // Let the first waiter's timeout fire before anything is enqueued.
        try await Task.sleep(for: .milliseconds(200))
        await queue.enqueue(5, direction: Self.direction, streamID: 5)

        let expiringResult = await expiring.result
        #expect(throws: (any Error).self) {
            _ = try expiringResult.get()
        }
        let survived = try await surviving.value
        #expect(survived == 5)
    }

    @Test
    func directionsDoNotConsumeEachOthersStreams() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.enqueue(1, direction: 0, streamID: 1)

        await #expect(throws: (any Error).self) {
            try await queue.next(direction: 1, timeoutMilliseconds: 50)
        }
        #expect(try await queue.next(direction: 0, timeoutMilliseconds: 5_000) == 1)
    }

    @Test
    func failureIsReportedToWaitersAndToLaterCallers() async throws {
        struct QueueFailure: Error {}
        let queue = InteroperableQUICStreamQueue<Int>()

        let waiting = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }
        try await Task.sleep(for: .milliseconds(50))
        await queue.fail(QueueFailure())

        let waitingResult = await waiting.result
        #expect(throws: QueueFailure.self) {
            _ = try waitingResult.get()
        }
        await #expect(throws: QueueFailure.self) {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }
    }

    /// A stream identifier is never reused within a QUIC connection, so the same
    /// identifier arriving twice is a repeat of a stream already handed out.
    ///
    /// Delivering it again is what produced both remaining failure shapes on
    /// loopback: the peer's CONNECT request stream was delivered a second time
    /// after the session was established, and was then either misparsed as a
    /// WebTransport stream or handed to a reader that blocked on it forever.
    @Test
    func aRepeatedStreamIdentifierIsIgnored() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()

        await queue.enqueue(1, direction: Self.direction, streamID: 0)
        await queue.enqueue(2, direction: Self.direction, streamID: 0)

        let first = try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        #expect(first == 1)

        // The repeat must not be sitting behind it.
        await #expect(throws: (any Error).self) {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 50)
        }
    }

    /// The repeat must be rejected even when a caller is already parked, since
    /// that is the case that hands a dead stream straight to a live reader.
    @Test
    func aRepeatedIdentifierIsNotHandedToAWaitingCaller() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.enqueue(1, direction: Self.direction, streamID: 4)
        #expect(try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000) == 1)

        let waiter = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 300)
        }
        try await Task.sleep(for: .milliseconds(50))
        await queue.enqueue(99, direction: Self.direction, streamID: 4)

        let result = await waiter.result
        #expect(throws: (any Error).self) {
            _ = try result.get()
        }
    }

    /// Distinct identifiers must still both be delivered.
    @Test
    func differentIdentifiersAreBothDelivered() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.enqueue(1, direction: Self.direction, streamID: 0)
        await queue.enqueue(2, direction: Self.direction, streamID: 4)

        #expect(try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000) == 1)
        #expect(try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000) == 2)
    }

    /// The same identifier in the other direction is a different stream.
    @Test
    func theSameIdentifierInAnotherDirectionIsNotADuplicate() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.enqueue(1, direction: 0, streamID: 0)
        await queue.enqueue(2, direction: 1, streamID: 0)

        #expect(try await queue.next(direction: 0, timeoutMilliseconds: 5_000) == 1)
        #expect(try await queue.next(direction: 1, timeoutMilliseconds: 5_000) == 2)
    }
}
