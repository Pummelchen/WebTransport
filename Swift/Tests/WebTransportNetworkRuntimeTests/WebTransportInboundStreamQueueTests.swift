import Foundation
import Testing
import WebTransportHTTP3Core
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

    /// The queue is a retention bound, not an unbounded inbox.
    ///
    /// RFC 9000 section 4.6 counts a stream against `initial_max_streams_*` only
    /// until it is closed, and a stream the peer FINs is closed whether or not
    /// the application ever read it, so the advertised stream limit does not
    /// bound how many `QUIC.Stream` objects a connection accumulates over its
    /// life. The per-direction ceiling — taken from those same advertised
    /// limits — is what does, so a stream beyond it must not be retained.
    @Test
    func streamsBeyondThePerDirectionCeilingAreNotRetained() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        let limit = WebTransportTransportLimits.default.initialMaxUnidirectionalStreams
        #expect(limit > 0)

        for index in 0..<limit {
            await queue.enqueue(index, direction: Self.direction, streamID: UInt64(index))
        }
        // The queue holds its ceiling now, so this stream must be refused
        // rather than retained behind the others.
        await queue.enqueue(limit, direction: Self.direction, streamID: UInt64(limit))

        for index in 0..<limit {
            #expect(try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000) == index)
        }
        await #expect(throws: (any Error).self) {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 50)
        }
    }

    /// Critically-typed streams are retained under the same discipline as
    /// ordinary inbound streams, but with a much smaller entitlement.
    ///
    /// RFC 9114 section 6.2.1 gives a connection exactly one HTTP/3 control
    /// stream and RFC 9204 section 4.2 exactly one QPACK encoder and one decoder
    /// stream, and a second of any of them is a connection error rather than
    /// something to retain. Before the entitlement was enforced, `retainCritical`
    /// appended with no bound: a peer that opened control-typed streams the
    /// runtime had no consumer for made it retain each one, and the buffers
    /// behind it, for the connection's whole life — and each retained handle
    /// permanently consumed one unit of the peer's unidirectional-stream credit.
    @Test
    func criticalStreamRetentionIsBoundedToTheThreeEntitledStreams() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()

        #expect(await queue.retainCritical(0, type: HTTP3StreamType.control))
        #expect(!(await queue.retainCritical(1, type: HTTP3StreamType.control)))
        #expect(await queue.retainCritical(2, type: HTTP3StreamType.qpackEncoder))
        #expect(!(await queue.retainCritical(3, type: HTTP3StreamType.qpackEncoder)))
        #expect(await queue.retainCritical(4, type: HTTP3StreamType.qpackDecoder))
        #expect(!(await queue.retainCritical(5, type: HTTP3StreamType.qpackDecoder)))
        #expect(await queue.retainedCriticalCount == 3)

        // A peer that keeps opening control-typed streams must not be able to
        // grow retention past the entitlement. The count is the observable the
        // audit probe used (`retainedCount=100000` on the old code).
        for index in 0..<1_000 {
            #expect(!(await queue.retainCritical(index, type: HTTP3StreamType.control)))
        }
        #expect(await queue.retainedCriticalCount == 3)

        // A type outside the entitlement is refused on sight: only the one
        // control and two QPACK streams are ever retained, so the array cannot
        // grow by a caller choosing some other type.
        #expect(!(await queue.retainCritical(6, type: HTTP3StreamType.push)))
        #expect(await queue.retainedCriticalCount == 3)
    }

    /// F-swift-perf-tests-04: remembering a delivery must not shift the history.
    ///
    /// `enqueue` appended the delivery key and, once the 4,096-entry history was
    /// full, called `deliveryOrder.removeFirst()`, which moves every remaining
    /// element. The number of deliveries is peer-driven and unbounded over a
    /// connection's life, so each delivery past the cap cost O(4,096). The probe
    /// counts elements physically moved, so the assertion is independent of load.
    @Test
    func deliveryHistoryIsNotShiftedPerDelivery() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        let deliveries = 40_000
        for index in 0..<deliveries {
            await queue.enqueue(index, direction: Self.direction, streamID: UInt64(index))
        }

        let moves = await queue.deliveryOrderMoves
        #expect(
            moves <= deliveries * 2,
            "recording \(deliveries) deliveries moved \(moves) history elements"
        )
    }
}
