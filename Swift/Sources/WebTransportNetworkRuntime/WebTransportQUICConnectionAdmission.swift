// Connection admission for the interoperable runtime: the listener's concurrency
// budget and leases, the queue accepted connections wait in, and the demultiplexing
// of a peer's inbound QUIC streams.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

/// An accepted connection together with the stream handler already attached to it.
///
/// The handler cannot be attached later by whoever eventually serves the
/// connection: the peer starts opening streams as soon as the handshake
/// completes, which happens while the connection is still sitting in the accept
/// queue. Attaching it before `start()` and carrying it along is what keeps the
/// peer's control stream from being delivered to nothing.
/// The listener's concurrency budget.
///
/// Held apart from the listener so the accept handler can be built before the
/// listener's own stored properties are initialized, and so releasing a slot does
/// not reach back into the listener.
final class InteroperableQUICConnectionBudget: @unchecked Sendable {
    let limit: Int
    private let live = Mutex(0)

    init(limit: Int) {
        self.limit = limit
    }

    /// Take one slot in the budget, or `nil` when it is full.
    func admit() -> InteroperableQUICConnectionLease? {
        let admitted = live.withLock { live -> Bool in
            guard live < limit else {
                return false
            }
            live += 1
            return true
        }
        guard admitted else {
            return nil
        }
        return InteroperableQUICConnectionLease { [self] in
            live.withLock { live in
                live = max(0, live - 1)
            }
        }
    }
}

/// One accepted connection's slot in a listener's concurrency budget.
///
/// Network.framework's `NetworkListener.newConnectionLimit` is a lifetime cap, not a
/// concurrency cap: measured on macOS 26.6.2, a listener built with a limit of 2
/// hands exactly two connections to its handler and never a third, even after both
/// have ended, and a connection that ends does not return its slot. The runtime
/// therefore runs its listeners without that limit and counts live connections
/// itself. A lease is taken when a connection is admitted and released when the
/// runtime is done with it.
///
/// The release is one-shot because a connection has several endings — clean close,
/// peer close, refused accept, dropped queue entry, released session — and no path
/// may return the same slot twice. Dropping the lease releases it, so a connection
/// abandoned between admission and a session cannot strand a slot.
final class InteroperableQUICConnectionLease: @unchecked Sendable {
    private let releaseSlot: @Sendable () -> Void
    private let released = Mutex(false)

    init(releaseSlot: @escaping @Sendable () -> Void) {
        self.releaseSlot = releaseSlot
    }

    deinit {
        release()
    }

    func release() {
        let alreadyReleased = released.withLock { released -> Bool in
            guard !released else {
                return true
            }
            released = true
            return false
        }
        guard !alreadyReleased else {
            return
        }
        releaseSlot()
    }
}

struct InteroperableQUICAcceptedConnection: Sendable {
    let connection: NetworkConnection<QUIC>
    let inboundStreams: InteroperableQUICInboundStreamCollector
    let inboundTask: Task<Void, Never>
    /// Held for as long as the connection is the runtime's to serve.
    let lease: InteroperableQUICConnectionLease
}

/// Queues accepted connections for whoever accepts them.
///
/// Generic over the element purely so the delivery and failure semantics can be tested
/// without a live QUIC connection, mirroring ``InteroperableQUICStreamQueue``; the runtime
/// only ever uses the `InteroperableQUICAcceptedConnection` specialization. `release` is
/// the element's teardown, because the runtime's element carries an inbound-stream handler
/// task that is parked and holds the connection alive, so dropping the reference alone
/// would not end it.
actor InteroperableQUICConnectionQueue<Element: Sendable> {
    /// A parked accept, tagged so its own caller can take it back out.
    ///
    /// `acceptSession` bounds the wait with a timeout, and a continuation that is only
    /// cancelled is never resumed. Untagged, such an abandoned waiter stays at the head
    /// of the queue, is handed the next accepted connection, and drops it, so the live
    /// accept behind it never sees a connection.
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<Element, Error>
    }

    private var queue: [Element] = []
    private var waiters: [Waiter] = []
    private var nextWaiterID: UInt64 = 0
    private var failure: Error?

    /// Releases an element this queue will never deliver.
    private let release: @Sendable (Element) -> Void

    init(release: @escaping @Sendable (Element) -> Void = { _ in }) {
        self.release = release
    }

    /// Delivered to parked accepts when the listener stops accepting.
    static var listenerStopped: WebTransportNetworkRuntimeError {
        .invalidTransport("listener is shutting down")
    }

    func enqueue(_ element: Element) {
        guard failure == nil else {
            // The listener has already failed, so nothing will ever serve this
            // connection. Its handler task would otherwise run for the lifetime
            // of the process.
            release(element)
            return
        }
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.continuation.resume(returning: element)
        } else {
            queue.append(element)
        }
    }

    func dequeue() async throws -> Element {
        if let failure {
            throw failure
        }
        if let element = queue.first {
            queue.removeFirst()
            return try releaseIfAbandoned(element)
        }
        let id = nextWaiterID
        nextWaiterID += 1
        let element = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiters.append(Waiter(id: id, continuation: continuation))
            }
        } onCancel: {
            Task { await self.removeWaiter(id) }
        }
        return try releaseIfAbandoned(element)
    }

    /// Hands a connection back if the task waiting for it has already been abandoned.
    ///
    /// `withTimeout` runs this `dequeue` in a separate unstructured task and, on expiry,
    /// cancels *that* task and throws to its own caller. Removing the parked waiter is an
    /// asynchronous actor hop, so an `enqueue` can win the race and resume the abandoned
    /// waiter with a connection. The value is then discarded, and without this the
    /// connection's handler task would keep the connection and its socket alive with
    /// nothing left to serve them. The check has to happen here, in the task that
    /// observes the cancellation — the caller's task is never cancelled.
    private func releaseIfAbandoned(_ element: Element) throws -> Element {
        if Task.isCancelled {
            release(element)
            throw CancellationError()
        }
        return element
    }

    /// Detaches a waiter whose caller has stopped waiting, and lets it unwind.
    ///
    /// The continuation must be resumed, not merely dropped. `withTimeout` abandons
    /// the operation task rather than awaiting it, so that task is still suspended on
    /// this continuation: dropping the reference leaves it suspended for the process
    /// lifetime and the Swift runtime reports a leaked continuation. Resuming with an
    /// error lets it unwind; the caller has already stopped waiting, so the value is
    /// discarded by its one-shot gate.
    ///
    /// This cannot resume twice: an entry is only ever resumed after it has been
    /// removed from `waiters`, and ids are unique.
    func removeWaiter(_ id: UInt64) {
        let removed = waiters.filter { $0.id == id }
        guard !removed.isEmpty else {
            return
        }
        waiters.removeAll { $0.id == id }
        for waiter in removed {
            waiter.continuation.resume(throwing: CancellationError())
        }
    }

    /// Fails every waiter and every later `dequeue` with the same error.
    ///
    /// The error is translated here, once, so a parked waiter resumed directly and a
    /// caller that reaches `dequeue` later both see the named error rather than a bare
    /// framework one (WT-197); see ``InteroperableQUICHelpers/connectionQueueFailure(role:error:)``.
    func fail(_ error: Error, role: String) {
        let translated = InteroperableQUICHelpers.connectionQueueFailure(role: role, error: error)
        failure = translated
        let waiters = self.waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume(throwing: translated)
        }
        cancelQueued()
    }

    /// Releases connections that were accepted but will never be served.
    ///
    /// Each carries a handler task that is parked in `inboundStreams` and holds
    /// the connection alive, so dropping the queue alone would not end them.
    func cancelQueued() {
        let abandoned = queue
        queue.removeAll()
        for element in abandoned {
            release(element)
        }
        // Parked accepts have to be woken as well. Shutdown previously left them
        // blocking for their whole timeout, and each one that then expired became
        // exactly the abandoned waiter described above.
        let parked = waiters
        waiters.removeAll()
        for waiter in parked {
            waiter.continuation.resume(throwing: Self.listenerStopped)
        }
    }
}

/// Holds a connection back until its inbound-stream handler is on the scheduler.
///
/// `connection.inboundStreams` can only be entered from inside a task, and a
/// freshly spawned task does not run at the point it is created. Starting the
/// connection first therefore opens a window in which the peer completes its
/// handshake, opens its HTTP/3 control stream, and has it delivered to a handler
/// that does not exist yet. Network.framework does not replay those streams, so
/// the control stream is lost and both ends wait for each other until the
/// operation times out.
///
/// The window is small and the loss is total, which is what made this present as
/// an occasional hang rather than a reproducible failure. Waiting here costs one
/// scheduling hop on a path that is about to perform a network handshake.
actor InteroperableQUICInboundRegistration {
    private var entered = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func markEntered() {
        guard !entered else {
            return
        }
        entered = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume()
        }
    }

    func waitUntilEntered() async {
        guard !entered else {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

/// What the inbound-stream collector did with a stream offered to it.
///
/// Spelled out rather than returned as a `Bool` so a caller cannot ignore a
/// refusal by accident. A stream the collector did not retain is one the peer
/// still believes is open, so the caller has to refuse it at the transport; see
/// ``InteroperableQUICStreamQueue/enqueue(_:direction:streamID:)``.
enum InteroperableQUICInboundStreamDisposition: Equatable, Sendable {
    /// The stream was handed to a parked caller, queued for the next one, or
    /// recognised as a repeat of a stream already delivered. In every one of
    /// those cases the caller must leave the stream alone — a duplicate is the
    /// live stream, not a new one, so refusing it would signal an error on a
    /// stream a reader is using.
    case accepted
    /// The per-direction ceiling is already reached, so nothing was retained.
    case refusedQueueFull(limit: Int)
    /// Inbound delivery for this connection has already failed, so nothing more
    /// can be retained.
    case refusedInboundDeliveryFailed
}

/// What the runtime did with a peer unidirectional stream that carries no
/// WebTransport prefix.
///
/// The outcomes are kept distinct because they call for different handling: a
/// retained stream is parked and the wait continues, an ignored one is an unknown
/// stream type discarded under RFC 9114 section 6.2, a defined-but-unserved type
/// is reported, and malformed bytes are the one case reported for their grammar.
enum InteroperableQUICPeerStreamClassification: Equatable, Sendable {
    /// A control or QPACK-encoder/decoder stream, retained for the connection's
    /// life and not delivered to the application.
    case retained
    /// An HTTP/3 stream type this runtime does not serve, and which RFC 9114
    /// section 6.2 forbids reporting as a connection error.
    case ignored
    /// A stream type HTTP/3 itself defines — the push stream — which this runtime
    /// has no use for and which is therefore reported rather than treated as
    /// unknown.
    case unserved
    /// The leading bytes are not a decodable HTTP/3 stream type at all.
    case malformed
}

/// The HTTP/3 stream types a connection is entitled to retain, in one place.
///
/// RFC 9114 section 6.2.1 allows exactly one control stream, and RFC 9204 section
/// 4.2 exactly one QPACK encoder and one decoder stream. Spelled out as a set so
/// the bound on retention is structural: a type outside it is refused on sight,
/// whatever a future caller passes.
enum InteroperableQUICCriticalStreamEntitlement {
    static let types: Set<UInt64> = [
        HTTP3StreamType.control,
        HTTP3StreamType.qpackEncoder,
        HTTP3StreamType.qpackDecoder,
    ]
}

typealias InteroperableQUICInboundStreamCollector = InteroperableQUICStreamQueue<QUIC.Stream<QUICStream>>

/// Delivers inbound streams to whoever is waiting for one of that direction.
///
/// Generic over the element purely so the delivery and timeout semantics can be
/// tested without a live QUIC connection; the runtime only ever uses the
/// `InteroperableQUICInboundStreamCollector` specialization below.
actor InteroperableQUICStreamQueue<Element: Sendable> {
    /// A parked caller. The identifier lets a timeout fail exactly its own
    /// waiter, so a stream delivered a moment earlier is never discarded.
    private struct Waiter {
        let id: UInt64
        let continuation: CheckedContinuation<Element, Error>
    }

    /// One inbound stream, identified so a repeat delivery can be recognised.
    private struct DeliveredStream: Hashable {
        let direction: Int
        let streamID: UInt64
    }

    private var queued: [Int: [Element]] = [:]
    private var waiting: [Int: [Waiter]] = [:]
    private var nextWaiterID: UInt64 = 0
    private let maxRememberedDeliveries = 4096
    private var deliveredKeys: Set<DeliveredStream> = []
    private var deliveryOrder: [DeliveredStream] = []
    /// How many leading entries of ``deliveryOrder`` have been evicted.
    private var deliveryHead = 0

    /// How many elements the delivery history moved while evicting.
    ///
    /// A cost probe for the regression test in `WebTransportInboundStreamQueueTests`:
    /// remembering a delivery must not shift the whole history.
    private(set) var deliveryOrderMoves = 0
    private var failure: Error?

    /// Ceiling on streams held at once for one direction.
    ///
    /// Taken from the transport limits this endpoint advertised, because that is
    /// the number of streams the peer was told it may have open. It is a
    /// *retention* bound rather than an enforcement of the advertisement — QUIC
    /// enforces that itself — so each entry keeps at least one slot: the CONNECT
    /// request stream and the peer's control stream can both arrive before a
    /// reader parks, and refusing those because an operator advertised zero
    /// streams would break the connection instead of bounding it.
    private let ceilingByDirection: [Int: Int]

    init(
        bidirectionalLimit: Int = WebTransportTransportLimits.default.initialMaxBidirectionalStreams,
        unidirectionalLimit: Int = WebTransportTransportLimits.default.initialMaxUnidirectionalStreams
    ) {
        ceilingByDirection = [
            InteroperableQUICHelpers.bidirectionalStreamDirection: max(1, bidirectionalLimit),
            InteroperableQUICHelpers.unidirectionalStreamDirection: max(1, unidirectionalLimit),
        ]
    }

    private func ceiling(for direction: Int) -> Int {
        ceilingByDirection[direction]
            ?? max(1, WebTransportTransportLimits.default.initialMaxBidirectionalStreams)
    }

    /// Peer control and QPACK streams, held for the lifetime of the connection.
    ///
    /// These are critical streams: RFC 9114 section 6.2.1 and RFC 9204 section
    /// 4.2 forbid closing them, and a peer that receives STOP_SENDING on one
    /// closes the connection with H3_CLOSED_CRITICAL_STREAM. Releasing the
    /// handle after reading lets the transport cancel the receive side, which
    /// the peer sees as exactly that. This collector is owned by the session, so
    /// anything parked here lives as long as the connection does.
    ///
    /// Retention is bounded by the protocol entitlement rather than by a
    /// separate ceiling: RFC 9114 section 6.2.1 allows exactly one control stream
    /// and RFC 9204 section 4.2 exactly one QPACK encoder and one decoder stream,
    /// so ``retainCritical(_:type:)`` refuses a second stream of a type it
    /// already holds. A peer that opens control-typed streams this endpoint has
    /// no consumer for therefore cannot make the runtime retain them, and each
    /// refused stream returns its unidirectional-stream credit instead of
    /// spending it for the connection's life.
    private var retainedCriticalStreams: [Element] = []

    /// The HTTP/3 stream types already represented in
    /// ``retainedCriticalStreams``.
    private var retainedCriticalTypes: Set<UInt64> = []

    /// How many critical peer streams this collector is holding.
    ///
    /// Exposed for the regression test in
    /// `WebTransportInboundStreamQueueTests`: retention used to be unbounded, so
    /// a peer could make this grow for the connection's whole life.
    var retainedCriticalCount: Int {
        retainedCriticalStreams.count
    }

    /// Retains a peer HTTP/3-critical stream, reporting whether the connection
    /// was entitled to one of that type.
    ///
    /// Returns `false` for any type outside
    /// ``InteroperableQUICCriticalStreamEntitlement`` and for a second stream of
    /// a type already retained; the caller reports the latter as
    /// `H3_STREAM_CREATION_ERROR`. Refusing rather than appending is also what
    /// bounds the memory this collector holds: the entitlement is one control,
    /// one encoder and one decoder stream, so the retained array can never exceed
    /// three entries.
    @discardableResult
    func retainCritical(_ stream: Element, type: UInt64) -> Bool {
        guard InteroperableQUICCriticalStreamEntitlement.types.contains(type),
            retainedCriticalTypes.insert(type).inserted
        else {
            return false
        }
        retainedCriticalStreams.append(stream)
        return true
    }

    /// Accepts an inbound stream, ignoring one that has already been delivered.
    ///
    /// A QUIC stream identifier is unique for the life of a connection and is
    /// never reused, so the same identifier arriving twice on the same collector
    /// is a repeat of a stream already handed out, not a new one. Passing it on
    /// is actively harmful: the peer's CONNECT request stream gets delivered a
    /// second time after the session is established, is taken for a new
    /// WebTransport stream, and fails the session with a stream-marker error
    /// against bytes the peer never framed that way.
    ///
    /// Only recent identifiers are remembered. A duplicate observed in practice
    /// follows its original almost immediately, and a connection is free to open
    /// unboundedly many streams over its lifetime, so retaining every identifier
    /// would trade this defect for unbounded growth.
    ///
    /// ## Retention bound and refusal
    ///
    /// At most ``ceiling(for:)`` streams are held per direction. RFC 9000
    /// section 4.6 stops counting a stream against `initial_max_streams_*` once
    /// it is closed, and a stream the peer FINs is closed whether or not the
    /// application read it, so the advertised stream limit does not bound how
    /// many stream objects a long-lived connection accumulates. Without a
    /// ceiling, a peer that opens streams this endpoint has no consumer for —
    /// post-establishment unidirectional streams in particular — makes the
    /// runtime retain each one, and the buffers behind it, until the connection
    /// ends.
    ///
    /// A stream that does not fit is **not** retained and is reported as
    /// ``InteroperableQUICInboundStreamDisposition/refusedQueueFull(limit:)``.
    /// The caller owns refusing it: dropping the handle alone tells the peer
    /// nothing, and the peer keeps writing into a stream this endpoint has
    /// forgotten. ``InteroperableQUICHelpers/enqueueInboundStream(_:into:role:)``
    /// is that caller for the runtime and performs the transport-level refusal.
    @discardableResult
    func enqueue(
        _ stream: Element,
        direction: Int,
        streamID: UInt64
    ) -> InteroperableQUICInboundStreamDisposition {
        guard failure == nil else {
            return .refusedInboundDeliveryFailed
        }
        let key = DeliveredStream(direction: direction, streamID: streamID)
        guard !deliveredKeys.contains(key) else {
            InteroperableQUICDebug.log("ignoring duplicate inbound stream delivery id=\(streamID)")
            return .accepted
        }
        deliveredKeys.insert(key)
        deliveryOrder.append(key)
        while deliveryOrder.count - deliveryHead > maxRememberedDeliveries {
            let evicted = deliveryOrder[deliveryHead]
            deliveryHead += 1
            deliveredKeys.remove(evicted)
        }
        compactDeliveryOrderIfWorthwhile()
        if var waiters = waiting[direction], !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            if waiters.isEmpty {
                waiting.removeValue(forKey: direction)
            } else {
                waiting[direction] = waiters
            }
            waiter.continuation.resume(returning: stream)
            return .accepted
        }
        let limit = ceiling(for: direction)
        guard (queued[direction]?.count ?? 0) < limit else {
            return .refusedQueueFull(limit: limit)
        }
        queued[direction, default: []].append(stream)
        return .accepted
    }

    /// Reclaims the evicted prefix once it is at least half the history.
    ///
    /// Removing from the front moves every remaining entry, so doing it per
    /// delivery is what made recording a delivery past the cap cost O(4,096).
    /// Waiting until the evicted prefix is as large as the live tail makes the
    /// move amortised O(1) per delivery.
    private func compactDeliveryOrderIfWorthwhile() {
        guard deliveryHead > 0 else {
            return
        }
        guard deliveryHead == deliveryOrder.count || deliveryHead * 2 >= deliveryOrder.count else {
            return
        }
        deliveryOrderMoves += deliveryOrder.count - deliveryHead
        deliveryOrder.removeFirst(deliveryHead)
        deliveryHead = 0
    }

    /// Removes and returns the oldest queued stream for `direction`.
    private func takeQueued(direction: Int) -> Element? {
        guard var streams = queued[direction], !streams.isEmpty else {
            return nil
        }
        let stream = streams.removeFirst()
        if streams.isEmpty {
            queued.removeValue(forKey: direction)
        } else {
            queued[direction] = streams
        }
        return stream
    }

    /// Waits for the next stream in `direction`, giving up after the timeout.
    ///
    /// The timeout is run as a task that resumes the waiter through the actor
    /// rather than by racing and abandoning the wait. Abandoning is what the
    /// general-purpose `withTimeout` does, and it is wrong here for two reasons:
    /// the abandoned waiter stays parked and a later stream is handed to a caller
    /// that already gave up — silently swallowing it — and the wait had to be
    /// entered from a separate task, which is a suspension point during which a
    /// stream can be queued and then never noticed. Here the waiter is resumed
    /// exactly once, by whichever of the two arrives first, and both run on the
    /// actor so neither can interleave with the other.
    func next(direction: Int, timeoutMilliseconds: Int32) async throws -> Element {
        if let failure {
            throw failure
        }
        if let stream = takeQueued(direction: direction) {
            return stream
        }
        guard timeoutMilliseconds > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
        }

        let id = nextWaiterID
        nextWaiterID &+= 1
        let timer = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(Int(timeoutMilliseconds)))
            await self?.expire(direction: direction, id: id, timeoutMilliseconds: timeoutMilliseconds)
        }
        defer {
            timer.cancel()
        }
        return try await waitFor(direction: direction, id: id)
    }

    /// Fails every waiter and every later `next` with the same error.
    ///
    /// The error is translated here, once, so a parked waiter resumed directly and a
    /// caller that reaches `next` (or `waitFor`'s own failure re-check) later both see the
    /// named error rather than a bare framework one (WT-197); see
    /// ``InteroperableQUICHelpers/connectionQueueFailure(role:error:)``.
    func fail(_ error: Error, role: String) {
        let translated = InteroperableQUICHelpers.connectionQueueFailure(role: role, error: error)
        failure = translated
        let waitingByDirection = waiting
        waiting.removeAll()
        // A failed collector can never deliver what it still holds: every later
        // `next` throws `error` before reaching the queue. Keeping the queued
        // streams would only pin the peer's stream objects and their buffers for
        // the remaining life of the connection.
        queued.removeAll()
        for (_, waiters) in waitingByDirection {
            for waiter in waiters {
                waiter.continuation.resume(throwing: translated)
            }
        }
    }

    /// Fails one specific waiter, identified so a stream that arrived first wins.
    private func expire(direction: Int, id: UInt64, timeoutMilliseconds: Int32) {
        guard var waiters = waiting[direction],
            let index = waiters.firstIndex(where: { $0.id == id })
        else {
            // Already resumed with a stream; the timeout lost the race.
            return
        }
        let waiter = waiters.remove(at: index)
        if waiters.isEmpty {
            waiting.removeValue(forKey: direction)
        } else {
            waiting[direction] = waiters
        }
        waiter.continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
    }

    private func waitFor(direction: Int, id: UInt64) async throws -> Element {
        return try await withCheckedThrowingContinuation { continuation in
            if let failure {
                continuation.resume(throwing: failure)
                return
            }
            // Re-check under the same actor step that parks: `next` may have
            // suspended between its own check and here.
            if let stream = takeQueued(direction: direction) {
                continuation.resume(returning: stream)
                return
            }
            waiting[direction, default: []].append(Waiter(id: id, continuation: continuation))
        }
    }
}
