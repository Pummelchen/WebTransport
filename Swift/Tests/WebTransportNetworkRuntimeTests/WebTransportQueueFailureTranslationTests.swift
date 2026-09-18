import Foundation
import Network
import Testing
@testable import WebTransportNetworkRuntime

/// WT-197: a framework error delivered through a connection queue is named, not rethrown raw.
///
/// The earlier WT-185 fix translated the error at `waitForReady`, but two queues delivered
/// the framework's own error verbatim afterwards: `InteroperableQUICConnectionQueue.dequeue`
/// and `InteroperableQUICInboundStreamCollector.next`. Under Thread Sanitizer that reached
/// `listenerServesMoreSequentialSessionsThanTheDefaultCeiling` as a bare
/// `POSIXErrorCode(rawValue: 57)` (ENOTCONN) — the description of `NWError.posix(.ENOTCONN)`,
/// which is what Network.framework hands to both queues.
///
/// Both queues are also used *after* establishment, so naming their failure
/// `connectionEstablishmentFailed` would be false and would let
/// `isTransientEstablishmentFailure` retry a session that may already have carried data.
/// They are named `connectionTransportFailed` instead. These tests drive each boundary with
/// the framework error the runtime actually receives, without needing a live QUIC connection.
@Suite("Queue failure translation")
struct WebTransportQueueFailureTranslationTests {
    private static let direction = 1

    /// The observed escape: `NWError.posix(.ENOTCONN)` out of the connection queue.
    @Test
    func connectionQueueNamesAFrameworkFailureAtDequeue() async throws {
        let queue = InteroperableQUICConnectionQueue<Int>()
        await queue.fail(NWError.posix(.ENOTCONN), role: "server")

        let error = await #expect(throws: WebTransportNetworkRuntimeError.self) {
            _ = try await queue.dequeue()
        }
        let named = try #require(namedTransportFailure(error))
        #expect(named.role == "server")
        #expect(named.domain == NSPOSIXErrorDomain)
        #expect(named.code == Int(POSIXErrorCode.ENOTCONN.rawValue))
    }

    /// `fail` also resumes an already-parked accept directly, which is the other way a
    /// framework error reaches the same caller.
    @Test
    func connectionQueueNamesAFrameworkFailureForAParkedAccept() async throws {
        let queue = InteroperableQUICConnectionQueue<Int>()
        let parked = Task { try await queue.dequeue() }
        try await Task.sleep(for: .milliseconds(50))
        await queue.fail(NWError.posix(.ENETDOWN), role: "server")

        let result = await parked.result
        guard case .failure(let error) = result else {
            Issue.record("a failed connection queue should fail its parked accept")
            return
        }
        let named = try #require(namedTransportFailure(error))
        #expect(named.role == "server")
        #expect(named.code == Int(POSIXErrorCode.ENETDOWN.rawValue))
    }

    /// The inbound-stream boundary, reached the way the runtime reaches it: the collector
    /// fails, then a reader asks for the next stream.
    @Test
    func inboundStreamCollectorNamesAFrameworkFailureAtNext() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        await queue.fail(NWError.posix(.ENOTCONN), role: "client")

        let error = await #expect(throws: WebTransportNetworkRuntimeError.self) {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }
        let named = try #require(namedTransportFailure(error))
        #expect(named.role == "client")
        #expect(named.domain == NSPOSIXErrorDomain)
        #expect(named.code == Int(POSIXErrorCode.ENOTCONN.rawValue))
    }

    /// A reader already parked when the collector fails is resumed from inside `fail`, so
    /// it must see the same named error as a later `next` rather than the raw one.
    @Test
    func inboundStreamCollectorNamesAFrameworkFailureForAParkedReader() async throws {
        let queue = InteroperableQUICStreamQueue<Int>()
        let parked = Task {
            try await queue.next(direction: Self.direction, timeoutMilliseconds: 5_000)
        }
        try await Task.sleep(for: .milliseconds(50))
        await queue.fail(NWError.posix(.ENOTCONN), role: "client")

        let result = await parked.result
        guard case .failure(let error) = result else {
            Issue.record("a failed collector should fail its parked reader")
            return
        }
        let named = try #require(namedTransportFailure(error))
        #expect(named.role == "client")
        #expect(named.code == Int(POSIXErrorCode.ENOTCONN.rawValue))
    }

    /// The translated type is the accurate one, not the establishment case.
    ///
    /// A mid-session failure must not be retryable: `isTransientEstablishmentFailure` is
    /// what `serveSequentialSessions` retries on, and a session that has already carried
    /// data is not one to silently re-drive. Pinning that here is what keeps the new case
    /// from being folded into the establishment predicate later.
    @Test
    func aFrameworkFailureBecomesTheTransportCaseAndIsNotRetryable() async throws {
        let error = #expect(throws: WebTransportNetworkRuntimeError.self) {
            throw InteroperableQUICHelpers.connectionQueueFailure(
                role: "client",
                error: NWError.posix(.ENOTCONN)
            )
        }
        let runtimeError = try #require(error)
        guard case .connectionTransportFailed = runtimeError else {
            Issue.record("expected .connectionTransportFailed, got \(runtimeError)")
            return
        }
        #expect(!runtimeError.isTransientEstablishmentFailure)
        // The description carries the framework's domain and code so the failure stays
        // diagnosable, and names the role the queue supplied.
        #expect(runtimeError.description.contains("client"))
        #expect(runtimeError.description.contains(NSPOSIXErrorDomain))
        #expect(runtimeError.description.contains("\(POSIXErrorCode.ENOTCONN.rawValue)"))
    }

    /// The framework error can also arrive as the plain POSIX form rather than `NWError`.
    @Test
    func thePlainPOSIXFormIsNamedToo() {
        let translated = InteroperableQUICHelpers.connectionQueueFailure(
            role: "server",
            error: POSIXError(.ENOTCONN)
        )
        guard let runtimeError = translated as? WebTransportNetworkRuntimeError,
            case .connectionTransportFailed(let role, let domain, let code) = runtimeError
        else {
            Issue.record("a POSIXError should be named as a transport failure, got \(translated)")
            return
        }
        #expect(role == "server")
        #expect(domain == NSPOSIXErrorDomain)
        #expect(code == Int(POSIXErrorCode.ENOTCONN.rawValue))
    }

    /// An error the runtime did not receive from Network.framework is returned unchanged.
    ///
    /// Without this the translation would be a blanket rewrap, hiding the runtime's own
    /// named errors and cancellation behind a framework-shaped one.
    @Test
    func anErrorThatIsNotFromTheFrameworkPassesThrough() {
        let timeout = InteroperableQUICHelpers.connectionQueueFailure(
            role: "client",
            error: WebTransportNetworkRuntimeError.timeout(5_000)
        )
        #expect(timeout as? WebTransportNetworkRuntimeError == .timeout(5_000))

        struct CallerFailure: Error {}
        let caller = InteroperableQUICHelpers.connectionQueueFailure(
            role: "client",
            error: CallerFailure()
        )
        #expect(caller is CallerFailure)
    }
}

/// The fields of a named transport failure.
///
/// A struct rather than a tuple: three named members is past the point a tuple reads as a
/// value, and the call sites are unchanged because the member names are the same.
private struct NamedTransportFailure {
    let role: String
    let domain: String
    let code: Int
}

/// Extracts the fields of the named transport failure, or reports why it is not one.
private func namedTransportFailure(
    _ error: (any Error)?
) -> NamedTransportFailure? {
    guard let runtimeError = error as? WebTransportNetworkRuntimeError else {
        return nil
    }
    guard case .connectionTransportFailed(let role, let domain, let code) = runtimeError else {
        return nil
    }
    return NamedTransportFailure(role: role, domain: domain, code: code)
}
