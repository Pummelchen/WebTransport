import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore
@testable import WebTransportNetworkRuntime

/// F-swift-perf-tests-06: a wait for the peer's close must be resumed by the
/// close path, not polled out of the manager actor on a 5 ms timer.
///
/// The old `waitForPeerClosure` loop took the manager actor and read the session
/// state every 5 ms for up to 250 ms — up to 50 hops per echo — to notice a
/// transition the close path can signal directly. The probe counts state reads,
/// so the assertion is an operation count rather than a wall-clock bound.
@Suite("Session close wait")
struct WebTransportSessionCloseWaitTests {
    @Test
    func theClosePathResumesAClosureWaitWithoutPolling() async throws {
        let state = WebTransportNetworkSessionManagerState(
            manager: try makeServerManagerWithAcceptedSession()
        )
        let sessionID: UInt64 = 0

        async let parked: Void = state.waitForSessionClosure(
            sessionID: sessionID,
            timeoutMilliseconds: 5_000
        )

        // Readiness: registration is synchronous on the actor, so a bounded wait
        // confirms the waiter is parked before the close is driven.
        var isParked = false
        for _ in 0..<200 {
            if await state.waitingClosureCount == 1 {
                isParked = true
                break
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(isParked, "the closure wait did not park")

        // Leave the waiter parked long enough that a 5 ms poll would have read the
        // state many times before the close arrives.
        try await Task.sleep(for: .milliseconds(100))

        // Drive the transition the runtime's close-capsule path drives: a
        // `withManager` mutation that marks the session closed.
        await state.withManager { manager in
            _ = try? manager.makeCloseSessionCapsuleResult(
                sessionID: WebTransportSessionID(rawValue: sessionID),
                applicationErrorCode: 0,
                message: "done"
            )
        }
        await parked

        let stateReads = await state.closureWaitStateReads
        #expect(
            stateReads <= 5,
            "the wait read the session state \(stateReads) times; a signalled wait needs only the fast path, the registration and the close"
        )
        let stillParked = await state.waitingClosureCount
        #expect(stillParked == 0)
    }
}

/// A server-side manager holding one accepted session (id 0).
private func makeServerManagerWithAcceptedSession() throws -> WebTransportSessionManager {
    var clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
    _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
    var client = WebTransportSessionManager(http3: clientHTTP3)
    var server = WebTransportSessionManager(http3: serverHTTP3)

    let requestFrame = try client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )
    _ = try server.receiveClientSessionRequest(
        streamID: 0,
        frame: requestFrame,
        policy: try WebTransportServerSessionPolicy()
    )
    return server
}
