import Foundation
import Network
import Testing
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-02: `waitForReady` used to park a
/// `withCheckedThrowingContinuation` that only its connection observer could
/// resume. `withTimeout` cancels the operation task on expiry, but a checked
/// continuation does not observe cancellation, so the abandoned task stayed
/// suspended — retaining the connection observer's continuation and everything
/// the wait captured — for as long as the connection stayed non-terminal, i.e.
/// for the life of the process against a peer that completes the UDP path and
/// then stalls the handshake.
///
/// The leak is observable without reaching into the runtime: the closure the
/// caller hands to `start` is captured by the abandoned wait, so while the wait
/// leaks, a marker that only that closure owns stays alive. This test drops
/// every other reference and requires the marker to be released once the
/// timeout has fired.
@Test
func waitForReadyReleasesTheAbandonedWaitWhenTheHandshakeTimesOut() async throws {
    let destination = NWEndpoint.hostPort(host: .ipv4(.loopback), port: 9)
    // Never started: the connection stays in `.setup`, so the wait can only end
    // by timing out — exactly the hostile/broken-peer path.
    let connection = NetworkConnection(to: destination) {
        QUIC(alpn: ["h3"]) { UDP() }
    }
    defer { withExtendedLifetime(connection) {} }

    weak var weakMarker: InteroperableQUICWaitMarker?
    do {
        let start = makeMarkerCapturingStart(weakMarker: &weakMarker)
        await #expect(throws: WebTransportNetworkRuntimeError.self) {
            try await InteroperableQUICHelpers.waitForReady(
                connection: connection,
                role: "test",
                start: start,
                timeoutMilliseconds: 100
            )
        }
    }

    // The timeout has fired; give the abandoned task a bounded moment to unwind
    // and release the closure. Before the fix it never unwinds.
    for _ in 0..<50 where weakMarker != nil {
        try await Task.sleep(for: .milliseconds(20))
    }
    #expect(
        weakMarker == nil,
        "waitForReady leaked its abandoned continuation and the closure it captured"
    )
}

/// Builds the marker and the `start` closure that is its only strong owner in a
/// separate function, so nothing in the test body itself keeps the marker alive.
@inline(never)
private func makeMarkerCapturingStart(
    weakMarker: inout InteroperableQUICWaitMarker?
) -> @Sendable () -> Void {
    let marker = InteroperableQUICWaitMarker()
    weakMarker = marker
    return { marker.touch() }
}

private final class InteroperableQUICWaitMarker: @unchecked Sendable {
    func touch() {}
}
