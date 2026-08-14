import Foundation
import Testing
@testable import WebTransportNetworkRuntime
import WebTransportHTTP3Core
import WebTransportQUICCore

// Graceful shutdown, from the operator's point of view: a deploy should stop
// taking new work and tell existing peers it is going away, rather than
// severing every live connection and letting each one discover the loss on
// timeout.

@Test
func shutdownStopsAcceptingImmediatelyRatherThanBlockingUntilTimeout() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    _ = try await server.waitForListening(timeoutMilliseconds: 5_000)

    server.shutdown()

    // The point is the *speed* of the refusal. Before shutdown closed the accept
    // gate, this call blocked for its full timeout before failing, which on a
    // deploy means every in-flight accept hangs for seconds after the operator
    // asked the listener to stop.
    let started = Date()
    await #expect(throws: Error.self) {
        _ = try await server.acceptSession(timeoutMilliseconds: 5_000)
    }
    let elapsed = Date().timeIntervalSince(started)
    #expect(elapsed < 1.0, "accept should refuse at once after shutdown, took \(elapsed)s")
}

@Test
func gracefulShutdownStopsAcceptingAndCompletesWithNoLiveSessions() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    _ = try await server.waitForListening(timeoutMilliseconds: 5_000)

    // With nothing served, this must return promptly rather than waiting out the
    // whole grace period.
    let started = Date()
    await server.shutdown(gracePeriodMilliseconds: 5_000)
    let elapsed = Date().timeIntervalSince(started)
    #expect(elapsed < 2.0, "shutdown with no sessions should not wait out the grace period, took \(elapsed)s")

    await #expect(throws: Error.self) {
        _ = try await server.acceptSession(timeoutMilliseconds: 1_000)
    }
}

@Test
func gracefulShutdownIsIdempotentAndSafeToRepeat() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    _ = try await server.waitForListening(timeoutMilliseconds: 5_000)

    // A shutdown path that only works once is a liability: signal handlers and
    // deployment tooling routinely fire it more than once.
    await server.shutdown(gracePeriodMilliseconds: 500)
    await server.shutdown(gracePeriodMilliseconds: 500)
    server.shutdown()

    await #expect(throws: Error.self) {
        _ = try await server.acceptSession(timeoutMilliseconds: 500)
    }
}

@Test
func goawayFrameNamesTheFirstUnservedRequestStream() throws {
    // RFC 9114 section 5.2: a server's GOAWAY carries the first client-initiated
    // bidirectional stream it will NOT process, so everything already accepted
    // stays honoured. Client bidirectional stream IDs advance by four.
    var manager = WebTransportSessionManager(
        http3: HTTP3ConnectionState(role: .server, localSettings: .webTransportDraft16Defaults),
        settingsValidation: .draft16Strict
    )
    let frame = try manager.makeGoawayFrame(streamID: 4)
    #expect(frame.type == HTTP3FrameType.goaway)
    #expect(try frame.singleVarIntPayload() == 4)

    // The identifier must be recorded on the live connection state, not on a
    // discarded copy, or the endpoint cannot reject what it promised not to serve.
    #expect(manager.http3.sentGoawayID == 4)
}
