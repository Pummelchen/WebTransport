import Foundation
import Testing
@testable import WebTransportNetworkRuntime
import WebTransportHTTP3Core
import WebTransportQUICCore

// Regression coverage for a stale accept waiter.
//
// `acceptSession` bounds the queue wait with a timeout, and a continuation that is only
// cancelled is never resumed. Untagged, the abandoned waiter stayed at the head of the
// connection queue, was handed the next accepted connection, and dropped it — so the
// live accept behind it never saw a connection. In the documented accept loop
// (`while true { try await acceptSession() }`, default timeout one second) every
// connection arriving after an idle period was lost.

@Test
func timedOutAcceptDoesNotStarveTheNextAccept() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
    defer { server.shutdown() }

    // Plant a stale waiter: nothing connects, so this times out and leaves a
    // continuation parked in the connection queue.
    await #expect(throws: Error.self) {
        _ = try await server.acceptSession(timeoutMilliseconds: 200)
    }

    // Park a real accept, then connect. The connection must reach this accept rather
    // than being handed to the abandoned waiter.
    let acceptTask = Task {
        try await server.acceptSession(timeoutMilliseconds: 8_000)
    }
    try await Task.sleep(for: .milliseconds(150))

    let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
    let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
    let clientTask = Task {
        try await client.connectSession(to: target, timeoutMilliseconds: 8_000)
    }

    // Without the fix this throws a timeout: the abandoned waiter consumed the
    // connection and this accept never saw one.
    let accepted = try await acceptTask.value
    #expect(accepted.remoteEndpoint.port != 0)

    let clientSession = try await clientTask.value
    #expect(clientSession.sessionID == accepted.sessionID)
}

/// Shutdown must wake a parked accept rather than leaving it to time out, which is how
/// the abandoned waiters above were created in the first place.
@Test
func shutdownWakesAParkedAccept() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    _ = try await server.waitForListening(timeoutMilliseconds: 5_000)

    let acceptTask = Task {
        try await server.acceptSession(timeoutMilliseconds: 30_000)
    }
    try await Task.sleep(for: .milliseconds(200))

    let started = Date()
    server.shutdown()
    await #expect(throws: Error.self) {
        _ = try await acceptTask.value
    }
    let elapsed = Date().timeIntervalSince(started)
    #expect(elapsed < 5.0, "shutdown should wake a parked accept at once, took \(elapsed)s")
}
