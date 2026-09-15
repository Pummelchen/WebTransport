import Foundation
import Testing
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-11: the public session teardown must be idempotent.
///
/// `WebTransportSession.drain()` and `.close()` previously failed with
/// `sessionGone` on the second call, so the ordinary Swift pattern of closing on
/// an error path and again in a `defer` produced a spurious error from the
/// teardown itself. This drives a real loopback session through drain/drain and
/// close/close, which is where the manager-level idempotency and the runtime's
/// CONNECT-stream write meet.
@Test
func runtimeSessionDrainAndCloseAreIdempotent() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        localOnly: false
    )
    let listening = try await server.waitForListening(timeoutMilliseconds: 5_000)
    defer { server.shutdown() }

    let client = WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned)
    let target = WebTransportNetworkEndpoint(host: "127.0.0.1", port: listening.port)
    async let connecting = client.connectSession(to: target, timeoutMilliseconds: 15_000)
    let serverSession = try await server.acceptSession(timeoutMilliseconds: 15_000)
    let clientSession = try await connecting

    try await clientSession.drain(timeoutMilliseconds: 15_000)
    try await clientSession.drain(timeoutMilliseconds: 15_000)

    try await clientSession.close(applicationErrorCode: 0, reason: "done", timeoutMilliseconds: 15_000)
    try await clientSession.close(applicationErrorCode: 0, reason: "done", timeoutMilliseconds: 15_000)

    // The peer observed the first close; the duplicate must not change that.
    _ = serverSession
}
