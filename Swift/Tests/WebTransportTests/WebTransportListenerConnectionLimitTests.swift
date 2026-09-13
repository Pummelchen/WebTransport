import Foundation
import Testing
import WebTransport
import WebTransportNetworkRuntime

/// `NetworkListener.newConnectionLimit` is a lifetime cap, not a concurrency cap.
///
/// Measured on macOS 26.6.2 with a minimal listener: built with a limit of 2, it
/// hands exactly two connections to its handler and never a third, even after both
/// have ended and been cancelled. The runtime passed `maxConcurrentConnections`
/// straight through to it, so a listener stopped accepting forever once that many
/// *total* sessions had been served (issue #23), which reads to an operator as a
/// healthy process whose new WebTransport sessions all time out.
///
/// A ceiling on simultaneous sessions is what the policy advertises, so the runtime
/// enforces it itself and leaves the framework's lifetime cap alone. This test
/// serves more sequential sessions than the ceiling and requires every one to be
/// accepted.
@Test
func listenerServesMoreSequentialSessionsThanItsConcurrencyLimit() async throws {
    let concurrencyLimit = 2
    let rounds = 5
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["demo.v1"],
            timeoutMilliseconds: 5_000,
            admission: WebTransportAdmissionPolicy(maxConcurrentConnections: concurrencyLimit)
        )
    )
    let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    defer { listener.shutdown() }

    for round in 1...rounds {
        let client = WebTransportClient(
            configuration: WebTransportClientConfiguration(
                authority: "localhost",
                path: "/wt",
                origin: "https://localhost",
                availableProtocols: ["demo.v1"],
                trustPolicy: .localDevelopmentSelfSigned,
                timeoutMilliseconds: 5_000
            )
        )
        async let accepted = listener.acceptSession()
        let session = try await client.connect(to: listener.localEndpoint)
        let serverSession = try await accepted
        #expect(session.selectedProtocol == "demo.v1")
        #expect(serverSession.selectedProtocol == "demo.v1")
        // Session number `concurrencyLimit + 1` is the one the framework's lifetime
        // cap used to swallow. Close cleanly, as a client loop reconnecting on each
        // launch does, and require the listener to take the next one.
        try await session.close(applicationErrorCode: 0, reason: "round-\(round)")
    }
}

/// The other half of the ceiling: it has to still refuse.
///
/// Moving `maxConcurrentConnections` out of `newConnectionLimit` must not leave the
/// listener accepting everything. With a ceiling of one and a session already
/// established, a second connection must not become a session — either its handshake
/// never completes or the accept never returns before its timeout. The old
/// implementation also refused this, for a reason that turned out to be fatal to the
/// listener; the test is here so that dropping the ceiling altogether cannot pass
/// unnoticed.
@Test
func listenerRefusesConnectionsBeyondItsConcurrencyLimit() async throws {
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["demo.v1"],
            timeoutMilliseconds: 5_000,
            admission: WebTransportAdmissionPolicy(maxConcurrentConnections: 1)
        )
    )
    let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    defer { listener.shutdown() }

    func makeClient() -> WebTransportClient {
        WebTransportClient(
            configuration: WebTransportClientConfiguration(
                authority: "localhost",
                path: "/wt",
                origin: "https://localhost",
                availableProtocols: ["demo.v1"],
                trustPolicy: .localDevelopmentSelfSigned,
                timeoutMilliseconds: 5_000
            )
        )
    }

    async let firstAccepted = listener.acceptSession()
    let firstSession = try await makeClient().connect(to: listener.localEndpoint)
    let firstServerSession = try await firstAccepted
    #expect(firstSession.selectedProtocol == "demo.v1")
    #expect(firstServerSession.selectedProtocol == "demo.v1")

    // The ceiling is reached, so this connection is refused at the accept handler.
    async let secondConnect: Void = {
        do {
            _ = try await makeClient().connect(to: listener.localEndpoint)
        } catch {
            // Refused at the transport level: the handshake never completed.
        }
    }()
    await #expect(throws: (any Error).self) {
        _ = try await listener.acceptSession()
    }
    await secondConnect

    try await firstSession.close(applicationErrorCode: 0, reason: "done")
}
