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
    try await serveSequentialSessions(concurrencyLimit: 2, rounds: 5)
}

/// The shape the defect was reported in: the default ceiling of 16, with more sessions
/// than that attempted in sequence. The issue's measurements were 16 accepted, then 0
/// and 0 for the next twenty attempts, in the same process — a listener that had stopped
/// accepting for the rest of its life while the process stayed healthy.
@Test
func listenerServesMoreSequentialSessionsThanTheDefaultCeiling() async throws {
    try await serveSequentialSessions(concurrencyLimit: 16, rounds: 20)
}

private func serveSequentialSessions(concurrencyLimit: Int, rounds: Int) async throws {
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["demo.v1"],
            // The accept has to outlive the longest possible retry, or a recovered
            // transient would still fail the round: `acceptSession()` takes no timeout of
            // its own, so its budget is this value while the client's is 5 s per attempt
            // (see `connectWithTransientRetry`). 25 s covers 4 x 5 s with margin. It costs
            // nothing on the happy path — the waits return as soon as data arrives — and a
            // round against a genuinely broken listener fails on the *client's* timeout,
            // because the connect is what times out first.
            timeoutMilliseconds: 25_000,
            admission: WebTransportAdmissionPolicy(maxConcurrentConnections: concurrencyLimit)
        )
    )
    let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
    defer { listener.shutdown() }

    for round in 1...rounds {
        try await serveOneSession(listener: listener, round: round)
    }
}

/// Serves one session, retrying a connect the transport could not establish at all.
///
/// WT-185: on a loaded runner the framework fails the connection itself —
/// `NetworkConnection.State.failed` with `ENETDOWN` (50) or `ENOTCONN` (57) — which this
/// runtime now reports as `WebTransportNetworkRuntimeError.connectionEstablishmentFailed`
/// instead of rethrowing a bare `POSIXErrorCode`. That is the runner's network stack, not
/// this package's admission ceiling, so the connect is retried rather than counted against
/// the property under test.
///
/// **The retry cannot hide the defect this file exists for (issue #23).** A listener that
/// has stopped accepting never completes a handshake, so a round against one fails as a
/// `timeout` after the client's configured 5 s — and `timeout` is not the case retried
/// here. Only a named establishment failure whose framework error is one of the transient
/// POSIX codes is retried, and only `attempts` times; anything else, or an exhausted
/// budget, is rethrown so the round still fails loudly.
///
/// One accept waiter serves the whole round, so a retried connect is served by the same
/// waiter rather than by a new one. Opening a fresh accept per attempt and abandoning the
/// previous one would introduce a real hazard: the connection queue removes a cancelled
/// waiter asynchronously, so a connection can be handed to one that is already gone and
/// released instead of served — losing the very connection the retry is waiting for.
///
/// The waiter is not, however, reserved for the attempt that succeeds. The listener
/// enqueues a connection as soon as it arrives, independently of what the client's own
/// state does next, so the waiter can be handed the connection of an attempt that has
/// since failed. That cannot turn into a false pass — the mismatched client session then
/// fails on its own — but it can turn a recovered transient into a failure, which is why
/// the accept's budget is sized to cover the whole retry window.
private func serveOneSession(listener: WebTransportListeningServer, round: Int) async throws {
    let accepted = Task { try await listener.acceptSession() }
    do {
        let session = try await connectWithTransientRetry(listener: listener)
        let serverSession = try await accepted.value
        #expect(session.selectedProtocol == "demo.v1")
        #expect(serverSession.selectedProtocol == "demo.v1")
        // Session number `concurrencyLimit + 1` is the one the framework's lifetime
        // cap used to swallow. Close cleanly, as a client loop reconnecting on each
        // launch does, and require the listener to take the next one.
        try await session.close(applicationErrorCode: 0, reason: "round-\(round)")
    } catch {
        accepted.cancel()
        throw error
    }
}

/// Connects to the listener, retrying only a transient establishment failure (WT-185).
private func connectWithTransientRetry(listener: WebTransportListeningServer) async throws -> WebTransportSession {
    let attempts = 4
    var lastError: (any Error)?
    for attempt in 1...attempts {
        do {
            return try await makeSequentialClient().connect(to: listener.localEndpoint)
        } catch {
            lastError = error
            let runtimeError = error as? WebTransportNetworkRuntimeError
            guard runtimeError?.isTransientEstablishmentFailure == true, attempt < attempts else {
                throw error
            }
            // A brief pause before asking a stack that has just reported itself
            // unavailable to build another connection.
            try await Task.sleep(for: .milliseconds(50))
        }
    }
    throw lastError ?? WebTransportNetworkRuntimeError.timeout(0)
}

private func makeSequentialClient() -> WebTransportClient {
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

/// The other half of the ceiling: it has to still refuse.
///
/// Moving `maxConcurrentConnections` out of `newConnectionLimit` must not leave the
/// listener accepting everything. With a ceiling of one and a session already
/// established, a second connection must not become a session — either its handshake
/// never completes or the accept never returns before its timeout. The old
/// implementation also refused this, for a reason that turned out to be fatal to the
/// listener; the test is here so that dropping the ceiling altogether cannot pass
/// unnoticed.
///
/// F-swift-perf-tests-12: this test timed out once under parallel load and passed
/// alone and on re-runs. Every wait in it is now explicitly bounded and a
/// load-induced establishment failure is retried a fixed number of times, after
/// which the last error is rethrown, so a busy machine cannot hang the test while
/// a listener that really accepts past its ceiling still fails it.
@Test
func listenerRefusesConnectionsBeyondItsConcurrencyLimit() async throws {
    var lastError: (any Error)?
    for _ in 1...3 {
        do {
            try await observeRefusalBeyondTheConcurrencyCeiling()
            return
        } catch {
            lastError = error
            try await Task.sleep(for: .milliseconds(200))
        }
    }
    throw lastError ?? WebTransportNetworkRuntimeError.timeout(0)
}

private func observeRefusalBeyondTheConcurrencyCeiling() async throws {
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

    // The first session has to exist before the ceiling can be reached. A loaded
    // runner can fail this establishment at the transport level, which is not
    // what this test is about; the retry budget in the caller covers that.
    async let firstAccepted = listener.acceptSession()
    let firstSession = try await connectWithTransientRetry(listener: listener)
    let firstServerSession = try await firstAccepted
    #expect(firstSession.selectedProtocol == "demo.v1")
    #expect(firstServerSession.selectedProtocol == "demo.v1")

    // The ceiling is reached, so this connection is refused at the accept handler
    // and its handshake never completes.
    let secondConnect = Task { () -> Bool in
        do {
            _ = try await makeSequentialClient().connect(to: listener.localEndpoint)
            return true
        } catch {
            return false
        }
    }
    await #expect(throws: (any Error).self) {
        _ = try await listener.acceptSession()
    }
    // Bound the refused client's wait explicitly instead of awaiting it
    // unconditionally: `nil` means the transport never resolved within the bound,
    // which is itself a refusal, and it cannot hang the test.
    let secondEstablished = await boundedValue(secondConnect, milliseconds: 2_000)
    #expect(
        secondEstablished != true,
        "the listener established a second session past its concurrency ceiling"
    )

    try await firstSession.close(applicationErrorCode: 0, reason: "done")
}

/// Waits for `task` for at most `milliseconds`, then cancels it and returns `nil`.
private func boundedValue<T: Sendable>(_ task: Task<T, Never>, milliseconds: Int) async -> T? {
    await withTaskGroup(of: T?.self) { group in
        group.addTask { await task.value }
        group.addTask { () -> T? in
            try? await Task.sleep(for: .milliseconds(milliseconds))
            return nil
        }
        let first = await group.next() ?? nil
        group.cancelAll()
        return first
    }
}
