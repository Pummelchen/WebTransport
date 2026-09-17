import Foundation
import Network
import Testing
@testable import WebTransportNetworkRuntime

/// WT-85: what a WebTransport session's end does to the QUIC connection underneath it.
///
/// `NetworkConnection` declares no `cancel()` — checked by compiling against the macOS 26, 26.5 and 27 and
/// the iPhoneOS 27 interfaces, where the only `cancel()` declarations belong to the legacy `NW*` classes
/// — so how a connection this package started can be released is a question about the framework's own
/// properties. These two tests answer it with a real session rather than by reading the interface, and
/// what they pin is the *reason* a close-time release is not simply done:
///
/// 1. `applicationError` is the obvious candidate: Apple documents it as "the QUIC application error code
///    to send for the connection, or received from the peer" and it has a setter. Writing it to a ready
///    connection stores the value and does nothing else — the state stays `.ready` — so it is a code to
///    carry when the connection ends, not a way to end it.
/// 2. Closing the session sends WT_CLOSE_SESSION and leaves BOTH connections `.ready`. That is the leak
///    WT-85 records.
/// 3. Dropping the session cancels its tasks (`deinit`) and the peer's connection then fails within a few
///    hundred milliseconds. The connection IS releaseable from this package; what stops `close()` from
///    doing it is the close message itself — releasing the connection abandons what is still in flight on
///    it, and what is in flight is the capsule carrying the peer the session's code and reason (draft-16
///    section 5.4). A release at close time needs a bounded grace for that capsule, which is a policy
///    choice rather than a missing API.
///
/// A failure of the "still ready" expectations below is not necessarily bad news: it means the framework
/// (or this runtime) began releasing the connection on one of those steps, and the tracker row and
/// [[Known Limitations]] need updating rather than the test.
@Test
func applicationErrorIsNotAReleasePath() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        path: "/wt",
        allowedOrigin: "https://localhost",
        protocols: ["demo.v1"],
        localOnly: true,
        admission: WebTransportAdmissionPolicy(maxConcurrentConnections: 2)
    )
    defer { server.shutdown() }

    // The peer's half is held for the whole test: dropping it would cancel its tasks, which releases its
    // connection and takes this one with it — the very mechanism the other test measures.
    let (clientHalf, serverHalf) = try await connectSessionPair(server: server)
    var clientSession: WebTransportNetworkSession? = clientHalf
    let connection = try #require(clientSession?.underlyingConnection)
    #expect(serverHalf.underlyingConnection.state == .ready)
    #expect(connection.state == .ready)

    connection.applicationError = NWProtocolQUIC.ApplicationError(code: 0x1234, reason: "wt-85")
    #expect(connection.applicationError.code == 0x1234, "the code the framework would carry is stored")

    try await Task.sleep(for: .milliseconds(1_000))
    #expect(
        connection.state == .ready,
        "writing applicationError closed a ready connection, which contradicts the WT-85 record and would be the release path to adopt"
    )
    clientSession = nil
}

/// The half that names the release path, and the one a fix would build on.
@Test
func closingASessionLeavesItsConnectionUntilTheSessionIsDropped() async throws {
    let server = try WebTransportQUICServer(
        endpoint: WebTransportNetworkEndpoint(host: "127.0.0.1", port: 0),
        authority: "localhost",
        path: "/wt",
        allowedOrigin: "https://localhost",
        protocols: ["demo.v1"],
        localOnly: true,
        admission: WebTransportAdmissionPolicy(maxConcurrentConnections: 2)
    )
    defer { server.shutdown() }

    // Established inline rather than through the helper below: the helper returns both halves as a tuple,
    // and a `let` binding of the client half would keep the session alive past the `clientSession = nil`
    // that is the measurement. `serverHalf` has to be held all the same — dropping it ends the peer's
    // session and releases its connection, which is the mechanism this test measures.
    let endpoint = try await server.waitForListening(timeoutMilliseconds: 5_000)
    async let accepted = server.acceptSession(timeoutMilliseconds: 10_000)
    var clientSession: WebTransportNetworkSession? = try await WebTransportQUICClient(
        trustPolicy: .localDevelopmentSelfSigned
    ).connectSession(
        to: endpoint,
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        protocols: ["demo.v1"],
        optimisticCapsules: [],
        settingsValidation: .draft16Strict,
        timeoutMilliseconds: 8_000
    )
    let serverHalf = try await accepted
    let clientConnection = try #require(clientSession?.underlyingConnection)
    let peerConnection = serverHalf.underlyingConnection
    #expect(clientConnection.state == .ready)
    #expect(peerConnection.state == .ready)

    try await clientSession?.close(applicationErrorCode: 0, reason: "wt-85")

    try await Task.sleep(for: .milliseconds(1_500))
    #expect(
        clientConnection.state == .ready,
        "the closing side released its own connection at close(), so WT-85 is fixed on that side"
    )
    #expect(
        peerConnection.state == .ready,
        "the peer released its connection on the close capsule, so WT-85 is fixed on that side"
    )

    // Dropping the session is the path that exists. It has to be prompt — the point of the row is that the
    // alternative is the QUIC idle timeout, which is thirty seconds — so a release inside three seconds is
    // the assertion, and the measured figure is in the row's note.
    clientSession = nil
    let releasedAfter = try await waitUntilNotReady(peerConnection, withinMilliseconds: 3_000)
    #expect(releasedAfter != nil, "dropping the session did not release the peer's connection within 3s")
}

/// Establishes one session on a loopback `server` and returns both halves.
///
/// Both are returned deliberately: a test that keeps only the client half and drops the server's ends the
/// peer's session, which releases the peer's connection and fails the client's — so the caller has to hold
/// both to measure what one side's close does.
private func connectSessionPair(
    server: WebTransportQUICServer
) async throws -> (client: WebTransportNetworkSession, server: WebTransportNetworkSession) {
    let endpoint = try await server.waitForListening(timeoutMilliseconds: 5_000)
    async let accepted = server.acceptSession(timeoutMilliseconds: 10_000)
    let client = try await WebTransportQUICClient(trustPolicy: .localDevelopmentSelfSigned).connectSession(
        to: endpoint,
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        protocols: ["demo.v1"],
        optimisticCapsules: [],
        settingsValidation: .draft16Strict,
        timeoutMilliseconds: 8_000
    )
    return (client, try await accepted)
}

/// Polls until the connection leaves `.ready`, returning how long that took in milliseconds, or `nil` if it
/// was still ready when the budget ran out.
private func waitUntilNotReady(
    _ connection: NetworkConnection<QUIC>,
    withinMilliseconds milliseconds: Int
) async throws -> Int? {
    var elapsed = 0
    while elapsed < milliseconds {
        if connection.state != .ready {
            return elapsed
        }
        try await Task.sleep(for: .milliseconds(20))
        elapsed += 20
    }
    return connection.state != .ready ? elapsed : nil
}
