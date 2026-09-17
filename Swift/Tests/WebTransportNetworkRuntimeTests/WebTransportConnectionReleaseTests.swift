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
/// 2. Closing the session sends WT_CLOSE_SESSION, and the side that RECEIVES it releases its connection: the
///    capsule has arrived, nothing is in flight towards the peer, and the connection serves one session. That
///    closes the socket on both ends within about 50 ms, which is the fix for the leak WT-85 recorded — and it
///    needs no grace period, because the message it must not overtake is the one that triggered it.
/// 3. Dropping a session that was never closed cancels its tasks (`deinit`) and releases the connection the same
///    way, which the peer notices just as quickly.
///
/// The closing side's own initiative is still the one that needs a policy: a peer that does not release (a
/// third-party implementation) leaves the closing side's socket open until QUIC's idle timeout, or until the
/// session object is dropped. That is recorded in the tracker row and in [[Known Limitations]].
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

/// The fix: the peer that receives the close releases its connection, and the socket goes away on BOTH ends.
@Test
func closingASessionReleasesTheConnectionOnThePeerThatReceivesIt() async throws {
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

    let (clientHalf, serverHalf) = try await connectSessionPair(server: server)
    let clientConnection = clientHalf.underlyingConnection
    let peerConnection = serverHalf.underlyingConnection
    #expect(clientConnection.state == .ready)
    #expect(peerConnection.state == .ready)

    try await clientHalf.close(applicationErrorCode: 0, reason: "wt-85")

    // The server releases when the capsule arrives; the client's own connection then fails because the socket it
    // was using is gone. Neither side waits for the idle timeout, and the caller does not have to drop anything.
    let peerGone = try await waitUntilNotReady(peerConnection, withinMilliseconds: 3_000)
    #expect(peerGone != nil, "the peer did not release the connection its session's close ended")
    let clientGone = try await waitUntilNotReady(clientConnection, withinMilliseconds: 3_000)
    #expect(clientGone != nil, "the closing side's connection outlived the peer's release")
}

/// The other release path, unchanged by the fix: a session dropped without a close still hands its connection back,
/// and the peer notices just as quickly.
@Test
func droppingASessionWithoutClosingItReleasesTheConnection() async throws {
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

    // Inline for the same reason as ever: a `let` binding of the client half would keep the session alive past
    // the `nil` that is the measurement.
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
    let peerConnection = serverHalf.underlyingConnection
    #expect(peerConnection.state == .ready)
    #expect(clientSession != nil, "the session has to exist before it is dropped")

    clientSession = nil
    let peerGone = try await waitUntilNotReady(peerConnection, withinMilliseconds: 3_000)
    #expect(peerGone != nil, "dropping the session did not release the peer's connection within 3s")
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
