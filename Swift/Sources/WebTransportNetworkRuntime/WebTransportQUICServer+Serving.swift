import Foundation
import CryptoKit
import Network
import Security
import Synchronization
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

extension WebTransportQUICServer {
    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkSessionResult {
        let session = try await acceptSession(timeoutMilliseconds: timeoutMilliseconds)

        // The peer picks the transport, so the server cannot. `datagramsAvailable`
        // now states whether `SETTINGS_H3_DATAGRAM` was negotiated, but a peer that
        // negotiated it can still open a stream, and a browser that did not is
        // stream-only from the start. Waiting only for a datagram hung on a peer
        // that had already opened a stream, so when datagrams are negotiated this
        // waits for both and echoes on whichever the peer actually used.
        // Racing means one entrant loses and is abandoned, and an abandoned
        // entrant keeps the session alive until its own wait expires. Handing it
        // the caller's full timeout makes that window arbitrarily long: with a
        // ten-minute timeout under sustained churn, sessions accumulate at the
        // churn rate for ten minutes. Measured as resident growth that scales
        // with the configured timeout and vanishes at short ones.
        //
        // The wait is therefore capped. A peer that has established a session
        // and then sent nothing for this long is not mid-exchange, so the cap
        // costs nothing real while bounding what an abandoned entrant can hold.
        let echoed: Data
        if session.datagramsAvailable {
            let raceTimeout = min(timeoutMilliseconds, Self.firstMessageWaitMilliseconds)
            echoed = try await InteroperableQUICHelpers.raceFirstSuccess([
                { try await Self.echoOneDatagram(on: session, timeoutMilliseconds: raceTimeout) },
                { try await Self.echoOneStream(on: session, timeoutMilliseconds: raceTimeout) },
            ])
        } else {
            echoed = try await Self.echoOneStream(on: session, timeoutMilliseconds: timeoutMilliseconds)
        }
        await session.waitForPeerClosure(timeoutMilliseconds: min(timeoutMilliseconds, 250))
        guard let echoedMessage = String(data: echoed, encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return WebTransportNetworkSessionResult(
            localEndpoint: session.localEndpoint,
            remoteEndpoint: session.remoteEndpoint,
            message: echoedMessage,
            transport: session.transport,
            sessionEstablished: true
        )
    }

    /// Longest the sample echo server waits for a peer's first message.
    ///
    /// Bounds how long an abandoned race entrant can keep a session alive,
    /// independently of how generous the caller's session timeout is.
    static let firstMessageWaitMilliseconds: Int32 = 15_000

    /// Receives one datagram and echoes it back verbatim.
    private static func echoOneDatagram(
        on session: WebTransportNetworkSession,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        let payload = try await session.receiveDatagram(timeoutMilliseconds: timeoutMilliseconds)
        try await session.sendDatagram(payload, timeoutMilliseconds: timeoutMilliseconds)
        return payload
    }

    /// Accepts one bidirectional stream and echoes its payload back verbatim.
    private static func echoOneStream(
        on session: WebTransportNetworkSession,
        timeoutMilliseconds: Int32
    ) async throws -> Data {
        let stream = try await session.acceptBidirectionalStream(timeoutMilliseconds: timeoutMilliseconds)
        let payload = try await stream.receive(timeoutMilliseconds: timeoutMilliseconds)
        try await stream.send(payload, endOfStream: true, timeoutMilliseconds: timeoutMilliseconds)
        return payload
    }
}

