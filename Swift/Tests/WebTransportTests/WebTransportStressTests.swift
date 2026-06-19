import Foundation
import Testing
import WebTransport
import WebTransportHTTP3Core

@Test
func webTransportConcurrentMultiSessionStress() async throws {
    var pair = try WebTransportLibrarySmokePair.connectedWithFlowControl()
    var sessionIDs: [WebTransportSessionID] = []
    for index in 0..<16 {
        sessionIDs.append(try pair.establishSession(
            streamID: UInt64(index * 4),
            request: WebTransportSessionRequest(authority: "example.com", path: "/stress-\(index)")
        ))
    }

    for (index, sessionID) in sessionIDs.enumerated() {
        _ = try pair.server.manager.receiveDatagramFrame(.datagram(try WebTransportDatagramSignaling.serialize(
            sessionID: sessionID.rawValue,
            payload: Data("stress-datagram-\(index)".utf8)
        )))
        #expect(pair.server.manager.popDatagramPayload(sessionID: sessionID) == Data("stress-datagram-\(index)".utf8))
    }
}

@Test
func webTransportDeterministicSoakRunsRepeatedSessionLifecycle() async throws {
    let iterations = Int(ProcessInfo.processInfo.environment["WEBTRANSPORT_SOAK_ITERATIONS"] ?? "") ?? 128

    var pair = try WebTransportLibrarySmokePair.connectedWithFlowControl()
    for index in 0..<iterations {
        let payload = Data("soak-\(index)".utf8)
        let sessionID = try pair.establishSession(
            streamID: UInt64(index * 4),
            request: WebTransportSessionRequest(
                authority: "localhost",
                path: "/wt",
                origin: "https://localhost",
                availableProtocols: ["soak.v1"]
            )
        )
        _ = try pair.server.manager.receiveDatagramFrame(.datagram(try WebTransportDatagramSignaling.serialize(
            sessionID: sessionID.rawValue,
            payload: payload
        )))
        #expect(pair.server.manager.popDatagramPayload(sessionID: sessionID) == payload)
        _ = try pair.server.manager.receiveFlowControlCapsuleWithActions(
            sessionID: sessionID,
            bytes: try pair.client.manager.makeCloseSessionCapsule(
                sessionID: sessionID,
                applicationErrorCode: UInt32(index & 0xffff),
                message: "soak-close"
            )
        )
    }
}

@Test
func webTransportPublicAPILoadKeepsLogSurfaceBoundedToCounts() async throws {
    let events = WebTransportStressEventRecorder()
    let logger = WebTransportLogger { events.append($0) }

    for index in 0..<256 {
        let payload = Data("load-secret-payload-\(index)".utf8)
        logger.record(.datagramSent(byteCount: payload.count))
        logger.record(.datagramReceived(byteCount: payload.count))
    }
    logger.record(.sessionClosed(applicationErrorCode: 0, reasonByteCount: Data("load-secret-close".utf8).count))

    let descriptions = events.snapshot().map(\.description)
    #expect(descriptions.filter { $0.contains("webtransport.datagram_sent") }.count == 256)
    #expect(descriptions.filter { $0.contains("webtransport.datagram_received") }.count == 256)
    for description in descriptions {
        #expect(!description.contains("load-secret-payload"))
        #expect(!description.contains("load-secret-close"))
        #expect(!description.contains("session_id"))
    }
}

private final class WebTransportStressEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [WebTransportLogEvent] = []

    func append(_ event: WebTransportLogEvent) {
        lock.lock()
        events.append(event)
        lock.unlock()
    }

    func snapshot() -> [WebTransportLogEvent] {
        lock.lock()
        let copy = events
        lock.unlock()
        return copy
    }
}
