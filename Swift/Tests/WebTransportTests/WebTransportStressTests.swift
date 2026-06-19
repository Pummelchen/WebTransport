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

    for index in 0..<iterations {
        let server = WebTransportServer(configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["soak.v1"]
        ))
        let client = WebTransportClient(configuration: WebTransportClientConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            availableProtocols: ["soak.v1"]
        ))
        let session = try await client.connect(to: server)
        let payload = Data("soak-\(index)".utf8)
        let stream = session.receiveDatagrams()
        try await session.sendDatagram(payload)
        var iterator = stream.makeAsyncIterator()
        #expect(try await iterator.next() == payload)
        try await session.close(code: UInt32(index & 0xffff), reason: "soak-close")
    }
}

@Test
func webTransportFacadeLoadKeepsLogSurfaceBoundedToCounts() async throws {
    let events = WebTransportStressEventRecorder()
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(authority: "localhost", path: "/wt"),
        logger: WebTransportLogger { events.append($0) }
    )
    let client = WebTransportClient(
        configuration: WebTransportClientConfiguration(authority: "localhost", path: "/wt"),
        logger: WebTransportLogger { events.append($0) }
    )
    let session = try await client.connect(to: server)
    let stream = session.receiveDatagrams()
    var iterator = stream.makeAsyncIterator()

    for index in 0..<256 {
        let payload = Data("load-secret-payload-\(index)".utf8)
        try await session.sendDatagram(payload)
        #expect(try await iterator.next() == payload)
    }
    try await session.close(code: 0, reason: "load-secret-close")

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
