import Foundation
import Testing
import WebTransport
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportClientServerFacadeConnectsAndDeliversDatagram() async throws {
    let server = WebTransportServer(configuration: WebTransportServerConfiguration(
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        supportedProtocols: ["demo.v1"]
    ))
    let client = WebTransportClient(configuration: WebTransportClientConfiguration(
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        availableProtocols: ["demo.v1"]
    ))

    let session = try await client.connect(to: server)
    let datagrams = session.receiveDatagrams()
    try await session.sendDatagram(Data("ping".utf8))

    var iterator = datagrams.makeAsyncIterator()
    let received = try await iterator.next()
    #expect(received == Data("ping".utf8))

    try await session.close(code: 0, reason: "done")
}

@Test
func webTransportFacadeLogsOnlySanitizedProductionEvents() async throws {
    let clientEvents = WebTransportEventRecorder()
    let serverEvents = WebTransportEventRecorder()
    let server = WebTransportServer(
        configuration: WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["demo.v1"]
        ),
        logger: WebTransportLogger { serverEvents.append($0) }
    )
    let client = WebTransportClient(
        configuration: WebTransportClientConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            availableProtocols: ["demo.v1"]
        ),
        logger: WebTransportLogger { clientEvents.append($0) }
    )

    let session = try await client.connect(to: server)
    try await session.sendDatagram(Data("secret-payload".utf8))
    try await session.close(code: 7, reason: "secret-close-reason")

    let descriptions = (clientEvents.snapshot() + serverEvents.snapshot()).map(\.description)
    #expect(descriptions.contains("webtransport.client_control_exchanged"))
    #expect(descriptions.contains("webtransport.server_control_accepted"))
    #expect(descriptions.contains("webtransport.session_established role=client"))
    #expect(descriptions.contains("webtransport.session_established role=server"))
    #expect(descriptions.contains("webtransport.datagram_sent bytes=14"))
    #expect(descriptions.contains("webtransport.datagram_received bytes=14"))
    #expect(descriptions.contains("webtransport.session_closed code=7 reason_bytes=19"))
    for description in descriptions {
        #expect(!description.contains("secret-payload"))
        #expect(!description.contains("secret-close-reason"))
        #expect(!description.contains("session="))
        #expect(!description.contains("session_id"))
    }
}

@Test
func webTransportPublicErrorSurfaceRedactsPeerControlledDetail() {
    let draftError = WebTransportDraft15Error(kind: .requirementsNotMet, message: "secret-origin https://internal.example")
    #expect(WebTransportErrorSurface.publicDescription(for: draftError) == "WebTransport peer requirements were not met")

    let codecError = QUICCodecError.malformed("secret packet bytes 010203")
    #expect(WebTransportErrorSurface.publicDescription(for: codecError) == "WebTransport protocol codec rejected malformed input")
}

private final class WebTransportEventRecorder: @unchecked Sendable {
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
