import Foundation
import Testing
import WebTransport

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
