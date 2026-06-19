import Foundation
import WebTransport

@main
struct WebTransportClientCLI {
    static func main() async {
        do {
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
            let stream = session.receiveDatagrams()
            try await session.sendDatagram(Data("hello from WebTransportClient".utf8))
            var iterator = stream.makeAsyncIterator()
            if let datagram = try await iterator.next(), let text = String(data: datagram, encoding: .utf8) {
                print("client received datagram echo path: \(text)")
            }
            try await session.close(code: 0, reason: "client demo complete")
            print("WebTransportClient demo completed")
        } catch {
            fputs("WebTransportClient failed: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }
}
