import Foundation
import WebTransport

@main
struct WebTransportServerCLI {
    static func main() async {
        let configuration = WebTransportServerConfiguration(
            authority: "localhost",
            path: "/wt",
            origin: "https://localhost",
            supportedProtocols: ["demo.v1"]
        )
        _ = WebTransportServer(configuration: configuration)
        print("WebTransportServer demo endpoint ready: authority=\(configuration.authority) path=\(configuration.path)")
        print("Use `swift run WebTransportClient` to run the deterministic client/server facade demo.")
    }
}
