import Foundation
import WebTransport
import WebTransportCLIConformance

@main
struct WebTransportClientCLI {
    static func main() async {
        let executable = "WebTransportClient"
        do {
            let options = try WebTransportCLIConformanceOptions.parse(
                executableName: executable,
                arguments: Array(CommandLine.arguments.dropFirst())
            )
            if !CommandLine.arguments.dropFirst().isEmpty {
                Foundation.exit(await WebTransportCLIConformance.run(options: options))
            }
        } catch WebTransportCLIConformanceExit.requestedHelp {
            print(WebTransportCLIConformance.helpText(executableName: executable))
            return
        } catch WebTransportCLIConformanceExit.requestedList {
            print(WebTransportCLIConformance.listText())
            return
        } catch WebTransportCLIConformanceExit.invalidArguments(let message) {
            fputs("\(executable) argument error: \(message)\n", stderr)
            fputs(WebTransportCLIConformance.helpText(executableName: executable) + "\n", stderr)
            Foundation.exit(2)
        } catch {
            fputs("\(executable) argument error: \(error)\n", stderr)
            Foundation.exit(2)
        }

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
