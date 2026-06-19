import Foundation
import WebTransport
import WebTransportCLIConformance
import WebTransportNetworkRuntime

@main
struct WebTransportClientCLI {
    static func main() async {
        let executable = "WebTransportClient"
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--connect") || arguments.contains(where: { $0.hasPrefix("--connect=") }) {
            do {
                let options = try NetworkClientOptions.parse(arguments)
                let result: WebTransportNetworkProbeResult
                switch options.transport {
                case .packet:
                    result = try await WebTransportQUICInteroperablePacketProbeClient().run(
                        to: options.endpoint,
                        message: options.message,
                        timeoutMilliseconds: options.timeoutMilliseconds
                    )
                case .frame:
                    result = try await WebTransportQUICInteroperablePacketProbeClient().run(
                        to: options.endpoint,
                        message: options.message,
                        timeoutMilliseconds: options.timeoutMilliseconds
                    )
                }
                let session = result.sessionEstablished ? " session=established" : ""
                print("network \(result.transport.rawValue) probe connected: local=\(result.localEndpoint.host):\(result.localEndpoint.port) remote=\(result.remoteEndpoint.host):\(result.remoteEndpoint.port)\(session) message=\"\(result.message)\"")
                return
            } catch {
                fputs("\(executable) network probe failed: \(error)\n", stderr)
                Foundation.exit(1)
            }
        }

        do {
            let options = try WebTransportCLIConformanceOptions.parse(
                executableName: executable,
                arguments: arguments
            )
            if !arguments.isEmpty {
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

private struct NetworkClientOptions {
    var endpoint: WebTransportNetworkEndpoint
    var message: String
    var timeoutMilliseconds: Int32
    var transport: WebTransportNetworkProbeTransport

    static func parse(_ arguments: [String]) throws -> NetworkClientOptions {
        var endpoint: WebTransportNetworkEndpoint?
        var message = "webtransport-network-probe"
        var timeoutMilliseconds: Int32 = 1_000
        var transport = WebTransportNetworkProbeTransport.packet
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--connect":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidEndpoint("--connect requires host:port")
                }
                endpoint = try WebTransportNetworkEndpoint.parse(arguments[index])
            case "--message":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidProbePayload
                }
                message = arguments[index]
            case "--timeout-ms":
                index += 1
                guard index < arguments.count, let value = Int32(arguments[index]) else {
                    throw WebTransportNetworkRuntimeError.invalidProbePayload
                }
                timeoutMilliseconds = value
            case "--transport":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidTransport("--transport requires packet or frame")
                }
                transport = try WebTransportNetworkProbeTransport.parse(arguments[index])
            default:
                if argument.hasPrefix("--connect=") {
                    endpoint = try WebTransportNetworkEndpoint.parse(String(argument.dropFirst("--connect=".count)))
                } else if argument.hasPrefix("--message=") {
                    message = String(argument.dropFirst("--message=".count))
                } else if argument.hasPrefix("--timeout-ms="),
                          let value = Int32(argument.dropFirst("--timeout-ms=".count)) {
                    timeoutMilliseconds = value
                } else if argument.hasPrefix("--transport=") {
                    transport = try WebTransportNetworkProbeTransport.parse(String(argument.dropFirst("--transport=".count)))
                } else {
                    throw WebTransportNetworkRuntimeError.invalidProbePayload
                }
            }
            index += 1
        }

        guard let endpoint else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--connect requires host:port")
        }
        return NetworkClientOptions(
            endpoint: endpoint,
            message: message,
            timeoutMilliseconds: timeoutMilliseconds,
            transport: transport
        )
    }
}
