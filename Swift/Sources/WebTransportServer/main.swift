import Foundation
import WebTransport
import WebTransportCLIConformance
import WebTransportNetworkRuntime

@main
struct WebTransportServerCLI {
    static func main() async {
        let executable = "WebTransportServer"
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--listen") || arguments.contains(where: { $0.hasPrefix("--listen=") }) {
            do {
                let options = try NetworkServerOptions.parse(arguments)
                let result: WebTransportNetworkProbeResult
                let local: WebTransportNetworkEndpoint
                switch options.transport {
                case .packet:
                    let server = try WebTransportQUICPacketProbeServer(bindPort: options.endpoint.port)
                    local = server.localEndpoint
                    print("network packet probe listening: \(local.host):\(local.port)")
                    result = try server.serveOne(timeoutMilliseconds: options.timeoutMilliseconds)
                case .frame:
                    let server = try WebTransportNetworkProbeServer(bindPort: options.endpoint.port)
                    local = server.localEndpoint
                    print("network frame probe listening: \(local.host):\(local.port)")
                    result = try server.serveOne(timeoutMilliseconds: options.timeoutMilliseconds)
                }
                print("network \(result.transport.rawValue) probe served: remote=\(result.remoteEndpoint.host):\(result.remoteEndpoint.port) message=\"\(result.message)\"")
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

private struct NetworkServerOptions {
    var endpoint: WebTransportNetworkEndpoint
    var timeoutMilliseconds: Int32
    var transport: WebTransportNetworkProbeTransport

    static func parse(_ arguments: [String]) throws -> NetworkServerOptions {
        var endpoint: WebTransportNetworkEndpoint?
        var timeoutMilliseconds: Int32 = 10_000
        var transport = WebTransportNetworkProbeTransport.packet
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--listen":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidEndpoint("--listen requires host:port")
                }
                endpoint = try WebTransportNetworkEndpoint.parse(arguments[index])
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
                if argument.hasPrefix("--listen=") {
                    endpoint = try WebTransportNetworkEndpoint.parse(String(argument.dropFirst("--listen=".count)))
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
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--listen requires host:port")
        }
        return NetworkServerOptions(
            endpoint: endpoint,
            timeoutMilliseconds: timeoutMilliseconds,
            transport: transport
        )
    }
}
