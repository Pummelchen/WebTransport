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
                var results: [WebTransportNetworkSessionResult] = []
                let local: WebTransportNetworkEndpoint
                switch options.transport {
                case .packet:
                    let server = try WebTransportQUICServer(
                        endpoint: options.endpoint,
                        maxConcurrentConnections: options.maxSessions
                    )
                    local = try await server.waitForListening(timeoutMilliseconds: options.timeoutMilliseconds)
                    print("network packet session listening: \(local.commandLineValue)")
                    fflush(stdout)
                    let tasks: [Task<WebTransportNetworkSessionResult, Error>] = (0..<options.maxSessions).map { _ in
                        Task {
                            try await server.serveOne(timeoutMilliseconds: options.timeoutMilliseconds)
                        }
                    }
                    for task in tasks {
                        do {
                            let result = try await task.value
                            results.append(result)
                        } catch {
                            fputs("network packet session serve error: \(error)\n", stderr)
                        }
                    }
                case .frame:
                    let server = try WebTransportQUICServer(
                        endpoint: options.endpoint,
                        maxConcurrentConnections: options.maxSessions
                    )
                    local = try await server.waitForListening(timeoutMilliseconds: options.timeoutMilliseconds)
                    print("network frame session listening: \(local.commandLineValue)")
                    fflush(stdout)
                    let tasks: [Task<WebTransportNetworkSessionResult, Error>] = (0..<options.maxSessions).map { _ in
                        Task {
                            try await server.serveOne(timeoutMilliseconds: options.timeoutMilliseconds)
                        }
                    }
                    for task in tasks {
                        do {
                            let result = try await task.value
                            results.append(result)
                        } catch {
                            fputs("network frame session serve error: \(error)\n", stderr)
                        }
                    }
                }
                for result in results {
                    let session = result.sessionEstablished ? " session=established" : ""
                    print("network \(result.transport.rawValue) session served: remote=\(result.remoteEndpoint.commandLineValue)\(session) message=\"\(result.message)\"")
                }
                return
            } catch {
                fputs("\(executable) network session failed: \(error)\n", stderr)
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
        print("WebTransportServer local demo endpoint ready: authority=\(configuration.authority) path=\(configuration.path)")
        print("Use `swift run WebTransportClient --connect HOST:PORT` with a listening server for the Network.framework QUIC session path.")
    }
}

private struct NetworkServerOptions {
    var endpoint: WebTransportNetworkEndpoint
    var timeoutMilliseconds: Int32
    var transport: WebTransportNetworkTransport
    var maxSessions: Int

    static func parse(_ arguments: [String]) throws -> NetworkServerOptions {
        var endpoint: WebTransportNetworkEndpoint?
        var timeoutMilliseconds: Int32 = 10_000
        var transport = WebTransportNetworkTransport.packet
        var maxSessions = 1
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
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                timeoutMilliseconds = value
            case "--transport":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidTransport("--transport requires packet or frame")
                }
                transport = try WebTransportNetworkTransport.parse(arguments[index])
            case "--max-sessions":
                index += 1
                guard index < arguments.count, let value = Int(arguments[index]), value > 0 else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                maxSessions = value
            default:
                if argument.hasPrefix("--listen=") {
                    endpoint = try WebTransportNetworkEndpoint.parse(String(argument.dropFirst("--listen=".count)))
                } else if argument.hasPrefix("--timeout-ms="),
                          let value = Int32(argument.dropFirst("--timeout-ms=".count)) {
                    timeoutMilliseconds = value
                } else if argument.hasPrefix("--transport=") {
                    transport = try WebTransportNetworkTransport.parse(String(argument.dropFirst("--transport=".count)))
                } else if argument.hasPrefix("--max-sessions="),
                          let value = Int(argument.dropFirst("--max-sessions=".count)), value > 0 {
                    maxSessions = value
                } else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
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
            transport: transport,
            maxSessions: maxSessions
        )
    }
}
