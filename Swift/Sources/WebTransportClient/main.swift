import Foundation
import WebTransport
import WebTransportCLIConformance
import WebTransportHTTP3Core
import WebTransportNetworkRuntime

@main
struct WebTransportClientCLI {
    static func main() async {
        let executable = "WebTransportClient"
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--connect") || arguments.contains(where: { $0.hasPrefix("--connect=") }) {
            do {
                let options = try NetworkClientOptions.parse(arguments)
                guard options.transport == .packet else {
                    throw WebTransportNetworkRuntimeError.invalidTransport(
                        "real --connect sessions support packet transport only"
                    )
                }
                let result = try await WebTransportQUICClient(
                    trustPolicy: options.trustPolicy
                ).run(
                    to: options.endpoint,
                    message: options.message,
                    authority: options.authority,
                    path: options.path,
                    origin: options.origin,
                    protocols: options.protocols,
                    settingsValidation: options.settingsValidation,
                    exchangeMode: options.exchangeMode,
                    timeoutMilliseconds: options.timeoutMilliseconds
                )
                let session = result.sessionEstablished ? " session=established" : ""
                print("network \(result.transport.rawValue) session connected: local=\(result.localEndpoint.commandLineValue) remote=\(result.remoteEndpoint.commandLineValue)\(session) exchange=\(options.exchangeMode.rawValue) message=\"\(result.message)\"")
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

        do {
            let server = WebTransportServer(configuration: WebTransportServerConfiguration(
                authority: "localhost",
                path: "/wt",
                origin: "https://localhost",
                supportedProtocols: ["demo.v1"],
                timeoutMilliseconds: 12_000
            ))
            let client = WebTransportClient(configuration: WebTransportClientConfiguration(
                authority: "localhost",
                path: "/wt",
                origin: "https://localhost",
                availableProtocols: ["demo.v1"],
                trustPolicy: .localDevelopmentSelfSigned,
                timeoutMilliseconds: 12_000
            ))
            let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
            async let served = listener.serveOne()
            let result = try await client.echo(to: listener.localEndpoint, message: "hello from WebTransportClient")
            _ = try await served
            print("client received reliable stream echo path: \(result.message)")
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
    var transport: WebTransportNetworkTransport
    var authority: String?
    var path: String
    var origin: String?
    var protocols: [String]
    var trustPolicy: WebTransportQUICPeerTrustPolicy
    var settingsValidation: HTTP3WebTransportSettingsValidation
    var exchangeMode: WebTransportNetworkExchangeMode

    static func parse(_ arguments: [String]) throws -> NetworkClientOptions {
        var endpoint: WebTransportNetworkEndpoint?
        var message = "webtransport-network-session"
        var timeoutMilliseconds: Int32 = 1_000
        var transport = WebTransportNetworkTransport.packet
        var authority: String?
        var path = "/wt"
        var origin: String? = "https://localhost"
        var protocols = ["demo.v1"]
        var trustPolicy: WebTransportQUICPeerTrustPolicy?
        var settingsValidation = HTTP3WebTransportSettingsValidation.draft15Strict
        var exchangeMode = WebTransportNetworkExchangeMode.auto
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
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                message = arguments[index]
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
            case "--authority":
                index += 1
                guard index < arguments.count, !arguments[index].isEmpty else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                authority = arguments[index]
            case "--path":
                index += 1
                guard index < arguments.count, arguments[index].hasPrefix("/") else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                path = arguments[index]
            case "--origin":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                origin = arguments[index] == "none" ? nil : arguments[index]
            case "--protocol":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                protocols = arguments[index] == "none" ? [] : [arguments[index]]
            case "--trust":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                trustPolicy = try WebTransportQUICPeerTrustPolicy.parse(arguments[index])
            case "--settings-validation":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                settingsValidation = try HTTP3WebTransportSettingsValidation.parse(arguments[index])
            case "--exchange":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidTransport("--exchange requires auto, stream, or datagram")
                }
                exchangeMode = try WebTransportNetworkExchangeMode.parse(arguments[index])
            default:
                if argument.hasPrefix("--connect=") {
                    endpoint = try WebTransportNetworkEndpoint.parse(String(argument.dropFirst("--connect=".count)))
                } else if argument.hasPrefix("--message=") {
                    message = String(argument.dropFirst("--message=".count))
                } else if argument.hasPrefix("--timeout-ms="),
                          let value = Int32(argument.dropFirst("--timeout-ms=".count)) {
                    timeoutMilliseconds = value
                } else if argument.hasPrefix("--transport=") {
                    transport = try WebTransportNetworkTransport.parse(String(argument.dropFirst("--transport=".count)))
                } else if argument.hasPrefix("--authority=") {
                    let value = String(argument.dropFirst("--authority=".count))
                    guard !value.isEmpty else {
                        throw WebTransportNetworkRuntimeError.invalidPayload
                    }
                    authority = value
                } else if argument.hasPrefix("--path=") {
                    let value = String(argument.dropFirst("--path=".count))
                    guard value.hasPrefix("/") else {
                        throw WebTransportNetworkRuntimeError.invalidPayload
                    }
                    path = value
                } else if argument.hasPrefix("--origin=") {
                    let value = String(argument.dropFirst("--origin=".count))
                    origin = value == "none" ? nil : value
                } else if argument.hasPrefix("--protocol=") {
                    let value = String(argument.dropFirst("--protocol=".count))
                    protocols = value == "none" ? [] : [value]
                } else if argument.hasPrefix("--trust=") {
                    trustPolicy = try WebTransportQUICPeerTrustPolicy.parse(String(argument.dropFirst("--trust=".count)))
                } else if argument.hasPrefix("--settings-validation=") {
                    settingsValidation = try HTTP3WebTransportSettingsValidation.parse(String(argument.dropFirst("--settings-validation=".count)))
                } else if argument.hasPrefix("--exchange=") {
                    exchangeMode = try WebTransportNetworkExchangeMode.parse(String(argument.dropFirst("--exchange=".count)))
                } else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
            }
            index += 1
        }

        guard let endpoint else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--connect requires host:port")
        }
        let resolvedTrustPolicy = trustPolicy ?? .systemTrust
        return NetworkClientOptions(
            endpoint: endpoint,
            message: message,
            timeoutMilliseconds: timeoutMilliseconds,
            transport: transport,
            authority: authority,
            path: path,
            origin: origin,
            protocols: protocols,
            trustPolicy: resolvedTrustPolicy,
            settingsValidation: settingsValidation,
            exchangeMode: exchangeMode
        )
    }

}
