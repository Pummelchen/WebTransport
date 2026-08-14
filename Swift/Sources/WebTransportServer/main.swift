import Foundation
import WebTransport
import WebTransportCLIConformance
import WebTransportHTTP3Core
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
                guard options.transport == .packet else {
                    throw WebTransportNetworkRuntimeError.invalidTransport(
                        "real --listen sessions support packet transport only"
                    )
                }
                let server = try WebTransportQUICServer(
                    endpoint: options.endpoint,
                    maxConcurrentConnections: options.maxSessions,
                    authority: options.authority,
                    path: options.path,
                    allowedOrigin: options.allowedOrigin,
                    protocols: options.protocols,
                    settingsValidation: options.settingsValidation,
                    identity: options.identity
                )
                let local = try await server.waitForListening(timeoutMilliseconds: options.timeoutMilliseconds)
                writeStandardOutput(
                    "network packet session listening: \(local.commandLineValue)\n"
                    + "network packet session certificate-sha256: \(server.certificateSHA256.base64EncodedString())\n"
                )
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
                        writeStandardError("network packet session serve error: \(error)\n")
                    }
                }
                for result in results {
                    let session = result.sessionEstablished ? " session=established" : ""
                    print("network \(result.transport.rawValue) session served: remote=\(result.remoteEndpoint.commandLineValue)\(session) message=\"\(result.message)\"")
                }
                return
            } catch {
                writeStandardError("\(executable) network session failed: \(error)\n")
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
            writeStandardError("\(executable) argument error: \(message)\n")
            writeStandardError(WebTransportCLIConformance.helpText(executableName: executable) + "\n")
            Foundation.exit(2)
        } catch {
            writeStandardError("\(executable) argument error: \(error)\n")
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

private func writeStandardOutput(_ message: String) {
    FileHandle.standardOutput.write(Data(message.utf8))
}

private func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

private struct NetworkServerOptions {
    var endpoint: WebTransportNetworkEndpoint
    var timeoutMilliseconds: Int32
    var transport: WebTransportNetworkTransport
    var maxSessions: Int
    var authority: String
    var path: String
    var allowedOrigin: String?
    var protocols: [String]
    var settingsValidation: HTTP3WebTransportSettingsValidation
    var identity: WebTransportServerIdentity

    static func parse(_ arguments: [String]) throws -> NetworkServerOptions {
        var endpoint: WebTransportNetworkEndpoint?
        var timeoutMilliseconds: Int32 = 10_000
        var transport = WebTransportNetworkTransport.packet
        var maxSessions = 1
        var authority = "localhost"
        var path = "/wt"
        var allowedOrigin: String? = "https://localhost"
        var protocols = ["demo.v1"]
        var settingsValidation = HTTP3WebTransportSettingsValidation.draft16Strict
        var pkcs12Path: String?
        var pkcs12Passphrase = ""
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
                allowedOrigin = arguments[index] == "none" ? nil : arguments[index]
            case "--protocol":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                protocols = arguments[index] == "none" ? [] : [arguments[index]]
            case "--identity-pkcs12":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                pkcs12Path = arguments[index]
            case "--identity-passphrase":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                pkcs12Passphrase = arguments[index]
            case "--settings-validation":
                index += 1
                guard index < arguments.count else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
                settingsValidation = try HTTP3WebTransportSettingsValidation.parse(arguments[index])
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
                    allowedOrigin = value == "none" ? nil : value
                } else if argument.hasPrefix("--protocol=") {
                    let value = String(argument.dropFirst("--protocol=".count))
                    protocols = value == "none" ? [] : [value]
                } else if argument.hasPrefix("--settings-validation=") {
                    let value = String(argument.dropFirst("--settings-validation=".count))
                    settingsValidation = try HTTP3WebTransportSettingsValidation.parse(value)
                } else {
                    throw WebTransportNetworkRuntimeError.invalidPayload
                }
            }
            index += 1
        }

        guard let endpoint else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--listen requires host:port")
        }
        // Without an injected identity the listener falls back to the
        // development certificate, which is refused on any non-loopback bind.
        // That is what previously made this executable unable to serve anything
        // but loopback.
        let identity: WebTransportServerIdentity
        if let pkcs12Path {
            let url = URL(fileURLWithPath: pkcs12Path)
            guard let bundle = try? Data(contentsOf: url) else {
                throw WebTransportNetworkRuntimeError.invalidTransport(
                    "could not read PKCS#12 bundle at \(pkcs12Path)"
                )
            }
            identity = .pkcs12(data: bundle, passphrase: pkcs12Passphrase)
        } else {
            identity = .developmentSelfSigned
        }

        return NetworkServerOptions(
            endpoint: endpoint,
            timeoutMilliseconds: timeoutMilliseconds,
            transport: transport,
            maxSessions: maxSessions,
            authority: authority,
            path: path,
            allowedOrigin: allowedOrigin,
            protocols: protocols,
            settingsValidation: settingsValidation,
            identity: identity
        )
    }
}
