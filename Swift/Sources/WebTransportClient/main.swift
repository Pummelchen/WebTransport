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
            await runNetworkSession(arguments: arguments, executable: executable)
            return
        }
        // The conformance CLI answers --help and --list itself; only an invocation it did
        // not handle falls through to the demo.
        if await runConformance(arguments: arguments, executable: executable) {
            return
        }
        await runDemo()
    }

    /// `--connect`: one real network session against a running peer.
    private static func runNetworkSession(arguments: [String], executable: String) async {
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
            print(
                "network \(result.transport.rawValue) session connected: local=\(result.localEndpoint.commandLineValue) "
                    + "remote=\(result.remoteEndpoint.commandLineValue)\(session) exchange=\(options.exchangeMode.rawValue) "
                    + "message=\"\(WebTransportLogText.escaped(result.message))\""
            )
        } catch {
            writeStandardError("\(executable) network session failed: \(error)\n")
            Foundation.exit(1)
        }
    }

    /// The shared conformance CLI. Returns whether it answered the invocation itself.
    private static func runConformance(arguments: [String], executable: String) async -> Bool {
        do {
            let options = try WebTransportCLIConformanceOptions.parse(
                executableName: executable,
                arguments: arguments
            )
            if !arguments.isEmpty {
                Foundation.exit(await WebTransportCLIConformance.run(options: options))
            }
            return false
        } catch WebTransportCLIConformanceExit.requestedHelp {
            print(WebTransportCLIConformance.helpText(executableName: executable))
            return true
        } catch WebTransportCLIConformanceExit.requestedList {
            print(WebTransportCLIConformance.listText())
            return true
        } catch WebTransportCLIConformanceExit.invalidArguments(let message) {
            writeStandardError("\(executable) argument error: \(message)\n")
            writeStandardError(WebTransportCLIConformance.helpText(executableName: executable) + "\n")
            Foundation.exit(2)
        } catch {
            writeStandardError("\(executable) argument error: \(error)\n")
            Foundation.exit(2)
        }
    }

    /// The no-argument demo: an in-process client and server echo.
    private static func runDemo() async {
        do {
            let server = WebTransportServer(
                configuration: WebTransportServerConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    supportedProtocols: ["demo.v1"],
                    timeoutMilliseconds: 12_000
                ))
            let client = WebTransportClient(
                configuration: WebTransportClientConfiguration(
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
            writeStandardError("WebTransportClient failed: \(error)\n")
            Foundation.exit(1)
        }
    }
}
private func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
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
        var builder = NetworkClientOptionsBuilder()
        // `--flag=value` is split into two tokens up front, so the loop below has one
        // spelling to handle and the two forms cannot drift apart.
        let normalized = normalizeAssignments(arguments)
        var index = 0
        while index < normalized.count {
            try apply(argument: normalized[index], arguments: normalized, index: &index, builder: &builder)
            index += 1
        }
        return try builder.build()
    }

}

extension NetworkClientOptions {
    /// Splits `--flag=value` into `--flag` and `value`.
    ///
    /// The value keeps any further `=`, which is what `dropFirst("--flag=".count)` did.
    private static func normalizeAssignments(_ arguments: [String]) -> [String] {
        arguments.flatMap { argument -> [String] in
            guard argument.hasPrefix("--"), let separator = argument.firstIndex(of: "=") else {
                return [argument]
            }
            return [
                String(argument[argument.startIndex..<separator]),
                String(argument[argument.index(after: separator)...]),
            ]
        }
    }

    /// One argument, one effect, so the loop above stays a loop.
    ///
    /// The switch is cut in two only because twelve value-taking options in one switch exceed
    /// the complexity threshold; each half reports whether it recognised the argument.
    private static func apply(
        argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkClientOptionsBuilder
    ) throws {
        if try applyConnectionArgument(argument, arguments: arguments, index: &index, builder: &builder) {
            return
        }
        if try applyPolicyArgument(argument, arguments: arguments, index: &index, builder: &builder) {
            return
        }
        throw WebTransportNetworkRuntimeError.invalidPayload
    }

    /// The arguments that describe where to connect and what to send.
    private static func applyConnectionArgument(
        _ argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkClientOptionsBuilder
    ) throws -> Bool {
        switch argument {
        case "--connect":
            builder.endpoint = try WebTransportNetworkEndpoint.parse(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidEndpoint("--connect requires host:port")
                ))
        case "--message":
            builder.message = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
        case "--timeout-ms":
            builder.timeoutMilliseconds = try checkedTimeout(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
        case "--transport":
            builder.transport = try WebTransportNetworkTransport.parse(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidTransport("--transport requires packet or frame")
                ))
        case "--authority":
            builder.authority = try nonEmpty(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
        case "--path":
            builder.path = try absolutePath(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
        default:
            return false
        }
        return true
    }

    /// The arguments that describe the session policy.
    private static func applyPolicyArgument(
        _ argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkClientOptionsBuilder
    ) throws -> Bool {
        switch argument {
        case "--origin":
            let value = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            builder.origin = value == "none" ? nil : value
        case "--protocol":
            let value = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            builder.protocols = value == "none" ? [] : [value]
        case "--trust":
            builder.trustPolicy = try WebTransportQUICPeerTrustPolicy.parse(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
        case "--settings-validation":
            builder.settingsValidation = try HTTP3WebTransportSettingsValidation.parse(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
        case "--exchange":
            builder.exchangeMode = try WebTransportNetworkExchangeMode.parse(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidTransport("--exchange requires auto, stream, or datagram")
                ))
        default:
            return false
        }
        return true
    }

    /// The value that follows a space-separated option.
    private static func nextValue(
        arguments: [String],
        index: inout Int,
        missing: WebTransportNetworkRuntimeError
    ) throws -> String {
        index += 1
        guard index < arguments.count else {
            throw missing
        }
        return arguments[index]
    }

    private static func checkedTimeout(_ raw: String) throws -> Int32 {
        guard let value = Int32(raw) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return value
    }

    private static func nonEmpty(_ value: String) throws -> String {
        guard !value.isEmpty else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return value
    }

    private static func absolutePath(_ value: String) throws -> String {
        guard value.hasPrefix("/") else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return value
    }
}

/// The options as the parser accumulates them, before the defaults are resolved.
private struct NetworkClientOptionsBuilder {
    var endpoint: WebTransportNetworkEndpoint?
    var message = "webtransport-network-session"
    var timeoutMilliseconds: Int32 = 1_000
    var transport = WebTransportNetworkTransport.packet
    var authority: String?
    var path = "/wt"
    var origin: String? = "https://localhost"
    var protocols = ["demo.v1"]
    var trustPolicy: WebTransportQUICPeerTrustPolicy?
    var settingsValidation = HTTP3WebTransportSettingsValidation.draft16Strict
    var exchangeMode = WebTransportNetworkExchangeMode.auto

    func build() throws -> NetworkClientOptions {
        guard let endpoint else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--connect requires host:port")
        }
        return NetworkClientOptions(
            endpoint: endpoint,
            message: message,
            timeoutMilliseconds: timeoutMilliseconds,
            transport: transport,
            authority: authority,
            path: path,
            origin: origin,
            protocols: protocols,
            trustPolicy: trustPolicy ?? .systemTrust,
            settingsValidation: settingsValidation,
            exchangeMode: exchangeMode
        )
    }
}
