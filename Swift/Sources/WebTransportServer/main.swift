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
            await runListener(arguments: arguments, executable: executable)
            return
        }
        if await runConformance(arguments: arguments, executable: executable) {
            return
        }
        refuseNoMode(executable: executable)
    }
}

extension WebTransportServerCLI {
    /// `--listen`: one real listener serving the sessions it was asked for.
    private static func runListener(arguments: [String], executable: String) async {
        do {
            let options = try NetworkServerOptions.parse(arguments)
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
            let results = await serveSessions(server: server, options: options)
            // Serving nothing is a failure, not a success. Every session attempt that timed
            // out or errored has already been reported; returning zero here would tell a
            // script or a CI job that the run succeeded when no peer was ever served.
            guard !results.isEmpty else {
                writeStandardError("\(executable) served no sessions and returned no results\n")
                Foundation.exit(1)
            }
            report(results)
        } catch {
            writeStandardError("\(executable) network session failed: \(error)\n")
            Foundation.exit(1)
        }
    }

    /// One task per session, and the results of those that completed.
    private static func serveSessions(
        server: WebTransportQUICServer,
        options: NetworkServerOptions
    ) async -> [WebTransportNetworkSessionResult] {
        let tasks: [Task<WebTransportNetworkSessionResult, Error>] = (0..<options.maxSessions).map { _ in
            Task {
                try await server.serveOne(timeoutMilliseconds: options.timeoutMilliseconds)
            }
        }
        var results: [WebTransportNetworkSessionResult] = []
        for task in tasks {
            do {
                results.append(try await task.value)
            } catch {
                writeStandardError("network packet session serve error: \(error)\n")
            }
        }
        return results
    }

    private static func report(_ results: [WebTransportNetworkSessionResult]) {
        for result in results {
            let session = result.sessionEstablished ? " session=established" : ""
            print(
                "network \(result.transport.rawValue) session served: remote=\(result.remoteEndpoint.commandLineValue)\(session) "
                    + "message=\"\(WebTransportLogText.escaped(result.message))\""
            )
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

    /// No argument selected a mode, and that is an argument error, not a running endpoint.
    ///
    /// `WebTransportServer.init` only stores its configuration; it does not bind a socket.
    /// Reporting readiness here would be a true-looking success signal for a listener that
    /// does not exist, and a supervisor or health probe that keys on the exit status would
    /// read this process as a served endpoint. Refuse instead, name the arguments that do
    /// start something, and exit non-zero.
    private static func refuseNoMode(executable: String) -> Never {
        writeStandardError(
            "\(executable) started no listener: no mode was selected\n"
                + "\(executable) needs `--listen host:port` to serve a network session, "
                + "or `--scenario <name>` to run the conformance scenarios\n"
        )
        writeStandardError(WebTransportCLIConformance.helpText(executableName: executable) + "\n")
        Foundation.exit(2)
    }
}

private func writeStandardOutput(_ message: String) {
    FileHandle.standardOutput.write(Data(message.utf8))
}

private func writeStandardError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

private struct NetworkServerOptions {
    /// Upper bound accepted for `--max-sessions`.
    ///
    /// The value sizes an array of `Task`s, one per session, so it has to be bounded:
    /// without a cap an argument like `--max-sessions=1000000` commits memory
    /// proportional to the request and the process can be made to exhaust the machine
    /// before it serves anything.
    ///
    /// The bound exists to stop that, not to describe a concurrency ceiling — the
    /// listener's own limit comes from the admission policy (`--max-sessions` *becomes*
    /// that limit, via `maxConcurrentConnections`), so it is unrelated. The number is
    /// chosen well above any smoke or soak run so that it cannot reject a legitimate
    /// configuration; `Swift/run-soak.sh` passes `CONNECTIONS + 10`, and a soak of
    /// tens of thousands of connections is the realistic upper end.
    static let maximumSessions = 65_536

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
        var builder = NetworkServerOptionsBuilder()
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

extension NetworkServerOptions {
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
    private static func apply(
        argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkServerOptionsBuilder
    ) throws {
        if try applyConnectionArgument(argument, arguments: arguments, index: &index, builder: &builder) {
            return
        }
        if try applyPolicyArgument(argument, arguments: arguments, index: &index, builder: &builder) {
            return
        }
        throw WebTransportNetworkRuntimeError.invalidPayload
    }

    /// The arguments that describe where to listen and how many sessions to serve.
    private static func applyConnectionArgument(
        _ argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkServerOptionsBuilder
    ) throws -> Bool {
        switch argument {
        case "--listen":
            builder.endpoint = try WebTransportNetworkEndpoint.parse(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidEndpoint("--listen requires host:port")
                ))
        case "--timeout-ms":
            builder.timeoutMilliseconds = try checkedPositiveTimeout(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidTransport("--timeout-ms requires a positive integer in milliseconds")
                ))
        case "--transport":
            builder.transport = try WebTransportNetworkTransport.parse(
                nextValue(
                    arguments: arguments,
                    index: &index,
                    missing: .invalidTransport("--transport requires packet or frame")
                ))
        case "--max-sessions":
            builder.maxSessions = try checkedMaximumSessions(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
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

    /// The arguments that describe the session policy and the server identity.
    private static func applyPolicyArgument(
        _ argument: String,
        arguments: [String],
        index: inout Int,
        builder: inout NetworkServerOptionsBuilder
    ) throws -> Bool {
        switch argument {
        case "--origin":
            let value = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            builder.allowedOrigin = value == "none" ? nil : value
        case "--protocol":
            let value = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            builder.protocols = value == "none" ? [] : [value]
        case "--identity-pkcs12":
            builder.pkcs12Path = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
        case "--identity-passphrase":
            builder.pkcs12Passphrase = try nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
        case "--settings-validation":
            builder.settingsValidation = try HTTP3WebTransportSettingsValidation.parse(
                nextValue(arguments: arguments, index: &index, missing: .invalidPayload)
            )
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

    /// F-repo-ops-15: a non-positive value is refused here, as the C99 parser refuses a zero
    /// timeout ("a zero timeout would wait forever"). Left unchecked it reaches the runtime,
    /// which reports `.timeout(0)` for every session instead of an argument error an operator
    /// can act on.
    ///
    /// The message names the offending value, which only the `=` form used to do; both forms
    /// now share this parser, so they cannot disagree about what is accepted.
    private static func checkedPositiveTimeout(_ raw: String) throws -> Int32 {
        guard let value = Int32(raw), value > 0 else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "--timeout-ms requires a positive integer in milliseconds, got \"\(raw)\""
            )
        }
        return value
    }

    /// The bound exists so `--max-sessions=1000000` cannot commit memory proportional to the
    /// request before anything is served. The message names the bad value, as the `=` form did.
    private static func checkedMaximumSessions(_ raw: String) throws -> Int {
        guard let value = Int(raw), (1...Self.maximumSessions).contains(value) else {
            throw WebTransportNetworkRuntimeError.invalidTransport(
                "--max-sessions requires an integer in 1...\(Self.maximumSessions), got \"\(raw)\""
            )
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

/// The options as the parser accumulates them, before the identity is resolved.
private struct NetworkServerOptionsBuilder {
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

    func build() throws -> NetworkServerOptions {
        guard let endpoint else {
            throw WebTransportNetworkRuntimeError.invalidEndpoint("--listen requires host:port")
        }
        // Without an injected identity the listener falls back to the development
        // certificate, which is refused on any non-loopback bind. That is what previously
        // made this executable unable to serve anything but loopback.
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
