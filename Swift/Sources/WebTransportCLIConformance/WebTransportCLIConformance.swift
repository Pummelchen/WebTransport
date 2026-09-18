import Foundation
import WebTransport
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple

public enum WebTransportCLIConformanceExit: Error, Equatable {
    case requestedHelp
    case requestedList
    case invalidArguments(String)
}

public struct WebTransportCLIConformanceOptions: Equatable, Sendable {
    public var executableName: String
    public var selectedScenarios: [String]
    public var json: Bool
    public var verbose: Bool
    public var logDirectory: String

    public init(
        executableName: String,
        selectedScenarios: [String] = ["demo"],
        json: Bool = false,
        verbose: Bool = false,
        logDirectory: String = ".webtransport-cli-logs"
    ) {
        self.executableName = executableName
        self.selectedScenarios = selectedScenarios
        self.json = json
        self.verbose = verbose
        self.logDirectory = logDirectory
    }

    public static func parse(executableName: String, arguments: [String]) throws -> WebTransportCLIConformanceOptions {
        var options = WebTransportCLIConformanceOptions(executableName: executableName)
        guard !arguments.isEmpty else {
            return options
        }

        options.selectedScenarios = []
        var index = 0
        while index < arguments.count {
            try apply(argument: arguments[index], arguments: arguments, index: &index, options: &options)
            index += 1
        }

        if options.selectedScenarios.isEmpty {
            options.selectedScenarios = ["all"]
        }
        return options
    }

    /// One argument, one effect, so the loop above stays a loop. The `--flag=value`
    /// spellings are separated out below; the space-separated ones need the index that
    /// only this function has.
    private static func apply(
        argument: String,
        arguments: [String],
        index: inout Int,
        options: inout WebTransportCLIConformanceOptions
    ) throws {
        switch argument {
        case "--help", "-h":
            throw WebTransportCLIConformanceExit.requestedHelp
        case "--list":
            throw WebTransportCLIConformanceExit.requestedList
        case "--json":
            options.json = true
        case "--verbose", "-v":
            options.verbose = true
        case "--scenario":
            index += 1
            guard index < arguments.count else {
                throw WebTransportCLIConformanceExit.invalidArguments("--scenario requires a value")
            }
            options.selectedScenarios.append(contentsOf: splitScenarioList(arguments[index]))
        case "--log-dir":
            index += 1
            guard index < arguments.count else {
                throw WebTransportCLIConformanceExit.invalidArguments("--log-dir requires a path")
            }
            options.logDirectory = arguments[index]
        default:
            try applyAssignment(argument: argument, options: &options)
        }
    }

    /// The `--flag=value` spellings, which carry their value in the same argument.
    private static func applyAssignment(
        argument: String,
        options: inout WebTransportCLIConformanceOptions
    ) throws {
        if argument.hasPrefix("--scenario=") {
            options.selectedScenarios.append(
                contentsOf: splitScenarioList(String(argument.dropFirst("--scenario=".count))))
        } else if argument.hasPrefix("--log-dir=") {
            options.logDirectory = String(argument.dropFirst("--log-dir=".count))
        } else {
            throw WebTransportCLIConformanceExit.invalidArguments("unknown argument: \(argument)")
        }
    }

    private static func splitScenarioList(_ value: String) -> [String] {
        value.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

/// How a conformance scenario ended.
///
/// Three states rather than a boolean, because a scenario that could not be attempted is
/// neither a pass nor a failure. Reporting it as a failure is what made a checkout-less
/// run of the released binaries say `passed=38 failed=2` for two scenarios that never ran
/// (WT-186). The C99 tree models the same distinction as `WT_CLI_RESULT_UNSUPPORTED`, and
/// this mirrors it so the two implementations' reports read alike.
public enum WebTransportCLIConformanceStatus: String, Equatable, Sendable {
    case passed
    case failed
    case skipped
}

public struct WebTransportCLIConformanceResult: Equatable, Sendable {
    public var name: String
    public var status: WebTransportCLIConformanceStatus
    public var durationSeconds: Double
    public var detail: String

    /// Whether the scenario ran and succeeded.
    ///
    /// Retained because it is the question almost every caller asks. A skipped scenario
    /// did not pass, so this is false for it — and `status` is what tells the two apart.
    public var passed: Bool { status == .passed }
}

public enum WebTransportCLIConformance {
    public static func helpText(executableName: String) -> String {
        """
        Usage: \(executableName) [--scenario NAME|all] [--json] [--verbose] [--log-dir PATH]

        Scenarios:
        \(groupedScenarioHelpText())

        Exit status:
          0  every selected scenario ran and passed
          1  a scenario failed
          2  the arguments were invalid
          3  nothing failed, but a scenario could not be attempted here and was skipped
             (the Release scenarios read the source tree, so they are skipped outside a
             checkout rather than reported as failures)

        Examples:
          \(executableName) --scenario all --verbose
          \(executableName) --scenario session-accept,datagram-round-trip --json
        """
    }

    public static func listText() -> String {
        scenarioCatalog().map(\.name).joined(separator: "\n")
    }

    public static func run(options: WebTransportCLIConformanceOptions) async -> Int32 {
        let catalog = scenarioCatalog()
        let selectedNames = selectedScenarioNames(options: options, catalog: catalog)
        let scenariosByName = scenarioIndex(catalog: catalog)

        var results: [WebTransportCLIConformanceResult] = []
        var failures: [String] = []
        var verboseGroup: String?
        let logURL = URL(fileURLWithPath: options.logDirectory, isDirectory: true)
        try? FileManager.default.createDirectory(at: logURL, withIntermediateDirectories: true)

        for name in selectedNames {
            let outcome = await runScenario(
                named: name,
                in: scenariosByName,
                options: options,
                logURL: logURL,
                verboseGroup: &verboseGroup
            )
            results.append(outcome.result)
            if let failure = outcome.failure {
                failures.append(failure)
            }
        }

        writeSummaryLog(results: results, executableName: options.executableName, directory: logURL)
        emit(
            results: results,
            executableName: options.executableName,
            json: options.json,
            includeDetails: !options.verbose || !failures.isEmpty,
            scenarioGroupsByName: Dictionary(uniqueKeysWithValues: catalog.map { ($0.name, $0.group) })
        )
        return exitCode(for: results)
    }

    /// `all` is the documented shorthand for the whole catalogue; anything else is a list.
    private static func selectedScenarioNames(
        options: WebTransportCLIConformanceOptions,
        catalog: [CLIConformanceScenario]
    ) -> [String] {
        options.selectedScenarios.contains("all") ? catalog.map(\.name) : options.selectedScenarios
    }

    private static func scenarioIndex(catalog: [CLIConformanceScenario]) -> [String: CLIConformanceScenario] {
        Dictionary(catalog.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// Runs one selected name, or records why it could not run.
    ///
    /// The three outcomes -- unknown name, skipped, and run -- are decided in one place
    /// each rather than inline in the loop, which is what the orchestrator above needs to
    /// stay a loop and a summary.
    private static func runScenario(
        named name: String,
        in scenariosByName: [String: CLIConformanceScenario],
        options: WebTransportCLIConformanceOptions,
        logURL: URL,
        verboseGroup: inout String?
    ) async -> (result: WebTransportCLIConformanceResult, failure: String?) {
        guard let scenario = scenariosByName[name] else {
            let detail = "unknown scenario: \(name)"
            let result = WebTransportCLIConformanceResult(
                name: name,
                status: .failed,
                durationSeconds: 0,
                detail: detail
            )
            writeFailureLog(result: result, executableName: options.executableName, directory: logURL)
            return (result, detail)
        }

        // A scenario that needs the repository and has none is not attempted at all.
        // It is skipped with its reason rather than failed on a missing file, so the
        // report separates "this run was incomplete" from "this build is broken"
        // (WT-186).
        if let reason = scenarioSkipReason(scenario) {
            let result = WebTransportCLIConformanceResult(
                name: scenario.name,
                status: .skipped,
                durationSeconds: 0,
                detail: reason
            )
            printVerbose(options: options) {
                printScenarioGroupHeading(scenario.group, current: &verboseGroup)
                print("  SKIP \(scenario.name) \(reason)")
            }
            return (result, nil)
        }

        printVerbose(options: options) {
            printScenarioGroupHeading(scenario.group, current: &verboseGroup)
            print("  RUN \(scenario.name): \(scenario.description)")
        }
        return await execute(scenario: scenario, options: options, logURL: logURL)
    }

    /// The run itself, separated so the decision-making above stays short enough to read
    /// in one screen.
    private static func execute(
        scenario: CLIConformanceScenario,
        options: WebTransportCLIConformanceOptions,
        logURL: URL
    ) async -> (result: WebTransportCLIConformanceResult, failure: String?) {
        let started = Date()
        do {
            try await scenario.run()
            let duration = Date().timeIntervalSince(started)
            printVerbose(options: options) { print("  PASS \(scenario.name) \(format(duration))s") }
            return (
                WebTransportCLIConformanceResult(
                    name: scenario.name,
                    status: .passed,
                    durationSeconds: duration,
                    detail: "passed"
                ),
                nil
            )
        } catch {
            let duration = Date().timeIntervalSince(started)
            let detail = String(describing: error)
            let result = WebTransportCLIConformanceResult(
                name: scenario.name,
                status: .failed,
                durationSeconds: duration,
                detail: detail
            )
            writeFailureLog(result: result, executableName: options.executableName, directory: logURL)
            printVerbose(options: options) { print("  FAIL \(scenario.name) \(format(duration))s \(detail)") }
            return (result, "\(scenario.name): \(detail)")
        }
    }

    /// Verbose printing is gated in four places; one gate keeps the condition from
    /// drifting between them.
    private static func printVerbose(options: WebTransportCLIConformanceOptions, _ body: () -> Void) {
        guard options.verbose, !options.json else {
            return
        }
        body()
    }
}

/// The process exit status for a completed run.
///
/// Three outcomes, mirroring the C99 conformance tool: `1` when anything failed, `3` when
/// nothing failed but something was not attempted, and `0` when every selected scenario
/// ran and passed. The middle case is what lets a caller tell a complete run from an
/// incomplete one without parsing the report — the same distinction CTest draws with its
/// skip return code, and the reason a checkout-less run of the released binaries stops
/// being indistinguishable from a broken build (WT-186).
private func exitCode(for results: [WebTransportCLIConformanceResult]) -> Int32 {
    if results.contains(where: { $0.status == .failed }) {
        return 1
    }
    if results.contains(where: { $0.status == .skipped }) {
        return 3
    }
    return 0
}

// internal because the scenario catalogue and the report writers are in separate files
internal func groupedScenarioHelpText() -> String {
    let catalog = scenarioCatalog()
    var groupOrder: [String] = []
    var scenariosByGroup: [String: [CLIConformanceScenario]] = [:]

    for scenario in catalog {
        if scenariosByGroup[scenario.group] == nil {
            groupOrder.append(scenario.group)
        }
        scenariosByGroup[scenario.group, default: []].append(scenario)
    }

    return groupOrder.map { group in
        let scenarios = scenariosByGroup[group, default: []]
            .map { "    \($0.name) - \($0.description)" }
            .joined(separator: "\n")
        return "  \(group):\n\(scenarios)"
    }.joined(separator: "\n\n")
}

private func printScenarioGroupHeading(_ group: String, current: inout String?) {
    guard current != group else {
        return
    }
    if current != nil {
        print("")
    }
    print("\(group):")
    current = group
}

// internal because the scenario catalogue and the runner that consults it are in
// separate files
internal struct CLIConformanceScenario: Sendable {
    var group: String
    var name: String
    var description: String
    /// Working-directory files this scenario reads.
    ///
    /// A scenario listed here asserts properties of the source tree rather than of the
    /// transport, so when none of these exists it cannot be attempted at all: it is
    /// reported as skipped with that reason instead of failing on a missing file
    /// (WT-186). Empty for the scenarios that exercise the transport and run anywhere.
    var repositoryFiles: [String] = []
    /// A marker the resolved file must contain for it to be *this* repository's.
    ///
    /// Existence alone is not enough for a file every Swift package has: a `Package.swift`
    /// belonging to an unrelated project in the working directory would let
    /// `release-products` run against the wrong tree instead of skipping. Where the file
    /// name is generic this is what identifies the checkout; where the name is already
    /// unique to this repository (`build-release-apple-silicon.sh`) none is needed.
    var repositoryMarker: String?
    var run: @Sendable () async throws -> Void
}

private func scenarioSkipReason(_ scenario: CLIConformanceScenario) -> String? {
    guard !scenario.repositoryFiles.isEmpty else {
        return nil
    }
    let candidates = scenario.repositoryFiles.joined(separator: ", ")
    guard let path = scenario.repositoryFiles.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
        return "requires a repository checkout: none of \(candidates) is in the working directory"
    }
    guard let marker = scenario.repositoryMarker else {
        return nil
    }
    guard let text = try? String(contentsOfFile: path, encoding: .utf8), text.contains(marker) else {
        return "requires a repository checkout: \(path) is present but is not this repository's"
    }
    return nil
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func require(_ condition: Bool, _ message: String) throws {
    guard condition else {
        throw QUICCodecError.malformed("CLI conformance failed: \(message)")
    }
}

/// The word a report uses for a status.
///
/// The three *states* mirror the C99 report's `passed` / `failed` / `unsupported`
/// (`C99/src/cli/report.c`), so the two implementations' reports read alike in structure
/// and in exit status. The tokens do not match C99's, and neither do the JSON keys — Swift
/// prints `PASS` / `FAIL` / `SKIP` with a `status` field and a `skipped` count — so a
/// consumer must not parse one report's words as the other's.
///
/// - Note: internal because the scenario catalogue and the report writers are in separate files.
internal func statusToken(_ status: WebTransportCLIConformanceStatus) -> String {
    switch status {
    case .passed: return "PASS"
    case .failed: return "FAIL"
    case .skipped: return "SKIP"
    }
}

// internal because the scenario catalogue and the report writers are in separate files
internal func count(_ status: WebTransportCLIConformanceStatus, in results: [WebTransportCLIConformanceResult]) -> Int {
    results.filter { $0.status == status }.count
}

private func emit(
    results: [WebTransportCLIConformanceResult],
    executableName: String,
    json: Bool,
    includeDetails: Bool,
    scenarioGroupsByName: [String: String]
) {
    let passed = count(.passed, in: results)
    let failed = count(.failed, in: results)
    let skipped = count(.skipped, in: results)
    if json {
        let payload: [String: Any] = [
            "executable": executableName,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "results": results.map { result in
                [
                    "name": result.name,
                    "status": result.status.rawValue,
                    "passed": result.passed,
                    "durationSeconds": result.durationSeconds,
                    "detail": result.detail,
                ] as [String: Any]
            },
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]),
            let text = String(data: data, encoding: .utf8)
        {
            print(text)
        }
    } else {
        if includeDetails {
            var currentGroup: String?
            for result in results {
                let line = "\(statusToken(result.status)) \(result.name) \(format(result.durationSeconds))s \(result.detail)"
                if let group = scenarioGroupsByName[result.name] {
                    printScenarioGroupHeading(group, current: &currentGroup)
                    print("  \(line)")
                } else {
                    print(line)
                }
            }
        }
        print("SUMMARY \(executableName): passed=\(passed) failed=\(failed) skipped=\(skipped) total=\(results.count)")
    }
}
