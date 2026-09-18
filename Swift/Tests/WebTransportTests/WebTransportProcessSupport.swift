import Foundation
import Darwin
import Testing
import WebTransportLoopbackTestSupport

enum WebTransportProcessSupport {
    private static let processLock = NSLock()

    static let packageDirectory: URL = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }()
    static let repositoryDirectory: URL = {
        packageDirectory.deletingLastPathComponent()
    }()

    static func withExclusiveProcessExecution<T>(
        label: String = #function,
        _ body: () throws -> T
    ) throws -> T {
        processLock.lock()
        defer {
            processLock.unlock()
        }
        return try body()
    }

    static func withExclusiveProcessExecution<T>(
        label: String = #function,
        _ body: () async throws -> T
    ) async throws -> T {
        try await WebTransportLoopbackTestLock.withLockAsync(label: label) { try await body() }
    }

    static func debugProductsAvailable() throws -> Bool {
        let available = ["WebTransportClient", "WebTransportServer"].allSatisfy {
            (try? productURL($0, configuration: "debug")) != nil
        }
        if !available && ProcessInfo.processInfo.environment["WEBTRANSPORT_REQUIRE_CLI_BINARIES"] == "1" {
            throw ProcessTestError.missingExecutable("debug CLI products")
        }
        return available
    }

    static func productURL(_ product: String, configuration: String) throws -> URL {
        let candidates = [
            repositoryDirectory.appendingPathComponent(".build/\(configuration)/\(product)"),
            repositoryDirectory.appendingPathComponent(".build/arm64-apple-macosx/\(configuration)/\(product)"),
            packageDirectory.appendingPathComponent(".build/\(configuration)/\(product)"),
            packageDirectory.appendingPathComponent(".build/arm64-apple-macosx/\(configuration)/\(product)"),
        ]
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        throw ProcessTestError.missingExecutable(product)
    }

    /// Runs one loopback exchange, retrying the whole pair rather than the client.
    ///
    /// The server serves for a bounded window that starts when it begins
    /// listening, so retrying only the client is not a retry at all: the first
    /// attempt consumes the entire window, and every later attempt connects to a
    /// server that has already exited and can only time out. That turned a single
    /// slow handshake into three stacked timeouts and reported the last one, which
    /// hid what had actually gone wrong. Each attempt now gets its own server.
    static func runLoopback(host: String, transport: String, expectsEstablishedSession: Bool) throws {
        let maximumAttempts = 3
        var lastFailure = ""

        for attempt in 1...maximumAttempts {
            let loopbackName = "loopback-\(transport)-\(host == "::1" ? "ipv6" : "ipv4")"
            let outcome = try runLoopbackAttempt(
                host: host,
                transport: transport,
                message: attempt == 1 ? loopbackName : "\(loopbackName)-retry-\(attempt)",
                expectsEstablishedSession: expectsEstablishedSession
            )
            switch outcome {
            case .succeeded:
                return
            case .failed(let description):
                lastFailure = "attempt \(attempt)/\(maximumAttempts): \(description)"
                if attempt < maximumAttempts {
                    Thread.sleep(forTimeInterval: 0.25)
                }
            }
        }

        Issue.record(Comment(rawValue: "loopback exchange never succeeded — \(lastFailure)"))
    }

    private enum LoopbackOutcome {
        case succeeded
        case failed(String)
    }

    private static func runLoopbackAttempt(
        host: String,
        transport: String,
        message: String,
        expectsEstablishedSession: Bool
    ) throws -> LoopbackOutcome {
        let server = try productURL("WebTransportServer", configuration: "debug")
        let client = try productURL("WebTransportClient", configuration: "debug")
        let listenEndpoint = endpointArgument(host: host, port: 0)
        let runningServer = try start(
            server,
            ["--listen", listenEndpoint, "--transport", transport, "--timeout-ms", "25000"]
        )
        defer {
            runningServer.terminateIfNeeded()
        }

        let line = try runningServer.waitForOutput(containing: "listening:", timeout: 5)
        _ = try runningServer.waitForOutput(containing: "certificate-sha256:", timeout: 5)
        let port = try parseListeningPort(from: line)
        let connectEndpoint = endpointArgument(host: host, port: port)
        let clientResult = try run(
            client,
            ["--connect", connectEndpoint, "--transport", transport, "--trust", "local-self-signed", "--message", message, "--timeout-ms", "25000"],
            timeout: 30
        )

        guard clientResult.exitCode == 0,
            clientResult.stdout.contains("connected"),
            clientResult.stdout.contains(message),
            !expectsEstablishedSession || clientResult.stdout.contains("session=established")
        else {
            return .failed("client exit=\(clientResult.exitCode) stdout=\(clientResult.stdout) stderr=\(clientResult.stderr)")
        }

        let serverResult = try runningServer.wait(timeout: 20)
        guard serverResult.exitCode == 0,
            serverResult.stdout.contains("served"),
            serverResult.stdout.contains(message)
        else {
            return .failed("server exit=\(serverResult.exitCode) stdout=\(serverResult.stdout) stderr=\(serverResult.stderr)")
        }

        return .succeeded
    }

    // internal because the process tests are split across several files
    internal static func run(
        _ executable: URL,
        _ arguments: [String],
        timeout: TimeInterval = 30,
        currentDirectory: URL? = packageDirectory
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
            throw ProcessTestError.timeout(executable.lastPathComponent, arguments)
        }
        return ProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            stderr: String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    // internal because the process tests are split across several files
    internal static func start(_ executable: URL, _ arguments: [String]) throws -> RunningProcess {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = packageDirectory
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        let running = RunningProcess(process: process, stdout: stdout, stderr: stderr)
        try process.run()
        running.startCapture()
        return running
    }

    static func parseListeningPort(from line: String) throws -> UInt16 {
        guard let range = line.range(of: #":(\d+)$"#, options: .regularExpression),
            let port = UInt16(line[range].dropFirst())
        else {
            throw ProcessTestError.malformedOutput(line)
        }
        return port
    }

    static func endpointArgument(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    static func parseJSONResult(_ text: String) throws -> [String: Any] {
        guard let data = text.data(using: .utf8) else {
            throw ProcessTestError.malformedOutput("non-text output")
        }
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ProcessTestError.malformedOutput(text)
        }
        return value
    }

    /// The status tokens a conformance report prints, in the order they appear.
    ///
    /// `SKIP` is a third state that is neither a pass nor a failure: a scenario that could
    /// not be attempted here is reported with its reason rather than as a failure (WT-186).
    /// Recognising it is what keeps a skipped scenario from being silently dropped by the
    /// tests that compare the reported names, which would otherwise under-report a run.
    static func scenarioResultStatuses(from output: String) -> [(status: String, name: String)] {
        output.split(separator: "\n").compactMap { line in
            let columns = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard columns.count >= 2 else {
                return nil
            }
            let token = String(columns[0])
            guard token == "PASS" || token == "FAIL" || token == "SKIP" else {
                return nil
            }
            return (token, String(columns[1]))
        }
    }

    static func scenarioResultNames(from output: String) -> [String] {
        scenarioResultStatuses(from: output).map(\.name)
    }

    static func temporaryLogDirectory(_ name: String) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("webtransport-cli-tests")
            .appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.removeItem(at: directory)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    // internal because the interop hook test that calls it is in another file
    /// The ten description fields a proof file records, as one value.
    internal struct ExternalInteropProofRequest {
        var implementation: String
        var endpoint: String
        var authority: String
        var path: String
        var origin: String
        var wtProtocol: String
        var transport: String
        var trust: String
        var message: String
        var timeoutMilliseconds: String
    }

    internal static func writeExternalInteropProof(
        _ request: ExternalInteropProofRequest,
        result: ProcessResult
    ) throws {
        let directory = packageDirectory.appendingPathComponent(".build/external-interop", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let proof: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "independentImplementation": request.implementation,
            "endpoint": request.endpoint,
            "authority": request.authority,
            "path": request.path,
            "origin": request.origin == "none" ? NSNull() : request.origin,
            "protocol": request.wtProtocol == "none" ? NSNull() : request.wtProtocol,
            "transport": request.transport,
            "trust": request.trust,
            "message": request.message,
            "timeoutMilliseconds": Int(request.timeoutMilliseconds) ?? 0,
            "exitCode": Int(result.exitCode),
            "passed": result.exitCode == 0 && result.stdout.contains("connected") && result.stdout.contains(request.message),
            "stdout": result.stdout,
            "stderr": result.stderr,
        ]
        let data = try JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: directory.appendingPathComponent("latest.json"))
        try result.stdout.write(to: directory.appendingPathComponent("latest.stdout"), atomically: true, encoding: .utf8)
        try result.stderr.write(to: directory.appendingPathComponent("latest.stderr"), atomically: true, encoding: .utf8)
    }
}

// internal because the scenario-matrix tests are split across several files
internal func runScenarioMatrix(_ scenarios: [String], expectedPasses: Int) throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let flag = scenarios.joined(separator: ",")
        let resultClient = try WebTransportProcessSupport.run(client, ["--scenario", flag, "--json"])
        let resultServer = try WebTransportProcessSupport.run(server, ["--scenario", flag, "--json"])
        #expect(resultClient.exitCode == 0)
        #expect(resultServer.exitCode == 0)

        let clientPayload = try WebTransportProcessSupport.parseJSONResult(resultClient.stdout)
        let serverPayload = try WebTransportProcessSupport.parseJSONResult(resultServer.stdout)

        let clientPassed = (clientPayload["passed"] as? Int) ?? Int((clientPayload["passed"] as? NSNumber)?.intValue ?? -1)
        let clientFailed = (clientPayload["failed"] as? Int) ?? Int((clientPayload["failed"] as? NSNumber)?.intValue ?? -1)
        let serverPassed = (serverPayload["passed"] as? Int) ?? Int((serverPayload["passed"] as? NSNumber)?.intValue ?? -1)
        let serverFailed = (serverPayload["failed"] as? Int) ?? Int((serverPayload["failed"] as? NSNumber)?.intValue ?? -1)

        let clientResults = clientPayload["results"] as? [[String: Any]]
        let serverResults = serverPayload["results"] as? [[String: Any]]
        let clientNames = Set(clientResults?.compactMap { $0["name"] as? String } ?? [])
        let serverNames = Set(serverResults?.compactMap { $0["name"] as? String } ?? [])

        #expect(clientPassed == expectedPasses)
        #expect(serverPassed == expectedPasses)
        #expect(clientFailed == 0)
        #expect(serverFailed == 0)
        #expect(clientNames == Set(scenarios))
        #expect(serverNames == Set(scenarios))
    }
}

// internal because WebTransportProcessSupport.start returns it from another file
internal final class RunningProcess: @unchecked Sendable {
    private let process: Process
    private let stdout: Pipe
    private let stderr: Pipe
    private let lock = NSLock()
    private var stdoutText = ""
    private var stderrText = ""

    init(process: Process, stdout: Pipe, stderr: Pipe) {
        self.process = process
        self.stdout = stdout
        self.stderr = stderr
    }

    func startCapture() {
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                return
            }
            self?.appendStdout(String(data: data, encoding: .utf8) ?? "")
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                return
            }
            self?.appendStderr(String(data: data, encoding: .utf8) ?? "")
        }
    }

    func waitForOutput(containing needle: String, timeout: TimeInterval) throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            lock.lock()
            let text = stdoutText
            lock.unlock()
            if let line = text.split(separator: "\n").map(String.init).first(where: { $0.contains(needle) }) {
                return line
            }
            if !process.isRunning {
                break
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        throw ProcessTestError.timeout("process-output", [needle])
    }

    func wait(timeout: TimeInterval) throws -> ProcessResult {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
            throw ProcessTestError.timeout("running-process", [])
        }
        stdout.fileHandleForReading.readabilityHandler = nil
        stderr.fileHandleForReading.readabilityHandler = nil
        lock.lock()
        let stdoutCopy = stdoutText
        let stderrCopy = stderrText
        lock.unlock()
        return ProcessResult(exitCode: process.terminationStatus, stdout: stdoutCopy, stderr: stderrCopy)
    }

    func terminateIfNeeded() {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        stdout.fileHandleForReading.readabilityHandler = nil
        stderr.fileHandleForReading.readabilityHandler = nil
    }

    private func appendStdout(_ text: String) {
        lock.lock()
        stdoutText += text
        lock.unlock()
    }

    private func appendStderr(_ text: String) {
        lock.lock()
        stderrText += text
        lock.unlock()
    }
}

// internal because WebTransportProcessSupport.run returns it from another file
internal struct ProcessResult {
    var exitCode: Int32
    var stdout: String
    var stderr: String
}

// internal because it appears in the signature of the internal run/start helpers
internal enum ProcessTestError: Error, CustomStringConvertible {
    case missingExecutable(String)
    case timeout(String, [String])
    case malformedOutput(String)

    var description: String {
        switch self {
        case .missingExecutable(let product):
            return "missing executable \(product)"
        case .timeout(let executable, let arguments):
            return "process timed out: \(executable) \(arguments.joined(separator: " "))"
        case .malformedOutput(let output):
            return "malformed process output: \(output)"
        }
    }
}
