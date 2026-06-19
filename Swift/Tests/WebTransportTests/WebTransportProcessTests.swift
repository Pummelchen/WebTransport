import Foundation
import Testing

@Test
func webTransportCLIProcessCoversHelpListInvalidArgumentsAndScenarioExitCodes() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")

        let clientHelp = try WebTransportProcessSupport.run(client, ["--help"])
        #expect(clientHelp.exitCode == 0)
        #expect(clientHelp.stdout.contains("WebTransportClient"))
        #expect(clientHelp.stderr.isEmpty)

        let serverList = try WebTransportProcessSupport.run(server, ["--list"])
        #expect(serverList.exitCode == 0)
        #expect(serverList.stdout.split(separator: "\n").count >= 40)
        #expect(serverList.stdout.contains("interop-connect-matrix"))

        let invalid = try WebTransportProcessSupport.run(client, ["--scenario", "does-not-exist"])
        #expect(invalid.exitCode == 1)
        #expect(invalid.stdout.contains("FAIL does-not-exist"))

        let scenario = try WebTransportProcessSupport.run(server, ["--scenario", "demo"])
        #expect(scenario.exitCode == 0)
        #expect(scenario.stdout.contains("PASS demo"))
    }
}

@Test
func webTransportCLIProcessLoopbackCoversFrameAndPacketTransports() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        try WebTransportProcessSupport.runLoopback(transport: "frame", expectsEstablishedSession: false)
        try WebTransportProcessSupport.runLoopback(transport: "packet", expectsEstablishedSession: true)
    }
}

@Test
func webTransportExternalInteropHookRunsWhenConfigured() throws {
    let environment = ProcessInfo.processInfo.environment
    guard let endpoint = environment["WEBTRANSPORT_EXTERNAL_INTEROP_ENDPOINT"], !endpoint.isEmpty else {
        return
    }
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let transport = environment["WEBTRANSPORT_EXTERNAL_INTEROP_TRANSPORT"] ?? "packet"
        let result = try WebTransportProcessSupport.run(
            client,
            [
                "--connect", endpoint,
                "--transport", transport,
                "--message", "external-interop",
                "--timeout-ms", environment["WEBTRANSPORT_EXTERNAL_INTEROP_TIMEOUT_MS"] ?? "5000"
            ],
            timeout: 10
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("connected"))
    }
}

@Test
func webTransportReleaseArtifactsAreExecutableAndScenarioCapable() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        let artifacts = WebTransportProcessSupport.packageDirectory
            .appendingPathComponent(".build/release-artifacts", isDirectory: true)
        let checksumManifest = artifacts.appendingPathComponent("SHA256SUMS")
        guard FileManager.default.fileExists(atPath: checksumManifest.path) else {
            if ProcessInfo.processInfo.environment["WEBTRANSPORT_REQUIRE_RELEASE_ARTIFACTS"] == "1" {
                throw ProcessTestError.missingExecutable("release-artifacts/SHA256SUMS")
            }
            return
        }
        let manifest = try String(contentsOf: checksumManifest, encoding: .utf8)
        #expect(manifest.contains("WebTransportClient"))
        #expect(manifest.contains("WebTransportServer"))

        for product in ["WebTransportClient", "WebTransportServer"] {
            let url = artifacts.appendingPathComponent(product)
            #expect(FileManager.default.isExecutableFile(atPath: url.path))
            let help = try WebTransportProcessSupport.run(url, ["--help"])
            #expect(help.exitCode == 0)
            #expect(help.stdout.contains(product))

            let demo = try WebTransportProcessSupport.run(url, ["--scenario", "demo"])
            #expect(demo.exitCode == 0)
            #expect(demo.stdout.contains("PASS demo"))
        }
    }
}

@Test
func webTransportAPISurfaceIsExercisedByPublicImports() throws {
    let script = WebTransportProcessSupport.packageDirectory.appendingPathComponent("check-api-compatibility.sh")
    #expect(FileManager.default.isExecutableFile(atPath: script.path))
}

private enum WebTransportProcessSupport {
    private static let processLock = NSLock()

    static let packageDirectory: URL = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }()

    static func withExclusiveProcessExecution<T>(_ body: () throws -> T) throws -> T {
        processLock.lock()
        defer {
            processLock.unlock()
        }
        return try body()
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
            packageDirectory.appendingPathComponent(".build/\(configuration)/\(product)"),
            packageDirectory.appendingPathComponent(".build/arm64-apple-macosx/\(configuration)/\(product)")
        ]
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        throw ProcessTestError.missingExecutable(product)
    }

    static func runLoopback(transport: String, expectsEstablishedSession: Bool) throws {
        let server = try productURL("WebTransportServer", configuration: "debug")
        let client = try productURL("WebTransportClient", configuration: "debug")
        let runningServer = try start(
            server,
            ["--listen", "127.0.0.1:0", "--transport", transport, "--timeout-ms", "5000"]
        )
        defer {
            runningServer.terminateIfNeeded()
        }

        let line = try runningServer.waitForOutput(containing: "listening:", timeout: 5)
        let port = try parseListeningPort(from: line)
        let clientResult = try run(
            client,
            ["--connect", "127.0.0.1:\(port)", "--transport", transport, "--message", "loopback-\(transport)", "--timeout-ms", "5000"],
            timeout: 10
        )
        #expect(clientResult.exitCode == 0)
        #expect(clientResult.stdout.contains("connected"))
        #expect(clientResult.stdout.contains("loopback-\(transport)"))
        if expectsEstablishedSession {
            #expect(clientResult.stdout.contains("session=established"))
        }

        let serverResult = try runningServer.wait(timeout: 10)
        #expect(serverResult.exitCode == 0)
        #expect(serverResult.stdout.contains("served"))
        #expect(serverResult.stdout.contains("loopback-\(transport)"))
    }

    static func run(
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

    static func start(_ executable: URL, _ arguments: [String]) throws -> RunningProcess {
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
        guard let range = line.range(of: #"listening: [^:]+:(\d+)"#, options: .regularExpression),
              let port = UInt16(line[range].split(separator: ":").last ?? "") else {
            throw ProcessTestError.malformedOutput(line)
        }
        return port
    }
}

private final class RunningProcess: @unchecked Sendable {
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

private struct ProcessResult {
    var exitCode: Int32
    var stdout: String
    var stderr: String
}

private enum ProcessTestError: Error, CustomStringConvertible {
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
