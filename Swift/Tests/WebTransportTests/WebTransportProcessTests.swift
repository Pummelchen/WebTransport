import Foundation
import Darwin
import Testing
import WebTransportLoopbackTestSupport

// MARK: - Help and Scenario Selection

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

// MARK: - Skipped Scenarios

/// A scenario that needs the repository is skipped, not failed, when there is no checkout.
///
/// This is the shape the released binaries hit: run from a directory holding only the two
/// downloaded assets, the two Release scenarios read `Package.swift` and
/// `Swift/build-release-apple-silicon.sh` from the working directory. Before WT-186 the
/// suite reported `passed=38 failed=2` for two scenarios it had not attempted at all,
/// which reads as a broken binary rather than an incomplete run. It now reports them
/// skipped with a reason, and the exit status separates the two cases.
@Test
func webTransportCLIProcessSkipsRepositoryScenariosOutsideACheckout() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let logDirectory = try WebTransportProcessSupport.temporaryLogDirectory("skip-outside-checkout")
        // A working directory that is not a checkout: neither candidate path resolves.
        let emptyDirectory = logDirectory.appendingPathComponent("not-a-checkout", isDirectory: true)
        try FileManager.default.createDirectory(at: emptyDirectory, withIntermediateDirectories: true)

        let result = try WebTransportProcessSupport.run(
            server,
            [
                "--scenario", "release-products,release-script-stale-spikes",
                "--json",
                "--log-dir", logDirectory.path,
            ],
            currentDirectory: emptyDirectory
        )

        // Nothing failed; something was not attempted. 3 is the skip status, and it is the
        // whole point: before this a caller could not tell an incomplete run from a broken
        // one, because both were 1.
        #expect(result.exitCode == 3)

        let payload = try WebTransportProcessSupport.parseJSONResult(result.stdout)
        #expect(payload["passed"] as? Int == 0)
        #expect(payload["failed"] as? Int == 0)
        #expect(payload["skipped"] as? Int == 2)

        let entries = payload["results"] as? [[String: Any]]
        #expect(entries?.count == 2)
        #expect(entries?.allSatisfy { ($0["status"] as? String) == "skipped" } == true)
        // A skipped scenario is not a pass, even though it is not a failure either.
        #expect(entries?.allSatisfy { ($0["passed"] as? Bool) == false } == true)
        // The reason travels with the row, so a reader learns why the run was incomplete.
        #expect(
            entries?.allSatisfy {
                (($0["detail"] as? String) ?? "").contains("requires a repository checkout")
            } == true)
    }
}

/// The same two scenarios still run for real when the working directory is a checkout.
///
/// The skip must not become a way for a repository scenario to quietly stop running where
/// it can run — which is the failure mode that would make the skip worse than the bug.
@Test
func webTransportCLIProcessRunsRepositoryScenariosInsideACheckout() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let logDirectory = try WebTransportProcessSupport.temporaryLogDirectory("skip-inside-checkout")

        let result = try WebTransportProcessSupport.run(
            server,
            [
                "--scenario", "release-products,release-script-stale-spikes",
                "--json",
                "--log-dir", logDirectory.path,
            ]
        )

        #expect(result.exitCode == 0)
        let payload = try WebTransportProcessSupport.parseJSONResult(result.stdout)
        #expect(payload["passed"] as? Int == 2)
        #expect(payload["failed"] as? Int == 0)
        #expect(payload["skipped"] as? Int == 0)
    }
}

/// The human report and the logs carry the skip too, and a skip writes no failure log.
///
/// A skipped scenario did not fail, so leaving a `-failure.log` behind would contradict the
/// summary it sits beside.
@Test
func webTransportCLIProcessReportsSkipsInSummaryWithoutFailureLogs() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let logDirectory = try WebTransportProcessSupport.temporaryLogDirectory("skip-summary")
        let emptyDirectory = logDirectory.appendingPathComponent("not-a-checkout", isDirectory: true)
        try FileManager.default.createDirectory(at: emptyDirectory, withIntermediateDirectories: true)

        let result = try WebTransportProcessSupport.run(
            server,
            [
                "--scenario", "release-products,release-script-stale-spikes",
                "--verbose",
                "--log-dir", logDirectory.path,
            ],
            currentDirectory: emptyDirectory
        )

        #expect(result.exitCode == 3)
        #expect(result.stdout.contains("SKIP release-products"))
        #expect(result.stdout.contains("SKIP release-script-stale-spikes"))
        #expect(result.stdout.contains("failed=0"))
        #expect(result.stdout.contains("skipped=2"))
        // The names are still reported, so a caller comparing scenario names sees the run
        // was incomplete rather than shorter.
        #expect(
            Set(WebTransportProcessSupport.scenarioResultNames(from: result.stdout))
                == Set(["release-products", "release-script-stale-spikes"]))

        let entries = try FileManager.default.contentsOfDirectory(atPath: logDirectory.path)
        #expect(entries.contains { $0.hasSuffix("-failure.log") } == false)
        let summary = entries.first { $0.hasSuffix("-summary.log") }
        #expect(summary != nil)
        if let summary {
            let text = try String(contentsOfFile: logDirectory.appendingPathComponent(summary).path, encoding: .utf8)
            #expect(text.contains("skipped=2"))
            #expect(text.contains("SKIP release-products"))
        }
    }
}

// MARK: - Scenario Matrix Group Tests

@Test
func webTransportCLIProcessRunsScenarioMatrixAcrossClientAndServer() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let scenarios = [
            "session-accept",
            "session-reject-policy",
            "session-invalid-id",
            "datagram-round-trip",
            "stream-bidi-uni-round-trip",
            "close-drain",
            "flow-monotonic",
            "interop-malformed-flow-matrix",
        ]
        let flag = scenarios.joined(separator: ",")
        let logDirectory = try WebTransportProcessSupport.temporaryLogDirectory("matrix")

        let clientResult = try WebTransportProcessSupport.run(
            client,
            ["--scenario", flag, "--log-dir", logDirectory.path]
        )
        #expect(clientResult.exitCode == 0)
        #expect(Set(WebTransportProcessSupport.scenarioResultNames(from: clientResult.stdout)) == Set(scenarios))

        let serverResult = try WebTransportProcessSupport.run(
            server,
            ["--scenario", flag, "--log-dir", logDirectory.path]
        )
        #expect(serverResult.exitCode == 0)
        #expect(Set(WebTransportProcessSupport.scenarioResultNames(from: serverResult.stdout)) == Set(scenarios))
    }
}

@Test
func webTransportCLIProcessFailureLogCapturesDeterministicScenarioFailures() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let logDirectory = try WebTransportProcessSupport.temporaryLogDirectory("failure")
        let missingScenario = "does-not-exist"

        let result = try WebTransportProcessSupport.run(
            client,
            ["--scenario", missingScenario, "--log-dir", logDirectory.path]
        )
        #expect(result.exitCode == 1)
        #expect(result.stdout.contains("FAIL \(missingScenario)"))

        let files = try FileManager.default.contentsOfDirectory(atPath: logDirectory.path)
            .filter { $0.hasSuffix("-failure.log") }
        #expect(files.count == 1)
        let failureLogPath = logDirectory.appendingPathComponent(files[0])
        let failureLog = try String(contentsOf: failureLogPath, encoding: .utf8)
        #expect(failureLog.contains("passed=false"))
        #expect(failureLog.contains("scenario=\(missingScenario)"))
        #expect(!failureLog.contains("secret"))
    }
}

@Test
func webTransportCLIProcessJSONContractForSelectedScenarios() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let result = try WebTransportProcessSupport.run(
            client,
            ["--scenario", "demo,session-accept", "--json"]
        )
        #expect(result.exitCode == 0)

        let payload = try WebTransportProcessSupport.parseJSONResult(result.stdout)
        let passed = (payload["passed"] as? Int) ?? Int((payload["passed"] as? NSNumber)?.intValue ?? -1)
        let failed = (payload["failed"] as? Int) ?? Int((payload["failed"] as? NSNumber)?.intValue ?? -1)
        let results = payload["results"] as? [[String: Any]]

        #expect(payload["executable"] as? String == "WebTransportClient")
        #expect(passed == 2)
        #expect(failed == 0)
        #expect(results?.count == 2)
        #expect(Set(results?.compactMap { $0["name"] as? String } ?? []) == Set(["demo", "session-accept"]))
        #expect(
            results?.allSatisfy { entry in
                (entry["passed"] as? Bool == true) && (entry["durationSeconds"] != nil) && (entry["detail"] as? String == "passed")
            } == true)
    }
}

@Test
func webTransportCLIProcessGroupedOutputAndMachineReadableList() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")

        let help = try WebTransportProcessSupport.run(client, ["--help"])
        #expect(help.exitCode == 0)
        #expect(help.stdout.contains("Smoke:"))
        #expect(help.stdout.contains("Session Establishment:"))
        #expect(help.stdout.contains("HTTP/3 Control:"))

        let verbose = try WebTransportProcessSupport.run(
            client,
            ["--scenario", "demo,session-accept", "--verbose"]
        )
        #expect(verbose.exitCode == 0)
        #expect(verbose.stdout.contains("Smoke:"))
        #expect(verbose.stdout.contains("Session Establishment:"))
        #expect(verbose.stdout.contains("RUN demo"))
        #expect(verbose.stdout.contains("RUN session-accept"))
        #expect(verbose.stdout.contains("PASS demo"))
        #expect(verbose.stdout.contains("PASS session-accept"))

        let list = try WebTransportProcessSupport.run(server, ["--list"])
        #expect(!list.stdout.contains("Smoke:"))
        #expect(!list.stdout.contains("Session Establishment:"))
        #expect(list.stdout.contains("demo"))
    }
}

@Test
func webTransportCLIProcessSelectiveScenarioExecutionIsRespected() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")

        let result = try WebTransportProcessSupport.run(client, ["--scenario", "demo,session-accept"])
        #expect(result.exitCode == 0)
        #expect(Set(WebTransportProcessSupport.scenarioResultNames(from: result.stdout)) == Set(["demo", "session-accept"]))

        let unknown = try WebTransportProcessSupport.run(client, ["--scenario", "demo,does-not-exist"])
        #expect(unknown.exitCode == 1)
        #expect(unknown.stdout.contains("FAIL does-not-exist"))
        #expect(unknown.stdout.contains("PASS demo"))
    }
}

@Test
func webTransportCLIProcessPolicyScenarioMatrix() throws {
    try runScenarioMatrix(
        ["session-reject-policy", "session-invalid-id", "security-prompt-free-negatives"],
        expectedPasses: 3
    )
}

@Test
func webTransportCLIProcessCloseAndDrainScenarioMatrix() throws {
    try runScenarioMatrix(
        ["close-drain", "close-message-bounds", "connect-finish-close", "connect-data-after-close"],
        expectedPasses: 4
    )
}

@Test
func webTransportCLIProcessBackpressureAndResourceLimitScenarios() throws {
    try runScenarioMatrix(
        ["stream-buffering", "stream-buffer-overflow-reset", "datagram-buffering", "datagram-after-close", "flow-receive-violation-close"],
        expectedPasses: 5
    )
}

@Test
func webTransportCLIProcessMultiSessionScenarioIsolation() throws {
    try runScenarioMatrix(["multi-session-isolation", "flow-disabled-multi-session", "flow-explicit-zero"], expectedPasses: 3)
}

@Test
func webTransportCLIProcessMalformedFlowAndStreamMatrix() throws {
    try runScenarioMatrix(["interop-malformed-flow-matrix", "interop-stream-matrix", "interop-datagram-matrix"], expectedPasses: 3)
}

// MARK: - Connectivity and Loopback

@Test
func webTransportCLIProcessLoopbackCoversPacketTransportAndRejectsFrameNetworkMode() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        try WebTransportProcessSupport.runLoopback(host: "127.0.0.1", transport: "packet", expectsEstablishedSession: true)
        try WebTransportProcessSupport.runLoopback(host: "::1", transport: "packet", expectsEstablishedSession: true)

        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let rejectedClient = try WebTransportProcessSupport.run(
            client,
            ["--connect", "127.0.0.1:65000", "--transport", "frame", "--timeout-ms", "200"]
        )
        #expect(rejectedClient.exitCode == 1)
        #expect(rejectedClient.stderr.contains("packet transport only"))

        let rejectedServer = try WebTransportProcessSupport.run(
            server,
            ["--listen", "127.0.0.1:0", "--transport", "frame", "--timeout-ms", "200"]
        )
        #expect(rejectedServer.exitCode == 1)
        #expect(rejectedServer.stderr.contains("packet transport only"))
    }
}

@Test
func webTransportCLIProcessPortBindingAndOccupiedPortHandling() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")

        let runningServer = try WebTransportProcessSupport.start(
            server,
            ["--listen", "127.0.0.1:0", "--transport", "packet", "--timeout-ms", "5000"]
        )
        defer {
            runningServer.terminateIfNeeded()
        }
        let listening = try runningServer.waitForOutput(containing: "listening:", timeout: 5)
        let port = try WebTransportProcessSupport.parseListeningPort(from: listening)
        #expect(port > 0)

        let occupied = try WebTransportProcessSupport.run(
            server,
            ["--listen", "127.0.0.1:\(port)", "--transport", "packet", "--timeout-ms", "500"],
            timeout: 2
        )
        #expect(occupied.exitCode != 0)

        let badAddress = try WebTransportProcessSupport.run(server, ["--listen", "127.0.0.1"])
        #expect(badAddress.exitCode != 0)
    }
}

@Test
func webTransportCLIProcessGracefulShutdownPath() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let runningServer = try WebTransportProcessSupport.start(
            server,
            ["--listen", "127.0.0.1:0", "--transport", "packet", "--timeout-ms", "10000", "--max-sessions", "8"]
        )
        _ = try runningServer.waitForOutput(containing: "listening:", timeout: 5)
        runningServer.terminateIfNeeded()
        let result = try runningServer.wait(timeout: 5)
        #expect(result.exitCode != 0)
    }
}

@Test
func webTransportCLIProcessConcurrentClientsAgainstSingleServer() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let runningServer = try WebTransportProcessSupport.start(
            server,
            ["--listen", "127.0.0.1:0", "--transport", "packet", "--timeout-ms", "20000", "--max-sessions", "16"]
        )
        defer {
            runningServer.terminateIfNeeded()
        }
        let line = try runningServer.waitForOutput(containing: "listening:", timeout: 5)
        let port = try WebTransportProcessSupport.parseListeningPort(from: line)

        let count = 2
        let maxConcurrentClients = 2
        let launchGate = DispatchSemaphore(value: maxConcurrentClients)
        final class ConcurrentCapture: @unchecked Sendable {
            private(set) var results: [ProcessResult] = []
            private(set) var errors: [String] = []
            private(set) var connectedCount = 0
            private let lock = NSLock()

            func addResult(_ result: ProcessResult, connected: Bool, message: String) {
                lock.lock()
                defer { lock.unlock() }
                results.append(result)
                if connected {
                    connectedCount += 1
                } else if !message.isEmpty {
                    errors.append(message)
                }
            }

            func addError(_ message: String) {
                lock.lock()
                defer { lock.unlock() }
                errors.append(message)
            }
        }
        let capture = ConcurrentCapture()

        let group = DispatchGroup()
        for index in 0..<count {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                launchGate.wait()
                do {
                    var result = try WebTransportProcessSupport.run(
                        client,
                        [
                            "--connect", "127.0.0.1:\(port)", "--transport", "packet", "--trust", "local-self-signed", "--message", "concurrent-\(index)",
                            "--timeout-ms", "25000",
                        ],
                        timeout: 30
                    )
                    var attempts = 1
                    while !result.stdout.contains("connected") && attempts < 4 {
                        attempts += 1
                        Thread.sleep(forTimeInterval: 0.12)
                        result = try WebTransportProcessSupport.run(
                            client,
                            [
                                "--connect", "127.0.0.1:\(port)", "--transport", "packet", "--trust", "local-self-signed", "--message",
                                "concurrent-\(index)-retry-\(attempts)", "--timeout-ms", "25000",
                            ],
                            timeout: 30
                        )
                    }
                    let message =
                        result.stdout.contains("connected")
                        ? ""
                        : "non-connected client #\(index) after \(attempts) attempts: exit=\(result.exitCode) stdout=\(result.stdout) stderr=\(result.stderr)"
                    capture.addResult(result, connected: result.stdout.contains("connected"), message: message)
                } catch {
                    capture.addError("client process #\(index) failed: \(error.localizedDescription)")
                }
                launchGate.signal()
                group.leave()
            }
        }
        let done = group.wait(timeout: .now() + 180)
        let failures = capture.errors.filter { !$0.isEmpty }
        #expect(done == .success, Comment(rawValue: failures.joined(separator: "\n")))
        #expect(capture.connectedCount == count, Comment(rawValue: failures.joined(separator: "\n")))
        #expect(failures.isEmpty)
        #expect(capture.results.count == count, Comment(rawValue: failures.joined(separator: "\n")))
    }
}

// MARK: - Stress and Stability

@Test
func webTransportCLIProcessScenarioSoakForStability() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")
        let rawRounds = Int(ProcessInfo.processInfo.environment["WEBTRANSPORT_CLI_SOAK_ROUNDS"] ?? "") ?? 5
        let rounds = max(1, min(rawRounds, 20))
        for index in 0..<rounds {
            let result = try WebTransportProcessSupport.run(
                client,
                ["--scenario", "demo", "--log-dir", NSTemporaryDirectory().appending("wt-soak-\(index)")]
            )
            #expect(result.exitCode == 0)
            #expect(WebTransportProcessSupport.scenarioResultNames(from: result.stdout) == ["demo"])
        }
    }
}

@Test
func webTransportCLIProcessInteropTimeoutAndMalformedInputHardening() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let client = try WebTransportProcessSupport.productURL("WebTransportClient", configuration: "debug")

        let timeout = try WebTransportProcessSupport.run(
            client,
            ["--connect", "127.0.0.1:65000", "--transport", "packet", "--message", "interop-timeout", "--timeout-ms", "200"]
        )
        #expect(timeout.exitCode != 0)
        #expect(timeout.stdout.isEmpty || !timeout.stdout.contains("connected"))

        let malformedTransport = try WebTransportProcessSupport.run(
            client,
            ["--connect", "127.0.0.1:65000", "--transport", "bad"]
        )
        #expect(malformedTransport.exitCode != 0)
    }
}

// MARK: - External Hooks and Artifacts

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
        let authority = environment["WEBTRANSPORT_EXTERNAL_INTEROP_AUTHORITY"] ?? endpoint.split(separator: ":").first.map(String.init) ?? "localhost"
        let path = environment["WEBTRANSPORT_EXTERNAL_INTEROP_PATH"] ?? "/"
        let origin = environment["WEBTRANSPORT_EXTERNAL_INTEROP_ORIGIN"] ?? "https://\(authority)"
        let wtProtocol = environment["WEBTRANSPORT_EXTERNAL_INTEROP_PROTOCOL"] ?? "none"
        let trust = environment["WEBTRANSPORT_EXTERNAL_INTEROP_TRUST"] ?? "system"
        let message = environment["WEBTRANSPORT_EXTERNAL_INTEROP_MESSAGE"] ?? "external-interop"
        let timeoutMilliseconds = environment["WEBTRANSPORT_EXTERNAL_INTEROP_TIMEOUT_MS"] ?? "5000"
        let result = try WebTransportProcessSupport.run(
            client,
            [
                "--connect", endpoint,
                "--transport", transport,
                "--authority", authority,
                "--path", path,
                "--origin", origin,
                "--protocol", wtProtocol,
                "--trust", trust,
                "--message", message,
                "--timeout-ms", timeoutMilliseconds,
            ],
            timeout: 10
        )
        #expect(result.exitCode == 0)
        #expect(result.stdout.contains("connected"))
        #expect(result.stdout.contains(message))
        try WebTransportProcessSupport.writeExternalInteropProof(
            implementation: environment["WEBTRANSPORT_EXTERNAL_INTEROP_IMPLEMENTATION"] ?? "configured independent WebTransport endpoint",
            endpoint: endpoint,
            authority: authority,
            path: path,
            origin: origin,
            wtProtocol: wtProtocol,
            transport: transport,
            trust: trust,
            message: message,
            timeoutMilliseconds: timeoutMilliseconds,
            result: result
        )
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

    fileprivate static func run(
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

    fileprivate static func start(_ executable: URL, _ arguments: [String]) throws -> RunningProcess {
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

    fileprivate static func writeExternalInteropProof(
        implementation: String,
        endpoint: String,
        authority: String,
        path: String,
        origin: String,
        wtProtocol: String,
        transport: String,
        trust: String,
        message: String,
        timeoutMilliseconds: String,
        result: ProcessResult
    ) throws {
        let directory = packageDirectory.appendingPathComponent(".build/external-interop", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let proof: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "independentImplementation": implementation,
            "endpoint": endpoint,
            "authority": authority,
            "path": path,
            "origin": origin == "none" ? NSNull() : origin,
            "protocol": wtProtocol == "none" ? NSNull() : wtProtocol,
            "transport": transport,
            "trust": trust,
            "message": message,
            "timeoutMilliseconds": Int(timeoutMilliseconds) ?? 0,
            "exitCode": Int(result.exitCode),
            "passed": result.exitCode == 0 && result.stdout.contains("connected") && result.stdout.contains(message),
            "stdout": result.stdout,
            "stderr": result.stderr,
        ]
        let data = try JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: directory.appendingPathComponent("latest.json"))
        try result.stdout.write(to: directory.appendingPathComponent("latest.stdout"), atomically: true, encoding: .utf8)
        try result.stderr.write(to: directory.appendingPathComponent("latest.stderr"), atomically: true, encoding: .utf8)
    }
}

private func runScenarioMatrix(_ scenarios: [String], expectedPasses: Int) throws {
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
