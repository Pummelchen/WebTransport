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

// MARK: - No Listener Without A Mode

/// The no-argument invocation must not report a listener it never started.
///
/// `WebTransportServer` with no arguments used to build a configuration, store it in a
/// discarded `WebTransportServer` value, print "local demo endpoint ready" and exit 0.
/// `WebTransportServer.init` only stores the configuration; it does not bind a socket. A
/// supervisor or health probe that keys on the exit status therefore read a dead process as a
/// running endpoint, which is the "hardcoded success / surface wired to nothing" shape the
/// audit brief bans on a production path (F-repo-ops-07).
@Test
func webTransportCLIProcessRefusesToClaimReadinessWithoutAListener() throws {
    try WebTransportProcessSupport.withExclusiveProcessExecution {
        guard try WebTransportProcessSupport.debugProductsAvailable() else {
            return
        }
        let server = try WebTransportProcessSupport.productURL("WebTransportServer", configuration: "debug")

        let result = try WebTransportProcessSupport.run(server, [])

        // Nothing was started, so nothing may report success (2 is this tool's argument error).
        #expect(result.exitCode == 2)
        #expect(result.stdout.contains("ready") == false)
        #expect(result.stdout.contains("listening") == false)
        // The refusal names the argument that would start a listener.
        #expect(result.stderr.contains("--listen"))
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
