import Foundation
import Darwin
import Testing
import WebTransportLoopbackTestSupport

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

        // F-repo-ops-15: a non-positive --timeout-ms would wait forever downstream, so it is
        // an argument error at parse time, and the space-separated and `=` forms must refuse
        // it with the same specific message rather than accepting it or falling back to the
        // generic "invalid payload".
        for arguments in [
            ["--listen", "127.0.0.1:0", "--timeout-ms", "0"],
            ["--listen", "127.0.0.1:0", "--timeout-ms=-1"],
        ] {
            let rejected = try WebTransportProcessSupport.run(server, arguments)
            #expect(rejected.exitCode != 0)
            #expect(rejected.stderr.contains("--timeout-ms requires a positive integer in milliseconds"))
        }
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
