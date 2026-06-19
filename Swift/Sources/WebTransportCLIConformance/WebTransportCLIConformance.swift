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
            let argument = arguments[index]
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
                if argument.hasPrefix("--scenario=") {
                    let value = String(argument.dropFirst("--scenario=".count))
                    options.selectedScenarios.append(contentsOf: splitScenarioList(value))
                } else if argument.hasPrefix("--log-dir=") {
                    options.logDirectory = String(argument.dropFirst("--log-dir=".count))
                } else {
                    throw WebTransportCLIConformanceExit.invalidArguments("unknown argument: \(argument)")
                }
            }
            index += 1
        }

        if options.selectedScenarios.isEmpty {
            options.selectedScenarios = ["all"]
        }
        return options
    }

    private static func splitScenarioList(_ value: String) -> [String] {
        value.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

public struct WebTransportCLIConformanceResult: Equatable, Sendable {
    public var name: String
    public var passed: Bool
    public var durationSeconds: Double
    public var detail: String
}

public enum WebTransportCLIConformance {
    public static func helpText(executableName: String) -> String {
        """
        Usage: \(executableName) [--scenario NAME|all] [--json] [--verbose] [--log-dir PATH]

        Scenarios:
        \(groupedScenarioHelpText())

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
        let selectedNames: [String]
        if options.selectedScenarios.contains("all") {
            selectedNames = catalog.map(\.name)
        } else {
            selectedNames = options.selectedScenarios
        }

        var scenariosByName: [String: CLIConformanceScenario] = [:]
        for scenario in catalog {
            scenariosByName[scenario.name] = scenario
        }

        var results: [WebTransportCLIConformanceResult] = []
        var failures: [String] = []
        var verboseGroup: String?
        let logURL = URL(fileURLWithPath: options.logDirectory, isDirectory: true)
        try? FileManager.default.createDirectory(at: logURL, withIntermediateDirectories: true)

        for name in selectedNames {
            guard let scenario = scenariosByName[name] else {
                let detail = "unknown scenario: \(name)"
                let result = WebTransportCLIConformanceResult(name: name, passed: false, durationSeconds: 0, detail: detail)
                results.append(result)
                failures.append(detail)
                writeFailureLog(result: result, executableName: options.executableName, directory: logURL)
                continue
            }

            if options.verbose, !options.json {
                printScenarioGroupHeading(scenario.group, current: &verboseGroup)
                print("  RUN \(scenario.name): \(scenario.description)")
            }
            let started = Date()
            do {
                try await scenario.run()
                let duration = Date().timeIntervalSince(started)
                results.append(WebTransportCLIConformanceResult(
                    name: scenario.name,
                    passed: true,
                    durationSeconds: duration,
                    detail: "passed"
                ))
                if options.verbose, !options.json {
                    print("  PASS \(scenario.name) \(format(duration))s")
                }
            } catch {
                let duration = Date().timeIntervalSince(started)
                let detail = String(describing: error)
                let result = WebTransportCLIConformanceResult(
                    name: scenario.name,
                    passed: false,
                    durationSeconds: duration,
                    detail: detail
                )
                results.append(result)
                failures.append("\(scenario.name): \(detail)")
                writeFailureLog(result: result, executableName: options.executableName, directory: logURL)
                if options.verbose, !options.json {
                    print("  FAIL \(scenario.name) \(format(duration))s \(detail)")
                }
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
        return failures.isEmpty ? 0 : 1
    }
}

private func groupedScenarioHelpText() -> String {
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

private struct CLIConformanceScenario: Sendable {
    var group: String
    var name: String
    var description: String
    var run: @Sendable () async throws -> Void
}

private func scenarioCatalog() -> [CLIConformanceScenario] {
    [
        scenario("Smoke", "demo", "async client/server API connect, datagram, and close") {
            try await runClientServerAPIDemo()
        },
        scenario("Smoke", "library-smoke-matrix", "library smoke matrix passes close, rejection, backpressure, ordering, and multi-session") {
            let results = WebTransportLibrarySmokeMatrix.runAll()
            let failures = results.filter { !$0.passed }
            try require(failures.isEmpty, "library smoke failures: \(failures)")
        },
        scenario("Session Establishment", "session-accept", "extended CONNECT accepts and selects a protocol") {
            var pair = try makeReadyPair()
            let request = try WebTransportSessionRequest(
                authority: "example.com",
                path: "/wt",
                origin: "https://example.com",
                availableProtocols: ["chat.v1", "chat.v2"]
            )
            let policy = try WebTransportServerSessionPolicy(
                allowedAuthorities: ["example.com"],
                allowedPaths: ["/wt"],
                allowedOrigins: ["https://example.com"],
                supportedProtocols: ["chat.v2"],
                requireProtocolSelection: true
            )
            let sessionID = try establishSession(pair: &pair, streamID: 0, request: request, policy: policy)
            try require(sessionID.rawValue == 0, "session ID derived from request stream ID")
            try require(pair.client.session(forRequestStreamID: 0)?.selectedProtocol == "chat.v2", "client selected protocol")
            try require(pair.server.session(forRequestStreamID: 0)?.selectedProtocol == "chat.v2", "server selected protocol")
        },
        scenario("Session Establishment", "session-reject-policy", "path, origin, and protocol policy rejections are deterministic") {
            var pair = try makeReadyPair()
            let pathDecision = try rejectSession(
                pair: &pair,
                streamID: 0,
                request: try WebTransportSessionRequest(authority: "example.com", path: "/blocked"),
                policy: try WebTransportServerSessionPolicy(allowedPaths: ["/wt"])
            )
            try require(pathDecision.session.state == .rejected(status: 404), "bad path rejected with 404")

            pair = try makeReadyPair()
            let originDecision = try rejectSession(
                pair: &pair,
                streamID: 0,
                request: try WebTransportSessionRequest(authority: "example.com", path: "/wt", origin: "https://bad.example"),
                policy: try WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
            )
            try require(originDecision.session.state == .rejected(status: 403), "bad origin rejected with 403")

            pair = try makeReadyPair()
            let protocolDecision = try rejectSession(
                pair: &pair,
                streamID: 0,
                request: try WebTransportSessionRequest(authority: "example.com", path: "/wt", availableProtocols: ["chat.v1"]),
                policy: try WebTransportServerSessionPolicy(supportedProtocols: ["chat.v2"], requireProtocolSelection: true)
            )
            try require(protocolDecision.session.state == .rejected(status: 400), "protocol mismatch rejected with 400")
        },
        scenario("Session Establishment", "session-invalid-id", "invalid WebTransport session IDs map to H3_ID_ERROR paths") {
            try expectThrows { _ = try WebTransportSessionID.fromRequestStreamID(1) }
            try expectThrows { _ = try WebTransportSessionID.fromRequestStreamID(2) }
            let prefix = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 2)
            try expectThrows {
                _ = try WebTransportStreamSignaling.parsePrefix(prefix)
            }
        },
        scenario("HTTP/3 Control", "settings-required", "HTTP/3 WebTransport settings requirements are enforced") {
            let constants = WebTransportHTTP3DraftConstants.current
            try HTTP3Settings.webTransportDraft15Defaults.validateWebTransportDraft15Requirements(peerRole: .server)
            var missingDatagram = HTTP3Settings.webTransportDraft15Defaults
            try missingDatagram.set(0, for: constants.settingsH3Datagram)
            try expectThrows {
                try missingDatagram.validateWebTransportDraft15Requirements(peerRole: .server)
            }
            var serverPeerSettings = HTTP3Settings.webTransportDraft15Defaults
            try serverPeerSettings.set(0, for: constants.settingsEnableConnectProtocol)
            try serverPeerSettings.validateWebTransportDraft15Requirements(peerRole: .client)
        },
        scenario("HTTP/3 Control", "settings-control-stream-errors", "control stream duplicate and request-frame errors are rejected") {
            let connection = HTTP3ConnectionState(role: .client)
            let control = try connection.localControlStreamBytes()
            var peer = HTTP3ConnectionState(role: .server)
            _ = try peer.receivePeerControlStream(control)
            try expectThrows { _ = try peer.receivePeerControlStream(control) }
            try expectThrows {
                try peer.receiveControlFrame(try QPACK.headersFrame(fields: [HTTPFieldLine(name: ":status", value: "200")]))
            }
        },
        scenario("HTTP/3 Control", "zero-rtt-settings", "remembered 0-RTT settings reject reduced WebTransport capacity") {
            let constants = WebTransportHTTP3DraftConstants.current
            var remembered = HTTP3Settings.webTransportDraft15Defaults
            var current = HTTP3Settings.webTransportDraft15Defaults
            try remembered.set(8, for: constants.settingsWTInitialMaxStreamsBidi)
            try current.set(4, for: constants.settingsWTInitialMaxStreamsBidi)
            try expectThrows {
                try current.validateWebTransportZeroRTTCompatibility(remembered: remembered)
            }
        },
        scenario("Headers and QPACK", "protocol-structured-fields", "WT protocol negotiation uses Structured Fields strings and lists") {
            let encoded = try WebTransportProtocolNegotiation.encodeList(["chat.v1", "demo-v2"])
            try require(try WebTransportProtocolNegotiation.decodeList(encoded) == ["chat.v1", "demo-v2"], "structured list round trip")
            let item = WebTransportProtocolNegotiation.encodeItem("chat.v2")
            try require(try WebTransportProtocolNegotiation.decodeItem(item + "; q=1") == "chat.v2", "structured item parameter ignored")
            try expectThrows {
                _ = try WebTransportProtocolNegotiation.decodeList("\"bad\\n\"")
            }
        },
        scenario("Headers and QPACK", "headers-connect-round-trip", "CONNECT request and response HEADERS round-trip through QPACK") {
            let request = try WebTransportSessionRequest(
                authority: "example.com",
                path: "/wt",
                origin: "https://example.com",
                availableProtocols: ["chat.v1"]
            )
            let frame = try QPACK.headersFrame(fields: request.headers())
            let fields = try QPACK.decodeHeadersFrame(frame)
            try WebTransportHTTP3Headers.validateConnectRequest(fields)
            let response = try QPACK.headersFrame(fields: [
                HTTPFieldLine(name: ":status", value: "200"),
                HTTPFieldLine(name: WebTransportHeaderName.selectedProtocol, value: WebTransportProtocolNegotiation.encodeItem("chat.v1"))
            ])
            try WebTransportHTTP3Headers.validateSuccessfulResponse(try QPACK.decodeHeadersFrame(response))
        },
        scenario("Headers and QPACK", "qpack-static-literal-huffman", "QPACK static, literal, and Huffman field sections round-trip") {
            let fields = try [
                HTTPFieldLine(name: ":status", value: "200"),
                HTTPFieldLine(name: "x-webtransport", value: "demo")
            ]
            let plain = try QPACK.decodeFieldSection(QPACK.encodeFieldSection(fields))
            try require(plain == fields, "plain QPACK round trip")
            let huffman = try QPACK.decodeFieldSection(QPACK.encodeFieldSection(fields, huffman: true))
            try require(huffman == fields, "Huffman QPACK round trip")
        },
        scenario("Headers and QPACK", "qpack-dynamic-base-postbase", "QPACK dynamic Base and post-Base references decode correctly") {
            var table = try QPACKDynamicTable(capacity: 256)
            let first = try HTTPFieldLine(name: "origin", value: "https://one.example")
            let second = try HTTPFieldLine(name: "x-demo", value: "two")
            let third = try HTTPFieldLine(name: "x-demo", value: "three")
            try table.insert(first)
            try table.insert(second)
            try table.insert(third)
            var fieldSection = Data([0x03, 0x81, 0x11, 0x00, 0x08])
            fieldSection.append(Data("override".utf8))
            let decoded = try QPACK.decodeFieldSection(fieldSection, dynamicTable: table)
            try require(decoded == [third, HTTPFieldLine(name: "x-demo", value: "override")], "post-Base fields decoded")
            try expectThrows {
                _ = try QPACK.decodeFieldSection(Data([0x01, 0x81]), dynamicTable: table)
            }
        },
        scenario("Headers and QPACK", "qpack-limits", "QPACK malformed input and decoder limits fail") {
            try expectThrows { _ = try QPACK.decodeFieldSection(Data([0x01, 0x00])) }
            let field = try HTTPFieldLine(name: "x-too-large", value: String(repeating: "x", count: 16))
            let data = try QPACK.encodeFieldSection([field])
            try expectThrows {
                _ = try QPACK.decodeFieldSection(data, limits: QPACKDecoderLimits(maxFieldSectionBytes: 512, maxFieldLineBytes: 4, maxFieldLineCount: 4))
            }
        },
        scenario("Datagrams", "datagram-round-trip", "session datagrams route by quarter stream ID and preserve payload") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            let frame = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("hello".utf8))
            let received = try pair.server.receiveDatagramFrame(frame)
            try require(received == sessionID, "datagram session routed")
            try require(pair.server.popDatagramPayload(sessionID: sessionID) == Data("hello".utf8), "datagram payload preserved")
            let parsed = try WebTransportDatagramSignaling.parse(try WebTransportDatagramSignaling.serialize(sessionID: sessionID.rawValue, payload: Data("x".utf8)))
            try require(parsed.quarterStreamID == 0, "quarter stream ID encoded")
        },
        scenario("Datagrams", "datagram-unknown-session", "unknown datagram session ID is rejected") {
            var pair = try makeReadyPair()
            try expectThrows {
                _ = try pair.client.receiveDatagramFrame(.datagram(
                    try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("orphan".utf8))
                ))
            }
        },
        scenario("Datagrams", "datagram-buffering", "early datagrams buffer before accept and excess early datagrams drop") {
            var pair = try makeReadyPair(maxBufferedDatagramsPerSession: 1)
            _ = try pair.server.receiveDatagramFrame(.datagram(
                try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("one".utf8))
            ))
            _ = try pair.server.receiveDatagramFrame(.datagram(
                try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("two".utf8))
            ))
            let sessionID = try establishDefaultSession(pair: &pair)
            try require(pair.server.popDatagramPayload(sessionID: sessionID) == Data("one".utf8), "first early datagram promoted")
            try require(pair.server.popDatagramPayload(sessionID: sessionID) == nil, "excess early datagram dropped")
        },
        scenario("Datagrams", "datagram-after-close", "datagram send after close fails with session gone") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            _ = try pair.client.makeCloseSessionCapsule(sessionID: sessionID, applicationErrorCode: 0, message: "")
            try expectThrows {
                _ = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("late".utf8))
            }
        },
        scenario("Streams", "stream-bidi-uni-round-trip", "bidirectional and unidirectional stream prefixes register by session") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            let bidiPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
            _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: bidiPrefix + Data("bidi".utf8))
            try require(pair.server.popStreamPayload(streamID: 4) == Data("bidi".utf8), "bidi payload preserved")
            let uniPrefix = try pair.client.openUnidirectionalStream(streamID: 2, sessionID: sessionID)
            _ = try pair.server.acceptUnidirectionalStream(streamID: 2, firstBytes: uniPrefix + Data("uni".utf8))
            try require(pair.server.popStreamPayload(streamID: 2) == Data("uni".utf8), "uni payload preserved")
        },
        scenario("Streams", "stream-buffering", "early streams buffer before accept and promote in order") {
            var pair = try makeReadyPair()
            let early = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0) + Data("early".utf8)
            _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: early)
            try require(pair.server.stream(for: 4) == nil, "early stream not registered before accept")
            let sessionID = try establishDefaultSession(pair: &pair)
            try require(pair.server.stream(for: 4) != nil, "early stream promoted")
            try require(pair.server.popStreamPayload(streamID: 4) == Data("early".utf8), "early payload promoted")
            try require(sessionID.rawValue == 0, "session ID expected")
        },
        scenario("Streams", "stream-buffer-overflow-reset", "excess buffered stream emits WT_BUFFERED_STREAM_REJECTED reset action") {
            var pair = try makeReadyPair(maxBufferedStreamsPerSession: 0)
            let early = try WebTransportStreamSignaling.serializePrefix(form: .bidirectional, sessionID: 0)
            let result = try pair.server.acceptBidirectionalStreamWithActions(streamID: 4, firstBytes: early)
            try require(result.prefix == nil, "overflow stream rejected")
            try require(result.rejectionFrame == .resetStreamAt(
                id: 4,
                applicationErrorCode: WebTransportHTTP3DraftConstants.current.wtBufferedStreamRejectedError,
                finalSize: 0,
                reliableSize: 0
            ), "overflow stream reset action")
        },
        scenario("Streams", "stream-reset-stop-sending", "stream reset and stop-sending use mapped WebTransport app errors") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
            _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
            try require(try pair.server.resetStream(streamID: 4, applicationErrorCode: 0x10) == .resetStreamAt(
                id: 4,
                applicationErrorCode: WebTransportDraft15ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x10),
                finalSize: 0,
                reliableSize: 0
            ), "RESET_STREAM_AT mapped")
            try require(try pair.server.stopSendingStream(streamID: 4, applicationErrorCode: 0x11) == .stopSending(
                id: 4,
                applicationErrorCode: WebTransportDraft15ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x11)
            ), "STOP_SENDING mapped")
        },
        scenario("Close and Drain", "close-drain", "WT_DRAIN_SESSION and WT_CLOSE_SESSION drive state and cleanup") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
            _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
            let drain = try pair.client.makeDrainSessionCapsule(sessionID: sessionID)
            try require(try pair.server.receiveFlowControlCapsule(sessionID: sessionID, bytes: drain) == .drainSession, "drain capsule received")
            try require(pair.server.sessionsByID[sessionID]?.state == .draining, "server marked draining")
            let close = try pair.client.makeCloseSessionCapsule(sessionID: sessionID, applicationErrorCode: 7, message: "done")
            let received = try pair.server.receiveFlowControlCapsuleWithActions(sessionID: sessionID, bytes: close)
            try require(received.capsule == .closeSession(applicationErrorCode: 7, message: "done"), "close capsule received")
            try require(received.terminationActions?.streamResetFrames.count == 1, "close reset stream")
            try require(pair.server.stream(for: 4) == nil, "close cleaned stream")
        },
        scenario("Close and Drain", "close-message-bounds", "WT_CLOSE_SESSION accepts 8192-byte UTF-8 and rejects larger messages") {
            let max = WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes
            _ = try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 1, message: String(repeating: "x", count: max)))
            try expectThrows {
                _ = try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 1, message: String(repeating: "x", count: max + 1)))
            }
        },
        scenario("Close and Drain", "connect-finish-close", "CONNECT stream FIN closes the session and gates follow-on work") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            _ = try pair.client.finishConnectStream(streamID: sessionID.rawValue)
            try require(pair.client.sessionsByID[sessionID]?.state == .closed(applicationErrorCode: 0, message: ""), "FIN closed session")
            try expectThrows { _ = try pair.client.openUnidirectionalStream(streamID: 2, sessionID: sessionID) }
        },
        scenario("Close and Drain", "connect-data-after-close", "CONNECT data after received close resets with H3_MESSAGE_ERROR") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            _ = try pair.server.receiveFlowControlCapsuleWithActions(
                sessionID: sessionID,
                bytes: try WebTransportFlowCapsuleCodec.serialize(.closeSession(applicationErrorCode: 1, message: "closed"))
            )
            try require(try pair.server.receiveConnectStreamData(streamID: sessionID.rawValue, data: Data("late".utf8)) == .resetStream(
                id: sessionID.rawValue,
                applicationErrorCode: HTTP3ApplicationErrorCode.messageError.rawValue,
                finalSize: 0
            ), "late CONNECT data reset")
        },
        scenario("Flow Control", "flow-disabled-multi-session", "disabled WebTransport flow control rejects simultaneous sessions") {
            var pair = try makeReadyPair()
            _ = try establishDefaultSession(pair: &pair, streamID: 0)
            try expectThrows {
                _ = try pair.client.makeClientSessionRequest(
                    streamID: 4,
                    request: WebTransportSessionRequest(authority: "example.com", path: "/two")
                )
            }
        },
        scenario("Flow Control", "flow-explicit-zero", "explicit zero stream limit is enforced distinctly from disabled flow control") {
            let constants = WebTransportHTTP3DraftConstants.current
            var clientSettings = HTTP3Settings.webTransportDraft15Defaults
            var serverSettings = HTTP3Settings.webTransportDraft15Defaults
            try clientSettings.set(0, for: constants.settingsWTInitialMaxStreamsBidi)
            try serverSettings.set(0, for: constants.settingsWTInitialMaxStreamsBidi)
            var pair = try makeReadyPair(clientSettings: clientSettings, serverSettings: serverSettings)
            let sessionID = try establishDefaultSession(pair: &pair)
            try require(pair.client.flowState(for: sessionID)?.isEnabled == true, "flow control enabled")
            try require(pair.client.flowState(for: sessionID)?.maxStreamsBidi == 0, "explicit zero preserved")
            try expectThrows { _ = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID) }
        },
        scenario("Flow Control", "flow-monotonic", "WT_MAX_DATA and WT_MAX_STREAMS updates are monotonic") {
            var state = WebTransportFlowControlState(maxData: 4, maxStreamsBidi: 1, maxStreamsUni: 1)
            try state.apply(.maxData(limit: 8))
            try state.apply(.maxStreamsBidi(limit: 2))
            try state.apply(.maxStreamsUni(limit: 2))
            try expectThrows { try state.apply(.maxData(limit: 7)) }
            try expectThrows { try state.apply(.maxStreamsBidi(limit: 1)) }
            try expectThrows { try state.apply(.maxStreamsUni(limit: 1)) }
            try expectThrows { try state.apply(.maxStreamsBidi(limit: WebTransportHTTP3DraftConstants.current.maximumMaxStreamsValue + 1)) }
        },
        scenario("Flow Control", "flow-receive-violation-close", "receive-side advertised-limit violation closes with WT_FLOW_CONTROL_ERROR") {
            let constants = WebTransportHTTP3DraftConstants.current
            var clientSettings = HTTP3Settings.webTransportDraft15Defaults
            var serverSettings = HTTP3Settings.webTransportDraft15Defaults
            try clientSettings.set(4, for: constants.settingsWTInitialMaxData)
            try serverSettings.set(4, for: constants.settingsWTInitialMaxData)
            var pair = try makeReadyPair(clientSettings: clientSettings, serverSettings: serverSettings)
            let sessionID = try establishDefaultSession(pair: &pair)
            let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
            _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
            try expectThrows { try pair.server.receiveStreamPayload(streamID: 4, payload: Data(repeating: 1, count: 5)) }
            try require(pair.server.sessionsByID[sessionID]?.state == .closed(
                applicationErrorCode: UInt32(constants.wtFlowControlError),
                message: "WebTransport flow-control violation"
            ), "receive-side violation closed session")
        },
        scenario("Errors and Shutdown", "error-mapping", "WebTransport app error mapping is reversible and rejects reserved/out-of-range codes") {
            let code = WebTransportDraft15ErrorMapper.httpErrorCode(forApplicationErrorCode: 0x1234)
            try require(try WebTransportDraft15ErrorMapper.applicationErrorCode(forHTTPErrorCode: code) == 0x1234, "app error mapping reversible")
            try expectThrows {
                _ = try WebTransportDraft15ErrorMapper.applicationErrorCode(forHTTPErrorCode: 0x21)
            }
            try expectThrows {
                _ = try WebTransportDraft15ErrorMapper.applicationErrorCode(forHTTPErrorCode: WebTransportHTTP3DraftConstants.current.wtApplicationErrorRange.upperBound + 1)
            }
        },
        scenario("Errors and Shutdown", "goaway", "GOAWAY drains existing sessions and blocks late sessions") {
            var pair = try makeReadyPair()
            let sessionID = try establishDefaultSession(pair: &pair)
            try pair.client.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 0))
            try require(pair.client.sessionsByID[sessionID]?.state == .draining, "GOAWAY drains session")
            try expectThrows {
                _ = try pair.client.makeClientSessionRequest(
                    streamID: 4,
                    request: WebTransportSessionRequest(authority: "example.com", path: "/late")
                )
            }
        },
        scenario("Errors and Shutdown", "multi-session-isolation", "flow-control-enabled sessions isolate streams, datagrams, and close") {
            var pair = try WebTransportLibrarySmokePair.connectedWithFlowControl()
            let first = try pair.establishSession(streamID: 0, request: WebTransportSessionRequest(authority: "example.com", path: "/one"))
            let second = try pair.establishSession(streamID: 4, request: WebTransportSessionRequest(authority: "example.com", path: "/two"))
            _ = try pair.server.manager.receiveDatagramFrame(try pair.client.manager.makeDatagramFrame(sessionID: first, payload: Data("one".utf8)))
            _ = try pair.server.manager.receiveDatagramFrame(try pair.client.manager.makeDatagramFrame(sessionID: second, payload: Data("two".utf8)))
            try require(pair.server.manager.popDatagramPayload(sessionID: first) == Data("one".utf8), "first datagram isolated")
            try require(pair.server.manager.popDatagramPayload(sessionID: second) == Data("two".utf8), "second datagram isolated")
            let close = try pair.client.manager.makeCloseSessionCapsule(sessionID: first, applicationErrorCode: 1, message: "done")
            _ = try pair.server.manager.receiveFlowControlCapsuleWithActions(sessionID: first, bytes: close)
            try require(pair.server.manager.sessionsByID[first]?.state == .closed(applicationErrorCode: 1, message: "done"), "first closed")
            try require(pair.server.manager.sessionsByID[second]?.state == .accepted, "second remains accepted")
        },
        scenario("Interop Matrices", "interop-connect-matrix", "CONNECT interop accepts valid peers and rejects malformed or policy-invalid peers") {
            try runConnectInteropMatrix()
        },
        scenario("Interop Matrices", "interop-stream-matrix", "stream interop covers bidirectional/unidirectional success and invalid stream inputs") {
            try runStreamInteropMatrix()
        },
        scenario("Interop Matrices", "interop-datagram-matrix", "datagram interop covers routed payloads and invalid session, size, and prefix errors") {
            try runDatagramInteropMatrix()
        },
        scenario("Interop Matrices", "interop-goaway-close-drain-matrix", "GOAWAY, drain, and close interop gates late peer activity") {
            try runGoawayCloseDrainInteropMatrix()
        },
        scenario("Interop Matrices", "interop-malformed-flow-matrix", "malformed input and flow-control interop close or reject with deterministic errors") {
            try runMalformedFlowInteropMatrix()
        },
        scenario("Security", "security-prompt-free-negatives", "wrong ALPN, bad origin, bad settings, and trust failure are deterministic") {
            try expectThrows { try WebTransportALPNPolicy.validateNegotiatedProtocol("h2") }
            var pair = try makeReadyPair()
            let decision = try rejectSession(
                pair: &pair,
                streamID: 0,
                request: WebTransportSessionRequest(authority: "example.com", path: "/wt", origin: "https://bad.example"),
                policy: WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
            )
            try require(decision.rejectionError?.kind == .requirementsNotMet, "bad origin maps to requirements not met")
            var badSettings = HTTP3Settings.webTransportDraft15Defaults
            try badSettings.set(0, for: WebTransportHTTP3DraftConstants.current.settingsWTEnabled)
            try expectThrows { try badSettings.validateWebTransportDraft15Requirements(peerRole: .server) }
            let wrongPin = Data(repeating: 0xaa, count: TLS13KeySchedule.sha256Length)
            let policy = try TLSPinnedCertificateTrustPolicy(allowedLeafCertificateSHA256Fingerprints: [wrongPin])
            try expectThrows { try policy.evaluate(certificateChainDER: [Data("not a certificate".utf8)]) }
        },
        scenario("Release", "release-products", "Package.swift exposes production CLI products and not spike products") {
            let packageURL = URL(fileURLWithPath: "Swift/Package.swift")
            let fallbackURL = URL(fileURLWithPath: "Package.swift")
            let url = FileManager.default.fileExists(atPath: packageURL.path) ? packageURL : fallbackURL
            let text = try String(contentsOf: url, encoding: .utf8)
            try require(text.contains("name: \"WebTransportClient\""), "client product present")
            try require(text.contains("name: \"WebTransportServer\""), "server product present")
            try require(!text.contains(".executable(\n            name: \"AppleQUICSpike\""), "AppleQUICSpike not a product")
            try require(!text.contains(".executable(\n            name: \"NativeQUICCoreSpike\""), "NativeQUICCoreSpike not a product")
        },
        scenario("Release", "release-script-stale-spikes", "release script rejects stale spike binaries") {
            let scriptURL = URL(fileURLWithPath: "Swift/build-release-apple-silicon.sh")
            let fallbackURL = URL(fileURLWithPath: "build-release-apple-silicon.sh")
            let url = FileManager.default.fileExists(atPath: scriptURL.path) ? scriptURL : fallbackURL
            let text = try String(contentsOf: url, encoding: .utf8)
            try require(text.contains("rm -rf .build/arm64-apple-macosx/release .build/release"), "release output cleaned")
            try require(text.contains("Unexpected spike binary in production release output"), "stale spike rejection present")
            try require(text.contains("Release artifact is not reproducible"), "reproducibility failure path present")
            try require(text.contains("SHA256SUMS"), "checksum manifest is emitted")
        }
    ]
}

private func scenario(
    _ group: String,
    _ name: String,
    _ description: String,
    _ run: @escaping @Sendable () async throws -> Void
) -> CLIConformanceScenario {
    CLIConformanceScenario(group: group, name: name, description: description, run: run)
}

private struct ManagerPair {
    var client: WebTransportSessionManager
    var server: WebTransportSessionManager
}

private func makeReadyPair(
    clientSettings: HTTP3Settings = .webTransportDraft15Defaults,
    serverSettings: HTTP3Settings = .webTransportDraft15Defaults,
    maxStreamReceiveBufferBytes: Int = 64 * 1024,
    maxDatagramFrameSize: Int = 1_200,
    maxDatagramReceiveBufferBytes: Int = 64 * 1024,
    maxBufferedStreamsPerSession: Int = 64,
    maxBufferedDatagramsPerSession: Int = 64,
    maxBufferedSessions: Int = 64
) throws -> ManagerPair {
    var clientHTTP3 = HTTP3ConnectionState(role: .client, localSettings: clientSettings)
    var serverHTTP3 = HTTP3ConnectionState(role: .server, localSettings: serverSettings)
    _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
    _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
    return ManagerPair(
        client: WebTransportSessionManager(
            http3: clientHTTP3,
            maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
            maxDatagramFrameSize: maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
            maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
            maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
            maxBufferedSessions: maxBufferedSessions
        ),
        server: WebTransportSessionManager(
            http3: serverHTTP3,
            maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
            maxDatagramFrameSize: maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
            maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
            maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
            maxBufferedSessions: maxBufferedSessions
        )
    )
}

private func establishDefaultSession(
    pair: inout ManagerPair,
    streamID: UInt64 = 0
) throws -> WebTransportSessionID {
    try establishSession(
        pair: &pair,
        streamID: streamID,
        request: WebTransportSessionRequest(authority: "example.com", path: streamID == 0 ? "/wt" : "/wt-\(streamID)"),
        policy: WebTransportServerSessionPolicy()
    )
}

private func establishSession(
    pair: inout ManagerPair,
    streamID: UInt64,
    request: WebTransportSessionRequest,
    policy: WebTransportServerSessionPolicy
) throws -> WebTransportSessionID {
    let requestFrame = try pair.client.makeClientSessionRequest(streamID: streamID, request: request)
    let decision = try pair.server.receiveClientSessionRequest(streamID: streamID, frame: requestFrame, policy: policy)
    let clientSession = try pair.client.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
    try require(decision.session.state == .accepted, "server accepted session")
    try require(clientSession.state == .accepted, "client accepted session")
    return clientSession.id
}

private func rejectSession(
    pair: inout ManagerPair,
    streamID: UInt64,
    request: WebTransportSessionRequest,
    policy: WebTransportServerSessionPolicy
) throws -> WebTransportServerSessionDecision {
    let requestFrame = try pair.client.makeClientSessionRequest(streamID: streamID, request: request)
    let decision = try pair.server.receiveClientSessionRequest(streamID: streamID, frame: requestFrame, policy: policy)
    _ = try pair.client.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
    return decision
}

private func runConnectInteropMatrix() throws {
    var pair = try makeReadyPair()
    let request = try WebTransportSessionRequest(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com",
        availableProtocols: ["chat.v1", "chat.v2"]
    )
    let policy = try WebTransportServerSessionPolicy(
        allowedAuthorities: ["example.com"],
        allowedPaths: ["/wt"],
        allowedOrigins: ["https://example.com"],
        supportedProtocols: ["chat.v2"],
        requireProtocolSelection: true
    )
    let sessionID = try establishSession(pair: &pair, streamID: 0, request: request, policy: policy)
    try require(pair.client.session(forRequestStreamID: sessionID.rawValue)?.selectedProtocol == "chat.v2", "valid CONNECT selected protocol")
    try require(pair.server.session(forRequestStreamID: sessionID.rawValue)?.state == .accepted, "server accepted valid CONNECT")

    pair = try makeReadyPair()
    try expectThrows {
        _ = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: HTTP3Frame(type: HTTP3FrameType.data, payload: Data("data-before-headers".utf8)),
            policy: WebTransportServerSessionPolicy()
        )
    }

    pair = try makeReadyPair()
    let rejected = try rejectSession(
        pair: &pair,
        streamID: 0,
        request: WebTransportSessionRequest(authority: "example.com", path: "/wt", origin: "https://evil.example"),
        policy: WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
    )
    try require(rejected.session.state == .rejected(status: 403), "bad-origin CONNECT rejected")
    try require(rejected.rejectionError?.kind == .requirementsNotMet, "bad-origin CONNECT maps to requirements-not-met")

    pair = try makeReadyPair()
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: WebTransportSessionRequest(authority: "example.com", path: "/wt", availableProtocols: ["chat.v1"])
    )
    var invalidSelectedProtocolFields = try WebTransportHTTP3Headers.successfulResponse(status: 200)
    invalidSelectedProtocolFields.append(try HTTPFieldLine(
        name: WebTransportHeaderName.selectedProtocol,
        value: WebTransportProtocolNegotiation.encodeItem("chat.v2")
    ))
    let invalidSelectedProtocol = try QPACK.headersFrame(fields: invalidSelectedProtocolFields)
    try expectThrows {
        _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: invalidSelectedProtocol)
    }
}

private func runStreamInteropMatrix() throws {
    var pair = try makeReadyPair()
    let sessionID = try establishDefaultSession(pair: &pair)
    let clientBidiPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: clientBidiPrefix + Data("client-bidi".utf8))
    try require(pair.server.popStreamPayload(streamID: 4) == Data("client-bidi".utf8), "client bidi stream delivered")

    let clientUniPrefix = try pair.client.openUnidirectionalStream(streamID: 2, sessionID: sessionID)
    _ = try pair.server.acceptUnidirectionalStream(streamID: 2, firstBytes: clientUniPrefix + Data("client-uni".utf8))
    try require(pair.server.popStreamPayload(streamID: 2) == Data("client-uni".utf8), "client uni stream delivered")

    let serverBidiPrefix = try pair.server.openBidirectionalStream(streamID: 1, sessionID: sessionID)
    _ = try pair.client.acceptBidirectionalStream(streamID: 1, firstBytes: serverBidiPrefix + Data("server-bidi".utf8))
    try require(pair.client.popStreamPayload(streamID: 1) == Data("server-bidi".utf8), "server bidi stream delivered")

    let serverUniPrefix = try pair.server.openUnidirectionalStream(streamID: 3, sessionID: sessionID)
    _ = try pair.client.acceptUnidirectionalStream(streamID: 3, firstBytes: serverUniPrefix + Data("server-uni".utf8))
    try require(pair.client.popStreamPayload(streamID: 3) == Data("server-uni".utf8), "server uni stream delivered")

    try expectThrows {
        _ = try pair.server.acceptBidirectionalStream(streamID: 1, firstBytes: clientBidiPrefix)
    }
    try expectThrows {
        _ = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: Data([0xff]))
    }
    try expectThrows {
        try pair.server.receiveStreamPayload(streamID: 99, payload: Data("orphan".utf8))
    }
}

private func runDatagramInteropMatrix() throws {
    var pair = try makeReadyPair()
    let sessionID = try establishDefaultSession(pair: &pair)
    let clientDatagram = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("client-dgram".utf8))
    try require(try pair.server.receiveDatagramFrame(clientDatagram) == sessionID, "client datagram routed")
    try require(pair.server.popDatagramPayload(sessionID: sessionID) == Data("client-dgram".utf8), "client datagram payload delivered")

    let serverDatagram = try pair.server.makeDatagramFrame(sessionID: sessionID, payload: Data("server-dgram".utf8))
    try require(try pair.client.receiveDatagramFrame(serverDatagram) == sessionID, "server datagram routed")
    try require(pair.client.popDatagramPayload(sessionID: sessionID) == Data("server-dgram".utf8), "server datagram payload delivered")

    try expectThrows {
        _ = try pair.server.receiveDatagramFrame(.datagram(Data([0xff])))
    }
    var orphanPair = try makeReadyPair()
    try expectThrows {
        _ = try orphanPair.client.receiveDatagramFrame(.datagram(
            try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("unknown".utf8))
        ))
    }

    var smallFramePair = try makeReadyPair(maxDatagramFrameSize: 4)
    let smallSession = try establishDefaultSession(pair: &smallFramePair)
    try expectThrows {
        _ = try smallFramePair.client.makeDatagramFrame(sessionID: smallSession, payload: Data("too-large".utf8))
    }
}

private func runGoawayCloseDrainInteropMatrix() throws {
    var pair = try WebTransportLibrarySmokePair.connectedWithFlowControl()
    let first = try pair.establishSession(streamID: 0, request: WebTransportSessionRequest(authority: "example.com", path: "/one"))
    let second = try pair.establishSession(streamID: 4, request: WebTransportSessionRequest(authority: "example.com", path: "/two"))
    try pair.client.manager.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4))
    try require(pair.client.manager.sessionsByID[first]?.state == .draining, "GOAWAY drains first session")
    try require(pair.client.manager.sessionsByID[second]?.state == .draining, "GOAWAY drains second session")
    try expectThrows {
        _ = try pair.client.manager.makeClientSessionRequest(
            streamID: 8,
            request: WebTransportSessionRequest(authority: "example.com", path: "/late")
        )
    }

    var managerPair = ManagerPair(client: pair.client.manager, server: pair.server.manager)
    let drain = try managerPair.client.makeDrainSessionCapsule(sessionID: first)
    try require(try managerPair.server.receiveFlowControlCapsule(sessionID: first, bytes: drain) == .drainSession, "drain capsule received by peer")
    let serverStreamPrefix = try managerPair.server.openBidirectionalStream(streamID: 9, sessionID: first)
    _ = try managerPair.client.acceptBidirectionalStream(streamID: 9, firstBytes: serverStreamPrefix + Data("during-drain".utf8))
    try require(managerPair.client.popStreamPayload(streamID: 9) == Data("during-drain".utf8), "existing draining session still accepts stream work")

    let close = try managerPair.client.makeCloseSessionCapsule(sessionID: first, applicationErrorCode: 22, message: "interop done")
    let closeResult = try managerPair.server.receiveFlowControlCapsuleWithActions(sessionID: first, bytes: close)
    try require(closeResult.capsule == .closeSession(applicationErrorCode: 22, message: "interop done"), "close capsule received by peer")
    try require(managerPair.server.sessionsByID[first]?.state == .closed(applicationErrorCode: 22, message: "interop done"), "close marked peer session closed")
    try expectThrows {
        _ = try managerPair.server.makeDatagramFrame(sessionID: first, payload: Data("late".utf8))
    }
}

private func runMalformedFlowInteropMatrix() throws {
    let clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    let clientControl = try clientHTTP3.localControlStreamBytes()
    _ = try serverHTTP3.receivePeerControlStream(clientControl)
    try expectThrows {
        _ = try serverHTTP3.receivePeerControlStream(clientControl)
    }
    try expectThrows {
        try serverHTTP3.receiveControlFrame(try QPACK.headersFrame(fields: [HTTPFieldLine(name: ":status", value: "200")]))
    }

    var requestStream = HTTP3RequestStream(streamID: 0, role: .server)
    try expectThrows {
        try requestStream.receive(frame: HTTP3Frame(type: HTTP3FrameType.data, payload: Data("before headers".utf8)))
    }
    try expectThrows {
        _ = try QPACK.decodeFieldSection(Data([0x01, 0x00]))
    }
    try expectThrows {
        _ = try WebTransportFlowCapsuleCodec.parse(Data([0xff]))
    }

    let constants = WebTransportHTTP3DraftConstants.current
    var clientSettings = HTTP3Settings.webTransportDraft15Defaults
    var serverSettings = HTTP3Settings.webTransportDraft15Defaults
    try clientSettings.set(4, for: constants.settingsWTInitialMaxData)
    try serverSettings.set(4, for: constants.settingsWTInitialMaxData)
    var pair = try makeReadyPair(clientSettings: clientSettings, serverSettings: serverSettings)
    let sessionID = try establishDefaultSession(pair: &pair)
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
    try pair.server.receiveStreamPayload(streamID: 4, payload: Data("1234".utf8))
    try require(pair.server.flowState(for: sessionID)?.usedData == 4, "flow-control positive limit reached")
    try expectThrows {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("5".utf8))
    }
    try require(pair.server.sessionsByID[sessionID]?.state == .closed(
        applicationErrorCode: UInt32(constants.wtFlowControlError),
        message: "WebTransport flow-control violation"
    ), "flow-control violation closed session")
}

private func runClientServerAPIDemo() async throws {
    let server = WebTransportServer(configuration: WebTransportServerConfiguration(
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        supportedProtocols: ["demo.v1"]
    ))
    let client = WebTransportClient(configuration: WebTransportClientConfiguration(
        authority: "localhost",
        path: "/wt",
        origin: "https://localhost",
        availableProtocols: ["demo.v1"]
    ))
    let session = try await client.connect(to: server)
    let stream = session.receiveDatagrams()
    try await session.sendDatagram(Data("hello from WebTransportClient".utf8))
    var iterator = stream.makeAsyncIterator()
    guard try await iterator.next() == Data("hello from WebTransportClient".utf8) else {
        throw QUICCodecError.malformed("WebTransport datagram was not delivered")
    }
    try await session.close(code: 0, reason: "client demo complete")
}

private func expectThrows(_ operation: () throws -> Void) throws {
    do {
        try operation()
    } catch {
        return
    }
    throw QUICCodecError.malformed("expected operation to throw")
}

private func require(_ condition: Bool, _ message: String) throws {
    guard condition else {
        throw QUICCodecError.malformed("CLI conformance failed: \(message)")
    }
}

private func emit(
    results: [WebTransportCLIConformanceResult],
    executableName: String,
    json: Bool,
    includeDetails: Bool,
    scenarioGroupsByName: [String: String]
) {
    let passed = results.filter(\.passed).count
    let failed = results.count - passed
    if json {
        let payload: [String: Any] = [
            "executable": executableName,
            "passed": passed,
            "failed": failed,
            "results": results.map { result in
                [
                    "name": result.name,
                    "passed": result.passed,
                    "durationSeconds": result.durationSeconds,
                    "detail": result.detail
                ] as [String: Any]
            }
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            print(text)
        }
    } else {
        if includeDetails {
            var currentGroup: String?
            for result in results {
                if let group = scenarioGroupsByName[result.name] {
                    printScenarioGroupHeading(group, current: &currentGroup)
                    print("  \(result.passed ? "PASS" : "FAIL") \(result.name) \(format(result.durationSeconds))s \(result.detail)")
                } else {
                    print("\(result.passed ? "PASS" : "FAIL") \(result.name) \(format(result.durationSeconds))s \(result.detail)")
                }
            }
        }
        print("SUMMARY \(executableName): passed=\(passed) failed=\(failed) total=\(results.count)")
    }
}

private func writeFailureLog(result: WebTransportCLIConformanceResult, executableName: String, directory: URL) {
    let file = directory.appendingPathComponent("\(safe(executableName))-\(safe(result.name))-failure.log")
    let text = """
    timestamp=\(timestamp())
    executable=\(executableName)
    scenario=\(result.name)
    passed=false
    durationSeconds=\(format(result.durationSeconds))
    detail=\(result.detail)
    """
    try? text.write(to: file, atomically: true, encoding: .utf8)
}

private func writeSummaryLog(results: [WebTransportCLIConformanceResult], executableName: String, directory: URL) {
    let passed = results.filter(\.passed).count
    let failed = results.count - passed
    let file = directory.appendingPathComponent("\(safe(executableName))-summary.log")
    let lines = [
        "timestamp=\(timestamp())",
        "executable=\(executableName)",
        "passed=\(passed)",
        "failed=\(failed)",
        "total=\(results.count)"
    ] + results.map { "\($0.passed ? "PASS" : "FAIL") \($0.name) \(format($0.durationSeconds))s \($0.detail)" }
    try? lines.joined(separator: "\n").write(to: file, atomically: true, encoding: .utf8)
}

private func safe(_ value: String) -> String {
    value.map { character in
        character.isLetter || character.isNumber || character == "-" ? character : "-"
    }.reduce(into: "") { $0.append($1) }
}

private func format(_ value: Double) -> String {
    String(format: "%.4f", value)
}

private func timestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
}
