import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum LibrarySmokeClient {
    static func main() {
        do {
            let config = try parseArgs()
            var runner = try Runner(config: config)
            try runner.run()
            print("LibrarySmokeClient: smoke test passed")
        } catch {
            fputs("LibrarySmokeClient failed: \(error)\n", stderr)
            exit(1)
        }
    }

    private static func parseArgs() throws -> Runner.Config {
        var config = Runner.Config()

        var index = 1
        let args = CommandLine.arguments
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--host":
                guard index + 1 < args.count else {
                    throw Runner.Error.syntax("missing value for --host")
                }
                config.host = args[index + 1]
                index += 2
            case "--port":
                guard index + 1 < args.count, let value = UInt16(args[index + 1]) else {
                    throw Runner.Error.syntax("missing or invalid value for --port")
                }
                config.port = value
                index += 2
            case "--iterations":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value > 0 else {
                    throw Runner.Error.syntax("missing or invalid value for --iterations")
                }
                config.iterations = value
                index += 2
            case "--max-datagram-frame-size":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value > 0 else {
                    throw Runner.Error.syntax("missing or invalid value for --max-datagram-frame-size")
                }
                config.maxDatagramFrameSize = value
                index += 2
            case "--max-datagram-buffer":
                guard index + 1 < args.count, let value = Int(args[index + 1]), value >= 0 else {
                    throw Runner.Error.syntax("missing or invalid value for --max-datagram-buffer")
                }
                config.maxDatagramReceiveBufferBytes = value
                index += 2
            case "--suite":
                config.runSuite = true
                index += 1
            case "--quick":
                config.runSuite = false
                index += 1
            case "--help":
                printUsage()
                exit(0)
            default:
                throw Runner.Error.syntax("unknown argument: \(arg)")
            }
        }

        return config
    }

    private static func printUsage() {
        print("Usage: swift run LibrarySmokeClient --host <host> --port <port> [--suite|--quick]")
        print("  --host <host>   Server host (default 127.0.0.1)")
        print("  --port <port>   UDP port (default 45500)")
        print("  --iterations <n> Run repeated payload checks in loops (default 4)")
        print("  --suite          Run full protocol suite (default)")
        print("  --quick          Run single smoke path only")
    }

    struct Runner {
        enum Error: Swift.Error, CustomStringConvertible {
            case syntax(String)
            case runtime(String)
            case transport(String)

            var description: String {
                switch self {
                case .syntax(let message):
                    return "syntax error: \(message)"
                case .runtime(let message):
                    return "runtime error: \(message)"
                case .transport(let message):
                    return "transport error: \(message)"
                }
            }
        }

        struct Config {
            var host = "127.0.0.1"
            var port: UInt16 = 45500
            var iterations = 4
            var maxDatagramFrameSize = 1_200
            var maxDatagramReceiveBufferBytes = 64 * 1024
            var runSuite = true
        }

        let config: Config
        let client: QUICUDPPort
        let serverEndpoint: QUICUDPEndpoint
        var manager: WebTransportSessionManager
        var nextClientRequestStreamIndex: UInt64 = 0
        var nextClientBidiStreamIndex: UInt64 = 1
        var nextClientUniStreamIndex: UInt64 = 0
        var nextServerBidiStreamIndex: UInt64 = 0
        var nextServerUniStreamIndex: UInt64 = 1

        init(config: Config) throws {
            self.config = config
            self.client = try QUICUDPPort()
            self.serverEndpoint = QUICUDPEndpoint(host: config.host, port: config.port)
            self.manager = WebTransportSessionManager(
                http3: HTTP3ConnectionState(role: .client),
                maxDatagramFrameSize: config.maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: config.maxDatagramReceiveBufferBytes
            )
            print("LibrarySmokeClient local port: \(client.localEndpoint.port)")
            print("LibrarySmokeClient running in \(config.runSuite ? "suite" : "quick") mode")
        }

        mutating func run() throws {
            let scenarioID: Phase11Scenario = .echoStreams

            try send(Phase11Envelope(scenario: scenarioID, kind: .hello))
            _ = try receive(expect: .helloAck)

            let localControl = try manager.http3.localControlStreamBytes()
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .control,
                    payload: localControl
                )
            )
            let controlAck = try receive(expect: .controlAck)
            guard let peerControl = controlAck.payload else {
                throw Error.transport("missing control response payload")
            }
            _ = try manager.receivePeerControlStream(peerControl)

            if config.runSuite {
                try runSuite()
                try send(
                    Phase11Envelope(
                        scenario: scenarioID,
                        kind: .result,
                        success: true,
                        message: "suite complete"
                    )
                )
            } else {
                try runQuick()
                try send(
                    Phase11Envelope(
                        scenario: scenarioID,
                        kind: .result,
                        success: true,
                        message: "checks complete"
                    )
                )
            }

            _ = try receive(expect: .result)
        }

        mutating func runQuick() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            let streamID = nextBidirectionalStreamID()

            let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: prefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            let outbound = Phase11Payload.utf8("stream-hello")
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: outbound
                )
            )
            let echoed = try receive(expect: .streamEcho)
            guard echoed.payload == outbound else {
                throw Error.runtime("stream echo payload mismatch")
            }

            try runEchoDatagrams(session: session, scenario: .echoDatagrams)
            print("client: quick smoke checks passed")
        }

        mutating func runSuite() throws {
            let suiteStart = Date()
            print("client: starting smoke suite")

            var start = Date()
            do {
                print("client: running echo streams (multi-stream)")
                try runEchoStreamsScenario()
                print("client: ✓ echo streams (multi-stream) in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step echo streams (multi-stream) failed: \(error)")
            }

            start = Date()
            do {
                print("client: running control stream reuse")
                try runControlStreamReuseScenario()
                print("client: ✓ control stream reuse in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step control stream reuse failed: \(error)")
            }

            start = Date()
            do {
                print("client: running datagram burst")
                try runEchoDatagramBurst()
                print("client: ✓ datagram burst in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step datagram burst failed: \(error)")
            }

            start = Date()
            do {
                print("client: running datagram ordering and buffer boundary")
                try runDatagramOrderingScenario()
                print("client: ✓ datagram ordering in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step datagram ordering failed: \(error)")
            }

            start = Date()
            do {
                print("client: running interleaved stream flow")
                try runInterleavedStreamScenario()
                print("client: ✓ interleaved stream flow in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step interleaved stream flow failed: \(error)")
            }

            start = Date()
            do {
                print("client: running concurrent sessions")
                try runConcurrentSessionsScenario()
                print("client: ✓ concurrent sessions in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step concurrent sessions failed: \(error)")
            }

            start = Date()
            do {
                print("client: running protocol negotiation")
                try runProtocolNegotiationScenario()
                print("client: ✓ protocol negotiation in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step protocol negotiation failed: \(error)")
            }

            start = Date()
            do {
                print("client: running flow-control capsules")
                try runFlowControlCapsuleScenario()
                print("client: ✓ flow-control capsules in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step flow-control capsules failed: \(error)")
            }

            start = Date()
            do {
                print("client: running stream identity + duplicate open")
                try runStreamIdentityAndDuplicateOpenScenario()
                print("client: ✓ stream identity + duplicate open in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step stream identity + duplicate open failed: \(error)")
            }

            start = Date()
            do {
                print("client: running malformed stream open")
                try runMalformedStreamScenario()
                print("client: ✓ malformed stream open in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step malformed stream open failed: \(error)")
            }

            start = Date()
            do {
                print("client: running datagram/session integrity")
                try runDatagramIntegrityScenario()
                print("client: ✓ datagram/session integrity in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step datagram/session integrity failed: \(error)")
            }

            start = Date()
            do {
                print("client: running malformed datagram frame")
                try runMalformedDatagramScenario()
                print("client: ✓ malformed datagram frame in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step malformed datagram frame failed: \(error)")
            }

            start = Date()
            do {
                print("client: running duplicate session request")
                try runDuplicateSessionRequestScenario()
                print("client: ✓ duplicate session request in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step duplicate session request failed: \(error)")
            }

            start = Date()
            do {
                print("client: running malformed session request")
                try runMalformedSessionRequestScenario()
                print("client: ✓ malformed session request in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step malformed session request failed: \(error)")
            }

            start = Date()
            do {
                print("client: running close/reset path")
                try runCloseAndResetScenario()
                print("client: ✓ close/reset path in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step close/reset path failed: \(error)")
            }

            start = Date()
            do {
                print("client: running session rejection")
                try runRejectedSessionScenario()
                print("client: ✓ session rejection in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step session rejection failed: \(error)")
            }

            start = Date()
            do {
                print("client: running oversized datagram rejection")
                try runOversizedDatagramScenario()
                print("client: ✓ oversized datagram rejection in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step oversized datagram rejection failed: \(error)")
            }

            start = Date()
            do {
                print("client: running malformed stream open")
                try runMalformedFrameScenario()
                print("client: ✓ malformed frame path in \(String(format: "%.3f", Date().timeIntervalSince(start)))s")
            } catch {
                throw Error.runtime("suite step malformed frame failed: \(error)")
            }

            let elapsed = Date().timeIntervalSince(suiteStart)
            print("client: full suite checks passed in \(String(format: "%.3f", elapsed))s")
        }


        mutating func runMalformedDatagramScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            try send(
                Phase11Envelope(
                    scenario: .oversizedDatagram,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: Data([0x00, 0x01, 0x02, 0x03])
                )
            )
            _ = try receive(expect: .error)
            print("client: malformed datagram scenario passed")
        }

        mutating func runControlStreamReuseScenario() throws {
            let localControl = try manager.http3.localControlStreamBytes()
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .control,
                    payload: localControl
                )
            )
            let response = try receive(expect: .error)
            if response.kind != .error {
                throw Error.runtime("control stream duplicate should be rejected")
            }
            print("client: control stream reuse scenario passed")
        }

        mutating func runDatagramOrderingScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            let count = max(2, min(config.iterations, 12))
            for index in 0..<count {
                let payload = Phase11Payload.utf8("ordered-\(index)")
                let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
                try send(
                    Phase11Envelope(
                        scenario: .echoDatagrams,
                        kind: .datagram,
                        sessionID: session.id.rawValue,
                        payload: try Phase11FramePacket.encodeQUICFrame(frame)
                    )
                )
                let echoed = try receive(expect: .datagramEcho)
                guard echoed.payload == payload else {
                    throw Error.runtime("datagram ordering failed at index \(index)")
                }
            }
            print("client: datagram ordering scenario passed")
        }

        mutating func runInterleavedStreamScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            let streamCount = max(2, min(config.iterations, 4))
            var bidirectionalStreams: [UInt64] = []
            var unidirectionalStreams: [UInt64] = []

            for _ in 0..<streamCount {
                let bidiID = nextBidirectionalStreamID()
                let bidiPrefix = try manager.openBidirectionalStream(streamID: bidiID, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamOpen,
                        streamID: bidiID,
                        streamKind: .bidirectional,
                        payload: bidiPrefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)
                bidirectionalStreams.append(bidiID)

                let uniID = nextUnidirectionalStreamID()
                let uniPrefix = try manager.openUnidirectionalStream(streamID: uniID, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .closeAndReset,
                        kind: .streamOpen,
                        streamID: uniID,
                        streamKind: .unidirectional,
                        payload: uniPrefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)
                unidirectionalStreams.append(uniID)
            }

            for index in 0..<streamCount {
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamData,
                        streamID: bidirectionalStreams[index],
                        payload: Phase11Payload.utf8("bidi-\(index)")
                    )
                )
                try send(
                    Phase11Envelope(
                        scenario: .closeAndReset,
                        kind: .streamData,
                        streamID: unidirectionalStreams[index],
                        payload: Phase11Payload.utf8("uni-\(index)")
                    )
                )
            }

            var expectedPayloads: [UInt64: Set<String>] = [:]
            var observedPayloads: [UInt64: Set<String>] = [:]
            for index in 0..<streamCount {
                expectedPayloads[bidirectionalStreams[index], default: Set<String>()].insert("bidi-\(index)")
                expectedPayloads[unidirectionalStreams[index], default: Set<String>()].insert("uni-\(index)")
            }

            for _ in 0..<(streamCount * 2) {
                let response = try receive(expect: .streamEcho)
                guard let streamID = response.streamID, let payload = response.payload,
                      let text = String(data: payload, encoding: .utf8) else {
                    throw Error.runtime("interleaved stream response missing stream/payload")
                }
                observedPayloads[streamID, default: Set<String>()].insert(text)
            }

            for index in 0..<streamCount {
                let streamID = bidirectionalStreams[index]
                let expected = expectedPayloads[streamID] ?? []
                let observed = observedPayloads[streamID] ?? []
                if expected != observed {
                    throw Error.runtime("bidi interleaved echo mismatch at index \(index)")
                }
            }

            for index in 0..<streamCount {
                let streamID = unidirectionalStreams[index]
                let expected = expectedPayloads[streamID] ?? []
                let observed = observedPayloads[streamID] ?? []
                if expected != observed {
                    throw Error.runtime("uni interleaved echo mismatch at index \(index)")
                }
            }

            print("client: interleaved stream scenario passed")
        }

        mutating func runStreamIdentityAndDuplicateOpenScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let truncatedPrefix = try WebTransportStreamSignaling.serializePrefix(
                form: .unidirectional,
                sessionID: session.id.rawValue
            ).prefix(1)
            let streamID = nextBidirectionalStreamID()
            try send(
                Phase11Envelope(
                    scenario: .malformedFrame,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: Data(truncatedPrefix)
                )
            )
            let mismatch = try receive()
            if mismatch.kind != .error {
                    throw Error.runtime("malformed stream prefix should be rejected")
                }

            let validStreamID = nextBidirectionalStreamID()
            let validPrefix = try manager.openBidirectionalStream(streamID: validStreamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: validStreamID,
                    streamKind: .bidirectional,
                    payload: validPrefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: validStreamID,
                    streamKind: .bidirectional,
                    payload: validPrefix
                )
            )
            let duplicate = try receive()
            if duplicate.kind != .error {
                throw Error.runtime("duplicate stream open should be rejected")
            }

            print("client: stream identity and duplicate open scenario passed")
        }

        mutating func runDatagramIntegrityScenario() throws {
            let _ = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let unknownSessionFrame = try Phase11FramePacket.encodeQUICFrame(
                .datagram(
                    try WebTransportDatagramSignaling.serialize(
                        sessionID: 0x1234_5678_90ab_cdef,
                        payload: Phase11Payload.utf8("unknown-session")
                    )
                )
            )
            try send(
                Phase11Envelope(
                    scenario: .oversizedDatagram,
                    kind: .datagram,
                    sessionID: 0x1234_5678_90ab_cdef,
                    payload: unknownSessionFrame
                )
            )
            _ = try receive(expect: .error)

            try send(
                Phase11Envelope(
                    scenario: .malformedFrame,
                    kind: .sessionRequest,
                    requestStreamID: nextRequestStreamID(),
                    payload: Data([0x00, 0x01, 0x02, 0x03, 0x04])
                )
            )
            _ = try receive(expect: .error)

            let closedLikeStreamID = nextBidirectionalStreamID()
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamData,
                    streamID: closedLikeStreamID,
                    payload: Phase11Payload.utf8("pre-open")
                )
            )
            _ = try receive(expect: .error)
            print("client: datagram/session integrity scenario passed")
        }

        mutating func runMalformedSessionRequestScenario() throws {
            let requestStreamID = nextRequestStreamID()
            try send(
                Phase11Envelope(
                    scenario: .malformedFrame,
                    kind: .sessionRequest,
                    requestStreamID: requestStreamID,
                    payload: Data([0x00, 0x00, 0x00, 0x00, 0x00])
                )
            )
            let response = try receive()
            if response.kind != .error {
                throw Error.runtime("malformed session request should be rejected")
            }
            print("client: malformed session request scenario passed")
        }

        mutating func runEchoStreamsScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            for index in 0..<config.iterations {
                let streamID = nextBidirectionalStreamID()
                let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamOpen,
                        streamID: streamID,
                        streamKind: .bidirectional,
                        payload: prefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)

                let message = "stream-bidi-\(index)"
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamData,
                        streamID: streamID,
                        payload: Phase11Payload.utf8(message)
                    )
                )
                let echoed = try receive(expect: .streamEcho)
                guard let payload = echoed.payload,
                      let response = String(data: payload, encoding: .utf8),
                      response == message else {
                    throw Error.runtime("stream echo mismatch for scenario stream #\(index)")
                }
            }
            print("client: stream echo scenario passed")
        }

        mutating func runEchoDatagrams(session: WebTransportSession, scenario: Phase11Scenario) throws {
            for index in 0..<config.iterations {
                let payload = Phase11Payload.utf8("dg-\(index)")
                let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
                try send(
                    Phase11Envelope(
                        scenario: scenario,
                        kind: .datagram,
                        sessionID: session.id.rawValue,
                        payload: try Phase11FramePacket.encodeQUICFrame(frame)
                    )
                )
                let echoed = try receive(expect: .datagramEcho)
                guard echoed.payload == payload else {
                    throw Error.runtime("datagram echo mismatch for message #\(index)")
                }
            }
        }

        mutating func runEchoDatagramBurst() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            try runEchoDatagrams(session: session, scenario: .echoDatagrams)
            print("client: datagram burst scenario passed")
        }

        mutating func runUnidirectionalStreamScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            let streamID = nextUnidirectionalStreamID()
            let prefix = try manager.openUnidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .unidirectional,
                    payload: prefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            let payload = Phase11Payload.utf8("stream-uni")
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamData,
                    streamID: streamID,
                    payload: payload
                )
            )
            let echoed = try receive(expect: .streamEcho)
            guard echoed.payload == payload else {
                throw Error.runtime("unidirectional stream echo mismatch")
            }
            print("client: unidirectional stream scenario passed")
        }

        mutating func runMalformedStreamScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let mismatchPrefix = try WebTransportStreamSignaling.serializePrefix(
                form: .unidirectional,
                sessionID: session.id.rawValue
            )
            let streamID = nextBidirectionalStreamID()
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: mismatchPrefix
                )
            )
            let mismatchResponse = try receive()
            if mismatchResponse.kind != .error {
                throw Error.runtime("stream prefix mismatch should be rejected")
            }

            let peerInitiatorStreamID = nextServerBidiStreamID()
            let invalidRolePrefix = try WebTransportStreamSignaling.serializePrefix(
                form: .bidirectional,
                sessionID: session.id.rawValue
            )
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: peerInitiatorStreamID,
                    streamKind: .bidirectional,
                    payload: invalidRolePrefix
                )
            )
            let roleResponse = try receive()
            if roleResponse.kind != .error {
                throw Error.runtime("peer-initiated stream sent by local client should be rejected")
            }

            print("client: stream prefix/initiator validation scenario passed")
        }

        mutating func runConcurrentSessionsScenario() throws {
            let sessionCount = max(2, min(config.iterations, 5))
            var sessions: [WebTransportSession] = []

            for index in 0..<sessionCount {
                let session = try establishAcceptedSession(
                    authority: "example.com",
                    path: "/wt",
                    requestStreamID: nextRequestStreamID()
                )
                sessions.append(session)

                let streamID = nextBidirectionalStreamID()
                let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamOpen,
                        streamID: streamID,
                        streamKind: .bidirectional,
                        payload: prefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)

                let message = "parallel-\(index)"
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamData,
                        streamID: streamID,
                        payload: Phase11Payload.utf8(message)
                    )
                )
                let echoed = try receive(expect: .streamEcho)
                if echoed.payload != Phase11Payload.utf8(message) {
                    throw Error.runtime("parallel session #\(index) stream echo mismatch")
                }
            }

            if sessions.count != sessionCount {
                throw Error.runtime("concurrent session setup failed")
            }
            print("client: concurrent sessions scenario passed")
        }

        mutating func runProtocolNegotiationScenario() throws {
            let streamID = nextRequestStreamID()
            let requestFrame = try makeSessionRequestFrame(
                requestStreamID: streamID,
                authority: "example.com",
                path: "/wt",
                availableProtocols: ["proto-other", "wt-echo", "unused"]
            )
            let response = try runSessionRequest(
                requestFrame: requestFrame,
                requestStreamID: streamID,
                scenario: .echoDatagrams,
                expectedAccepted: true
            )
            guard response.status == nil else {
                throw Error.runtime("server unexpectedly rejected protocol negotiation")
            }
            guard let session = manager.session(forRequestStreamID: streamID),
                  session.selectedProtocol == "wt-echo" else {
                throw Error.runtime("protocol negotiation did not select wt-echo")
            }
            print("client: protocol negotiation scenario passed")
        }

        mutating func runFlowControlCapsuleScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let maxDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 64))
            _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: maxDataCapsule)

            do {
                let payload = Data(repeating: 0x55, count: 128)
                let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
                _ = try Phase11FramePacket.encodeQUICFrame(frame)
                throw Error.runtime("oversized datagram unexpectedly allowed under maxData")
            } catch {
                // Expected: max_data reached.
            }

            let payload = Data(repeating: 0x22, count: 32)
            let safeFrame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            try send(
                Phase11Envelope(
                    scenario: .echoDatagrams,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(safeFrame)
                )
            )
            let echoed = try receive(expect: .datagramEcho)
            guard echoed.payload == payload else {
                throw Error.runtime("flow control datagram check failed")
            }

            let maxStreamsCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 1))
            _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: maxStreamsCapsule)

            var streamID: UInt64
            do {
                let firstStream = nextBidirectionalStreamID()
                let firstPrefix = try manager.openBidirectionalStream(streamID: firstStream, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamOpen,
                        streamID: firstStream,
                        streamKind: .bidirectional,
                        payload: firstPrefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)

                let secondStream = nextBidirectionalStreamID()
                do {
                    _ = try manager.openBidirectionalStream(streamID: secondStream, sessionID: session.id)
                    throw Error.runtime("second stream unexpectedly opened under stream limit")
                } catch {
                    guard let queued = try manager.popFlowControlCapsule(sessionID: session.id) else {
                        throw Error.runtime("expected blocked stream flow capsule")
                    }
                    let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
                    if case .streamsBlockedBidi(let limit) = parsed.capsule {
                        guard limit > 0 else {
                            throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                        }
                    }
                }

                streamID = firstStream
            } catch {
                if let queued = try manager.popFlowControlCapsule(sessionID: session.id) {
                    let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
                    if case .streamsBlockedBidi(let limit) = parsed.capsule {
                        guard limit > 0 else {
                            throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                        }
                    }
                }

                let liftedStreamCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
                _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedStreamCapsule)

                streamID = nextBidirectionalStreamID()
                let recoveryPrefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
                try send(
                    Phase11Envelope(
                        scenario: .echoStreams,
                        kind: .streamOpen,
                        streamID: streamID,
                        streamKind: .bidirectional,
                        payload: recoveryPrefix
                    )
                )
                _ = try receive(expect: .streamOpenAck)
            }

            do {
                try manager.receiveStreamPayload(streamID: streamID, payload: Data(repeating: 0x77, count: 128))
                throw Error.runtime("local flow-control maxData should reject oversized inbound stream payload")
            } catch {
                // expected
            }

            let baselinePayload = Data(repeating: 0x55, count: 24)
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: baselinePayload
                )
            )
            let streamBaselineEcho = try receive(expect: .streamEcho)
            guard streamBaselineEcho.payload == baselinePayload else {
                throw Error.runtime("flow-control maxData baseline payload should echo")
            }

            let liftedDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 256))
            _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedDataCapsule)

            let liftPayload = Data(repeating: 0x33, count: 24)
            try manager.receiveStreamPayload(streamID: streamID, payload: liftPayload)
            let localRecoveredPayload = manager.popStreamPayload(streamID: streamID)
            guard localRecoveredPayload == liftPayload else {
                throw Error.runtime("flow-control maxData lift should allow inbound stream payload")
            }

            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: liftPayload
                )
            )
            let streamEcho = try receive(expect: .streamEcho)
            guard streamEcho.payload == liftPayload else {
                throw Error.runtime("stream data should be accepted after maxData raised")
            }

            // Allow another stream after an update to unlimited.
            let unlimitedStreamsCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
            _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: unlimitedStreamsCapsule)
            let recoveryStream = nextBidirectionalStreamID()
            _ = try manager.openBidirectionalStream(streamID: recoveryStream, sessionID: session.id)

            print("client: flow-control capsule scenario passed")
        }

        mutating func runDuplicateSessionRequestScenario() throws {
            let requestStreamID = nextRequestStreamID()
            let requestFrame = try makeSessionRequestFrame(
                requestStreamID: requestStreamID,
                authority: "example.com",
                path: "/wt",
                availableProtocols: ["wt-echo"]
            )

            _ = try runSessionRequest(
                requestFrame: requestFrame,
                requestStreamID: requestStreamID,
                scenario: .echoStreams,
                expectedAccepted: true
            )

            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .sessionRequest,
                    requestStreamID: requestStreamID,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )
            let duplicate = try receive()
            if duplicate.kind != .error {
                throw Error.runtime("duplicate session request should be rejected")
            }
            print("client: duplicate session request scenario passed")
        }

        mutating func runCloseAndResetScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let streamID = nextBidirectionalStreamID()
            let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: prefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamReset,
                    streamID: streamID,
                    errorCode: 0x54
                )
            )
            let resetAck = try receive(expect: .streamResetAck)
            guard let payload = resetAck.payload else {
                throw Error.runtime("missing stream reset frame from server")
            }
            _ = try Phase11FramePacket.decodeQUICFrame(payload)
            print("client: close/reset scenario passed")
        }

        mutating func runOversizedDatagramScenario() throws {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            let hugePayload = Data(repeating: 0x66, count: config.maxDatagramFrameSize + 10)
            let oversized = try WebTransportDatagramSignaling.serialize(sessionID: session.id.rawValue, payload: hugePayload)
            let datagramFrame = QUICFrame.datagram(oversized)
            try send(
                Phase11Envelope(
                    scenario: .oversizedDatagram,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
                )
            )
            let response = try receive(expect: .error)
            if response.success == true {
                throw Error.runtime("server should reject oversized datagram")
            }
            print("client: oversized datagram scenario passed")
        }

        mutating func runMalformedFrameScenario() throws {
            _ = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )

            let streamID = nextBidirectionalStreamID()
            try send(
                Phase11Envelope(
                    scenario: .malformedFrame,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: Data([0x00, 0x00])
                )
            )
            let response = try receive()
            if response.kind != .error {
                throw Error.runtime("malformed stream open should be rejected")
            }
            print("client: malformed frame scenario passed")
        }

        mutating func runRejectedSessionScenario() throws {
            let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
            let requestStreamID = nextRequestStreamID()
            let requestFrame = try makeSessionRequestFrame(
                requestStreamID: requestStreamID,
                authority: request.authority,
                path: request.path
            )
            try send(
                Phase11Envelope(
                    scenario: .rejectedSession,
                    kind: .sessionRequest,
                    requestStreamID: requestStreamID,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )
            let response = try receive(expect: .sessionResponse)
            guard let status = response.status, status != 0 else {
                throw Error.runtime("server rejected session did not return status")
            }
            print("client: rejected-session scenario passed (\(status))")
        }

        mutating func establishAcceptedSession(
            authority: String,
            path: String,
            includeOrigin: Bool = false,
            availableProtocols: [String] = ["wt-echo"],
            requestStreamID: UInt64
        ) throws -> WebTransportSession {
            let requestFrame = try makeSessionRequestFrame(
                requestStreamID: requestStreamID,
                authority: authority,
                path: path,
                includeOrigin: includeOrigin,
                availableProtocols: availableProtocols
            )
            _ = try runSessionRequest(
                requestFrame: requestFrame,
                requestStreamID: requestStreamID,
                scenario: .echoStreams,
                expectedAccepted: true
            )

            guard let session = manager.session(forRequestStreamID: requestStreamID) else {
                throw Error.runtime("client session missing after request")
            }
            print("client: established session id \(session.id.rawValue) on request stream \(requestStreamID)")
            return session
        }

        mutating func establishRejectedSession() throws {
            let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
            let requestStreamID = nextRequestStreamID()
            let requestFrame = try makeSessionRequestFrame(
                requestStreamID: requestStreamID,
                authority: request.authority,
                path: request.path
            )
            let encoded = try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            try send(
                Phase11Envelope(
                    scenario: .rejectedSession,
                    kind: .sessionRequest,
                    requestStreamID: requestStreamID,
                    payload: encoded
                )
            )
            let response = try receive(expect: .sessionResponse)
            _ = try Phase11FramePacket.decodeHTTP3Frame(response.payload ?? Data())
            _ = response.status
        }

        mutating func makeSessionRequestFrame(
            requestStreamID: UInt64,
            authority: String,
            path: String,
            includeOrigin: Bool = false,
            availableProtocols: [String] = ["wt-echo"]
        ) throws -> HTTP3Frame {
            let request = try WebTransportSessionRequest(
                authority: authority,
                path: path,
                origin: includeOrigin ? "https://\(authority)" : nil,
                availableProtocols: availableProtocols
            )
            return try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
        }

        mutating func runSessionRequest(
            requestFrame: HTTP3Frame,
            requestStreamID: UInt64,
            scenario: Phase11Scenario,
            expectedAccepted: Bool
        ) throws -> Phase11Envelope {
            try send(
                Phase11Envelope(
                    scenario: scenario,
                    kind: .sessionRequest,
                    requestStreamID: requestStreamID,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )

            let response = try receive(expect: .sessionResponse)
            guard let payload = response.payload else {
                throw Error.runtime("missing session response payload")
            }
            let responseFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
            _ = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responseFrame)
            print("client: manager has session? \(manager.session(forRequestStreamID: requestStreamID) != nil)")

            if expectedAccepted && response.status != nil {
                throw Error.runtime("session rejected unexpectedly with status \(String(describing: response.status))")
            }
            if !expectedAccepted && response.status == nil {
                throw Error.runtime("session accepted unexpectedly")
            }
            return response
        }

        mutating func send(_ envelope: Phase11Envelope) throws {
            let encoded = try Phase11Protocol.encode(envelope)
            try client.send(encoded, to: serverEndpoint)
        }

        mutating func receive(expect expected: Phase11MessageKind? = nil) throws -> Phase11Envelope {
            let (bytes, _) = try client.receive(timeoutMilliseconds: 10_000)
            let envelope = try Phase11Protocol.decode(bytes)
            if let expected,
               envelope.kind != expected {
                throw Error.transport("expected \(expected) got \(envelope.kind)")
            }
            return envelope
        }

        mutating func nextRequestStreamID() -> UInt64 {
            let streamID = nextClientRequestStreamIndex
            nextClientRequestStreamIndex += 2
            return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
        }

        mutating func nextServerBidiStreamID() -> UInt64 {
            let streamID = nextServerBidiStreamIndex
            nextServerBidiStreamIndex += 2
            return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .server)
        }

        mutating func nextServerUniStreamID() -> UInt64 {
            let streamID = nextServerUniStreamIndex
            nextServerUniStreamIndex += 2
            return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .server)
        }

        mutating func nextBidirectionalStreamID() -> UInt64 {
            let streamID = nextClientBidiStreamIndex
            nextClientBidiStreamIndex += 2
            return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
        }

        mutating func nextUnidirectionalStreamID() -> UInt64 {
            let streamID = nextClientUniStreamIndex
            nextClientUniStreamIndex += 2
            return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .client)
        }
    }
}
