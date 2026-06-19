import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportUDPApple
import WebTransportTestSupport

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum ClientCLI {
    static func main() {
        setbuf(stdout, nil)
        do {
            var runner = try Runner(config: parseArgs())
            try runner.run()
        } catch let error as Runner.Error {
            if error.shouldExitWithSuccess {
                Foundation.exit(0)
            }
            fputs("ClientCLI failed: \(error)\n", stderr)
            Foundation.exit(1)
        } catch {
            fputs("ClientCLI failed: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    static func parseArgs() throws -> Runner.Config {
        var config = Runner.Config()

        var index = 1
        let arguments = CommandLine.arguments
        while index < arguments.count {
            let arg = arguments[index]
            switch arg {
            case "--host":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --host")
                }
                config.host = arguments[index + 1]
                index += 2
            case "--port":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --port")
                }
                guard let value = UInt16(arguments[index + 1]) else {
                    throw Runner.Error.syntax("invalid --port value")
                }
                config.port = value
                index += 2
            case "--scenario":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --scenario")
                }
                guard let scenario = Phase11Scenario(rawValue: arguments[index + 1]) else {
                    throw Runner.Error.syntax("unknown scenario: \(arguments[index + 1])")
                }
                config.scenario = scenario
                index += 2
            case "--max-datagram-frame-size":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --max-datagram-frame-size")
                }
                guard let value = Int(arguments[index + 1]), value > 0 else {
                    throw Runner.Error.syntax("invalid --max-datagram-frame-size value")
                }
                config.maxDatagramFrameSize = value
                index += 2
            case "--max-datagram-buffer":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --max-datagram-buffer")
                }
                guard let value = Int(arguments[index + 1]), value >= 0 else {
                    throw Runner.Error.syntax("invalid --max-datagram-buffer value")
                }
                config.maxDatagramReceiveBufferBytes = value
                index += 2
            case "--server-authority":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --server-authority")
                }
                config.serverAuthority = arguments[index + 1]
                index += 2
            case "--help":
                printUsage()
                throw Runner.Error.requestedHelp
            default:
                throw Runner.Error.syntax("unknown argument: \(arg)")
            }
        }

        return config
    }

    static func printUsage() {
        print("Usage:")
        print("swift run ClientCLI --scenario <echoStreams|echoDatagrams|closeAndReset|oversizedDatagram|malformedFrame|rejectedSession>")
        print("  --host <host>")
        print("  --port <port>")
        print("  --max-datagram-frame-size <bytes>")
        print("  --max-datagram-buffer <bytes>")
        print("  --server-authority <host>")
    }

    struct Runner {
        enum Error: Swift.Error, CustomStringConvertible {
            case syntax(String)
            case requestedHelp
            case runtime(String)
            case transport(String)

            var description: String {
                switch self {
                case .syntax(let message):
                    return "syntax error: \(message)"
                case .requestedHelp:
                    return "help requested"
                case .runtime(let message):
                    return "runtime error: \(message)"
                case .transport(let message):
                    return "transport error: \(message)"
                }
            }

            var shouldExitWithSuccess: Bool {
                if case .requestedHelp = self { true } else { false }
            }
        }

        struct Config {
            var host = "127.0.0.1"
            var port: UInt16 = 0
            var scenario: Phase11Scenario = .echoStreams
            var maxDatagramFrameSize = 1_200
            var maxDatagramReceiveBufferBytes = 64 * 1024
            var serverAuthority = "example.com"
        }

        let config: Config
        let client: QUICUDPPort
        let serverEndpoint: QUICUDPEndpoint
        var manager: WebTransportSessionManager

        init(config: Config) throws {
            self.config = config
            self.client = try QUICUDPPort()
            self.serverEndpoint = QUICUDPEndpoint(host: config.host, port: config.port)
            let http3 = HTTP3ConnectionState(role: .client)
            self.manager = WebTransportSessionManager(
                http3: http3,
                maxDatagramFrameSize: config.maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: config.maxDatagramReceiveBufferBytes
            )
            print("client: local ephemeral port \(client.localEndpoint.port)")
        }

        mutating func run() throws {
            try send(Phase11Envelope(scenario: config.scenario, kind: .hello))
            let helloResponse = try receive(expect: .helloAck)
            print("client: \(helloResponse.message ?? "server acknowledged")")

            let localControl = try manager.http3.localControlStreamBytes()
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .control,
                    payload: localControl
                )
            )
            let controlResponse = try receive(expect: .controlAck)
            guard let peerControl = controlResponse.payload else {
                throw Error.runtime("server did not return control stream payload")
            }
            _ = try manager.receivePeerControlStream(peerControl)

            switch config.scenario {
            case .echoStreams:
                try runEchoStreamsScenario()
            case .echoDatagrams:
                try runEchoDatagramsScenario()
            case .closeAndReset:
                try runCloseAndResetScenario()
            case .oversizedDatagram:
                try runOversizedDatagramScenario()
            case .malformedFrame:
                try runMalformedScenario()
            case .rejectedSession:
                try runRejectedSessionScenario()
            }

            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .result,
                    success: true,
                    message: "scenario complete"
                )
            )
            let result = try receive(expect: .result)
            print("client: \(result.message ?? "scenario finished")")
        }

        mutating func runEchoStreamsScenario() throws {
            let session = try establishAcceptedSession(authority: config.serverAuthority, path: "/wt", includeOrigin: true)

            let streamID = QUICStreamID.make(index: 1, direction: .bidirectional, initiator: .client)
            let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
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
                    scenario: config.scenario,
                    kind: .streamData,
                    streamID: streamID,
                    payload: outbound
                )
            )
            let echoed = try receive(expect: .streamEcho)
            guard let payload = echoed.payload, payload == outbound else {
                throw Error.runtime("stream echo payload mismatch")
            }
            try manager.receiveStreamPayload(streamID: streamID, payload: payload)
            let popped = manager.popStreamPayload(streamID: streamID)
            if popped != payload {
                throw Error.runtime("stream payload not recorded locally")
            }

            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .streamData,
                    streamID: streamID,
                    payload: Phase11Payload.utf8("stream-check")
                )
            )
            _ = try receive(expect: .streamEcho)
            print("client: stream echo scenario passed")
        }

        mutating func runEchoDatagramsScenario() throws {
            let session = try establishAcceptedSession(authority: config.serverAuthority, path: "/wt")

            let payload = Phase11Payload.utf8("ping-datagram")
            let datagramFrame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
                )
            )

            let echoed = try receive(expect: .datagramEcho)
            guard echoed.payload == payload else {
                throw Error.runtime("datagram echo payload mismatch")
            }
            print("client: datagram echo scenario passed")
        }

        mutating func runCloseAndResetScenario() throws {
            let session = try establishAcceptedSession(authority: config.serverAuthority, path: "/wt")

            let streamID = QUICStreamID.make(index: 2, direction: .bidirectional, initiator: .client)
            let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: prefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            try send(
                Phase11Envelope(
                    scenario: config.scenario,
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
            let session = try establishAcceptedSession(authority: config.serverAuthority, path: "/wt")

            let hugePayload = Data(repeating: 0x66, count: config.maxDatagramFrameSize + 10)
            let oversized = try WebTransportDatagramSignaling.serialize(sessionID: session.id.rawValue, payload: hugePayload)
            let datagramFrame = QUICFrame.datagram(oversized)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
                )
            )

            let oversizedResult = try receive(expect: .error)
            if oversizedResult.success == true {
                throw Error.runtime("server should reject oversized datagram")
            }
            print("client: oversized datagram scenario passed")
        }

        mutating func runMalformedScenario() throws {
            _ = try establishAcceptedSession(authority: config.serverAuthority, path: "/wt")

            let streamID = QUICStreamID.make(index: 3, direction: .bidirectional, initiator: .client)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: Data([0x00, 0x00])
                )
            )
            let response = try receive()
            if response.kind != .error && response.kind != .streamOpenAck {
                throw Error.runtime("malformed stream open should be rejected or accepted")
            }
            if response.kind == .error {
                print("client: malformed frame scenario passed")
            } else {
                throw Error.runtime("unexpectedly accepted malformed frame")
            }
        }

        mutating func runRejectedSessionScenario() throws {
            let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
            let requestFrame = try manager.makeClientSessionRequest(streamID: 0, request: request)
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .sessionRequest,
                    requestStreamID: 0,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )

            let response = try receive(expect: .sessionResponse)
            guard let status = response.status, status != 0 else {
                throw Error.runtime("server rejected session did not return status")
            }
            print("client: rejected-session scenario passed with status \(status)")
        }

        mutating func establishAcceptedSession(
            authority: String,
            path: String,
            includeOrigin: Bool = false
        ) throws -> WebTransportSession {
            let request = try WebTransportSessionRequest(
                authority: authority,
                path: path,
                origin: includeOrigin ? "https://\(authority)" : nil,
                availableProtocols: ["wt-echo"]
            )
            let requestFrame = try manager.makeClientSessionRequest(streamID: 0, request: request)
            try runSessionRequest(requestFrame: requestFrame, expectedAccepted: true)

            guard let session = manager.session(forRequestStreamID: 0) else {
                throw Error.runtime("client session missing after request")
            }
            return session
        }

        mutating func runSessionRequest(requestFrame: HTTP3Frame, expectedAccepted: Bool) throws {
            try send(
                Phase11Envelope(
                    scenario: config.scenario,
                    kind: .sessionRequest,
                    requestStreamID: 0,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )

            let response = try receive(expect: .sessionResponse)
            guard let payload = response.payload else {
                throw Error.runtime("missing session response payload")
            }
            let responseFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
            _ = try manager.receiveServerSessionResponse(streamID: 0, frame: responseFrame)

            if expectedAccepted && response.status != nil {
                throw Error.runtime("session rejected unexpectedly with status \(String(describing: response.status))")
            }
            if !expectedAccepted && response.status == nil {
                throw Error.runtime("session accepted unexpectedly")
            }
        }

        func send(_ envelope: Phase11Envelope) throws {
            let encoded = try Phase11Protocol.encode(envelope)
            try client.send(encoded, to: serverEndpoint)
        }

        func receive(expect expected: Phase11MessageKind? = nil) throws -> Phase11Envelope {
            let (data, _) = try client.receive(timeoutMilliseconds: 5_000)
            let envelope = try Phase11Protocol.decode(data)
            if let expected,
               envelope.kind != expected {
                throw Error.transport("unexpected response \(envelope.kind) expected \(expected)")
            }
            return envelope
        }
    }
}
