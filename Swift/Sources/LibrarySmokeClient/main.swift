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
        print("Usage: swift run LibrarySmokeClient --host <host> --port <port>")
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
        }

        let config: Config
        let client: QUICUDPPort
        let serverEndpoint: QUICUDPEndpoint
        var manager: WebTransportSessionManager

        init(config: Config) throws {
            self.config = config
            self.client = try QUICUDPPort()
            self.serverEndpoint = QUICUDPEndpoint(host: config.host, port: config.port)
            self.manager = WebTransportSessionManager(http3: HTTP3ConnectionState(role: .client))
            print("LibrarySmokeClient local port: \(client.localEndpoint.port)")
        }

        mutating func run() throws {
            let scenarioID: Phase11Scenario = .echoStreams

            try send(Phase11Envelope(scenario: scenarioID, kind: .hello))
            _ = try receive(expect: .helloAck)

            let localControl = try manager.http3.localControlStreamBytes()
            try send(Phase11Envelope(scenario: scenarioID, kind: .control, payload: localControl))
            let controlAck = try receive(expect: .controlAck)
            guard let peerControl = controlAck.payload else {
                throw Error.transport("missing control response payload")
            }
            _ = try manager.receivePeerControlStream(peerControl)

            let session = try establishSession(authority: "example.com", path: "/wt")

            let streamID = QUICStreamID.make(index: 1, direction: .bidirectional, initiator: .client)
            let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .streamOpen,
                    streamID: streamID,
                    streamKind: .bidirectional,
                    payload: prefix
                )
            )
            _ = try receive(expect: .streamOpenAck)

            let streamMessage = Phase11Payload.utf8("stream-hello")
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .streamData,
                    streamID: streamID,
                    payload: streamMessage
                )
            )
            let streamEcho = try receive(expect: .streamEcho)
            guard streamEcho.payload == streamMessage else {
                throw Error.runtime("stream echo mismatch")
            }

            let datagramMessage = Phase11Payload.utf8("datagram-ping")
            let datagramFrame = try manager.makeDatagramFrame(sessionID: session.id, payload: datagramMessage)
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
                )
            )
            let datagramEcho = try receive(expect: .datagramEcho)
            guard datagramEcho.payload == datagramMessage else {
                throw Error.runtime("datagram echo mismatch")
            }

            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .result,
                    success: true,
                    message: "checks complete"
                )
            )
            _ = try receive(expect: .result)
        }

        private mutating func establishSession(authority: String, path: String) throws -> WebTransportSession {
            let request = try WebTransportSessionRequest(
                authority: authority,
                path: path,
                availableProtocols: ["wt-echo"]
            )
            let requestFrame = try manager.makeClientSessionRequest(streamID: 0, request: request)
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .sessionRequest,
                    requestStreamID: 0,
                    payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
                )
            )

            let response = try receive(expect: .sessionResponse)
            guard response.status == nil else {
                throw Error.runtime("server rejected session")
            }
            guard let payload = response.payload else {
                throw Error.runtime("session response missing frame payload")
            }
            let responseFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
            _ = try manager.receiveServerSessionResponse(streamID: 0, frame: responseFrame)

            guard let session = manager.session(forRequestStreamID: 0) else {
                throw Error.runtime("missing session state after response")
            }
            return session
        }

        mutating func send(_ envelope: Phase11Envelope) throws {
            let encoded = try Phase11Protocol.encode(envelope)
            try client.send(encoded, to: serverEndpoint)
        }

        mutating func receive(expect expected: Phase11MessageKind) throws -> Phase11Envelope {
            let (bytes, _) = try client.receive(timeoutMilliseconds: 10_000)
            let envelope = try Phase11Protocol.decode(bytes)
            guard envelope.kind == expected else {
                throw Error.transport("expected \(expected) got \(envelope.kind)")
            }
            return envelope
        }
    }
}
