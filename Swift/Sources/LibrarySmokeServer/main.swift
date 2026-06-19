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
enum LibrarySmokeServer {
    static func main() {
        do {
            let config = try parseArgs()
            var runner = try Runner(config: config)
            try runner.run()
            print("LibrarySmokeServer: smoke test passed")
        } catch {
            fputs("LibrarySmokeServer failed: \(error)\n", stderr)
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
        print("Usage: swift run LibrarySmokeServer --port <port>")
    }

    struct Runner {
        struct Config {
            var port: UInt16 = 45500
        }

        enum Error: Swift.Error, CustomStringConvertible {
            case syntax(String)
            case runtime(String)

            var description: String {
                switch self {
                case .syntax(let message):
                    return "syntax error: \(message)"
                case .runtime(let message):
                    return "runtime error: \(message)"
                }
            }
        }

        let config: Config
        let server: QUICUDPPort
        let policy: WebTransportServerSessionPolicy
        var manager: WebTransportSessionManager

        init(config: Config) throws {
            self.config = config
            self.server = try QUICUDPPort(bindPort: config.port)

            self.policy = try WebTransportServerSessionPolicy(
                allowedAuthorities: ["example.com"],
                allowedPaths: ["/wt"],
                supportedProtocols: ["wt-echo"],
                requireProtocolSelection: false
            )

            let http3 = HTTP3ConnectionState(role: .server)
            self.manager = WebTransportSessionManager(http3: http3)

            print("LibrarySmokeServer listening on 127.0.0.1:\(server.localEndpoint.port)")
            print("LibrarySmokeServer ready for stream + datagram smoke checks")
        }

        mutating func run() throws {
            var peer: QUICUDPEndpoint?
            var completed = false
            var steps = 0

            while !completed && steps < 20 {
                let (bytes, sender) = try server.receive(timeoutMilliseconds: 10_000)
                if let activePeer = peer, activePeer != sender {
                    continue
                }
                peer = sender

                let request = try Phase11Protocol.decode(bytes)
                let response = try handle(request)
                steps += 1

                if let response {
                    try send(response, to: sender)
                    if response.kind == .result {
                        completed = true
                    }
                }
            }

            if !completed {
                throw Error.runtime("smoke test did not reach completion")
            }
        }

        mutating func handle(_ envelope: Phase11Envelope) throws -> Phase11Envelope? {
            switch envelope.kind {
            case .hello:
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .helloAck,
                    message: "hello"
                )
            case .control:
                guard let payload = envelope.payload else {
                    throw Error.runtime("control envelope missing payload")
                }
                _ = try manager.receivePeerControlStream(payload)
                let localControl = try manager.http3.localControlStreamBytes()
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .controlAck,
                    payload: localControl,
                    message: "control synchronized"
                )
            case .sessionRequest:
                guard let requestStreamID = envelope.requestStreamID,
                      let payload = envelope.payload else {
                    throw Error.runtime("sessionRequest envelope missing stream id or payload")
                }
                let requestFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
                let decision = try manager.receiveClientSessionRequest(
                    streamID: requestStreamID,
                    frame: requestFrame,
                    policy: policy
                )
                let status: UInt16?
                if case .rejected(let code) = decision.session.state {
                    status = code
                } else {
                    status = nil
                }
                let responseFrame = try Phase11FramePacket.encodeHTTP3Frame(decision.responseFrame)
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .sessionResponse,
                    requestStreamID: requestStreamID,
                    sessionID: decision.session.id.rawValue,
                    status: status,
                    success: status == nil,
                    payload: responseFrame,
                    message: status == nil ? "session accepted" : "session rejected"
                )
            case .streamOpen:
                guard let streamID = envelope.streamID,
                      let streamKind = envelope.streamKind,
                      let payload = envelope.payload else {
                    throw Error.runtime("streamOpen envelope missing fields")
                }
                switch streamKind {
                case .bidirectional:
                    _ = try manager.acceptBidirectionalStream(streamID: streamID, firstBytes: payload)
                case .unidirectional:
                    _ = try manager.acceptUnidirectionalStream(streamID: streamID, firstBytes: payload)
                }
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .streamOpenAck,
                    streamID: streamID,
                    success: true,
                    message: "stream opened"
                )
            case .streamData:
                guard let streamID = envelope.streamID, let payload = envelope.payload else {
                    throw Error.runtime("streamData envelope missing stream id or payload")
                }
                try manager.receiveStreamPayload(streamID: streamID, payload: payload)
                let echoed = manager.popStreamPayload(streamID: streamID) ?? Data()
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .streamEcho,
                    streamID: streamID,
                    payload: echoed,
                    message: "stream echoed"
                )
            case .datagram:
                guard let payload = envelope.payload else {
                    throw Error.runtime("datagram envelope missing payload")
                }
                do {
                    let frame = try Phase11FramePacket.decodeQUICFrame(payload)
                    let sessionID = try manager.receiveDatagramFrame(frame)
                    let echoed = manager.popDatagramPayload(sessionID: sessionID) ?? Data()
                    return Phase11Envelope(
                        scenario: envelope.scenario,
                        kind: .datagramEcho,
                        sessionID: sessionID.rawValue,
                        payload: echoed,
                        message: "datagram echoed"
                    )
                } catch {
                    return Phase11Envelope(
                        scenario: envelope.scenario,
                        kind: .error,
                        success: false,
                        message: "datagram rejected: \(error)"
                    )
                }
            case .streamReset:
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .streamResetAck,
                    streamID: envelope.streamID,
                    errorCode: envelope.errorCode,
                    success: true,
                    message: "stream reset"
                )
            case .result:
                return Phase11Envelope(
                    scenario: envelope.scenario,
                    kind: .result,
                    success: true,
                    message: "complete"
                )
            case .helloAck, .controlAck, .sessionResponse, .streamOpenAck, .streamEcho, .streamResetAck, .datagramEcho, .resetReceived, .scenarioDone, .error:
                return nil
            }
        }

        private func send(_ envelope: Phase11Envelope, to endpoint: QUICUDPEndpoint) throws {
            let encoded = try Phase11Protocol.encode(envelope)
            try server.send(encoded, to: endpoint)
        }
    }
}
