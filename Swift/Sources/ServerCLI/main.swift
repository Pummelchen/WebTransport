import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportUDPApple
import WebTransportTestSupport
import WebTransportTLSCore

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum ServerCLI {
    static func main() {
        setbuf(stdout, nil)
        do {
            var runner = try Runner(config: parseArgs())
            try runner.run()
        } catch let error as Runner.Error {
            if error.shouldExitWithSuccess {
                Foundation.exit(0)
            }
            fputs("ServerCLI failed: \(error)\n", stderr)
            Foundation.exit(1)
        } catch {
            fputs("ServerCLI failed: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    static func parseArgs() throws -> Runner.Config {
        var result = Runner.Config()

        var index = 1
        let arguments = CommandLine.arguments
        while index < arguments.count {
            let arg = arguments[index]
            switch arg {
            case "--port":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --port")
                }
                guard let value = UInt16(arguments[index + 1]) else {
                    throw Runner.Error.syntax("invalid --port value")
                }
                result.listenPort = value
                index += 2
            case "--max-datagram-frame-size":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --max-datagram-frame-size")
                }
                guard let value = Int(arguments[index + 1]), value > 0 else {
                    throw Runner.Error.syntax("invalid --max-datagram-frame-size value")
                }
                result.maxDatagramFrameSize = value
                index += 2
            case "--max-datagram-buffer":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --max-datagram-buffer")
                }
                guard let value = Int(arguments[index + 1]), value >= 0 else {
                    throw Runner.Error.syntax("invalid --max-datagram-buffer value")
                }
                result.maxDatagramReceiveBufferBytes = value
                index += 2
            case "--allowed-authority":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --allowed-authority")
                }
                result.allowedAuthorities.insert(arguments[index + 1])
                index += 2
            case "--allowed-path":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --allowed-path")
                }
                result.allowedPaths.insert(arguments[index + 1])
                index += 2
            case "--server-certificate-path":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --server-certificate-path")
                }
                result.serverCertificatePath = arguments[index + 1]
                index += 2
            case "--server-private-key-path":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --server-private-key-path")
                }
                result.serverPrivateKeyPath = arguments[index + 1]
                index += 2
            case "--server-private-key-type":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --server-private-key-type")
                }
                result.serverPrivateKeyType = arguments[index + 1]
                index += 2
            case "--server-private-key-bits":
                guard index + 1 < arguments.count else {
                    throw Runner.Error.syntax("missing value for --server-private-key-bits")
                }
                guard let value = Int(arguments[index + 1]), value > 0 else {
                    throw Runner.Error.syntax("invalid --server-private-key-bits value")
                }
                result.serverPrivateKeyBits = value
                index += 2
            case "--help":
                printUsage()
                throw Runner.Error.requestedHelp
            default:
                throw Runner.Error.syntax("unknown argument: \(arg)")
            }
        }

        return result
    }

    static func printUsage() {
        print("Usage:")
        print("swift run ServerCLI [options]")
        print("  --port <port>")
        print("  --max-datagram-frame-size <bytes>")
        print("  --max-datagram-buffer <bytes>")
        print("  --allowed-authority <host>")
        print("  --allowed-path <path>")
        print("  --server-certificate-path <path>")
        print("  --server-private-key-path <path>")
        print("  --server-private-key-type <rsa|ec|ed25519>")
        print("  --server-private-key-bits <bits>")
    }

    struct Runner {
        struct Config {
            var listenPort: UInt16 = 0
            var maxDatagramFrameSize = 1_200
            var maxDatagramReceiveBufferBytes = 64 * 1024
            var allowedAuthorities: Set<String> = ["example.com"]
            var allowedPaths: Set<String> = ["/wt"]
            var serverCertificatePath: String?
            var serverPrivateKeyPath: String?
            var serverPrivateKeyType: String? = "rsa"
            var serverPrivateKeyBits: Int? = 2_048
        }

        enum Error: Swift.Error, CustomStringConvertible {
            case syntax(String)
            case requestedHelp
            case runtime(String)
            case manager(String)

            var description: String {
                switch self {
                case .syntax(let message):
                    return "syntax error: \(message)"
                case .requestedHelp:
                    return "help requested"
                case .runtime(let message):
                    return "runtime error: \(message)"
                case .manager(let message):
                    return "session manager error: \(message)"
                }
            }

            var shouldExitWithSuccess: Bool {
                if case .requestedHelp = self { true } else { false }
            }
        }

        let config: Config
        let server: QUICUDPPort
        let policy: WebTransportServerSessionPolicy
        var manager: WebTransportSessionManager

        init(config: Config) throws {
            self.config = config
            self.server = try QUICUDPPort(bindPort: config.listenPort)

            let identityConfig = Phase11IdentitySupport.Configuration(
                certificatePath: config.serverCertificatePath,
                privateKeyPath: config.serverPrivateKeyPath,
                privateKeyTypeName: config.serverPrivateKeyType,
                privateKeySizeInBits: config.serverPrivateKeyBits
            )
            if identityConfig.isComplete {
                let identity = try Phase11IdentitySupport.LoadedIdentity(configuration: identityConfig)
                print("server: identity loaded; fingerprint=\(identity.certificateFingerprintHex)")
                _ = identity.identity
            } else {
                print("server: running without identity material injection")
            }

            self.policy = try WebTransportServerSessionPolicy(
                allowedAuthorities: config.allowedAuthorities,
                allowedPaths: config.allowedPaths,
                supportedProtocols: ["wt-echo"],
                requireProtocolSelection: false
            )
            let http3 = HTTP3ConnectionState(role: .server)
            self.manager = WebTransportSessionManager(
                http3: http3,
                maxDatagramFrameSize: config.maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: config.maxDatagramReceiveBufferBytes
            )

            print("server: listening on 127.0.0.1:\(server.localEndpoint.port)")
            print("server: maxDatagramFrameSize=\(config.maxDatagramFrameSize) maxDatagramBuffer=\(config.maxDatagramReceiveBufferBytes)")
            print("server: policy authorities=\(policy.allowedAuthorities ?? []) paths=\(policy.allowedPaths ?? [])")
        }

        mutating func run() throws {
            var peer: QUICUDPEndpoint?
            var activeScenario: Phase11Scenario? = nil

            while true {
                let (bytes, sender) = try server.receive(timeoutMilliseconds: 5_000)
                if let expectedPeer = peer, expectedPeer != sender {
                    continue
                }
                peer = sender

                let envelope = try Phase11Protocol.decode(bytes)
                let response: Phase11Envelope?
                do {
                    response = try handle(envelope, activeScenario: &activeScenario)
                } catch {
                    response = Phase11Envelope(
                        scenario: activeScenario,
                        kind: .error,
                        success: false,
                        message: "runtime: \(error)"
                    )
                }
                guard let response else {
                    continue
                }
                try send(response, to: sender)

                if response.kind == .result, response.success == true {
                    break
                }
            }
        }

        mutating func handle(
            _ envelope: Phase11Envelope,
            activeScenario: inout Phase11Scenario?
        ) throws -> Phase11Envelope? {
            switch envelope.kind {
            case .hello:
                activeScenario = envelope.scenario
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .helloAck,
                    message: "server: hello acknowledged"
                )

            case .control:
                guard let payload = envelope.payload else {
                    throw Error.manager("missing peer control payload")
                }
                _ = try manager.receivePeerControlStream(payload)
                let localControl = try manager.http3.localControlStreamBytes()
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .controlAck,
                    payload: localControl,
                    message: "control stream synchronized"
                )

            case .sessionRequest:
                guard let requestStreamID = envelope.requestStreamID else {
                    throw Error.manager("missing requestStreamID")
                }
                let requestFrame = try singleFrame(from: envelope)
                let decision = try manager.receiveClientSessionRequest(
                    streamID: requestStreamID,
                    frame: requestFrame,
                    policy: policy
                )
                let response = try Phase11FramePacket.encodeHTTP3Frame(decision.responseFrame)
                var status: UInt16?
                if case .rejected(let code) = decision.session.state {
                    status = code
                }
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .sessionResponse,
                    requestStreamID: requestStreamID,
                    sessionID: decision.session.id.rawValue,
                    status: status,
                    success: status == nil,
                    payload: response,
                    message: status == nil ? "accepted" : "rejected"
                )

            case .streamOpen:
                guard let streamID = envelope.streamID,
                      let streamKind = envelope.streamKind,
                      let prefix = envelope.payload else {
                    throw Error.manager("missing stream ID, kind, or prefix")
                }
                switch streamKind {
                case .bidirectional:
                    _ = try manager.acceptBidirectionalStream(streamID: streamID, firstBytes: prefix)
                case .unidirectional:
                    _ = try manager.acceptUnidirectionalStream(streamID: streamID, firstBytes: prefix)
                }
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .streamOpenAck,
                    streamID: streamID,
                    success: true,
                    message: "stream opened"
                )

            case .streamData:
                guard let streamID = envelope.streamID,
                      let payload = envelope.payload else {
                    throw Error.manager("missing stream data")
                }
                try manager.receiveStreamPayload(streamID: streamID, payload: payload)
                let echoed = manager.popStreamPayload(streamID: streamID) ?? Data()
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .streamEcho,
                    streamID: streamID,
                    payload: echoed,
                    message: "stream echoed"
                )

            case .datagram:
                guard let payload = envelope.payload else {
                    throw Error.manager("missing datagram payload")
                }
                do {
                    let frame = try Phase11FramePacket.decodeQUICFrame(payload)
                    let sessionID = try manager.receiveDatagramFrame(frame)
                    let echoed = manager.popDatagramPayload(sessionID: sessionID) ?? Data()
                    return Phase11Envelope(
                        scenario: activeScenario,
                        kind: .datagramEcho,
                        sessionID: sessionID.rawValue,
                        success: true,
                        payload: echoed,
                        message: "datagram echoed"
                    )
                } catch {
                    return Phase11Envelope(
                        scenario: activeScenario,
                        kind: .error,
                        success: false,
                        message: "datagram rejected: \(error)"
                    )
                }

            case .streamReset:
                guard let streamID = envelope.streamID else {
                    throw Error.manager("missing stream ID for reset")
                }
                let resetCode = envelope.errorCode ?? 0
                let frame = try manager.resetStream(streamID: streamID, applicationErrorCode: resetCode)
                let framePayload = try Phase11FramePacket.encodeQUICFrame(frame)
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .streamResetAck,
                    streamID: streamID,
                    success: true,
                    payload: framePayload,
                    message: "stream reset"
                )

            case .result:
                return Phase11Envelope(
                    scenario: activeScenario,
                    kind: .result,
                    success: envelope.success,
                    message: envelope.message ?? "client reported scenario result"
                )

            case .sessionResponse, .streamOpenAck, .streamEcho, .streamResetAck, .datagramEcho, .helloAck, .controlAck, .scenarioDone, .resetReceived, .error:
                return nil
            }
        }

        private func singleFrame(from envelope: Phase11Envelope) throws -> HTTP3Frame {
            guard let payload = envelope.payload else {
                throw Error.manager("missing payload")
            }
            return try Phase11FramePacket.decodeHTTP3Frame(payload)
        }

        private func send(_ envelope: Phase11Envelope, to endpoint: QUICUDPEndpoint) throws {
            let responseBytes = try Phase11Protocol.encode(envelope)
            try server.send(responseBytes, to: endpoint)
        }
    }
}
