import Foundation
import LocalAuthentication
import Network
import Security

@available(macOS 26.0, *)
enum SpikeError: Error, CustomStringConvertible {
    case missingArgument(String)
    case invalidPort(String)
    case keychainIdentityNotFound(String, OSStatus)
    case unableToCreateProtocolIdentity
    case timeout(String)
    case connectionFailed(String)

    var description: String {
        switch self {
        case .missingArgument(let name):
            return "missing required argument: \(name)"
        case .invalidPort(let value):
            return "invalid port: \(value)"
        case .keychainIdentityNotFound(let label, let status):
            return "keychain identity not found for label '\(label)' (OSStatus \(status))"
        case .unableToCreateProtocolIdentity:
            return "unable to create sec_identity_t from SecIdentity"
        case .timeout(let operation):
            return "timed out waiting for \(operation)"
        case .connectionFailed(let state):
            return "connection failed: \(state)"
        }
    }
}

@available(macOS 26.0, *)
struct Arguments {
    var command: String
    var port: NWEndpoint.Port = 9443
    var identityLabel: String?
    var timeoutSeconds: UInt64 = 10

    init(_ rawArguments: [String]) throws {
        var args = Array(rawArguments.dropFirst())
        command = args.first ?? "capabilities"
        if !args.isEmpty {
            args.removeFirst()
        }

        while let option = args.first {
            args.removeFirst()
            switch option {
            case "--port":
                guard let value = args.first else { throw SpikeError.missingArgument("--port") }
                args.removeFirst()
                guard let numericPort = UInt16(value) else { throw SpikeError.invalidPort(value) }
                port = NWEndpoint.Port(rawValue: numericPort)!
            case "--identity-label":
                guard let value = args.first else { throw SpikeError.missingArgument("--identity-label") }
                args.removeFirst()
                identityLabel = value
            case "--timeout":
                guard let value = args.first else { throw SpikeError.missingArgument("--timeout") }
                args.removeFirst()
                guard let seconds = UInt64(value), seconds > 0 else { throw SpikeError.invalidPort(value) }
                timeoutSeconds = seconds
            default:
                throw SpikeError.missingArgument("unknown option \(option)")
            }
        }
    }
}

@available(macOS 26.0, *)
@main
enum AppleQUICSpike {
    static func main() async {
        do {
            let arguments = try Arguments(CommandLine.arguments)
            switch arguments.command {
            case "capabilities":
                printCapabilities()
            case "loopback":
                try await runLoopback(arguments: arguments)
            default:
                printUsage()
                throw SpikeError.missingArgument("command")
            }
        } catch {
            print("AppleQUICSpike error: \(error)")
            exit(1)
        }
    }

    static func printUsage() {
        print("""
        Usage:
          swift run AppleQUICSpike capabilities
          swift run AppleQUICSpike loopback --identity-label <keychain-label> [--port 9443] [--timeout 10]
        """)
    }

    static func log(_ message: String) {
        fputs("\(message)\n", stderr)
    }

    static func printCapabilities() {
        print("Apple QUIC spike capabilities:")
        print("- QUIC protocol stack: Network.QUIC")
        print("- QUIC ALPN: configured with h3")
        print("- Listener: NetworkListener<QUIC>")
        print("- Client connection: NetworkConnection<QUIC>")
        print("- Bidirectional streams: NetworkConnection<QUIC>.openStream(.bidirectional)")
        print("- Unidirectional streams: NetworkConnection<QUIC>.openStream(.unidirectional)")
        print("- Inbound streams: NetworkConnection<QUIC>.inboundStreams")
        print("- Datagrams: NetworkConnection<QUIC>.datagrams")
        print("- TLS identity: Security.sec_identity_t via keychain SecIdentity")
        print("- External dependencies: none")
    }

    static func runLoopback(arguments: Arguments) async throws {
        guard let identityLabel = arguments.identityLabel else {
            throw SpikeError.missingArgument("--identity-label")
        }

        log("identity.loading label=\(identityLabel)")
        let identity = try loadProtocolIdentity(label: identityLabel)
        log("identity.loaded")
        log("listener.creating port=\(arguments.port)")
        let server = try QUICLoopbackServer(port: arguments.port, identity: identity)
        let timeoutNanoseconds = arguments.timeoutSeconds * 1_000_000_000

        log("listener.starting")
        let serverTask = Task {
            try await server.run()
        }
        defer {
            serverTask.cancel()
        }

        try await withTimeout(nanoseconds: timeoutNanoseconds, operation: "listener readiness") {
            try await server.waitUntilReady()
        }

        log("server.ready port=\(arguments.port)")
        let client = QUICLoopbackClient(port: arguments.port)
        log("client.starting")
        try await withTimeout(nanoseconds: timeoutNanoseconds, operation: "client loopback") {
            try await client.run()
        }

        log("loopback.complete")
    }

    static func loadProtocolIdentity(label: String) throws -> sec_identity_t {
        let authenticationContext = LAContext()
        authenticationContext.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationContext as String: authenticationContext
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let identities = item as? [SecIdentity] else {
            throw SpikeError.keychainIdentityNotFound(label, status)
        }

        guard let identity = identities.first(where: { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate else {
                return false
            }
            return SecCertificateCopySubjectSummary(certificate) as String? == label
        }) else {
            throw SpikeError.keychainIdentityNotFound(label, errSecItemNotFound)
        }

        guard let protocolIdentity = sec_identity_create(identity) else {
            throw SpikeError.unableToCreateProtocolIdentity
        }

        return protocolIdentity
    }

    static func makeServerQUIC(identity: sec_identity_t) -> QUIC {
        var quic = QUIC(alpn: ["h3"]) {
            UDP()
        }
            .idleTimeout(30_000)
            .initialMaxData(1_048_576)
            .initialMaxStreamDataBidirectionalLocal(262_144)
            .initialMaxStreamDataBidirectionalRemote(262_144)
            .initialMaxStreamDataUnidirectional(262_144)
            .initialMaxBidirectionalStreams(16)
            .initialMaxUnidirectionalStreams(16)
            .maxDatagramFrameSize(1_200)
        quic = quic.tls.localIdentity(identity)
        quic = quic.tls.peerAuthentication(.none)
        return quic
    }

    static func makeClientQUIC() -> QUIC {
        var quic = QUIC(alpn: ["h3"]) {
            UDP()
        }
            .idleTimeout(30_000)
            .initialMaxData(1_048_576)
            .initialMaxStreamDataBidirectionalLocal(262_144)
            .initialMaxStreamDataBidirectionalRemote(262_144)
            .initialMaxStreamDataUnidirectional(262_144)
            .initialMaxBidirectionalStreams(16)
            .initialMaxUnidirectionalStreams(16)
            .maxDatagramFrameSize(1_200)
        quic = quic.tls.certificateValidator { _, _ in
            true
        }
        return quic
    }

    static func withTimeout<T: Sendable>(
        nanoseconds: UInt64,
        operation: String,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await body()
            }
            group.addTask {
                log("timeout.started operation=\(operation)")
                try await Task.sleep(nanoseconds: nanoseconds)
                log("timeout.fired operation=\(operation)")
                throw SpikeError.timeout(operation)
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

@available(macOS 26.0, *)
actor ReadySignal {
    private var ready = false
    private var failure: Error?
    private var continuations: [CheckedContinuation<Void, Error>] = []

    func markReady() {
        guard !ready else { return }
        ready = true
        let current = continuations
        continuations.removeAll()
        current.forEach { $0.resume() }
    }

    func markFailed(_ error: Error) {
        guard failure == nil else { return }
        failure = error
        let current = continuations
        continuations.removeAll()
        current.forEach { $0.resume(throwing: error) }
    }

    func wait() async throws {
        if ready {
            return
        }
        if let failure {
            throw failure
        }
        try await withCheckedThrowingContinuation { continuation in
            continuations.append(continuation)
        }
    }
}

@available(macOS 26.0, *)
struct QUICLoopbackServer {
    private let listener: NetworkListener<QUIC>
    private let readySignal: ReadySignal

    init(port: NWEndpoint.Port, identity: sec_identity_t) throws {
        let signal = ReadySignal()
        readySignal = signal
        let parameters = NWParametersBuilder
            .parameters { AppleQUICSpike.makeServerQUIC(identity: identity) }
            .localPort(port)
            .localOnly(true)
        listener = try NetworkListener<QUIC>(using: parameters)
        listener.onStateUpdate { _, state in
            AppleQUICSpike.log("listener.state=\(state)")
            Task {
                switch state {
                case .ready:
                    await signal.markReady()
                case .failed(let error):
                    await signal.markFailed(error)
                case .cancelled:
                    await signal.markFailed(SpikeError.connectionFailed("listener cancelled"))
                default:
                    break
                }
            }
        }
    }

    func waitUntilReady() async throws {
        try await readySignal.wait()
    }

    func run() async throws {
        try await listener.run { connection in
            AppleQUICSpike.log("server.accepted alpn=\(connection.negotiatedALPN ?? "none")")
            try await handle(connection: connection)
        }
    }

    private func handle(connection: NetworkConnection<QUIC>) async throws {
        AppleQUICSpike.log("server.connection.handling")
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await handleDatagramEcho(connection: connection)
            }
            group.addTask {
                try await connection.inboundStreams { stream in
                    try await handleInboundStream(stream)
                }
            }
            try await group.next()
            group.cancelAll()
        }
    }

    private func handleDatagramEcho(connection: NetworkConnection<QUIC>) async throws {
        AppleQUICSpike.log("server.datagram.waiting")
        let datagrams = try await connection.datagrams
        let message = try await datagrams.receive()
        AppleQUICSpike.log("server.datagram.received bytes=\(message.content.count)")
        try await datagrams.send(Data("datagram-echo".utf8))
        AppleQUICSpike.log("server.datagram.sent")
    }

    private func handleInboundStream(_ stream: QUIC.Stream<QUICStream>) async throws {
        AppleQUICSpike.log("server.stream.accepted id=\(stream.streamID) direction=\(stream.directionality)")
        let message = try await stream.receive(atMost: 4_096)
        let text = String(decoding: message.content, as: UTF8.self)
        AppleQUICSpike.log("server.stream.received id=\(stream.streamID) direction=\(stream.directionality) bytes=\(message.content.count)")

        if stream.directionality == .bidirectional {
            try await stream.send(Data("bidi-echo:\(text)".utf8), endOfStream: true)
            AppleQUICSpike.log("server.stream.sent id=\(stream.streamID)")
        }
    }
}

@available(macOS 26.0, *)
struct QUICLoopbackClient {
    let port: NWEndpoint.Port

    func run() async throws {
        let endpoint = NWEndpoint.hostPort(host: "localhost", port: port)
        try await withNetworkConnection(to: endpoint) {
            AppleQUICSpike.makeClientQUIC()
        } _: { connection in
            AppleQUICSpike.log("client.connection.start")
            _ = connection.start()
            AppleQUICSpike.log("client.connection.started")
            AppleQUICSpike.log("client.connection.ready alpn=\(connection.negotiatedALPN ?? "none")")
            AppleQUICSpike.log("client.connection.remoteMaxBidi=\(connection.remoteMaxStreamsBidirectional)")
            AppleQUICSpike.log("client.connection.remoteMaxUni=\(connection.remoteMaxStreamsUnidirectional)")
            AppleQUICSpike.log("client.connection.usableDatagramFrameSize=\(connection.usableDatagramFrameSize)")
            try await waitForTransportParameters(connection: connection)
            try await probeBidirectionalStream(connection: connection)
            try await probeUnidirectionalStream(connection: connection)
            try await probeDatagram(connection: connection)
            connection.applicationError = .init(code: 0)
        }
    }

    private func waitForTransportParameters(connection: NetworkConnection<QUIC>) async throws {
        for attempt in 1...100 {
            let remoteBidi = connection.remoteMaxStreamsBidirectional
            let remoteUni = connection.remoteMaxStreamsUnidirectional
            let datagramSize = connection.usableDatagramFrameSize
            if remoteBidi > 0, remoteUni > 0, datagramSize > 0 {
                AppleQUICSpike.log("client.transport.ready attempt=\(attempt) remoteMaxBidi=\(remoteBidi) remoteMaxUni=\(remoteUni) datagramFrameSize=\(datagramSize) alpn=\(connection.negotiatedALPN ?? "none")")
                return
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }

        throw SpikeError.timeout("QUIC transport parameter negotiation")
    }

    private func probeBidirectionalStream(connection: NetworkConnection<QUIC>) async throws {
        AppleQUICSpike.log("client.bidi.opening")
        let stream = try await connection.openStream(directionality: .bidirectional)
        AppleQUICSpike.log("client.bidi.opened id=\(stream.streamID)")
        try await stream.send(Data("bidi-ping".utf8))
        AppleQUICSpike.log("client.bidi.sent")
        let response = try await stream.receive(atMost: 4_096)
        AppleQUICSpike.log("client.bidi.received id=\(stream.streamID) bytes=\(response.content.count)")
    }

    private func probeUnidirectionalStream(connection: NetworkConnection<QUIC>) async throws {
        AppleQUICSpike.log("client.uni.opening")
        let stream = try await connection.openStream(directionality: .unidirectional)
        AppleQUICSpike.log("client.uni.opened id=\(stream.streamID)")
        try await stream.send(Data("uni-ping".utf8), endOfStream: true)
        AppleQUICSpike.log("client.uni.sent id=\(stream.streamID)")
    }

    private func probeDatagram(connection: NetworkConnection<QUIC>) async throws {
        AppleQUICSpike.log("client.datagram.opening")
        let datagrams = try await connection.datagrams
        AppleQUICSpike.log("client.datagram.usableFrameSize=\(connection.usableDatagramFrameSize)")
        try await datagrams.send(Data("datagram-ping".utf8))
        AppleQUICSpike.log("client.datagram.sent")
        let response = try await datagrams.receive()
        AppleQUICSpike.log("client.datagram.received bytes=\(response.content.count)")
    }
}
