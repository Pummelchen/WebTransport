import Foundation
import Network
import Security

#if !arch(arm64)
#error("WebTransport Swift supports Apple Silicon arm64 only. Intel/x86_64 builds are unsupported.")
#endif

@available(macOS 26.0, *)
@main
enum AppleQUICSpike {
    static func main() async {
        setbuf(stdout, nil)
        do {
            let arguments = CommandLine.arguments.dropFirst()
            if arguments.contains("--loopback") {
                try await LoopbackProbe(timeoutSeconds: 12).run()
            } else {
                printCapabilities()
                print("")
                print("Run `swift run AppleQUICSpike --loopback` to execute the prompt-free localhost QUIC proof.")
            }
        } catch {
            fputs("AppleQUICSpike failed: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    static func printCapabilities() {
        let quic = makeClientQUIC()
        _ = quic

        print("Apple QUIC spike capabilities:")
        print("- QUIC protocol stack: Network.QUIC")
        print("- QUIC ALPN: configured with h3")
        print("- Listener type: NetworkListener<QUIC>")
        print("- Client connection type: NetworkConnection<QUIC>")
        print("- Bidirectional streams: NetworkConnection<QUIC>.openStream(.bidirectional)")
        print("- Unidirectional streams: NetworkConnection<QUIC>.openStream(.unidirectional)")
        print("- Inbound streams: NetworkConnection<QUIC>.inboundStreams")
        print("- Datagrams: NetworkConnection<QUIC>.datagrams")
        print("- Runtime TLS identity: in-memory SecIdentity built from a non-persistent SecKey and generated certificate")
        print("- Security prompts: none; no keychain, LocalAuthentication, certificate import, or private-key authorization UI")
        print("- External dependencies: none")
    }

    static func makeBaseQUIC() -> QUIC {
        QUIC(alpn: ["h3"]) {
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
    }

    static func makeClientQUIC() -> QUIC {
        makeBaseQUIC().tls.certificateValidator { _, _ in
            true
        }
    }

    static func makeServerQUIC(identity: sec_identity_t) -> QUIC {
        makeBaseQUIC()
            .tls.localIdentity(identity)
            .tls.peerAuthentication(.none)
    }

    static func compileTimeAPIReferences(
        listener: NetworkListener<QUIC>,
        connection: NetworkConnection<QUIC>
    ) async throws {
        _ = listener.port
        _ = connection.negotiatedALPN
        _ = connection.remoteMaxStreamsBidirectional
        _ = connection.remoteMaxStreamsUnidirectional
        _ = connection.usableDatagramFrameSize
        _ = try await connection.openStream(directionality: .bidirectional)
        _ = try await connection.openStream(directionality: .unidirectional)
        _ = try await connection.datagrams
        try await connection.inboundStreams { stream in
            _ = stream.streamID
            _ = stream.directionality
            _ = stream.initiator
        }
    }
}

@available(macOS 26.0, *)
private struct LoopbackProbe {
    let timeoutSeconds: UInt64

    func run() async throws {
        let identity = try InMemoryTLSIdentity.make()
        let serverParameters = NWParametersBuilder(auto: {
            AppleQUICSpike.makeServerQUIC(identity: identity)
        })
        .localEndpoint(.hostPort(host: .ipv4(.loopback), port: .any))
        .localOnly(true)
        let listener = try NetworkListener<QUIC>(using: serverParameters)
            .newConnectionLimit(1)

        let server = ServerProbe(listener: listener)
        let serverTask = Task {
            try await server.run()
        }
        defer {
            serverTask.cancel()
        }

        let port = try await withTimeout(seconds: timeoutSeconds) {
            try await server.waitForPort()
        }
        print("listener: ready on 127.0.0.1:\(port.rawValue)")

        let endpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: port)
        let clientConnection = NetworkConnection(to: endpoint) {
            AppleQUICSpike.makeClientQUIC()
        }
        print("client: initial state \(clientConnection.state)")
        clientConnection.onStateUpdate { _, state in
            print("client: state \(state)")
        }
        _ = clientConnection.start()
        print("client: after start state \(clientConnection.state)")

        try await withTimeout(seconds: timeoutSeconds) {
            try await proveBidirectionalStream(clientConnection: clientConnection, server: server)
        }

        let serverConnection = try await withTimeout(seconds: timeoutSeconds) {
            try await server.waitForConnection()
        }
        serverConnection.onStateUpdate { _, state in
            print("server: state \(state)")
        }
        try await withTimeout(seconds: timeoutSeconds) {
            try await waitForReady(serverConnection)
        }
        print("server: accepted QUIC connection")

        try assertEqual(clientConnection.negotiatedALPN, "h3", "client ALPN")
        try assertEqual(serverConnection.negotiatedALPN, "h3", "server ALPN")
        print("alpn: h3 negotiated")

        try await proveUnidirectionalStream(clientConnection: clientConnection, server: server)
        try await proveCloseAndReset(clientConnection: clientConnection)
        try proveDraftPrefixControls(clientConnection: clientConnection)

        print("close: application error code property is exposed; runtime mutation is not safe to claim yet")
        try await proveDatagrams(clientConnection: clientConnection, serverConnection: serverConnection)
        print("phase1: all runtime checks passed without security prompts")
    }

    private func waitForReady(_ connection: NetworkConnection<QUIC>) async throws {
        if connection.state == .ready {
            return
        }

        try await withCheckedThrowingContinuation { continuation in
            let resume = OneShotContinuation()
            connection.onStateUpdate { _, state in
                Task {
                    await resume.complete {
                        switch state {
                        case .ready:
                            continuation.resume()
                        case .failed(let error):
                            continuation.resume(throwing: ProbeError.networkFailed("\(error)"))
                        case .cancelled:
                            continuation.resume(throwing: ProbeError.networkFailed("cancelled"))
                        default:
                            break
                        }
                    }
                }
            }
        }
    }

    private func proveBidirectionalStream(clientConnection: NetworkConnection<QUIC>, server: ServerProbe) async throws {
        let inbound = Task {
            try await server.waitForInboundStream(directionality: .bidirectional)
        }

        let stream = try await clientConnection.openStream(directionality: .bidirectional)
        try await stream.send(Data("client-bidi".utf8), endOfStream: false)

        let serverStream = try await inbound.value
        let received = try await serverStream.receive(atMost: 64).content
        try assertEqual(String(decoding: received, as: UTF8.self), "client-bidi", "bidirectional stream payload")

        try await serverStream.send(Data("server-bidi".utf8), endOfStream: false)
        let echo = try await stream.receive(atMost: 64).content
        try assertEqual(String(decoding: echo, as: UTF8.self), "server-bidi", "bidirectional stream echo")
        print("streams: client bidirectional stream opened and echoed")
    }

    private func proveUnidirectionalStream(clientConnection: NetworkConnection<QUIC>, server: ServerProbe) async throws {
        let inbound = Task {
            try await server.waitForInboundStream(directionality: .unidirectional)
        }

        let stream = try await clientConnection.openStream(directionality: .unidirectional)
        try await stream.send(Data([0x54, 0x41, 0x00]), endOfStream: false)

        let serverStream = try await inbound.value
        let received = try await serverStream.receive(atMost: 64).content
        try assertEqual(Array(received), [0x54, 0x41, 0x00], "unidirectional stream payload")
        print("streams: client unidirectional stream opened and accepted")
    }

    private func proveDatagrams(
        clientConnection: NetworkConnection<QUIC>,
        serverConnection: NetworkConnection<QUIC>
    ) async throws {
        print("datagrams: usable sizes client=\(clientConnection.usableDatagramFrameSize) server=\(serverConnection.usableDatagramFrameSize)")
        guard clientConnection.usableDatagramFrameSize > 0,
              serverConnection.usableDatagramFrameSize > 0 else {
            throw ProbeError.runtimeUnsupported("QUIC datagrams negotiated usable size 0")
        }

        let serverDatagrams = try await serverConnection.datagrams
        let clientDatagrams = try await clientConnection.datagrams

        try await clientDatagrams.send(Data("client-datagram".utf8))
        let serverReceived = try await serverDatagrams.receive().content
        try assertEqual(String(decoding: serverReceived, as: UTF8.self), "client-datagram", "client datagram payload")

        try await serverDatagrams.send(Data("server-datagram".utf8))
        let clientReceived = try await clientDatagrams.receive().content
        try assertEqual(String(decoding: clientReceived, as: UTF8.self), "server-datagram", "server datagram payload")
        print("datagrams: bidirectional datagram send and receive proved")
    }

    private func proveCloseAndReset(clientConnection: NetworkConnection<QUIC>) async throws {
        let stream = try await clientConnection.openStream(directionality: .bidirectional)
        stream.streamApplicationErrorCode = 0x54
        try await stream.send(Data("reset-candidate".utf8), endOfStream: true)
        print("reset: stream FIN path exercised; stream application error code setter is exposed")
    }

    private func proveDraftPrefixControls(clientConnection: NetworkConnection<QUIC>) throws {
        guard clientConnection.remoteMaxStreamsBidirectional > 0 else {
            throw ProbeError.runtimeUnsupported("remote bidirectional stream limit is 0")
        }
        guard clientConnection.remoteMaxStreamsUnidirectional > 0 else {
            throw ProbeError.runtimeUnsupported("remote unidirectional stream limit is 0")
        }

        let draftStreamType = HTTP3Varint.encode(0x54)
        let draftSessionID = HTTP3Varint.encode(0)
        guard draftStreamType == Data([0x40, 0x54]),
              draftSessionID == Data([0x00]) else {
            throw ProbeError.runtimeUnsupported("HTTP/3 varint prefix encoding check failed")
        }
        print("draft: stream controls can carry HTTP/3 stream type 0x54 and WebTransport session prefix")
    }
}

@available(macOS 26.0, *)
private actor ServerProbe {
    private let listener: NetworkListener<QUIC>
    private var portContinuation: CheckedContinuation<NWEndpoint.Port, Error>?
    private var connectionContinuation: CheckedContinuation<NetworkConnection<QUIC>, Error>?
    private var inboundContinuations: [QUICStream.Directionality: [CheckedContinuation<QUIC.Stream<QUICStream>, Error>]] = [:]
    private var readyPort: NWEndpoint.Port?
    private var acceptedConnection: NetworkConnection<QUIC>?
    private var inboundStreams: [QUICStream.Directionality: [QUIC.Stream<QUICStream>]] = [:]

    init(listener: NetworkListener<QUIC>) {
        self.listener = listener
    }

    func run() async throws {
        listener.onStateUpdate { listener, state in
            Task {
                self.handleListenerState(listener, state)
            }
        }

        try await listener.run { connection in
            self.accept(connection)
            try await connection.inboundStreams { stream in
                self.accept(stream)
            }
        }
    }

    func waitForPort() async throws -> NWEndpoint.Port {
        if let readyPort {
            return readyPort
        }

        return try await withCheckedThrowingContinuation { continuation in
            portContinuation = continuation
        }
    }

    func waitForConnection() async throws -> NetworkConnection<QUIC> {
        if let acceptedConnection {
            return acceptedConnection
        }

        return try await withCheckedThrowingContinuation { continuation in
            connectionContinuation = continuation
        }
    }

    func waitForInboundStream(directionality: QUICStream.Directionality) async throws -> QUIC.Stream<QUICStream> {
        if var streams = inboundStreams[directionality], !streams.isEmpty {
            let stream = streams.removeFirst()
            inboundStreams[directionality] = streams
            return stream
        }

        return try await withCheckedThrowingContinuation { continuation in
            inboundContinuations[directionality, default: []].append(continuation)
        }
    }

    private func handleListenerState(_ listener: NetworkListener<QUIC>, _ state: NetworkListener<QUIC>.State) {
        switch state {
        case .ready:
            guard let port = listener.port else {
                portContinuation?.resume(throwing: ProbeError.networkFailed("listener ready without port"))
                portContinuation = nil
                return
            }
            readyPort = port
            portContinuation?.resume(returning: port)
            portContinuation = nil
        case .failed(let error):
            portContinuation?.resume(throwing: ProbeError.networkFailed("\(error)"))
            portContinuation = nil
            connectionContinuation?.resume(throwing: ProbeError.networkFailed("\(error)"))
            connectionContinuation = nil
        case .cancelled:
            portContinuation?.resume(throwing: ProbeError.networkFailed("listener cancelled"))
            portContinuation = nil
            connectionContinuation?.resume(throwing: ProbeError.networkFailed("listener cancelled"))
            connectionContinuation = nil
        default:
            break
        }
    }

    private func accept(_ connection: NetworkConnection<QUIC>) {
        acceptedConnection = connection
        connectionContinuation?.resume(returning: connection)
        connectionContinuation = nil
    }

    private func accept(_ stream: QUIC.Stream<QUICStream>) {
        let directionality = stream.directionality
        if var continuations = inboundContinuations[directionality], !continuations.isEmpty {
            let continuation = continuations.removeFirst()
            inboundContinuations[directionality] = continuations
            continuation.resume(returning: stream)
        } else {
            inboundStreams[directionality, default: []].append(stream)
        }
    }
}

private enum HTTP3Varint {
    static func encode(_ value: UInt64) -> Data {
        switch value {
        case 0..<64:
            return Data([UInt8(value)])
        case 0..<16_384:
            return Data([
                UInt8((value >> 8) | 0x40),
                UInt8(value & 0xff)
            ])
        case 0..<1_073_741_824:
            return Data([
                UInt8((value >> 24) | 0x80),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ])
        default:
            return Data([
                UInt8((value >> 56) | 0xc0),
                UInt8((value >> 48) & 0xff),
                UInt8((value >> 40) & 0xff),
                UInt8((value >> 32) & 0xff),
                UInt8((value >> 24) & 0xff),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ])
        }
    }
}

private enum InMemoryTLSIdentity {
    static func make() throws -> sec_identity_t {
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2_048,
            kSecAttrIsPermanent: false
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw ProbeError.securityFailed(error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateRandomKey failed")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw ProbeError.securityFailed("SecKeyCopyPublicKey failed")
        }
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw ProbeError.securityFailed(error?.takeRetainedValue().localizedDescription ?? "SecKeyCopyExternalRepresentation failed")
        }

        let certificateDER = try SelfSignedCertificate.make(privateKey: privateKey, rsaPublicKeyDER: publicKeyData)
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw ProbeError.securityFailed("SecCertificateCreateWithData rejected generated certificate")
        }
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw ProbeError.securityFailed("SecIdentityCreate failed")
        }
        guard let networkIdentity = sec_identity_create_with_certificates(identity, [certificate] as CFArray) else {
            throw ProbeError.securityFailed("sec_identity_create_with_certificates failed")
        }
        return networkIdentity
    }
}

private enum SelfSignedCertificate {
    static func make(privateKey: SecKey, rsaPublicKeyDER: Data) throws -> Data {
        let signatureAlgorithm = DER.sequence([
            DER.objectIdentifier([1, 2, 840, 113_549, 1, 1, 11]),
            DER.null()
        ])
        let rsaAlgorithm = DER.sequence([
            DER.objectIdentifier([1, 2, 840, 113_549, 1, 1, 1]),
            DER.null()
        ])
        let name = DER.sequence([
            DER.set([
                DER.sequence([
                    DER.objectIdentifier([2, 5, 4, 3]),
                    DER.utf8String("localhost")
                ])
            ])
        ])
        let validity = DER.sequence([
            DER.utcTime(Date(timeIntervalSinceNow: -60)),
            DER.utcTime(Date(timeIntervalSinceNow: 86_400))
        ])
        let subjectPublicKeyInfo = DER.sequence([
            rsaAlgorithm,
            DER.bitString(rsaPublicKeyDER)
        ])
        let extensions = DER.explicit(3, DER.sequence([
            DER.sequence([
                DER.objectIdentifier([2, 5, 29, 19]),
                DER.boolean(true),
                DER.octetString(DER.sequence([DER.boolean(false)]))
            ]),
            DER.sequence([
                DER.objectIdentifier([2, 5, 29, 15]),
                DER.boolean(true),
                DER.octetString(DER.bitString(Data([0xa0]), unusedBits: 5))
            ]),
            DER.sequence([
                DER.objectIdentifier([2, 5, 29, 37]),
                DER.octetString(DER.sequence([
                    DER.objectIdentifier([1, 3, 6, 1, 5, 5, 7, 3, 1])
                ]))
            ]),
            DER.sequence([
                DER.objectIdentifier([2, 5, 29, 17]),
                DER.octetString(DER.sequence([
                    DER.contextSpecificPrimitive(2, Data("localhost".utf8))
                ]))
            ])
        ]))

        let tbsCertificate = DER.sequence([
            DER.explicit(0, DER.integer(Data([0x02]))),
            DER.integer(randomSerial()),
            signatureAlgorithm,
            name,
            validity,
            name,
            subjectPublicKeyInfo,
            extensions
        ])

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            tbsCertificate as CFData,
            &error
        ) as Data? else {
            throw ProbeError.securityFailed(error?.takeRetainedValue().localizedDescription ?? "SecKeyCreateSignature failed")
        }

        return DER.sequence([
            tbsCertificate,
            signatureAlgorithm,
            DER.bitString(signature)
        ])
    }

    private static func randomSerial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            bytes = Array(UUID().uuidString.utf8.prefix(16))
        }
        bytes[0] &= 0x7f
        if bytes.allSatisfy({ $0 == 0 }) {
            bytes[0] = 1
        }
        return Data(bytes)
    }
}

private enum DER {
    static func sequence(_ parts: [Data]) -> Data {
        tagged(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: [Data]) -> Data {
        tagged(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func explicit(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0xa0 + tag, content)
    }

    static func contextSpecificPrimitive(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0x80 + tag, content)
    }

    static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1, bytes[0] == 0, bytes[1] < 0x80 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tagged(0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func objectIdentifier(_ components: [UInt64]) -> Data {
        precondition(components.count >= 2)
        var bytes = [UInt8(components[0] * 40 + components[1])]
        for component in components.dropFirst(2) {
            var encoded = [UInt8(component & 0x7f)]
            var value = component >> 7
            while value > 0 {
                encoded.insert(UInt8(value & 0x7f) | 0x80, at: 0)
                value >>= 7
            }
            bytes.append(contentsOf: encoded)
        }
        return tagged(0x06, Data(bytes))
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func utcTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tagged(0x17, Data(formatter.string(from: value).utf8))
    }

    private static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    private static func length(_ count: Int) -> Data {
        if count < 128 {
            return Data([UInt8(count)])
        }

        var value = count
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

private enum ProbeError: Error, CustomStringConvertible {
    case timeout(UInt64)
    case networkFailed(String)
    case securityFailed(String)
    case runtimeUnsupported(String)
    case assertionFailed(String)

    var description: String {
        switch self {
        case .timeout(let seconds):
            "operation timed out after \(seconds)s"
        case .networkFailed(let message):
            "network failed: \(message)"
        case .securityFailed(let message):
            "security failed: \(message)"
        case .runtimeUnsupported(let message):
            "runtime unsupported: \(message)"
        case .assertionFailed(let message):
            "assertion failed: \(message)"
        }
    }
}

private actor OneShotContinuation {
    private var completed = false

    func complete(_ operation: () -> Void) {
        guard !completed else {
            return
        }
        completed = true
        operation()
    }
}

private func assertEqual<T: Equatable>(_ actual: T, _ expected: T, _ label: String) throws {
    guard actual == expected else {
        throw ProbeError.assertionFailed("\(label): expected \(expected), got \(actual)")
    }
}

private func withTimeout<T: Sendable>(seconds: UInt64, operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        let box = TimeoutContinuationBox(continuation)
        let operationTask = Task {
            do {
                let result = try await operation()
                _ = box.resume(.success(result))
            } catch {
                _ = box.resume(.failure(error))
            }
        }

        Task {
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            if box.resume(.failure(ProbeError.timeout(seconds))) {
                operationTask.cancel()
            }
        }
    }
}

private final class TimeoutContinuationBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<T, Error>) -> Bool {
        lock.lock()
        defer {
            lock.unlock()
        }

        guard let continuation else {
            return false
        }
        self.continuation = nil
        continuation.resume(with: result)
        return true
    }
}
